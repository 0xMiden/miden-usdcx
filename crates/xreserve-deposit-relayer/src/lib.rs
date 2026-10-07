//! Relays Circle xReserve deposit attestations to the xUSDC faucet.
//!
//! The unit of work is a **scan**: one pass over the part of the feed that is newer than the
//! watermark. It starts at the head of the feed, follows the `next` link into the past, and stops
//! at the watermark — or, on a first run that has none, at the oldest entry in the feed. When the
//! pass completes the watermark moves to where it started, so the next scan covers whatever grew
//! above it in the meantime.
//!
//! A scan is a pass rather than a process lifetime. Progress is persisted page by page, so one
//! interrupted part way through resumes where it stopped instead of starting over.
//! [`Relayer::run`] begins a scan every polling interval; a relayer that is caught up meets the
//! watermark at the top of the head page and ends the scan after that one request.
//!
//! Each scan is a `relayer.scan` root span, and each page it walks is a `relayer.page` span under
//! it. A page fails when anything stops it being recorded as done; the scan it stopped fails with
//! it. An attestation that will not build fails only the `relayer.build_notes` span that skipped
//! it, and the page counts it in `attestations.skipped.count`.

use anyhow::{Context, Result};
use miden_protocol::note::Note;
use tokio_util::sync::CancellationToken;
use tracing::field::Empty;
use tracing::{error, info, info_span, instrument, warn, Instrument as _, Span};
use usdcx_telemetry::{FailureClass, FailureSpanExt as _};

pub mod circle;
pub mod config;
pub mod failure;
pub mod miden;
pub mod mint;
pub mod store;

use circle::{Attestation, CircleClient, CircleCursor, MessageHash};
use config::Config;
use failure::{Classify, Failure};
use miden::{MidenClient, NodeClient};
use mint::{BuiltNotes, Minter};
use store::{ScanProgress, State, Store};

/// The relay loop's parts: the Circle feed, the store holding how far the scan got, the note
/// builder, and the Miden client that lands the notes on chain.
pub struct Relayer<M> {
    config: Config,
    circle: CircleClient,
    store: Store,
    miden_client: M,
    minter: Minter,
}

/// Renders the identifiers of a page's items as one tracing field, so a page's trace names every
/// deposit it carried rather than only counting them. The traffic this service handles is low
/// enough that the whole list fits in the trace.
fn identifiers(ids: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", ids.into_iter().collect::<Vec<_>>().join(", "))
}

/// What one page left for the scan to do next, once that page is on chain.
struct PageOutcome {
    /// The newest attestation on this page, or `None` when the page held none.
    ///
    /// The scan uses it from the head page only — the one it fetches without a cursor — where it
    /// becomes the watermark once the walk finishes. `None` there means the feed is empty.
    newest: Option<MessageHash>,
    /// The cursor to fetch the next page with, which doubles as where to resume after an
    /// interruption. `None` when the scan has everything.
    next: Option<CircleCursor>,
}

#[derive(Debug, PartialEq, Eq)]
enum ScanOutcome {
    Complete,
    Stopped,
}

impl Relayer<NodeClient> {
    /// Connects to the configured node and assembles the relayer, in the `relayer.startup` span. A
    /// failure marks that span failed as `actionable`.
    ///
    /// # Errors
    ///
    /// - The node cannot be reached, does not know the relayer account or the faucet, or the
    ///   faucet has not enabled the configured attester public key (see [`NodeClient::new`]).
    /// - Any of the checks of [`Relayer::new`] fails.
    #[instrument(name = "relayer.startup", skip_all)]
    pub async fn start(config: Config) -> Result<Self> {
        let result = Self::connect(config).await;
        if let Err(error) = &result {
            Span::current().record_actionable_failure("startup");
            error!(error = %format_args!("{error:#}"), "relayer startup failed");
        }
        result
    }

    async fn connect(config: Config) -> Result<Self> {
        let miden = NodeClient::new(&config)
            .await
            .context("connecting to miden")?;
        Self::new(config, miden)
    }
}

impl<M: MidenClient> Relayer<M> {
    /// Assembles a relayer and checks its local progress can be read and saved before polling.
    ///
    /// # Errors
    ///
    /// - The Circle client cannot be built (see [`CircleClient::new`]).
    /// - The progress file is malformed or cannot be read or replaced.
    pub fn new(config: Config, miden_client: M) -> Result<Self> {
        let store = Store::new(config.state_file.clone());
        let state = store.state().context("reading relayer startup progress")?;
        // Save the same progress to exercise the normal write/sync/rename path without advancing it.
        store
            .set_state(&state)
            .context("checking relayer progress persistence")?;
        Ok(Self {
            circle: CircleClient::new(
                config.circle_url.clone(),
                config.page_size,
                config.request_timeout,
            )?,
            store,
            minter: Minter::from_config(&config),
            miden_client,
            config,
        })
    }

    /// Runs one scan, as the crate docs define it, resuming an interrupted one if there is one.
    ///
    /// The pass runs from the head of the feed into the past because that is the only direction
    /// Circle offers. Following the feed the other way would walk towards its oldest entry and
    /// never ask for the head again, which is where new deposits appear.
    ///
    /// The watermark is a stop condition rather than a starting point, so the first request of a
    /// fresh scan carries no cursor. See [`store`] for why a pagination token would not let the
    /// pass cover fewer pages.
    ///
    /// Each page is recorded as done, by cursor, only once its mint transactions are on chain. A
    /// resumed scan therefore finishes the walk it began before it takes on anything newer: the
    /// head it recorded when it started is what becomes the watermark, and the deposits that
    /// arrived in the meantime sit above that head for the scan after it. That keeps what has been
    /// handled one contiguous run of the feed, which is what lets a single watermark describe it.
    ///
    /// Every failure has already been logged, in the span it happened in, when this returns it.
    ///
    /// # Errors
    ///
    /// - Reading or persisting the state fails.
    /// - Fetching a Circle page fails.
    /// - Submitting the mint notes fails.
    async fn scan(&mut self, shutdown: &CancellationToken) -> Result<ScanOutcome, Failure> {
        let mut state = match self
            .store
            .state()
            .classify(FailureClass::Actionable, "progress_file")
        {
            Ok(state) => state,
            Err(failure) => {
                failure.report("could not read the relayer's progress");
                return Err(failure);
            }
        };

        loop {
            if shutdown.is_cancelled() {
                return Ok(ScanOutcome::Stopped);
            }
            let Some(next) = self.run_page(&state).await? else {
                // The feed is empty, so there is nothing for the next scan to stop at.
                return Ok(ScanOutcome::Complete);
            };
            if shutdown.is_cancelled() {
                return Ok(ScanOutcome::Stopped);
            }
            if next.scan.is_none() {
                return Ok(ScanOutcome::Complete);
            }
            state = next;
        }
    }

    /// Runs one page of the scan in its `relayer.page` span: mints it, then records it as done.
    /// Returns the state the scan continues from, or `None` when the feed is empty.
    ///
    /// A failure marks the page span failed and is logged inside it, so the span says why the page
    /// was not recorded as done.
    async fn run_page(&mut self, state: &State) -> Result<Option<State>, Failure> {
        let span = info_span!(
            "relayer.page",
            remote_domain = %self.config.remote_domain,
            cursor = Empty,
            attestations.count = Empty,
            attestations.message_hashes = Empty,
            attestations.skipped.count = Empty,
            attestations.skipped.message_hashes = Empty,
            notes.already_minted.count = Empty,
            notes.count = Empty,
            notes.ids = Empty,
            transaction.id = Empty,
        );
        async {
            // Boxed because the page's future, which holds the Miden client's, is deep enough that
            // nesting it in the scan's future exceeds the compiler's recursion limit.
            let result = Box::pin(self.finish_page(state)).await;
            if let Err(failure) = &result {
                failure.report("the page failed; the next scan resumes at it");
            }
            result
        }
        .instrument(span)
        .await
    }

    /// Processes the page `state` resumes at and saves the state that follows it.
    async fn finish_page(&mut self, state: &State) -> Result<Option<State>, Failure> {
        let outcome = self
            .process_page(
                state.scan.as_ref().map(|scan| &scan.resume),
                state.watermark.as_ref(),
            )
            .await?;

        // A scan that has progress keeps the head it started at, so a fresh scan reads the page's
        // newest attestation only on its first page — by the second it has written progress of
        // its own and the stored head wins.
        let Some(head) = state.scan.as_ref().map(|scan| scan.head).or(outcome.newest) else {
            return Ok(None);
        };

        // The watermark moves only when the walk reaches its end, and the progress it replaces is
        // dropped in the same write, so the file never claims both.
        let next = State {
            watermark: match outcome.next {
                Some(_) => state.watermark,
                None => Some(head),
            },
            scan: outcome.next.map(|resume| ScanProgress { head, resume }),
        };

        // A caught-up poll finds the watermark at the top of the first page and leaves the state
        // exactly as it was, which is not worth an fsync every polling interval.
        if next != *state {
            self.store
                .set_state(&next)
                .classify(FailureClass::Actionable, "progress_file")?;
        }
        Ok(Some(next))
    }

    /// Fetches one page and mints the attestations on it above the watermark.
    ///
    /// `resume` is the cursor of the page to fetch, which is `None` for the first page of a fresh
    /// scan and the stored progress for the page an interrupted scan stopped at.
    ///
    /// It records what it finds on the current span, which is the `relayer.page` span.
    ///
    /// Malformed attestations are skipped inside [`Minter::build_notes`], and deposits the faucet
    /// has already minted are dropped by [`MidenClient::retain_unminted`], so no proof is spent on a note
    /// the faucet would refuse. Every remaining note goes into one transaction, and the page is
    /// done only once [`MidenClient::submit_notes`] confirms that transaction is included on
    /// chain — so returning is what entitles the caller to record the page as done. One page to
    /// one transaction is what makes the retry of a failed page clean: there is no part of it that
    /// could already be on chain.
    ///
    /// # Errors
    ///
    /// - Fetching the page fails.
    /// - Reading which deposits are already minted fails.
    /// - Submitting the mint notes fails.
    async fn process_page(
        &mut self,
        resume: Option<&CircleCursor>,
        watermark: Option<&MessageHash>,
    ) -> Result<PageOutcome, Failure> {
        let span = Span::current();
        span.record("cursor", resume.map(CircleCursor::as_str).unwrap_or("None"));

        let page = self
            .circle
            .fetch_page(self.config.remote_domain, resume)
            .await?;
        span.record("attestations.count", page.attestations.len());
        span.record(
            "attestations.message_hashes",
            identifiers(
                page.attestations
                    .iter()
                    .map(|attestation| attestation.message_hash.to_string()),
            )
            .as_str(),
        );

        // The page runs newest to oldest, so the watermark — if it is on this page at all — ends
        // the scan, and everything above it arrived since the last scan.
        let reached = page
            .attestations
            .iter()
            .position(|attestation| Some(&attestation.message_hash) == watermark);
        let fresh: Vec<&Attestation> = page.attestations
            [..reached.unwrap_or(page.attestations.len())]
            .iter()
            .collect();

        let BuiltNotes { notes, skipped } = self.minter.build_notes(&fresh);
        span.record("attestations.skipped.count", skipped.len());
        span.record(
            "attestations.skipped.message_hashes",
            identifiers(skipped.iter().map(ToString::to_string)).as_str(),
        );
        let built = notes.len();

        // A deposit the faucet has already minted would only be refused, so it is dropped here
        // rather than proven. This is what makes a replay of the feed cheap.
        let notes = self.miden_client.retain_unminted(notes).await?;
        span.record("notes.already_minted.count", built - notes.len());

        // The minter yields its own note type; the chain takes protocol notes, so the page is
        // converted here, once, on its way to being submitted.
        let notes: Vec<Note> = notes.into_iter().map(Note::from).collect();
        span.record("notes.count", notes.len());
        span.record(
            "notes.ids",
            identifiers(notes.iter().map(|note| note.id().to_string())).as_str(),
        );

        if built == 0 && !fresh.is_empty() {
            warn!(fresh.count = fresh.len(), "page produced no mint notes");
        } else if notes.is_empty() && built > 0 {
            info!("every deposit on the page is already minted");
        } else if !notes.is_empty() {
            let transaction = self
                .miden_client
                .submit_notes(self.minter.mint_account(), notes)
                .await?;
            span.record("transaction.id", transaction.to_string().as_str());
            info!("page minted and on chain");
        }

        Ok(PageOutcome {
            newest: page.attestations.first().map(|first| first.message_hash),
            // Reaching the watermark ends the scan even though the feed continues below it:
            // everything below was handled by an earlier scan.
            next: match reached {
                Some(_) => None,
                None => page.next_cursor().cloned(),
            },
        })
    }

    /// Scans the feed indefinitely, pausing for the polling interval between scans.
    ///
    /// A failed scan leaves the watermark where it was, and the next one resumes at the page the
    /// failure stopped it on rather than repeating the pages already on chain.
    pub async fn run(self) -> Result<()> {
        // A token nothing cancels keeps the standalone relayer running.
        self.run_until(CancellationToken::new()).await
    }

    /// Runs until `shutdown` is cancelled.
    ///
    /// The current page finishes and its progress is saved before stopping. Waiting for a mint
    /// transaction can continue indefinitely if the chain stops producing blocks.
    pub async fn run_until(mut self, shutdown: CancellationToken) -> Result<()> {
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            // Each scan is a root of its own, so a long-running relayer is a series of traces rather
            // than one that never ends.
            let span = info_span!(parent: None, "relayer.scan");
            match self.scan(&shutdown).instrument(span.clone()).await {
                Ok(ScanOutcome::Stopped) => return Ok(()),
                Ok(ScanOutcome::Complete) => {}
                // The failure was logged in the span it happened in, and the next scan resumes
                // where this one stopped. This marks the scan as a whole failed.
                Err(failure) => span.record_error(&failure),
            }
            tokio::select! {
                () = tokio::time::sleep(self.config.poll_interval) => {}
                () = shutdown.cancelled() => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/shutdown.rs"]
mod shutdown_tests;
