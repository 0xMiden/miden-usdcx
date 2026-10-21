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
//! [`Relayer::run_until`] begins a scan every polling interval; a relayer that is caught up meets the
//! watermark at the top of the head page and ends the scan after that one request.
//!
//! Each scan is a `relayer.scan` root span, and each page it walks is a `relayer.page` span under
//! it. A page fails when anything stops it being recorded as done; the scan it stopped fails with
//! it. An entry that does not decode, or an attestation that will not build, fails only the
//! `relayer.build_notes` span that skipped it, and the page counts it in
//! `attestations.skipped.count`. Every page also reports the
//! deposits earlier pages put on chain that the faucet has not minted yet (see [`unminted`]).

use std::time::Instant;

use anyhow::{Context, Result};
use miden_protocol::note::Note;
use miden_usdcx::note::xreserve_mint::XUsdcMintNote;
use tokio_util::sync::CancellationToken;
use tracing::field::Empty;
use tracing::{info, instrument, warn, Span};
use usdcx_telemetry::FailureClass::Actionable;
use usdcx_telemetry::{Classify, Failure, FailureSpanExt as _};

pub mod circle;
pub mod config;
pub mod miden;
pub mod mint;
mod prover;
pub mod store;
mod unminted;

use circle::{CircleClient, CircleCursor, Entry, MessageHash};
use config::Config;
use miden::{MidenClient, NodeClient};
use mint::{BuiltNotes, Minter};
use store::{ScanProgress, State, Store};
use unminted::Unminted;

/// The relay loop's parts: the Circle feed, the store holding how far the scan got, the note
/// builder, and the Miden client that lands the notes on chain.
pub struct Relayer<M> {
    config: Config,
    circle: CircleClient,
    store: Store,
    miden_client: M,
    minter: Minter,
    unminted: Unminted,
}

/// Renders the identifiers of a page's items as one tracing field, so a page's trace names every
/// deposit it carried rather than only counting them. The traffic this service handles is low
/// enough that the whole list fits in the trace.
fn identifiers(ids: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", ids.into_iter().collect::<Vec<_>>().join(", "))
}

/// How an entry is named in a trace: by its message hash, when it has a readable one.
fn hash_or_unreadable(hash: Option<MessageHash>) -> String {
    hash.map_or_else(|| "unreadable".to_owned(), |hash| hash.to_string())
}

/// What one page left for the scan to do next, once that page is on chain.
struct PageOutcome {
    /// The newest entry on this page with a readable message hash, or `None` when the page held
    /// none.
    ///
    /// The scan uses it only until it has a head: the first page that has one gives the scan its
    /// head, which becomes the watermark once the walk finishes.
    newest: Option<MessageHash>,
    /// The cursor to fetch the next page with, which doubles as where to resume after an
    /// interruption. `None` when the scan has everything.
    next: Option<CircleCursor>,
}

/// Where a scan stands between two of its pages.
struct Position {
    /// Where the walk stops.
    watermark: Option<MessageHash>,
    /// The newest readable message hash the scan has met, which becomes the watermark once the
    /// walk finishes. It is `None` while every entry so far has had an unreadable one.
    head: Option<MessageHash>,
    /// The cursor of the page to fetch next, or `None` for the head page.
    resume: Option<CircleCursor>,
}

impl Position {
    fn from_state(state: State) -> Self {
        let (head, resume) = state
            .scan
            .map_or((None, None), |scan| (Some(scan.head), Some(scan.resume)));
        Self {
            watermark: state.watermark,
            head,
            resume,
        }
    }

    /// The progress this position saves. Progress names the head the walk will move the watermark
    /// to, so a walk that has not met a readable message hash yet has none to save, and an
    /// interruption before then starts it over at the head page.
    fn state(&self) -> State {
        State {
            watermark: self.watermark,
            scan: self
                .head
                .zip(self.resume.clone())
                .map(|(head, resume)| ScanProgress { head, resume }),
        }
    }
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
        Self::connect(config)
            .await
            .classify(Actionable("startup"))
            .map_err(|failure| {
                failure.report("relayer startup failed");
                failure.error
            })
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
        config.validate_prover()?;
        let page_size = config.effective_page_size();
        info!(%page_size, remote_proving = config.prover_url.is_some(), "relayer proving configuration");
        let store = Store::new(config.state_file.clone());
        let state = store.state().context("reading relayer startup progress")?;
        // Save the same progress to exercise the normal write/sync/rename path without advancing it.
        store
            .set_state(&state)
            .context("checking relayer progress persistence")?;
        Ok(Self {
            circle: CircleClient::new(
                config.circle_url.clone(),
                page_size,
                config.request_timeout,
            )?,
            store,
            minter: Minter::from_config(&config),
            miden_client,
            unminted: Unminted::default(),
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
        let mut position = match self.store.state().classify(Actionable("progress_file")) {
            Ok(state) => Position::from_state(state),
            Err(failure) => {
                failure.report("could not read the relayer's progress");
                return Err(failure);
            }
        };

        loop {
            if shutdown.is_cancelled() {
                return Ok(ScanOutcome::Stopped);
            }
            let next = self.run_page(&position).await?;
            if shutdown.is_cancelled() {
                return Ok(ScanOutcome::Stopped);
            }
            let Some(next) = next else {
                return Ok(ScanOutcome::Complete);
            };
            position = next;
        }
    }

    /// Runs one page of the scan in its `relayer.page` span: mints it, then records it as done.
    /// Returns where the scan continues from, or `None` when the walk is over.
    ///
    /// A failure marks the page span failed and is logged inside it, so the span says why the page
    /// was not recorded as done.
    ///
    /// The deposits still waiting for the faucet are recorded once the page ends, failed or not, so
    /// they include the ones the page just put on chain, and a Circle or node outage does not hide
    /// them.
    #[instrument(
        name = "relayer.page",
        skip_all,
        fields(
            remote_domain = %self.config.remote_domain,
            cursor = Empty,
            attestations.count = Empty,
            attestations.message_hashes = Empty,
            attestations.skipped.count = Empty,
            attestations.skipped.message_hashes = Empty,
            notes.already_minted.count = Empty,
            deposits.unminted.count = Empty,
            deposits.unminted.oldest_age_secs = Empty,
            notes.count = Empty,
            notes.ids = Empty,
            transaction.id = Empty,
        )
    )]
    async fn run_page(&mut self, position: &Position) -> Result<Option<Position>, Failure> {
        // Boxed because the page's future, which holds the Miden client's, is deep enough that
        // nesting it in the scan's future exceeds the compiler's recursion limit.
        let result = Box::pin(self.finish_page(position)).await;
        let span = Span::current();
        span.record("deposits.unminted.count", self.unminted.count());
        span.record(
            "deposits.unminted.oldest_age_secs",
            self.unminted.oldest_age(Instant::now()).as_secs(),
        );
        if let Err(failure) = &result {
            if miden::is_expired_submission(&failure.error) && self.circle.limit_to_local_proving()
            {
                warn!("mint submission expired; limiting later pages to 10 deposits until restart");
            }
            failure.report("the page failed; the next scan resumes at it");
        }
        result
    }

    /// Processes the page `position` resumes at and saves the progress that follows it. Returns
    /// where the scan continues from, or `None` when the walk is over.
    async fn finish_page(&mut self, position: &Position) -> Result<Option<Position>, Failure> {
        let outcome = self
            .process_page(position.resume.as_ref(), position.watermark.as_ref())
            .await?;

        // A scan keeps the first head it finds. That is on the head page unless every entry there
        // had an unreadable message hash, in which case the walk goes on and a later page gives
        // it one; one that never finds any leaves the watermark where it was.
        let head = position.head.or(outcome.newest);

        // The watermark moves only when the walk reaches its end, and the progress it replaces is
        // dropped in the same write, so the file never claims both.
        let (next, saved) = match outcome.next {
            Some(resume) => {
                let next = Position {
                    watermark: position.watermark,
                    head,
                    resume: Some(resume),
                };
                let saved = next.state();
                (Some(next), saved)
            }
            None => (
                None,
                State {
                    watermark: head.or(position.watermark),
                    scan: None,
                },
            ),
        };

        // A caught-up poll finds the watermark at the top of the first page and leaves the state
        // exactly as it was, which is not worth an fsync every polling interval.
        if saved != position.state() {
            self.store
                .set_state(&saved)
                .classify(Actionable("progress_file"))?;
        }
        Ok(next)
    }

    /// Fetches one page and mints the attestations on it above the watermark.
    ///
    /// `resume` is the cursor of the page to fetch, which is `None` for the first page of a fresh
    /// scan and the stored progress for the page an interrupted scan stopped at.
    ///
    /// It records what it finds on the current span, which is the `relayer.page` span.
    ///
    /// Entries that do not decode or will not build are skipped inside [`Minter::build_notes`], and deposits the faucet
    /// has already minted are dropped by [`MidenClient::retain_unminted`], so no proof is spent on a note
    /// the faucet would refuse. The same check, under the same sync, drops the deposits of earlier
    /// pages that the faucet has minted since. Every remaining note goes into one transaction, and the page is
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
        span.record("attestations.count", page.entries.len());
        span.record(
            "attestations.message_hashes",
            identifiers(
                page.entries
                    .iter()
                    .map(|entry| hash_or_unreadable(entry.message_hash())),
            )
            .as_str(),
        );

        // The page runs newest to oldest, so the watermark — if it is on this page at all — ends
        // the scan, and everything above it arrived since the last scan. An entry without a
        // readable message hash is never the watermark.
        let reached = page.entries.iter().position(|entry| {
            entry
                .message_hash()
                .is_some_and(|hash| Some(&hash) == watermark)
        });
        let fresh = &page.entries[..reached.unwrap_or(page.entries.len())];

        let BuiltNotes { notes, skipped } = self.minter.build_notes(fresh);
        span.record("attestations.skipped.count", skipped.len());
        span.record(
            "attestations.skipped.message_hashes",
            identifiers(skipped.iter().copied().map(hash_or_unreadable)).as_str(),
        );
        let built = notes.len();

        // A deposit the faucet has already minted would only be refused, so it is dropped here
        // rather than proven. This is what makes a replay of the feed cheap. The deposits earlier
        // pages put on chain are checked in the same call, so one sync answers both.
        let unminted = self
            .miden_client
            .retain_unminted(
                notes
                    .iter()
                    .map(XUsdcMintNote::nonce)
                    .chain(self.unminted.nonces())
                    .collect(),
            )
            .await?;
        self.unminted.retain(&unminted);
        let notes: Vec<XUsdcMintNote> = notes
            .into_iter()
            .filter(|note| unminted.contains(&note.nonce()))
            .collect();
        span.record("notes.already_minted.count", built - notes.len());
        let nonces: Vec<_> = notes.iter().map(XUsdcMintNote::nonce).collect();

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
            let transaction = self.miden_client.submit_notes(notes).await?;
            span.record("transaction.id", transaction.to_string().as_str());
            info!("page minted and on chain");
            // On chain is not minted: the faucet consumes the notes later, and the next pages
            // check that it did.
            self.unminted.submitted(nonces, Instant::now());
        }

        Ok(PageOutcome {
            newest: page.entries.iter().find_map(Entry::message_hash),
            // Reaching the watermark ends the scan even though the feed continues below it:
            // everything below was handled by an earlier scan.
            next: match reached {
                Some(_) => None,
                None => page.next,
            },
        })
    }

    /// Runs one scan in its `relayer.scan` span. Each scan is a root of its own, so a long-running
    /// relayer is a series of traces rather than one that never ends.
    ///
    /// A failure was already logged in the span it happened in; this marks the scan as a whole
    /// failed.
    #[instrument(name = "relayer.scan", parent = None, skip_all)]
    async fn traced_scan(&mut self, shutdown: &CancellationToken) -> Result<ScanOutcome, Failure> {
        let outcome = self.scan(shutdown).await;
        if let Err(failure) = &outcome {
            Span::current().record_error(failure);
        }
        outcome
    }

    /// Scans the feed, pausing for the polling interval between scans, until `shutdown` is
    /// cancelled.
    ///
    /// A failed scan leaves the watermark where it was, and the next one resumes at the page the
    /// failure stopped it on rather than repeating the pages already on chain.
    ///
    /// The current page finishes and its progress is saved before stopping. Waiting for a mint
    /// transaction can continue indefinitely if the chain stops producing blocks.
    pub async fn run_until(mut self, shutdown: CancellationToken) -> Result<()> {
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            match self.traced_scan(&shutdown).await {
                Ok(ScanOutcome::Stopped) => return Ok(()),
                // The next scan resumes where a failed one stopped.
                Ok(ScanOutcome::Complete) | Err(_) => {}
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
