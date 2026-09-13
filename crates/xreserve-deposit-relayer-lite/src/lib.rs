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

use anyhow::Result;
use miden_protocol::note::Note;
use tracing::field::{display, Empty};
use tracing::{info, instrument, warn, Span};

pub mod circle;
pub mod config;
pub mod miden;
pub mod mint;
pub mod store;

use circle::{Attestation, CircleClient, CircleCursor, MessageHash};
use config::Config;
use miden::MidenClient;
use mint::Minter;
use store::{ScanProgress, State, Store};

/// The relay loop's parts: the Circle feed, the store holding how far the scan got, the note
/// builder, and the Miden client that lands the notes on chain.
pub struct Relayer {
    config: Config,
    circle: CircleClient,
    store: Store,
    miden_client: Box<dyn MidenClient>,
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

impl Relayer {
    /// Assembles a relayer from the operator configuration and the client that submits to Miden.
    ///
    /// # Errors
    ///
    /// - The Circle client cannot be built (see [`CircleClient::new`]).
    pub fn new(config: Config, miden_client: Box<dyn MidenClient>) -> Result<Self> {
        Ok(Self {
            circle: CircleClient::new(
                config.circle_url.clone(),
                config.page_size,
                config.request_timeout,
            )?,
            store: Store::new(config.state_file.clone()),
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
    /// # Errors
    ///
    /// - Reading or persisting the state fails.
    /// - Fetching a Circle page fails.
    /// - Submitting the mint notes fails.
    fn scan(&mut self) -> Result<()> {
        let mut state = self.store.state()?;

        loop {
            let outcome = self.process_page(
                state.scan.as_ref().map(|scan| &scan.resume),
                state.watermark.as_ref(),
            )?;

            // A scan that has progress keeps the head it started at, so a fresh scan reads the
            // page's newest attestation only on the first time round this loop — by the second it
            // has written progress of its own and the stored head wins.
            let Some(head) = state.scan.as_ref().map(|scan| scan.head).or(outcome.newest) else {
                // The feed is empty, so there is nothing for the next scan to stop at.
                return Ok(());
            };

            // The watermark moves only when the walk reaches its end, and the progress it replaces
            // is dropped in the same write, so the file never claims both.
            let next = State {
                watermark: match outcome.next {
                    Some(_) => state.watermark,
                    None => Some(head),
                },
                scan: outcome.next.map(|resume| ScanProgress { head, resume }),
            };

            // A caught-up poll finds the watermark at the top of the first page and leaves the
            // state exactly as it was, which is not worth an fsync every polling interval.
            if next != state {
                self.store.set_state(&next)?;
            }
            if next.scan.is_none() {
                return Ok(());
            }
            state = next;
        }
    }

    /// Fetches one page and mints the attestations on it above the watermark.
    ///
    /// `resume` is the cursor of the page to fetch, which is `None` for the first page of a fresh
    /// scan and the stored progress for the page an interrupted scan stopped at.
    ///
    /// Malformed attestations are skipped inside [`Minter::build_notes`]. Buildable notes are
    /// submitted in one transaction, and the page is done only once
    /// [`MidenClient::submit_notes`] confirms that the transaction is included on chain — so
    /// returning is what entitles the caller to record the page as done.
    ///
    /// # Errors
    ///
    /// - Fetching the page fails.
    /// - Submitting the mint notes fails.
    ///
    /// # Tracing
    ///
    /// **`parent = None` is load-bearing.** The forest renderer buffers a span into its parent and
    /// only prints once a root span closes; [`Relayer::run`] never returns, so an inherited parent
    /// would mean nothing was ever printed. Detached, each page is its own root and its tree —
    /// every skip and submit nested under it — is emitted the moment the page ends.
    #[instrument(
        parent = None,
        name = "page",
        skip_all,
        fields(
            remote_domain = %self.config.remote_domain,
            cursor = Empty,
            attestations.count = Empty,
            attestations.message_hashes = Empty,
            notes.count = Empty,
            notes.ids = Empty,
            transaction.id = Empty,
        ),
    )]
    fn process_page(
        &mut self,
        resume: Option<&CircleCursor>,
        watermark: Option<&MessageHash>,
    ) -> Result<PageOutcome> {
        let span = Span::current();
        span.record("cursor", resume.map(CircleCursor::as_str).unwrap_or("None"));

        let page = self.circle.fetch_page(self.config.remote_domain, resume)?;
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

        // The minter yields its own note type; the chain takes protocol notes, so the page is
        // converted here, once, on its way to being submitted.
        let notes: Vec<Note> = self
            .minter
            .build_notes(&fresh)
            .into_iter()
            .map(Note::from)
            .collect();
        span.record("notes.count", notes.len());
        span.record(
            "notes.ids",
            identifiers(notes.iter().map(|note| note.id().to_string())).as_str(),
        );

        if notes.is_empty() && !fresh.is_empty() {
            warn!(fresh.count = fresh.len(), "page produced no mint notes");
        } else if !notes.is_empty() {
            let tx = self
                .miden_client
                .submit_notes(self.minter.mint_account(), notes)?;
            span.record("transaction.id", display(tx));
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
    pub fn run(mut self) -> ! {
        loop {
            if let Err(error) = self.scan() {
                warn!(
                    error = format!("{error:#}"),
                    "the scan failed; the next one resumes where it stopped"
                );
            }
            std::thread::sleep(self.config.poll_interval);
        }
    }
}
