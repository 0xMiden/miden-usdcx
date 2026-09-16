//! Relays Circle xReserve deposit attestations to the xUSDC faucet.

use std::collections::HashSet;

use anyhow::Result;
use miden_protocol::note::Note;
use tracing::{info, warn};

pub mod circle;
pub mod config;
pub mod miden;
pub mod mint;
pub mod store;

use circle::{Attestation, CircleClient, MessageHash};
use config::Config;
use miden::MidenClient;
use mint::Minter;
use store::Store;

/// The relay loop's state: the Circle feed, the persisted cursor, the note builder, and the Miden
/// client that lands the notes on chain.
pub struct Relayer {
    config: Config,
    circle: CircleClient,
    store: Store,
    miden_client: Box<dyn MidenClient>,
    minter: Minter,
    /// The attestations handled since the cursor last advanced.
    ///
    /// The final page of the feed carries attestations but no next cursor, so the cursor stays
    /// where it is and every poll while the feed is caught up fetches that same page again. This
    /// set is what stops each of those polls from rebuilding and resubmitting the same deposits.
    /// It is cleared when the cursor advances, so it never holds more than one page, and it is not
    /// persisted, so a restart handles the final page once more.
    handled: HashSet<MessageHash>,
}

/// How a page ended, and therefore whether the loop should pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageOutcome {
    /// The page was handled and there is another one — keep going without sleeping.
    MorePages,
    /// The feed is caught up.
    CaughtUp,
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
            handled: HashSet::new(),
        })
    }

    /// Fetches the page after the stored cursor, builds and submits its notes, and advances the
    /// cursor.
    ///
    /// Attestations already handled since the cursor last advanced are left out, so re-polling
    /// the final page while the feed is caught up submits nothing. Malformed attestations are
    /// skipped inside [`Minter::build_notes`]. Buildable notes are submitted in one transaction,
    /// and the cursor advances only after [`MidenClient::submit_notes`] confirms that the
    /// transaction is included on chain. If any step fails, the cursor remains unchanged and the
    /// next call fetches the same page.
    ///
    /// # Errors
    ///
    /// - Reading the stored cursor fails.
    /// - Fetching the Circle page fails.
    /// - Submitting the mint notes fails.
    /// - Persisting the next cursor fails.
    fn process_next_page(&mut self) -> Result<PageOutcome> {
        let cursor = self.store.cursor()?;
        let page = self
            .circle
            .fetch_page(self.config.remote_domain, cursor.as_ref())?;

        let unhandled: Vec<&Attestation> = page
            .attestations
            .iter()
            .filter(|attestation| !self.handled.contains(&attestation.message_hash))
            .collect();
        // The minter yields its own note type; the chain takes protocol notes, so the page is
        // converted here, once, on its way to being submitted.
        let notes: Vec<Note> = self
            .minter
            .build_notes(&unhandled)
            .into_iter()
            .map(Note::from)
            .collect();

        if notes.is_empty() && !unhandled.is_empty() {
            warn!(fetched = unhandled.len(), "page produced no mint notes");
        } else if !notes.is_empty() {
            let submitted = notes.len();
            let tx = self
                .miden_client
                .submit_notes(self.minter.mint_account(), notes)?;
            info!(
                tx = %tx,
                fetched = unhandled.len(),
                submitted,
                "page minted and on chain"
            );
        }

        // Recorded only once the submission is on chain: a failed submission returns above and
        // the next poll retries these attestations.
        self.handled
            .extend(unhandled.iter().map(|attestation| attestation.message_hash));

        match page.next_cursor() {
            Some(next) => {
                self.store.set_cursor(next)?;
                self.handled.clear();
                Ok(PageOutcome::MorePages)
            }
            None => Ok(PageOutcome::CaughtUp),
        }
    }

    /// Processes pages indefinitely.
    ///
    /// Additional pages are processed immediately. When the feed is caught up or a page fails,
    /// the loop waits for the polling interval. A failed page leaves the cursor unchanged, so the
    /// next attempt retries the same page.
    pub fn run(mut self) -> ! {
        loop {
            match self.process_next_page() {
                Ok(PageOutcome::MorePages) => continue,
                Ok(PageOutcome::CaughtUp) => {}
                Err(error) => warn!(
                    error = format!("{error:#}"),
                    "the page failed; the cursor did not move"
                ),
            }
            std::thread::sleep(self.config.poll_interval);
        }
    }
}
