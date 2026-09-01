//! Relays Circle xReserve deposit attestations to the xUSDC faucet.

use anyhow::Result;
use tracing::{info, warn};

pub mod circle;
pub mod config;
pub mod miden;
pub mod mint;
pub mod store;

use circle::CircleClient;
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
    miden: Box<dyn MidenClient>,
    minter: Minter,
}

/// How a page ended, and therefore whether the loop should pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageOutcome {
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
    /// - The configured identities are invalid (see [`Minter::from_config`]).
    pub fn new(config: Config, miden: Box<dyn MidenClient>) -> Result<Self> {
        Ok(Self {
            circle: CircleClient::new(
                config.circle_url.clone(),
                config.page_size,
                config.request_timeout,
            )?,
            store: Store::new(config.state_file.clone()),
            minter: Minter::from_config(&config)?,
            miden,
            config,
        })
    }

    /// Fetches the page after the stored cursor, builds and submits its notes, and advances the
    /// cursor.
    ///
    /// Malformed attestations are skipped inside [`Minter::build_notes`]. Buildable notes are
    /// submitted in one transaction, and the cursor advances only after
    /// [`MidenClient::submit_notes`] confirms that the transaction is included on chain. If any
    /// step fails, the cursor remains unchanged and the next call fetches the same page.
    ///
    /// # Errors
    ///
    /// - Reading the stored cursor fails.
    /// - Fetching the Circle page fails.
    /// - Submitting the mint notes fails.
    /// - Persisting the next cursor fails.
    pub async fn process_next_page(&mut self) -> Result<PageOutcome> {
        let cursor = self.store.cursor()?;
        let page = self
            .circle
            .fetch_page(self.config.remote_domain, cursor.as_ref())
            .await?;

        let notes = self.minter.build_notes(&page.attestations);

        if notes.is_empty() && !page.attestations.is_empty() {
            warn!(
                fetched = page.attestations.len(),
                "page produced no mint notes"
            );
        } else if !notes.is_empty() {
            let submitted = notes.len();
            let tx = self.miden.submit_notes(self.minter.sender(), notes).await?;
            info!(
                tx = %tx,
                fetched = page.attestations.len(),
                submitted,
                "page minted and on chain"
            );
        }

        match page.next_cursor() {
            Some(next) => {
                self.store.set_cursor(next)?;
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
    pub async fn run(mut self) -> ! {
        loop {
            match self.process_next_page().await {
                Ok(PageOutcome::MorePages) => continue,
                Ok(PageOutcome::CaughtUp) => {}
                Err(error) => warn!(
                    error = format!("{error:#}"),
                    "the page failed; the cursor did not move"
                ),
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }
}
