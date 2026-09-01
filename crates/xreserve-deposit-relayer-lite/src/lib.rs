//! Relays Circle xReserve deposit attestations to the xUSDC faucet.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use miden_protocol::crypto::rand::FeltRng;
use tracing::{info, warn};

pub mod circle;
pub mod config;
pub mod miden;
pub mod mint;
pub mod store;

use circle::CircleFeed;
use config::Config;
use miden::MidenClient;
use mint::{build_notes, Identities};
use store::{CircleCursor, Store};

/// How long to wait once the scan has caught up with the feed. A deposit intent has no expiry, so
/// polling harder buys nothing but rate-limit pressure.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Dependencies and mutable state required to process feed pages.
pub struct Relayer<R: FeltRng> {
    pub config: Config,
    pub circle: Arc<dyn CircleFeed>,
    pub store: Store,
    pub miden: Arc<dyn MidenClient>,
    pub identities: Identities,
    pub rng: R,
}

/// How a cycle ended, and therefore whether the loop should pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    /// The page was handled and there is another one — keep going without sleeping.
    MorePages,
    /// The feed is caught up.
    CaughtUp,
}

/// Fetches one page from the stored cursor, builds and submits its notes, and advances the cursor.
///
/// Malformed attestations are skipped inside [`build_notes`]. Buildable notes are submitted in one
/// transaction, and the cursor advances only after [`MidenClient::submit_notes`] confirms that the
/// transaction is included on-chain. If an operation fails, the cursor remains unchanged and the
/// next cycle fetches the same page.
///
/// # Errors
///
/// - Reading the stored cursor fails.
/// - Fetching the Circle page fails.
/// - Submitting the mint notes fails.
/// - Persisting the next cursor fails.
pub async fn run_cycle<R: FeltRng>(relayer: &mut Relayer<R>) -> Result<CycleOutcome> {
    let cursor = relayer.store.cursor()?;
    let page = relayer
        .circle
        .fetch_page(
            relayer.config.remote_domain,
            cursor.as_ref().map(CircleCursor::as_str),
        )
        .await?;

    let notes = build_notes(
        &relayer.identities,
        relayer.config.remote_domain,
        &page.attestations,
        &mut relayer.rng,
    );

    if notes.is_empty() && !page.attestations.is_empty() {
        warn!(
            fetched = page.attestations.len(),
            "page produced no mint notes"
        );
    } else if !notes.is_empty() {
        let submitted = notes.len();
        let tx = relayer
            .miden
            .submit_notes(relayer.identities.sender(), notes)
            .await?;
        info!(
            tx,
            fetched = page.attestations.len(),
            submitted,
            "page minted and on chain"
        );
    }

    match page.next_cursor() {
        Some(next) => {
            relayer.store.set_cursor(&CircleCursor::new(next))?;
            Ok(CycleOutcome::MorePages)
        }
        None => Ok(CycleOutcome::CaughtUp),
    }
}

/// Runs relay cycles indefinitely.
///
/// Additional pages are processed immediately. When the feed is caught up or a cycle fails, the
/// loop waits for the polling interval. Failed cycles leave the cursor unchanged, so the next
/// cycle retries the same page.
pub async fn run<R: FeltRng>(mut relayer: Relayer<R>) -> ! {
    loop {
        match run_cycle(&mut relayer).await {
            Ok(CycleOutcome::MorePages) => continue,
            Ok(CycleOutcome::CaughtUp) => {}
            Err(error) => warn!(
                error = format!("{error:#}"),
                "the cycle failed; the cursor did not move"
            ),
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
