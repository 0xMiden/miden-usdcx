//! Relays Circle xReserve deposit attestations to the xUSDC faucet.

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
use store::CursorStore;

/// How long to wait once the scan has caught up with the feed. A deposit intent has no expiry, so
/// polling harder buys nothing but rate-limit pressure.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Everything one cycle needs, borrowed from the caller — so this module cannot grow a default for
/// the Miden seam: a relayer missing one must not start.
pub struct Relayer<'a, R: FeltRng> {
    pub config: &'a Config,
    pub circle: &'a dyn CircleFeed,
    pub store: &'a CursorStore,
    pub miden: &'a dyn MidenClient,
    pub identities: &'a Identities,
    pub rng: &'a mut R,
}

/// How a cycle ended, and therefore whether the loop should pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    /// The page was handled and there is another one — keep going without sleeping.
    MorePages,
    /// The feed is caught up.
    Idle,
}

/// One cycle: fetch a page from the stored cursor, mint what builds, advance the cursor.
///
/// The order is the whole design. Malformed attestations are skipped inside [`build_notes`] (one
/// bad element must never wedge the feed); the buildable ones go to the chain in ONE transaction;
/// and the cursor moves only after [`MidenClient::submit_notes`] returns — i.e. after that
/// transaction is included on chain. A crash or error anywhere leaves the cursor put, so the next
/// cycle replays the same page and the chain refuses the duplicate mints.
///
/// # Errors
/// The fetch, the submit, or the cursor write failed. All leave the cursor where it was; the loop
/// logs, sleeps, and retries the same page.
pub async fn run_cycle<R: FeltRng>(relayer: &mut Relayer<'_, R>) -> Result<CycleOutcome> {
    let cursor = relayer.store.cursor()?;
    let page = relayer
        .circle
        .fetch_page(relayer.config.remote_domain, cursor.as_deref())
        .await?;

    let notes = build_notes(
        relayer.identities,
        relayer.config.remote_domain,
        &page.attestations,
        &mut *relayer.rng,
    );

    if !notes.is_empty() {
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

    // an absent `next` is the documented final page: there is no resume point past the end
    match page.next {
        Some(next) => {
            relayer.store.set_cursor(&next)?;
            Ok(CycleOutcome::MorePages)
        }
        None => Ok(CycleOutcome::Idle),
    }
}

/// Runs cycles forever. A failed cycle does not stop the loop — a 500 from Circle or a lagging
/// node is exactly what the next cycle is for, and the cursor did not move, so nothing was
/// skipped — but it does pause first, so a persistent failure is retried at the poll interval
/// rather than in a hot spin.
pub async fn run<R: FeltRng>(relayer: &mut Relayer<'_, R>) -> ! {
    loop {
        match run_cycle(relayer).await {
            Ok(CycleOutcome::MorePages) => continue,
            Ok(CycleOutcome::Idle) => {}
            Err(error) => warn!(
                error = format!("{error:#}"),
                "the cycle failed; the cursor did not move"
            ),
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
