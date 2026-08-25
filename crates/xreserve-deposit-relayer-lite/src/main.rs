//! The binary: read the config, assemble the service, run the loop.
//!
//! # Why this refuses to start
//!
//! Every binding below is wired for real except the last: the Miden submit port has no production
//! adapter, because it needs a `miden-client` for v0.16 and there is no such release. So `main`
//! reports that and exits non-zero rather than run a relayer that mints nothing while looking
//! healthy in every log and metric except the chain's.
//!
//! The slice that implements the port changes one line here.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::{Felt, Word};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use xreserve_deposit_relayer_lite::circle::{CircleClient, ReqwestTransport};
use xreserve_deposit_relayer_lite::config::Config;
use xreserve_deposit_relayer_lite::cycle::{run_loop, Relayer};
use xreserve_deposit_relayer_lite::mint::Identities;
use xreserve_deposit_relayer_lite::store::Store;
use xreserve_deposit_relayer_lite::submit::production_submit_port;

#[tokio::main]
async fn main() -> Result<()> {
    // `ForestLayer` renders one indented TREE per root span instead of a flat line stream, so a
    // cycle and every attestation under it read as one unit. It is always on — not feature-gated.
    //
    // It prints a tree only when a ROOT span closes. The relayer's outermost work is a loop that
    // never returns, which is why `run_cycle` is `#[instrument(parent = None)]`: each cycle is its
    // own root and flushes as it ends, rather than buffering until shutdown.
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_forest::ForestLayer::default())
        .init();

    // Returning the error hands it to `Termination`, which prints it with its whole `source()`
    // chain — the top line names WHAT failed, the rest name WHY — and exits non-zero.
    run().await
}

async fn run() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("relayer.toml"));

    // Each of these refuses a bad value HERE rather than at the first deposit.
    let config = Config::load(&path)?;
    let store = Store::open(&config.store_path)?;
    let identities = Identities::from_config(&config)?;
    let transport = Arc::new(ReqwestTransport::from_config(&config)?);
    let circle = CircleClient::new(&config, transport);

    // THE SEAM. There is no adapter to hand back until a `miden-client` for v0.16 exists, so this
    // `?` ends the process. Everything below is the service, fully assembled and never reached — it
    // is written out rather than left as a comment so the slice implementing the port changes this
    // one binding and nothing else.
    let submit = production_submit_port()?;

    let mut rng = RandomCoin::new(entropy_seed());
    let mut relayer = Relayer {
        config: &config,
        circle: &circle,
        store: &store,
        submit: submit.as_ref(),
        identities: &identities,
        rng: &mut rng,
    };

    run_loop(&mut relayer, shutdown_signal()).await;

    Ok(())
}

/// A ctrl-c latch: once the signal arrives the predicate stays true, so the loop finishes the cycle
/// it is in and then stops.
fn shutdown_signal() -> impl FnMut() -> bool {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let setter = flag.clone();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            setter.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    });

    move || flag.load(std::sync::atomic::Ordering::Relaxed)
}

/// A 128-bit seed for the note serial numbers, from OS entropy.
///
/// The serial number is what makes a re-mint of the same deposit a DISTINCT note rather than a
/// collision, so it must not be reproducible across restarts — the opposite of what a test wants,
/// and why the RNG is a parameter of the cycle rather than a global.
///
/// Built from `u32`s: every one is a felt exactly, so the seed is the entropy that was drawn rather
/// than that entropy silently reduced modulo the field.
fn entropy_seed() -> Word {
    use rand::RngCore;

    let mut rng = rand::rngs::OsRng;
    Word::from([
        Felt::from(rng.next_u32()),
        Felt::from(rng.next_u32()),
        Felt::from(rng.next_u32()),
        Felt::from(rng.next_u32()),
    ])
}
