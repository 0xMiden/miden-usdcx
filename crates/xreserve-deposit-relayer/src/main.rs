//! The relayer binary: read the operator's config, assemble the service, run the loop.
//!
//! # Why this refuses to start
//!
//! Every part below is wired for real — the config, the Circle client with its auth posture and
//! rate ceilings, the durable idempotency store, the Miden identities, the event sink — and then
//! the last binding fails: the **Miden submit port has no production adapter**, because it needs a
//! `miden-client` for v0.16 and there is no such release. So `main` reports that and exits
//! non-zero.
//!
//! That is deliberate, and it is the honest end of this slice rather than a gap in it. The two
//! alternatives are both worse than not starting:
//!
//! * A no-op submit would let the relayer poll Circle, validate attestations, claim nonces, build
//!   notes — and mint nothing. It would look healthy in every log and every metric except the
//!   chain's, which is the one nobody watches until a user asks where their money is.
//! * A simulated submit would make the service's own tests evidence about themselves. The mock
//!   boundary forbids it outright: **Circle API may be mocked**; Miden behaviour must not be faked
//!   for final acceptance
//!
//! A later slice implements [`MintSubmit`](xreserve_deposit_relayer::cycle::MintSubmit) against a
//! real client and proves it against a real local node. The one line that changes here is the port
//! binding; everything else below is what will run behind it.

use std::process::ExitCode;
use std::sync::Arc;

use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::{Felt, Word};

use xreserve_deposit_relayer::circle::CircleClient;
use xreserve_deposit_relayer::config::RelayerConfig;
use xreserve_deposit_relayer::cycle::{
    production_submit_port, run_relayer_loop, MintIdentities, RelayerCtx,
};
use xreserve_deposit_relayer::error::{Cause, RelayerError};
use xreserve_deposit_relayer::idempotency::IdempotencyStore;
use xreserve_deposit_relayer::observability::WriteEventSink;

/// Exit code for a service that cannot be configured into a runnable state — `EX_CONFIG` from
/// `sysexits.h`, which an init system reads as "do not restart me, fix me".
const EX_CONFIG: u8 = 78;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // the whole `source()` chain: the top line names WHAT failed, the chain names WHY. An
            // operator reading "the configured faucet_account_id is not an account id" needs the
            // protocol's own complaint under it.
            eprintln!("xreserve-deposit-relayer: {error}");
            let mut cause = core::error::Error::source(&error);
            while let Some(current) = cause {
                eprintln!("  caused by: {current}");
                cause = current.source();
            }
            ExitCode::from(EX_CONFIG)
        }
    }
}

async fn run() -> Result<(), RelayerError> {
    let config = load_config()?;

    // ONE real event sink, shared behind an Arc, installed into BOTH the Circle client (so its
    // retry/rejection events are logged) and the RelayerCtx below (so every terminal per-attestation
    // event is). Installing the event-dropping `NoopSink` here would mean the service that must
    // never silently drop an attestation emits nothing. This
    // writes one structured line per event to stderr — the honest floor until the monitoring slice
    // (`P4-OPS`) wires a structured backend behind the same `EventSink` trait.
    let events = Arc::new(WriteEventSink::stderr());

    // Each of these refuses a bad value HERE, at startup, rather than at the first deposit: a typo
    // caught now costs a restart, and the same typo caught later costs every mint until someone reads
    // the logs.
    let client = CircleClient::from_config(&config)?.with_event_sink(events.clone());
    let store = IdempotencyStore::open(config.store_path())?;
    let identities = MintIdentities::from_config(&config)?;
    // Validate the crash-recovery policy at startup: a zero retry batch or a too-small stale threshold
    // would run a relayer that cannot recover, so it fails here rather than after a crash strands a
    // deposit. (The cycle re-validates too, so a directly invoked cycle also fails closed.)
    config.recovery_policy()?;

    // THE SEAM. `production_submit_port` has no adapter to hand back until a `miden-client` for v0.16
    // exists — it returns `MintSubmitPortUnavailable`, and this `?` ends the process.
    //
    // Everything below is the service, fully assembled and never reached. It is written out rather
    // than left as a comment so that the slice implementing the port changes this one binding and
    // nothing else, and so this file is a compile-checked statement of what the relayer IS, not a
    // promise about it.
    let submit = production_submit_port()?;

    let mut rng = RandomCoin::new(entropy_seed());

    let mut ctx = RelayerCtx::new(
        &config,
        &client,
        &store,
        submit.as_ref(),
        events.as_ref(),
        &identities,
        &mut rng,
    );

    // Runs until the process is signalled. There is no shutdown source to consult yet — the operator
    // supervisor's is `P4-OPS`'s to define — so the predicate is the honest constant rather than an
    // invented one.
    run_relayer_loop(&mut ctx, || false).await;

    Ok(())
}

/// Reads the config from the path in `argv[1]` (default `relayer.json`).
///
/// Parsing is [`RelayerConfig`]'s own (it is serde-deserializable and does no I/O); this is the ONE
/// place the file is read, so the config module stays testable without a filesystem.
fn load_config() -> Result<RelayerConfig, RelayerError> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "relayer.json".to_string());

    let text = std::fs::read_to_string(&path).map_err(|source| RelayerError::BadConfigFile {
        path: path.clone(),
        source: Cause::new(source),
    })?;

    serde_json::from_str(&text).map_err(|source| RelayerError::BadConfigFile {
        path,
        source: Cause::new(source),
    })
}

/// A 128-bit seed for the note serial numbers, from OS entropy.
///
/// The serial number is what makes a re-mint of the same DepositIntent a DISTINCT note rather than
/// a collision, so it must NOT be reproducible across restarts — which is exactly the opposite of
/// what a test wants, and why the RNG is a parameter of the context rather than a global here.
///
/// Built from `u32`s: every one is a felt exactly, so the seed is the entropy that was drawn rather
/// than that entropy silently reduced modulo the field.
fn entropy_seed() -> Word {
    use rand::TryRng;

    let mut rng = rand::rngs::SysRng;
    let mut next = || rng.try_next_u32().expect("the os rng must yield entropy");
    Word::from([
        Felt::from(next()),
        Felt::from(next()),
        Felt::from(next()),
        Felt::from(next()),
    ])
}
