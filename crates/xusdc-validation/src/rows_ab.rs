//! The LNV-1 row-A/B driver: one deterministic flow against a fresh local node, producing the
//! [`RowsAbObservations`] the assertion suite judges.
//!
//! Flow (path C — client-side build+prove+submit; discovered mechanics recorded in
//! `VALIDATION-RECORD.md` §3):
//!
//! 1. Bootstrap + start the fresh four-process stack ([`crate::stack`]).
//! 2. Assemble the client ([`crate::client`]) and the actors ([`crate::actors`]).
//! 3. Build the production faucet account locally ([`crate::deploy`]) — its id exists before any
//!    chain contact.
//! 4. The OWNER emits `domain_init` note #1 (creator-committed §5.9 params). This is the owner
//!    wallet's first transaction, which also materializes the owner on-chain.
//! 5. **Deploy = the faucet's first transaction consuming that note.** At v0.15.1 the user RPC
//!    admits network-account transactions ONLY at first deployment, so `domain_init` rides the
//!    deploy transaction — this IS "the first admin note" realized against the real node. The
//!    scriptless request consumes note #1 under `AuthNetworkAccount` (allowlisted note, new
//!    account → nonce 0→1).
//! 6. Fetch the account from the NODE (`GetAccount`) → row-A + row-B read-back observations.
//! 7. The OWNER emits `domain_init` note #2 (everywhere-different params) and the harness
//!    attempts the faucet-side consumption client-side: the kernel must trap the init-once gate
//!    (`ERR_XRESERVE_DOMAIN_REINIT`) during execution — no provable second-init transaction
//!    exists. The error text is captured verbatim.
//! 8. Watch a bounded window: note #2 must stay unconsumed on-chain (nothing — including the
//!    node's own ntx-builder, which sees an allowlisted note routed at a network account — may
//!    execute it), and the re-fetched account state must be byte-identical on every asserted
//!    surface.
//! 9. Tear the stack down (unless `keep_stack`), leaving logs + evidence under the run root.

use anyhow::Result;

use crate::config::RunConfig;
use crate::observations::RowsAbObservations;

/// Runs the full LNV-1 row-A/B flow. See the module docs for the step list.
pub async fn run_rows_ab(cfg: &RunConfig) -> Result<RowsAbObservations> {
    let _ = cfg;
    todo!("LNV-1 driver: stack up → actors → deploy+domain_init → reinit reject → observations")
}
