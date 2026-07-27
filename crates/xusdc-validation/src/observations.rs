//! The observation record the row-A/B driver produces and the assertion suite consumes.
//!
//! Drivers OBSERVE (fetch on-chain state, capture errors, record ids); assertions JUDGE. Keeping
//! the two apart makes every assertion unit-testable against synthetic observations and keeps the
//! driver free of pass/fail policy.

use miden_protocol::account::{Account, AccountId};

use crate::config::DomainParams;

/// Everything the LNV-1 row-A/B run observed on the real node. All `Account` values are the
/// NODE's answers (`GetAccount` via RPC), never the client's local store state.
#[derive(Debug)]
pub struct RowsAbObservations {
    /// The `main` commit the run was built from (toolchain ledger; recorded, not asserted).
    pub main_commit: String,
    /// The deployed faucet's account id (derived at build from the seed + composition).
    pub faucet_id: AccountId,
    /// `GetAccount` response AFTER the deploy(+identifier_init) transaction committed.
    /// `None` = the node does not recognize the account (row A fails).
    pub deployed: Option<Account>,
    /// The deploy transaction id (hex) and the block it committed in.
    pub deploy_tx_id: String,
    pub deploy_block: u32,
    /// The owner account id (the `identifier_init` sender the proc's owner gate checked).
    pub owner_id: AccountId,
    /// The run params: the three BUILD-SEEDED domain-config fields + the FIRST
    /// `identifier_init` note's identifier (all five expected in storage post-init).
    pub domain_params: DomainParams,
    /// The SECOND `identifier_init` note's params (its identifier must NOT appear in storage).
    pub reinit_params: DomainParams,
    /// Note ids (hex) of the two owner-sent `identifier_init` notes.
    pub first_note_id: String,
    pub second_note_id: String,
    /// The exact client-side execution error from attempting to consume the SECOND `identifier_init`
    /// against the deployed faucet state. `None` = the attempt did NOT fail (row B fails).
    pub reinit_error: Option<String>,
    /// `GetAccount` response re-fetched AFTER the reinit attempt window (state-unchanged check).
    pub after_reinit: Option<Account>,
    /// Whether the SECOND note was observed consumed on-chain within the bounded watch window
    /// (it must remain unconsumed — nothing may execute it, including the node's own ntx-builder).
    pub second_note_consumed: bool,
}
