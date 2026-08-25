//! The observation record the row-A driver produces and the assertion suite consumes.
//!
//! Drivers OBSERVE (fetch on-chain state, capture errors, record ids); assertions JUDGE. Keeping
//! the two apart makes every assertion unit-testable against synthetic observations and keeps the
//! driver free of pass/fail policy.

use miden_protocol::account::{Account, AccountId};

use crate::config::DomainParams;

/// Everything the LNV-1 row-A run observed on the real node. All `Account` values are the NODE's
/// answers (`GetAccount` via RPC), never the client's local store state.
#[derive(Debug)]
pub struct RowsAbObservations {
    /// The `main` commit the run was built from (toolchain ledger; recorded, not asserted).
    pub main_commit: String,
    /// The deployed faucet's account id (derived at build from the seed + composition).
    pub faucet_id: AccountId,
    /// `GetAccount` response AFTER the deploy transaction committed. `None` = the node does not
    /// recognize the account (row A fails).
    pub deployed: Option<Account>,
    /// The deploy transaction id (hex) and the block it committed in.
    pub deploy_tx_id: String,
    pub deploy_block: u32,
    /// The owner account id — the seeded `ADMIN` role member of the deployed faucet.
    pub owner_id: AccountId,
    /// The run params: the three BUILD-SEEDED domain-config fields, all expected in storage.
    pub domain_params: DomainParams,
}
