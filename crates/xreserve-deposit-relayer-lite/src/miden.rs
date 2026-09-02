//! Miden transaction submission for mint-note pages.
//!
//! [`MidenClient`] stands in for the `miden-client` API this crate will call once a release for
//! protocol v0.16 exists; until then there is no implementation, so [`production_miden_client`]
//! returns an error and the service refuses to poll Circle without submitting transactions.

use std::fmt;

use anyhow::{bail, Result};
use miden_protocol::account::AccountId;
use miden_protocol::note::Note;
use miden_protocol::transaction::TransactionId;

/// Submits a page of mint notes to Miden and waits for inclusion on-chain.
///
/// This is the surface the relay loop needs from a Miden client. It is a trait rather than a
/// concrete type only because the client it will wrap does not exist yet for protocol v0.16. The
/// relay loop is sequential, so the implementation blocks until the transaction is included.
pub trait MidenClient: fmt::Debug + Send + Sync {
    /// Submits `notes` in one transaction from `sender` and returns its ID after inclusion
    /// on-chain.
    ///
    /// The caller advances the Circle cursor after this method succeeds. Returning before
    /// inclusion could advance the cursor past deposits whose transaction is later dropped.
    fn submit_notes(&self, sender: AccountId, notes: Vec<Note>) -> Result<TransactionId>;
}

/// Returns the production Miden client.
///
/// # Errors
///
/// - A compatible `miden-client` implementation is not yet available.
pub fn production_miden_client() -> Result<Box<dyn MidenClient>> {
    bail!(
        "the miden leg has no production adapter: it needs a miden-client for protocol v0.16 and \
         there is no such release. Refusing to start rather than poll circle without minting."
    )
}

#[cfg(test)]
mod tests {
    use super::production_miden_client;

    /// There is no production Miden adapter, and the refusal says why.
    #[test]
    fn there_is_no_production_miden_adapter() {
        let error = production_miden_client().unwrap_err().to_string();
        assert!(error.contains("miden-client"), "unexpected error: {error}");
    }
}
