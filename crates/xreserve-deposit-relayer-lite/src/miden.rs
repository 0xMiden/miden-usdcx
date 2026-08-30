//! Miden transaction submission for mint-note pages.
//!
//! There is no production implementation because a `miden-client` release for protocol v0.16 is
//! not yet available. [`production_miden_client`] therefore returns an error and prevents the
//! service from polling Circle without submitting transactions.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use anyhow::{bail, Result};
use miden_protocol::account::AccountId;
use miden_protocol::note::Note;

/// Submits a page of mint notes to Miden and waits for inclusion on-chain.
pub trait MidenClient: fmt::Debug + Send + Sync {
    /// Submits `notes` in one transaction from `sender` and returns its ID after inclusion
    /// on-chain.
    ///
    /// The caller advances the Circle cursor after this method succeeds. Returning before
    /// inclusion could advance the cursor past deposits whose transaction is later dropped.
    fn submit_notes<'a>(
        &'a self,
        sender: AccountId,
        notes: Vec<Note>,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>;
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
