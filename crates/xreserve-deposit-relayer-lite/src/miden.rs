//! The seam at a Miden node: one transaction per page — build, prove, submit, wait for inclusion.
//!
//! There is **no production implementation**: it needs a `miden-client` for protocol v0.16 and
//! there is no such release. The two dishonest stand-ins are both worse than refusing — a no-op
//! would poll Circle while minting nothing (healthy in every log except the chain's), and a
//! simulation would make the tests evidence about themselves. Circle may be mocked; Miden may not.
//! So [`production_miden_client`] refuses by name and `main` exits on it; the later slice that
//! implements this against a real client changes that one function.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use anyhow::{bail, Result};
use miden_protocol::account::AccountId;
use miden_protocol::note::Note;

/// The Miden leg, whole: everything between "here are the page's mint notes" and "they are on
/// chain".
pub trait MidenClient: fmt::Debug + Send + Sync {
    /// Submits `notes` in ONE transaction from `sender` and returns the transaction id once that
    /// transaction is **included on chain** (build → prove → submit → wait).
    ///
    /// Inclusion-before-return is load-bearing: the caller advances the Circle cursor on success,
    /// and the cursor is the relayer's only state. Returning at mere acceptance would let a
    /// dropped transaction advance the cursor past deposits that never minted.
    fn submit_notes<'a>(
        &'a self,
        sender: AccountId,
        notes: Vec<Note>,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>;
}

/// The production adapter — which does not exist yet, and says so.
///
/// # Errors
/// Always, until a `miden-client` for protocol v0.16 is released and a later slice implements the
/// trait against it (proven on a real local node).
pub fn production_miden_client() -> Result<Box<dyn MidenClient>> {
    bail!(
        "the miden leg has no production adapter: it needs a miden-client for protocol v0.16 and \
         there is no such release. Refusing to start rather than poll circle without minting."
    )
}
