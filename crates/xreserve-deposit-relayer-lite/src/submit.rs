//! The seam at a Miden node — a trait with no production implementation.
//!
//! Handing a note to a node needs a `miden-client`, and there is **no `miden-client` release for
//! protocol v0.16**. Rather than fake it, the leg is a port: [`production_submit_port`] refuses by
//! name and `main` fails at startup on it.
//!
//! The two alternatives are both worse than not starting. A no-op submit would let the relayer
//! poll, decode, dedup and build — and mint nothing, looking healthy in every log and metric except
//! the chain's. A simulated submit would make the service's own tests evidence about themselves.
//! The mock boundary forbids it: Circle may be mocked; Miden behaviour must not be faked for final
//! acceptance.
//!
//! `miden-client` is deliberately absent from this crate's dependencies, so nothing here can
//! quietly acquire one.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use anyhow::{bail, Result};
use miden_protocol::account::AccountId;
use miden_protocol::note::Note;
use tracing::instrument;

/// What the node said, when it did not fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submitted {
    /// The node accepted the transaction; the id is what an operator looks the mint up by.
    Accepted(String),
    /// The on-chain `usedNonces` assert refused it: this deposit is already minted.
    ///
    /// **This is the safety backstop working, not a failure** — and it is the authoritative one.
    /// The relayer's own nonce set is only a fee optimization in front of it.
    AlreadyMinted,
}

/// Why a submit failed, split by the only distinction that drives control flow.
///
/// This is the one place the crate types an error instead of reaching for `anyhow` alone: the cycle
/// branches on it. [`Self::Transient`] holds the page (the same deposit is retried next cycle);
/// [`Self::Fatal`] skips the deposit (a retry could only fail the same way).
#[derive(Debug)]
pub enum SubmitError {
    /// A condition that clears: node sync lag, a dropped connection.
    Transient(anyhow::Error),
    /// A permanent refusal.
    Fatal(anyhow::Error),
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient(error) => write!(f, "{error}"),
            Self::Fatal(error) => write!(f, "{error}"),
        }
    }
}

/// Hands a built `XUsdcMintNote` to a Miden node.
///
/// The `Pin<Box<dyn Future>>` return rather than `async fn` is what makes the trait usable behind
/// `&dyn`.
pub trait MintSubmit: fmt::Debug + Send + Sync {
    fn submit<'a>(
        &'a self,
        sender: AccountId,
        note: &'a Note,
    ) -> Pin<Box<dyn Future<Output = Result<Submitted, SubmitError>> + Send + 'a>>;
}

/// The production adapter — **which does not exist yet**, and says so.
///
/// # Errors
/// Always. A later slice replaces this body with a real `miden-client`-backed adapter, proven
/// against a real local node; that slice changes this one function and nothing else.
#[instrument(name = "production_submit_port")]
pub fn production_submit_port() -> Result<Box<dyn MintSubmit>> {
    bail!(
        "the miden submit port has no production adapter: it needs a miden-client for protocol \
         v0.16 and there is no such release. Refusing to start rather than run with a submit that \
         mints nothing while looking healthy."
    )
}
