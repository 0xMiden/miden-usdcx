//! **The Miden submit PORT** — the seam between the orchestration and a Miden node.
//!
//! # Why this is a port and not a function
//!
//! Handing a built note to a node needs a `miden-client`, and there is **no `miden-client` release
//! for v0.16**. So the leg cannot be written here, and the two dishonest alternatives are worse
//! than not writing it: a stub that returns success would report mints that never happened, and a
//! simulation would make the whole service's test suite evidence about itself rather than about
//! Miden. The mock boundary forbids both outright — Circle API may be mocked; Miden behaviour must
//! not be faked for final acceptance
//!
//! So the leg is a **trait with no production implementation**. The orchestration composes against
//! it and is fully exercised; the adapter lands in a later slice, against a real client, and is
//! proven by the gating real-local-node rows. Until then [`production_submit_port`] refuses, by
//! name, and `main` fails at startup on it — a missing adapter is a loud startup failure, never a
//! silently skipped submit. The withdrawal track staged its node reads the same way: define the
//! port, compose against it, implement it last. `miden-client` is deliberately absent from this
//! crate's dependencies, so nothing here can quietly acquire one.
//!
//! # The shape is a 1:1 image of the real call
//!
//! [`MintSubmit::submit_mint_note`] takes the SENDER account and the built `Note` — the two things
//! `TransactionRequestBuilder` + `submit_new_transaction` need and nothing else — and answers with
//! a transaction id, an already-minted verdict, or one of exactly two errors. a later slice
//! implements it by mapping the client's real answers onto those; it does not have to reshape the
//! interface to do it.
//!
//! # The two errors are the orchestration's contract, not a taxonomy
//!
//! [`RelayerError::TransientSubmit`] retries and [`RelayerError::FatalSubmit`] does not — that
//! split is the whole reason the port returns typed errors rather than a `Box<dyn Error>`. WHICH
//! real failure is a judgement only a real node can make; that a node's sync lag must not
//! strand a deposit, and that a permanent refusal must not loop forever, is decided here.

use core::fmt;
use std::future::Future;
use std::pin::Pin;

use miden_protocol::account::AccountId;
use miden_protocol::note::Note;

use crate::error::RelayerError;
use crate::idempotency::TxId;

/// One mint note, and the account that submits it — the port's whole input.
///
/// A struct rather than two arguments because the pair is the unit: the note was BUILT with this
/// sender as its producer (the shared encoding crate's `XUsdcMintNote::create` takes it), and
/// submitting it from a different account would produce a transaction whose output note is not the
/// note that was built. Constructed only by the orchestration, so no caller can pair a note with a
/// stranger.
#[derive(Debug, Clone, Copy)]
pub struct MintSubmission<'a> {
    sender: AccountId,
    note: &'a Note,
}

impl<'a> MintSubmission<'a> {
    /// Pairs `note` with the account that produced it.
    pub(crate) fn new(sender: AccountId, note: &'a Note) -> Self {
        Self { sender, note }
    }

    /// The account executing the submitting transaction — the note's producer.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// The `XUsdcMintNote` to submit. Every byte of it is the shared encoding crate's
    /// (`XUsdcMintNote::create`); an adapter transports it and reads nothing out of it.
    pub fn note(&self) -> &'a Note {
        self.note
    }
}

/// What the node said, when it did not fail.
///
/// Closed, and NOT `#[non_exhaustive]`: the two answers mean opposite things to the idempotency log
/// — one records a submission, the other settles the nonce terminally — and a catch-all arm that
/// swallowed a future third would be a mint recorded as something it was not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintSubmitted {
    /// The node accepted the transaction. The id is what an operator looks the mint up by, and what
    /// the idempotency log records against the nonce.
    Accepted(TxId),
    /// The on-chain `usedNonces` assert-then-set refused it (the on-chain replay guard): this
    /// deposit is already minted, by an earlier attempt or a competing relayer.
    ///
    /// **This is the safety backstop working, not a failure.** It is the one duplicate defence that
    /// is authoritative — the relayer's own idempotency store is a liveness backstop in front of it
    /// — so the answer is terminal: another attempt could only fail the same assert.
    AlreadyMinted,
}

/// **The seam.** Hands a built `XUsdcMintNote` to a Miden node.
///
/// Implemented against a real `miden-client` in a later slice, and by the test adapter the
/// orchestration
/// suites drive (explicitly NON-GATING — it fakes no Miden behaviour; it answers this interface on
/// a script). There is no production implementation in this crate: see [`production_submit_port`].
///
/// The `Pin<Box<dyn Future>>` return (rather than `async fn`) is what makes the trait usable behind
/// `&dyn` — the same shape [`HttpTransport`](crate::circle::HttpTransport) uses, for the same
/// reason.
///
/// # Errors
/// [`RelayerError::TransientSubmit`] — a condition that clears (node sync lag, a dropped connection).
/// The orchestration retries it under the configured attempt budget, then defers the attestation to
/// the next cycle; the deposit intent has no expiry, so waiting costs nothing but time.
/// [`RelayerError::FatalSubmit`] — a permanent refusal. Recorded as the TERMINAL
/// `SubmissionStatus::Rejected` (not the retryable `Failed`), alerted, never retried and never
/// re-driven from the retry queue.
pub trait MintSubmit: fmt::Debug + Send + Sync {
    fn submit_mint_note<'a>(
        &'a self,
        submission: MintSubmission<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<MintSubmitted, RelayerError>> + Send + 'a>>;
}

/// The production submit adapter — **which does not exist yet**, and says so.
///
/// A later slice replaces this body with a real `miden-client`-backed adapter once v0.16 has a
/// release. Until
/// then it returns [`RelayerError::MintSubmitPortUnavailable`], and `main` refuses to start on it.
///
/// A refusal, not a stub: a relayer that started with a no-op submit would poll Circle, validate
/// attestations, claim nonces, build notes, and mint nothing — and would look, in every log and
/// every metric except the chain's, exactly like a relayer that was working.
///
/// # Errors
/// [`RelayerError::MintSubmitPortUnavailable`], always.
pub fn production_submit_port() -> Result<Box<dyn MintSubmit>, RelayerError> {
    Err(RelayerError::MintSubmitPortUnavailable)
}

/// The cause carried by a [`RelayerError::TransientSubmit`] when a submit attempt hit its DEADLINE
/// rather than the node answering. It is a TRANSIENT failure — a hung or slow node may recover —
/// and the deadline is what keeps one attempt from waiting forever, so the whole retry loop is
/// bounded (the envelope `RecoveryPolicy` validates against). A real `std::error::Error`, so it
/// sits in the `Cause` source chain exactly like a real adapter's timeout would.
#[derive(Debug)]
pub(crate) struct SubmitDeadlineExceeded {
    pub(crate) after_ms: u64,
}

impl fmt::Display for SubmitDeadlineExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the miden submit did not answer within its {}ms deadline",
            self.after_ms
        )
    }
}

impl std::error::Error for SubmitDeadlineExceeded {}
