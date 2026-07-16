//! Why the [`SubmitLedger`](super::SubmitLedger) refused.
//!
//! It is a type of its own rather than a [`ListenerError`](crate::error::ListenerError) family, and it
//! lives beside the ledger rather than in `error.rs`, for the same reason
//! [`DecodeError`](crate::error::DecodeError) is its own type: a ledger failure is a statement about
//! ONE burn's bookkeeping, and the caller's response to it (stop, surface, let an operator look) is not
//! the response to a Circle transport failure. It is re-exported through
//! [`crate::idempotency`](super), which is the only place it is reachable from.
//!
//! **Every variant is a REFUSAL, and every refusal fails CLOSED.** There is no variant that means
//! "probably fine, go ahead" — a ledger that cannot answer must never be read as "not submitted",
//! because that answer re-releases funds.

use core::fmt;

use crate::error::Cause;
use crate::idempotency::record::SubmissionStatus;

/// Everything the [`SubmitLedger`](super::SubmitLedger) can refuse to do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerError {
    /// The configured ledger path is one SQLite would not have made durable — it would open cleanly,
    /// take every claim, and lose them all on the next restart: a cache wearing the ledger's name. The
    /// service does not start.
    EphemeralStorePath { path: String, detail: String },

    /// The file was written with a different ledger layout. REFUSED rather than read with the wrong
    /// one — silently misreading a burn's status is exactly the failure the ledger exists to prevent,
    /// and a migration is an operator's deliberate act, not a side effect of a restart.
    UnsupportedLedgerSchema { found: u32, expected: u32 },

    /// The database could not be opened, read, or written (a missing parent directory, a permission, a
    /// full disk, a lock timeout). A listener that cannot reach its ledger must fail LOUDLY: running
    /// without one means re-submitting after the next restart.
    Store(Cause),

    /// A stored row cannot be read — an unknown status token, a timestamp that is not a timestamp. It
    /// is NEVER treated as absent: that would re-claim, and re-submit, a burn that may already be
    /// settled.
    CorruptLedgerRecord { detail: String },

    /// A status was recorded against a burn that was never claimed. A submission cannot be recorded
    /// for a burn with no claim behind it — the claim IS the decision, so a record without one means
    /// the decision was skipped.
    UnknownBurn { burn_tx_id: String },

    /// The machine has no `from → to` edge. The load-bearing case is `Submitted → Failed`: `Failed` is
    /// the re-claimable state, so that edge would let a retry driver re-POST a withdrawal Circle may
    /// already be releasing.
    IllegalStatusTransition {
        from: SubmissionStatus,
        to: SubmissionStatus,
    },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EphemeralStorePath { path, detail } => write!(
                f,
                "the submit ledger path `{path}` would not be durable: {detail}"
            ),
            Self::UnsupportedLedgerSchema { found, expected } => write!(
                f,
                "the submit ledger was written with layout version {found}, but this build speaks {expected}"
            ),
            Self::Store(cause) => write!(f, "the submit ledger failed: {cause}"),
            Self::CorruptLedgerRecord { detail } => {
                write!(f, "a submit ledger row cannot be read: {detail}")
            }
            Self::UnknownBurn { burn_tx_id } => write!(
                f,
                "burn `{burn_tx_id}` was never claimed, so nothing can be recorded against it"
            ),
            Self::IllegalStatusTransition { from, to } => {
                write!(f, "a submitted burn cannot move from {from} to {to}")
            }
        }
    }
}

impl core::error::Error for LedgerError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Store(source) => Some(source.as_error()),
            Self::EphemeralStorePath { .. }
            | Self::UnsupportedLedgerSchema { .. }
            | Self::CorruptLedgerRecord { .. }
            | Self::UnknownBurn { .. }
            | Self::IllegalStatusTransition { .. } => None,
        }
    }
}

/// Every `rusqlite` failure becomes ONE ledger error, with the original preserved as its source — the
/// SQLite primary/extended code is what an operator needs, and a flattened string is not.
pub(super) fn store_failed(err: rusqlite::Error) -> LedgerError {
    LedgerError::Store(Cause::new(err))
}

pub(super) fn corrupt(detail: String) -> LedgerError {
    LedgerError::CorruptLedgerRecord { detail }
}
