//! Persists withdrawal claims keyed by `burnTxId`.
//! The ledger acquires all batches atomically before submission. Pending claims block resubmission
//! and have no automatic expiry: after a crash, Circle may have received the request.
//! Recovery requires polling a known withdrawal or operator reconciliation.
//!
//! The ledger rejects ephemeral databases. Circle's acceptance of Miden transaction IDs as
//! `burnTxId` remains OPEN.

mod clock;
mod error;
mod record;
mod store;

pub use clock::{Clock, SystemClock};
pub use error::LedgerError;
pub use record::{BurnKey, ClaimOutcome, SubmissionRecord, SubmissionStatus};
pub use store::{SubmitLedger, LEDGER_SCHEMA_VERSION};
