//! Persists deposit claims and per-domain pagination cursors in SQLite.
//! [`IdempotencyStore::claim_nonce`] atomically acquires a nonce before submission; failed
//! records must be claimed again before retrying. The faucet's nonce check prevents double minting.
//!
//! Record each page's deposits before advancing its cursor so a crash cannot skip unrecorded work.
//! [`IdempotencyStore::retryable`] finds failures after their pages have been passed, and
//! [`IdempotencyStore::reclaim_stale_pending`] recovers abandoned claims. Ephemeral databases
//! are rejected because claims and cursors must survive restart.

mod clock;
mod cursor;
mod record;
mod recovery;
mod rows;
mod store;

pub use clock::{Clock, SystemClock};
pub use cursor::Cursor;
pub use record::{ClaimOutcome, IdempotencyRecord, SubmissionStatus, TxId};
pub use store::{IdempotencyStore, STORE_SCHEMA_VERSION};

// re-exported into the module docs' link scope
#[allow(unused_imports)]
use crate::error::RelayerError;
