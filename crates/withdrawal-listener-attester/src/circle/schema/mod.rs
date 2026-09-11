//! Circle withdrawal request and response types.
//! [`prepare`] defines prepare requests, [`intents`] defines returned intents, and [`withdraw`]
//! defines submission and status types. Construction and deserialization validate field formats
//! and cross-field constraints.
//!
//! Prepare and submit bodies use a `batches` wrapper. Submission responses are arrays of statuses;
//! status lookup returns one status. The partner supplies `remoteDepositor`; Circle supplies
//! `sourceDepositor` in the returned intent.
//!
//! Required fields cannot be omitted. Optional fields reject explicit nulls. Requests reject
//! unknown fields; responses tolerate additions. Schema validation does not authorize signing:
//! [`validate_returned`](crate::validate::validate_returned) checks the response against the burn.

pub mod intents;
pub mod prepare;
pub mod withdraw;

pub use intents::{
    BurnIntent, PrepareWithdrawalResponse, PreparedBatch, StructuredHookData, TransferSpec,
};
pub use prepare::{ForwardingOptions, PrepareBurnIntentInput, PrepareWithdrawalRequest};
pub use withdraw::{
    WithdrawBatch, WithdrawConflict, WithdrawRequest, WithdrawSubmissionResponse, WithdrawalStatus,
    WithdrawalStatusKind,
};
