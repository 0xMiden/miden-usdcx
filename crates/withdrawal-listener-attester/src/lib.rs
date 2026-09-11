//! Withdrawal validation, signing, evidence assembly, and Circle API submission.
//!
//! [`listener::run_once`] validates the discovered burn and Circle's prepared response before
//! signing. It assembles a quorum, authorizes the signers, and submits through the durable
//! [`idempotency`] ledger. Repeated or ambiguous submissions require recovery or reconciliation.
//! Only Circle's `finalized` status completes a withdrawal.
//!
//! [`evidence`] distinguishes cryptographic proof of note creation from node-reported consumption.
//! Miden discovery and evidence reads are supplied through adapters; the crate has no node client.
//! Tests use the shared encoding vectors, an in-process Circle mock, and synthetic node reads.
//!
//! Circle decisions remain OPEN: authentication, Miden's domain and account-ID encoding,
//! forwarding, source-depositor assignment, amount and fee semantics, signing-digest derivation,
//! and acceptance of Miden transaction IDs and burn evidence.

pub mod attester;
pub mod circle;
pub mod config;
pub mod error;
pub mod evidence;
pub mod idempotency;
pub mod listener;
pub mod note_decode;
pub mod submit;
pub mod types;
pub mod validate;
pub mod withdrawal_api;

pub use error::{
    DecodeError, DiscoveryReject, ListenerError, QuorumError, SignError, SignatureError,
    SubmitGateError, ValidationMismatch,
};
pub use evidence::{EvidenceError, EvidenceReadError};
pub use idempotency::LedgerError;
pub use submit::SubmitError;
