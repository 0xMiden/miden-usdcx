//! Validates Circle deposit attestations, builds mint notes, and coordinates submission.
//! [`validate`] checks the envelope and deposit fields using the shared codec; the faucet verifies
//! signatures and enforces mint authorization on-chain. [`circle`] handles API access, while
//! [`idempotency`] persists nonce claims and pagination cursors across restarts.
//!
//! [`cycle`] records an outcome for each fetched attestation and submits through [`cycle::MintSubmit`].
//! The production Miden adapter is unimplemented, so [`cycle::production_submit_port`] returns an
//! error and the binary refuses to start with a no-op submitter.

pub mod circle;
pub mod config;
pub mod cycle;
pub mod error;
pub mod idempotency;
pub mod miden;
pub mod observability;
pub mod validate;

pub use error::RelayerError;
