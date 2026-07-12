//! Rust mirror of the shared-encoding surface — module homes and signatures exactly
//! per the shared-encoding spec (mirrored read-only in `docs/spec/`).

mod account_id;
mod amount;
mod attestation;
mod burn_note;
mod bytes32;
mod deposit_intent;
mod error;

pub use account_id::*;
pub use amount::*;
pub use attestation::*;
pub use burn_note::*;
pub use bytes32::*;
pub use deposit_intent::*;
pub use error::*;
