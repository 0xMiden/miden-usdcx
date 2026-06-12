//! Rust mirror of the 04 shared-encoding surface — module homes and signatures exactly
//! per the frozen `COMPONENT-SPEC.md §6` (mirrored read-only in `docs/spec/`).

mod account_id;
mod amount;
mod bytes32;
mod deposit_intent;
mod error;

pub use account_id::*;
pub use amount::*;
pub use bytes32::*;
pub use deposit_intent::*;
pub use error::*;
