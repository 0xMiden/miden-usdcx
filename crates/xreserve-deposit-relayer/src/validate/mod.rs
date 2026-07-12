//! Circle-facing off-chain validation (the fail-fast checks before the seam; §3, §8.1). This slice
//! ships the DepositIntent structural decoder ([`deposit_intent`], the mirror of D5a); the
//! attestation-envelope + `messageHash == keccak256(payload)` checks land in a later slice.

pub mod deposit_intent;

pub use deposit_intent::{decode_and_validate_deposit_intent, DepositIntent};
