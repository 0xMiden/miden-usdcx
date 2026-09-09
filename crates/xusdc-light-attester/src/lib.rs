//! The off-chain xUSDC withdrawal attester.

pub mod attester;
pub(crate) mod burn;
pub mod chain;
pub mod circle;
pub mod config;
pub mod signer;
pub(crate) mod store;
// The submission stage will call this gate before anything can be signed.
#[allow(dead_code)]
pub(crate) mod verify;

pub use attester::{Attester, CycleReport, RunError};

#[cfg(test)]
mod tests;
