//! The off-chain xUSDC withdrawal attester.

pub mod attester;
pub(crate) mod burn;
pub mod chain;
pub mod circle;
pub mod config;
pub mod signer;
pub(crate) mod store;
pub(crate) mod submission;
// Fresh withdrawals pass this gate before either signer is called.
pub(crate) mod verify;

pub use attester::{Attester, CycleReport};

#[cfg(test)]
mod tests;
