//! The off-chain xUSDC withdrawal attester.

pub mod attester;
pub mod chain;
pub mod circle;
pub mod config;
pub mod signer;
pub(crate) mod store;

pub use attester::{Attester, CycleReport, RunError};

#[cfg(test)]
mod tests;
