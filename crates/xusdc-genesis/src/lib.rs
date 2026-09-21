//! The xUSDC genesis tool: builds the genesis xUSDC faucet offline from the role-account ids
//! in its config and writes the faucet's `.mac` account file. See the crate README for usage
//! and the config schema.

pub mod accounts;
pub mod config;
pub mod output;

pub use output::FAUCET_MAC_FILE;
