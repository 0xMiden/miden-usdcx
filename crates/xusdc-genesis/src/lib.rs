//! The xUSDC genesis tool: builds the genesis xUSDC faucet offline from the role-account ids
//! extracted out of the config-referenced `.mac` files, and writes the faucet's `.mac` account
//! file. See the crate README for usage and the config schema.

pub mod accounts;
pub mod config;
pub mod output;
