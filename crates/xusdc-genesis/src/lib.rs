//! The xUSDC genesis tool: builds the genesis xUSDC faucet fully OFFLINE — before any network
//! exists — and emits the node's genesis inputs for it.
//!
//! This is the ONLY account the tool builds. The six role accounts (the network operator plus
//! the five faucet role holders) are referenced by bare account id in the config. Account-id
//! derivation is a hash of the seed plus the code and storage commitments — no chain state — so
//! the faucet id is deterministic given the config: the faucet is built as the network's NATIVE
//! fee faucet via `XReserveStablecoinBuilder::build_genesis_account` and emitted at nonce one
//! with no seed (a genesis account exists, it is not deployed). The outputs are the faucet's
//! `.mac` account file, a plain-text `genesis.toml` fragment referencing it, an `accounts.json`
//! summary, and a stdout listing of the faucet id in hex and bech32.

pub mod accounts;
pub mod config;
pub mod output;
