//! The xUSDC genesis tool: derives the faucet and role accounts fully OFFLINE so their ids are
//! known before any network exists, and emits everything the node's genesis needs.
//!
//! Account-id derivation is a hash of the seed plus the code and storage commitments — no chain
//! state — so the whole pipeline is deterministic given the config: six basic wallets (operator
//! plus the five faucet role holders), then the xUSDC faucet built as the network's NATIVE fee
//! faucet via `XReserveStablecoinBuilder::build_genesis_account`, every account promoted to
//! nonce one (genesis accounts exist, they are not deployed). The outputs are the seven `.mac`
//! account files, a plain-text `genesis.toml` fragment referencing them, an `accounts.json`
//! summary, and a stdout listing of each id in hex and bech32.

pub mod accounts;
pub mod config;
pub mod keys;
pub mod output;
