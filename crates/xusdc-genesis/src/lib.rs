//! The xUSDC genesis tool: builds the genesis xUSDC faucet fully OFFLINE — before any network
//! exists — and writes its `.mac` account file.
//!
//! The faucet is the ONLY account the tool builds, and its `.mac` file is the only file
//! output. The six role accounts (the network operator plus the five faucet role holders) are
//! referenced in the config as paths to their externally-produced `.mac` files; each file is
//! read PURELY to extract its account id, so the faucet's role slots and the genesis account
//! set are consistent by construction. Account-id derivation is a hash of the seed plus the
//! code and storage commitments — no chain state — so the faucet id is deterministic given the
//! config: the faucet is built as the network's NATIVE fee faucet via
//! `XReserveStablecoinBuilder::build_genesis_account` and emitted at nonce one with no seed (a
//! genesis account exists, it is not deployed). The ids (faucet in hex and bech32, plus the
//! extracted role ids) go to stdout; assembling the node's `genesis.toml` from the account
//! files is the network operator's job (the crate README documents the recipe).

pub mod accounts;
pub mod config;
pub mod output;
