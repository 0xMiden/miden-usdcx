//! The xUSDC genesis tool: builds the genesis xUSDC faucet fully OFFLINE — before any network
//! exists — and emits the node's genesis inputs.
//!
//! The faucet is the ONLY account the tool builds. The six role accounts (the network operator
//! plus the five faucet role holders) are referenced in the config as paths to their
//! externally-produced `.mac` files; each file is read ONLY to extract its account id (and must
//! already be genesis-injectable: nonce one, no seed), so the faucet's role slots and the
//! genesis account set are consistent by construction. Account-id derivation is a hash of the
//! seed plus the code and storage commitments — no chain state — so the faucet id is
//! deterministic given the config: the faucet is built as the network's NATIVE fee faucet via
//! `XReserveStablecoinBuilder::build_genesis_account` and emitted at nonce one with no seed (a
//! genesis account exists, it is not deployed). The outputs are the faucet's `.mac` account
//! file, a plain-text `genesis.toml` fragment referencing it plus the role `.mac` files (by
//! reference — never copied), an `accounts.json` summary, and a stdout listing of the ids in
//! hex and bech32.

pub mod accounts;
pub mod config;
pub mod output;
