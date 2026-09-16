//! The xUSDC genesis tool: builds the genesis xUSDC faucet fully OFFLINE — before any network
//! exists — against six externally-provided role accounts, and emits everything the node's
//! genesis needs.
//!
//! The role wallets (the operator plus the five faucet role holders) are NOT created here: the
//! config references their protocol `AccountFile`s by path, produced by whatever account tooling
//! the deployment uses. Account-id derivation is a hash of the seed plus the code and storage
//! commitments — no chain state — so the faucet id is deterministic given the config: the xUSDC
//! faucet is built as the network's NATIVE fee faucet via
//! `XReserveStablecoinBuilder::build_genesis_account`, and every account is emitted at nonce one
//! (genesis accounts exist, they are not deployed). The outputs are the seven `.mac` account
//! files, a plain-text `genesis.toml` fragment referencing them, an `accounts.json` summary, and
//! a stdout listing of each id in hex and bech32.

pub mod accounts;
pub mod config;
pub mod output;
