//! # xusdc-validation — the local-node validation harness (LNV track)
//!
//! Real-node validation of the PRODUCTION xUSDC faucet (post-F5 composition, built by
//! `XReserveStablecoinBuilder`) against a pinned local Miden node stack. This crate is
//! **validation-only**: it deploys and drives the faucet through real RPC and asserts on-chain
//! outcomes — it never modifies production faucet code (validator-not-fixer), and a failing
//! assertion here is a surfaced production finding, not something to patch around.
//!
//! This slice (LNV-1) owns the harness foundation plus matrix row A (deploy + recognize).
//!
//! ## Architecture
//! - [`stack`] — lifecycle of the four-service v16 local node stack (validator + sequencer +
//!   ntx-builder + the remote tx prover the ntx-builder requires), brought up from the client
//!   repo's own `start-test-node.sh` against a fresh isolated genesis.
//! - [`actors`] — local test identities: the keyed wallets (owner / DOM_PAUSER / DOM_MANAGER /
//!   BLK_MANAGER holders / recipient / holder) and a locally generated secp256k1 attester (NEVER
//!   Circle keys).
//! - [`client`] — the `miden-client` assembly (gRPC + SQLite store + filesystem keystore) used for
//!   path-C (client-side build+prove+submit) execution.
//! - [`deploy`] — the production faucet composition (the `XReserveStablecoinBuilder` output under
//!   the frozen `AuthNetworkAccount` allowlist) and the deploy driver.
//! - [`rows_ab`] — the row-A driver: runs the full flow and returns [`RowsAbObservations`].
//! - [`assertions`] — the row-A assertion suite over those observations (written FIRST,
//!   test-first; the drivers exist to feed them).
//! - [`evidence`] — the machine-readable run evidence (JSON) + node-log archival manifest.

pub mod actors;
pub mod assertions;
pub mod assertions_cf;
pub mod assertions_de;
pub mod assertions_gj;
pub mod assertions_kl;
pub mod client;
pub mod config;
pub mod deploy;
pub mod evidence;
pub mod evidence_cf;
pub mod evidence_de;
pub mod evidence_gj;
pub mod mintburn;
pub mod observations;
pub mod observations_cf;
pub mod observations_de;
pub mod observations_gj;
pub mod observations_kl;
pub mod record;
pub mod rows_ab;
pub mod rows_cf;
pub mod rows_de;
pub mod rows_gj;
pub mod rows_kl;
pub mod sanity;
pub mod stack;

pub use config::{DomainParams, RunConfig, StackConfig};
pub use observations::RowsAbObservations;
pub use observations_cf::RowsCfObservations;
pub use observations_de::RowsDeObservations;
pub use observations_gj::RowsGjObservations;
pub use observations_kl::FullMatrixObservations;
pub use rows_ab::run_rows_ab;
pub use rows_cf::run_rows_cf;
pub use rows_de::run_rows_de;
pub use rows_gj::run_rows_gj;
pub use rows_kl::run_full_matrix;
pub use sanity::{run_sanity, SanityConfig, SanityReport};
