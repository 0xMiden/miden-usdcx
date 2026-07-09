//! The pinned `miden-client 0.15.3` assembly used for path-C execution.
//!
//! gRPC against the local sequencer RPC + SQLite store + filesystem keystore (all under the
//! gitignored run root) + the client's local transaction prover. The harness keeps its own
//! [`GrpcClient`] handle so evidence reads (`GetAccount`) hit the NODE directly rather than the
//! client's local store.

use std::sync::Arc;

use anyhow::Result;
use miden_client::keystore::FilesystemKeyStore;
use miden_client::rpc::GrpcClient;
use miden_client::Client;

use crate::config::StackConfig;

/// The assembled client + the pieces the harness needs alongside it.
pub struct HarnessClient {
    /// The full path-C client (execute + prove + submit + sync).
    pub client: Client<FilesystemKeyStore>,
    /// The keystore the actor wallets' Falcon keys live in.
    pub keystore: FilesystemKeyStore,
    /// A direct RPC handle for node-truth evidence reads (`GetAccount`).
    pub rpc: Arc<GrpcClient>,
}

/// Builds a fresh client rooted under `<run_root>/client-<label>` (store, keystore).
pub async fn build_client(stack: &StackConfig, label: &str) -> Result<HarnessClient> {
    let _ = (stack, label);
    todo!("LNV-1 driver: assemble GrpcClient + SqliteStore + FilesystemKeyStore client")
}
