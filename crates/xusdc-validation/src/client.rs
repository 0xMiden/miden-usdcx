//! The pinned `miden-client 0.15.3` assembly used for path-C execution.
//!
//! gRPC against the local sequencer RPC + SQLite store + filesystem keystore (all under the
//! gitignored run root) + the client's local transaction prover. The harness keeps its own
//! [`GrpcClient`] handle so evidence reads (`GetAccount`) hit the NODE directly rather than the
//! client's local store.

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use miden_client::builder::ClientBuilder;
use miden_client::keystore::FilesystemKeyStore;
use miden_client::rpc::{Endpoint, GrpcClient};
use miden_client::DebugMode;
use miden_client_sqlite_store::ClientBuilderSqliteExt;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::Felt;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::config::StackConfig;

/// RPC request timeout (ms) — local loopback node, generous for proof-verification calls.
const RPC_TIMEOUT_MS: u64 = 30_000;

/// The assembled client + the pieces the harness needs alongside it.
pub struct HarnessClient {
    /// The full path-C client (execute + prove + submit + sync).
    pub client: miden_client::Client<FilesystemKeyStore>,
    /// The keystore the actor wallets' Falcon keys live in.
    pub keystore: FilesystemKeyStore,
    /// A direct RPC handle for node-truth evidence reads (`GetAccount`).
    pub rpc: Arc<GrpcClient>,
}

/// Draws a 32-byte seed from OS entropy.
pub fn os_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

/// Builds a fresh client rooted under `<run_root>/client-<label>` (store, keystore).
pub async fn build_client(stack: &StackConfig, label: &str) -> Result<HarnessClient> {
    let client_root = stack.run_root.join(format!("client-{label}"));
    fs::create_dir_all(&client_root)
        .with_context(|| format!("creating {}", client_root.display()))?;

    let endpoint = Endpoint::new("http".into(), "127.0.0.1".into(), Some(stack.rpc_port));
    let rpc = Arc::new(GrpcClient::new(&endpoint, RPC_TIMEOUT_MS));

    let keystore = FilesystemKeyStore::new(client_root.join("keystore"))
        .map_err(|e| anyhow::anyhow!("creating the filesystem keystore: {e}"))?;

    let mut coin_seed = [0u64; 4];
    for felt in &mut coin_seed {
        *felt = OsRng.next_u64();
    }
    let rng = RandomCoin::new(coin_seed.map(Felt::new_unchecked).into());

    let client = ClientBuilder::new()
        .rpc(rpc.clone())
        .rng(Box::new(rng))
        .sqlite_store(client_root.join("store.sqlite3"))
        .authenticator(Arc::new(keystore.clone()))
        .in_debug_mode(DebugMode::Disabled)
        .tx_discard_delta(None)
        .build()
        .await
        .context("building the miden client")?;

    Ok(HarnessClient { client, keystore, rpc })
}
