//! Client assembly + RPC-URL parsing for the sanity gate.
//!
//! [`build_client_at`] mirrors [`crate::client::build_client`] but takes a full URL so the host is
//! NOT hardcoded to loopback — the devnet re-run points it at the deployed node.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use miden_client::builder::ClientBuilder;
use miden_client::keystore::FilesystemKeyStore;
use miden_client::rpc::{Endpoint, GrpcClient};
use miden_client_sqlite_store::ClientBuilderSqliteExt;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::Felt;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::client::HarnessClient;

/// RPC request timeout (ms) — generous for proof-verification round-trips.
const RPC_TIMEOUT_MS: u64 = 30_000;

/// Parses an RPC URL into `(scheme, host, port)`. Loopback URLs carry an explicit port
/// (`http://127.0.0.1:57291`); the devnet URL carries none (`https://rpc.devnet.miden.io`).
pub(crate) fn parse_url_parts(rpc_url: &str) -> Result<(String, String, Option<u16>)> {
    let (scheme, rest) = rpc_url
        .split_once("://")
        .map(|(s, r)| (s.to_string(), r))
        .unwrap_or_else(|| ("http".to_string(), rpc_url));
    let rest = rest.trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .with_context(|| format!("parsing the RPC port from '{rpc_url}'"))?;
            (h.to_string(), Some(port))
        }
        None => (rest.to_string(), None),
    };
    if host.is_empty() {
        bail!("could not parse a host from RPC URL '{rpc_url}'");
    }
    Ok((scheme, host, port))
}

fn parse_endpoint(rpc_url: &str) -> Result<Endpoint> {
    let (scheme, host, port) = parse_url_parts(rpc_url)?;
    Ok(Endpoint::new(scheme, host, port))
}

/// Builds a fresh client rooted under `<run_root>/client` against the endpoint parsed from `rpc_url`.
pub(crate) async fn build_client_at(
    rpc_url: &str,
    run_root: &std::path::Path,
) -> Result<HarnessClient> {
    let client_root = run_root.join("client");
    std::fs::create_dir_all(&client_root)
        .with_context(|| format!("creating {}", client_root.display()))?;

    let endpoint = parse_endpoint(rpc_url)?;
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
        .tx_discard_delta(None)
        .build()
        .await
        .context("building the miden client")?;

    Ok(HarnessClient {
        client,
        keystore,
        rpc,
    })
}
