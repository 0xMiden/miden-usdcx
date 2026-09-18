//! Startup configuration and preflight contract tests.

mod config;
mod preflight;
mod store;

use std::path::PathBuf;
use std::time::Duration;

use tempfile::TempDir;

use crate::attester::Attester;
use crate::circle::CircleApi;
use crate::config::Config;

use super::support::{
    development_signers, faucet_account_id, ready_circle, startup_anchor, CircleState, FakeCircle,
    ObservedRequest, TestChain, FAUCET_ACCOUNT_ID,
};

const SIGNING_KEY_ONE: &str =
    "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SIGNING_KEY_TWO: &str =
    "0x02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const CONFIG_FILE: &str = "attester.toml";
const STORE_FILE: &str = "state/checkpoints/withdrawal-cursor.sqlite3";
const REQUEST_TIMEOUT: Duration = Duration::from_millis(275);

fn replace_setting(config: &str, key: &str, replacement: &str) -> String {
    config
        .lines()
        .map(|line| {
            if line.starts_with(&format!("{key} =")) {
                replacement
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

pub(super) fn config_toml(deployment_block: u64) -> String {
    let anchor_commitment = startup_anchor().header().commitment().to_hex();
    format!(
        "miden_network = \"devnet\"\n\
         circle_request_timeout_ms = {}\n\
         faucet_account_id_hex = \"{FAUCET_ACCOUNT_ID}\"\n\
         circle_api_base_url = \"https://circle.example.invalid\"\n\
         use_circle_forwarding = false\n\
         withdrawal_limit = 10_000_000_000_000\n\
         poll_interval_ms = 1000\n\
         faucet_deployment_block = {deployment_block}\n\
         trusted_anchor_block = 0\n\
         trusted_anchor_commitment_hex = \"{anchor_commitment}\"\n\
         minimum_finality_depth_blocks = 1\n\
         expected_signing_public_keys_hex = [\"{SIGNING_KEY_ONE}\", \"{SIGNING_KEY_TWO}\"]\n\
         store_path = \"{STORE_FILE}\"\n",
        REQUEST_TIMEOUT.as_millis()
    )
}

fn write_config(tempdir: &TempDir, deployment_block: u32) -> PathBuf {
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, config_toml(u64::from(deployment_block))).unwrap();
    path
}

fn load_config(tempdir: &TempDir, deployment_block: u32) -> Config {
    Config::load(&write_config(tempdir, deployment_block)).unwrap()
}

pub(super) fn create_store_parent(tempdir: &TempDir) -> PathBuf {
    let path = tempdir.path().join(STORE_FILE);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

pub(super) async fn start(
    config: Config,
    chain: TestChain,
    circle: Box<dyn CircleApi>,
) -> anyhow::Result<Attester> {
    Attester::start(config, Box::new(chain), circle, development_signers()).await
}
