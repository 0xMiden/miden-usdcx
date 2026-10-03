//! Startup configuration and preflight contract tests.

mod config;
mod preflight;
mod store;

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use tempfile::TempDir;

use crate::attester::Attester;
use crate::circle::CircleApi;
use crate::config::{Cli, Config, Invocation};

use super::support::{
    development_pair, development_signers, faucet_account_id, ready_circle, startup_anchor,
    CircleState, FakeCircle, ObservedRequest, TestChain, FAUCET_ACCOUNT_ID,
};

const SIGNING_KEY_ONE: &str =
    "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SIGNING_KEY_TWO: &str =
    "0x02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const KMS_KEY_ONE: &str =
    "arn:aws:kms:eu-north-1:584968076953:key/1f82bbff-391f-4aec-8995-fe5782e1d559";
const KMS_KEY_TWO: &str =
    "arn:aws:kms:eu-north-1:584968076953:key/5f5e3e2f-8818-48c0-a6e0-54aada5747b5";
const STORE_FILE: &str = "state/checkpoints/withdrawal-cursor.sqlite3";
const REQUEST_TIMEOUT: Duration = Duration::from_millis(275);

#[derive(Clone)]
pub(super) struct TestArgs {
    args: Vec<OsString>,
}

impl TestArgs {
    pub(super) fn new(tempdir: &TempDir, deployment_block: u32) -> Self {
        let anchor_commitment = startup_anchor().header().commitment().to_hex();
        Self {
            args: [
                "xusdc-attester".into(),
                "--signer-provider".into(),
                "aws-kms".into(),
                "--aws-kms-region".into(),
                "eu-north-1".into(),
                "--aws-kms-key-arn".into(),
                KMS_KEY_ONE.into(),
                KMS_KEY_TWO.into(),
                "--aws-kms-operation-timeout".into(),
                "10s".into(),
                "--miden-rpc-url".into(),
                "https://rpc.devnet.miden.io".into(),
                "--circle-url".into(),
                "https://circle.example.invalid".into(),
                "--request-timeout".into(),
                "275ms".into(),
                "--faucet-account-id".into(),
                FAUCET_ACCOUNT_ID.into(),
                "--max-withdrawal-fee".into(),
                "1000000".into(),
                "--max-withdrawal-fee-bps".into(),
                "0".into(),
                "--cctp-forwarding-max-fee".into(),
                "500000".into(),
                "--cctp-forwarder-address".into(),
                "0x008888878f94c0d87defdf0b07f46b93c1934442".into(),
                "--cctp-token-messenger-address".into(),
                "0x8fe6b999dc680ccfdd5bf7eb0974218be2542daa".into(),
                "--poll-interval".into(),
                "1s".into(),
                "--faucet-deployment-block".into(),
                deployment_block.to_string().into(),
                "--trusted-anchor-block".into(),
                "0".into(),
                "--trusted-anchor-commitment".into(),
                anchor_commitment.into(),
                "--expected-signing-public-key".into(),
                SIGNING_KEY_ONE.into(),
                "--expected-signing-public-key".into(),
                SIGNING_KEY_TWO.into(),
                "--minimum-finality-depth-blocks".into(),
                "1".into(),
                "--store-path".into(),
                tempdir.path().join(STORE_FILE).into_os_string(),
            ]
            .into(),
        }
    }

    pub(super) fn replace(&mut self, flag: &str, value: impl Into<OsString>) {
        let position = self
            .args
            .iter()
            .position(|argument| argument == flag)
            .unwrap_or_else(|| panic!("missing test argument {flag}"));
        self.args[position + 1] = value.into();
    }

    /// Removes every occurrence of `flag` with all of its values.
    pub(super) fn remove(&mut self, flag: &str) {
        while let Some(position) = self.args.iter().position(|argument| argument == flag) {
            let values = self.args[position + 1..]
                .iter()
                .take_while(|argument| !argument.to_string_lossy().starts_with("--"))
                .count();
            self.args.drain(position..=position + values);
        }
    }

    pub(super) fn append(&mut self, flag: &str, value: impl Into<OsString>) {
        self.append_values(flag, &[value.into()]);
    }

    pub(super) fn append_values(&mut self, flag: &str, values: &[OsString]) {
        self.args.push(flag.into());
        self.args.extend_from_slice(values);
    }

    pub(super) fn switch(&mut self, flag: &str) {
        self.args.push(flag.into());
    }

    pub(super) fn parse(&self) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(&self.args)
    }

    pub(super) fn invocation(&self) -> Result<Invocation, clap::Error> {
        Invocation::try_parse_from(&self.args)
    }

    pub(super) fn config(&self) -> anyhow::Result<Config> {
        Config::try_from(
            self.parse()
                .expect("test arguments must have valid CLI syntax"),
        )
    }

    pub(super) fn load(&self) -> Config {
        self.config().expect("test configuration must be valid")
    }
}

fn load_config(tempdir: &TempDir, deployment_block: u32) -> Config {
    TestArgs::new(tempdir, deployment_block).load()
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
    Attester::start(config, Box::new(chain), circle, development_pair().await).await
}
