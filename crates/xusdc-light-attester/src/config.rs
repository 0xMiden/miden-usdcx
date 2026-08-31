//! Deployment-specific attester configuration.

use std::path::{Path, PathBuf};
use std::time::Duration;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use reqwest::Url;

use crate::signer::SigningPublicKey;

#[derive(Debug)]
pub struct ConfigError;

#[allow(dead_code)]
pub struct Config {
    node_rpc_url: Url,
    request_timeout: Duration,
    faucet_account_id: AccountId,
    circle_api_base_url: Url,
    poll_interval: Duration,
    fallback_checkpoint_block: BlockNumber,
    expected_signing_public_keys: Vec<SigningPublicKey>,
    store_path: PathBuf,
}

impl Config {
    #[allow(unused_variables)]
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        todo!()
    }
}
