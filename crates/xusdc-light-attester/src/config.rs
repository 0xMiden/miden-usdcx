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
    request_timeout: Duration,
    faucet_account_id: AccountId,
    circle_api_base_url: Url,
    poll_interval: Duration,
    fallback_checkpoint_block: BlockNumber,
    expected_signing_public_keys: Vec<SigningPublicKey>,
    store_path: PathBuf,
}

#[allow(dead_code)]
impl Config {
    #[allow(unused_variables)]
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        todo!()
    }

    pub(crate) fn request_timeout(&self) -> Duration {
        todo!()
    }

    pub(crate) fn faucet_account_id(&self) -> AccountId {
        todo!()
    }

    pub(crate) fn circle_api_base_url(&self) -> &Url {
        todo!()
    }

    pub(crate) fn poll_interval(&self) -> Duration {
        todo!()
    }

    pub(crate) fn fallback_checkpoint_block(&self) -> BlockNumber {
        todo!()
    }

    pub(crate) fn expected_signing_public_keys(&self) -> &[SigningPublicKey] {
        todo!()
    }

    pub(crate) fn store_path(&self) -> &Path {
        todo!()
    }
}
