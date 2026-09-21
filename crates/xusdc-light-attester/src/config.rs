//! Deployment-specific attester configuration.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use reqwest::Url;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
#[error("{context}")]
pub struct ConfigError {
    context: &'static str,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl ConfigError {
    fn invalid(context: &'static str) -> Self {
        Self {
            context,
            source: None,
        }
    }

    fn with_source(context: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            context,
            source: Some(Box::new(source)),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    circle_request_timeout_ms: u64,
    faucet_account_id_hex: String,
    circle_api_base_url: String,
    poll_interval_ms: u64,
    faucet_deployment_block: u32,
    expected_signing_public_keys_hex: Vec<String>,
    store_path: PathBuf,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Config {
    circle_request_timeout: Duration,
    faucet_account_id: AccountId,
    circle_api_base_url: Url,
    poll_interval: Duration,
    faucet_deployment_block: BlockNumber,
    expected_signing_public_keys_hex: Vec<String>,
    store_path: PathBuf,
}

#[allow(dead_code)]
impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let encoded = fs::read_to_string(path)
            .map_err(|source| ConfigError::with_source("failed to read config", source))?;
        let raw: RawConfig = toml::from_str(&encoded)
            .map_err(|source| ConfigError::with_source("failed to parse config", source))?;

        if raw.circle_request_timeout_ms == 0 {
            return Err(ConfigError::invalid(
                "circle request timeout must be greater than zero",
            ));
        }
        if raw.poll_interval_ms == 0 {
            return Err(ConfigError::invalid(
                "poll interval must be greater than zero",
            ));
        }

        let faucet_account_id = AccountId::from_hex(&raw.faucet_account_id_hex)
            .map_err(|source| ConfigError::with_source("faucet account id is invalid", source))?;
        if faucet_account_id.to_hex() != raw.faucet_account_id_hex {
            return Err(ConfigError::invalid(
                "faucet account id must use canonical 0x-prefixed lowercase hex",
            ));
        }

        let circle_api_base_url = Url::parse(&raw.circle_api_base_url)
            .map_err(|source| ConfigError::with_source("Circle API base URL is invalid", source))?;
        if circle_api_base_url.scheme() != "https" || circle_api_base_url.host_str().is_none() {
            return Err(ConfigError::invalid(
                "Circle API base URL must be an absolute HTTPS URL",
            ));
        }

        if raw.store_path.as_os_str().is_empty() {
            return Err(ConfigError::invalid("store path must not be empty"));
        }
        let config_parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let store_path = if raw.store_path.is_absolute() {
            raw.store_path
        } else {
            config_parent.join(raw.store_path)
        };
        let store_parent = store_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let store_parent_metadata = fs::metadata(store_parent).map_err(|source| {
            ConfigError::with_source("store path parent does not exist", source)
        })?;
        if !store_parent_metadata.is_dir() {
            return Err(ConfigError::invalid(
                "store path parent must be a directory",
            ));
        }

        Ok(Self {
            circle_request_timeout: Duration::from_millis(raw.circle_request_timeout_ms),
            faucet_account_id,
            circle_api_base_url,
            poll_interval: Duration::from_millis(raw.poll_interval_ms),
            faucet_deployment_block: BlockNumber::from(raw.faucet_deployment_block),
            expected_signing_public_keys_hex: raw.expected_signing_public_keys_hex,
            store_path,
        })
    }

    pub(crate) fn circle_request_timeout(&self) -> Duration {
        self.circle_request_timeout
    }

    pub(crate) fn faucet_account_id(&self) -> AccountId {
        self.faucet_account_id
    }

    pub(crate) fn circle_api_base_url(&self) -> &Url {
        &self.circle_api_base_url
    }

    pub(crate) fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    pub(crate) fn faucet_deployment_block(&self) -> BlockNumber {
        self.faucet_deployment_block
    }

    pub(crate) fn expected_signing_public_keys_hex(&self) -> &[String] {
        &self.expected_signing_public_keys_hex
    }

    pub(crate) fn store_path(&self) -> &Path {
        &self.store_path
    }
}
