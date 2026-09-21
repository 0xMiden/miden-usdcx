//! Deployment-specific attester configuration.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::BlockNumber;
use miden_protocol::Word;
use reqwest::Url;
use serde::Deserialize;

/// Public Miden network selected for the normal attester executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MidenNetwork {
    Devnet,
    Testnet,
}

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
    miden_network: MidenNetwork,
    circle_request_timeout_ms: u64,
    faucet_account_id_hex: String,
    circle_api_base_url: String,
    use_circle_forwarding: bool,
    #[serde(default)]
    max_withdrawal_fee: u64,
    withdrawal_limit: u64,
    #[serde(default = "default_withdrawal_window_hours")]
    withdrawal_window_hours: u64,
    withdrawal_cap_error_message: Option<String>,
    poll_interval_ms: u64,
    faucet_deployment_block: u32,
    trusted_anchor_block: u32,
    trusted_anchor_commitment_hex: String,
    minimum_finality_depth_blocks: u32,
    expected_signing_public_keys_hex: Vec<String>,
    store_path: PathBuf,
}

#[derive(Debug)]
pub struct Config {
    miden_network: MidenNetwork,
    circle_request_timeout: Duration,
    faucet_account_id: AccountId,
    circle_api_base_url: Url,
    use_circle_forwarding: bool,
    max_withdrawal_fee: AssetAmount,
    withdrawal_limit: u64,
    withdrawal_window_ms: i64,
    withdrawal_cap_error_message: Option<String>,
    poll_interval: Duration,
    faucet_deployment_block: BlockNumber,
    trusted_anchor_block: BlockNumber,
    trusted_anchor_commitment: Word,
    minimum_finality_depth_blocks: u32,
    expected_signing_public_keys_hex: Vec<String>,
    /// Durable ledger state; deploy it on persistent storage for exactly one attester instance.
    store_path: PathBuf,
}

fn default_withdrawal_window_hours() -> u64 {
    24
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let encoded = fs::read_to_string(path)
            .map_err(|source| ConfigError::with_source("failed to read config", source))?;
        let raw: RawConfig = toml::from_str(&encoded)
            .map_err(|source| ConfigError::with_source("failed to parse config", source))?;
        let max_withdrawal_fee = AssetAmount::new(raw.max_withdrawal_fee).map_err(|source| {
            ConfigError::with_source("maximum withdrawal fee is invalid", source)
        })?;
        let withdrawal_window_ms = raw
            .withdrawal_window_hours
            .checked_mul(3_600_000)
            .filter(|milliseconds| *milliseconds > 0)
            .and_then(|milliseconds| i64::try_from(milliseconds).ok())
            .ok_or_else(|| {
                ConfigError::invalid("withdrawal window must be positive and fit in milliseconds")
            })?;
        if raw
            .withdrawal_cap_error_message
            .as_deref()
            .is_some_and(|message| message.trim().is_empty())
        {
            return Err(ConfigError::invalid(
                "withdrawal cap error message must not be empty",
            ));
        }

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
        if raw.minimum_finality_depth_blocks == 0 {
            return Err(ConfigError::invalid(
                "minimum finality depth must be greater than zero",
            ));
        }
        let faucet_account_id = AccountId::from_hex(&raw.faucet_account_id_hex)
            .map_err(|source| ConfigError::with_source("faucet account id is invalid", source))?;
        if faucet_account_id.to_hex() != raw.faucet_account_id_hex {
            return Err(ConfigError::invalid(
                "faucet account id must use canonical 0x-prefixed lowercase hex",
            ));
        }

        let trusted_anchor_commitment_hex = raw.trusted_anchor_commitment_hex.as_bytes();
        if trusted_anchor_commitment_hex.len() != 66
            || !trusted_anchor_commitment_hex.starts_with(b"0x")
            || !trusted_anchor_commitment_hex[2..]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(ConfigError::invalid(
                "trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex",
            ));
        }
        let trusted_anchor_commitment = Word::parse(&raw.trusted_anchor_commitment_hex)
            .map_err(|_| ConfigError::invalid("trusted anchor commitment is invalid"))?;

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
            miden_network: raw.miden_network,
            circle_request_timeout: Duration::from_millis(raw.circle_request_timeout_ms),
            faucet_account_id,
            circle_api_base_url,
            use_circle_forwarding: raw.use_circle_forwarding,
            max_withdrawal_fee,
            withdrawal_limit: raw.withdrawal_limit,
            withdrawal_window_ms,
            withdrawal_cap_error_message: raw.withdrawal_cap_error_message,
            poll_interval: Duration::from_millis(raw.poll_interval_ms),
            faucet_deployment_block: BlockNumber::from(raw.faucet_deployment_block),
            trusted_anchor_block: BlockNumber::from(raw.trusted_anchor_block),
            trusted_anchor_commitment,
            minimum_finality_depth_blocks: raw.minimum_finality_depth_blocks,
            expected_signing_public_keys_hex: raw.expected_signing_public_keys_hex,
            store_path,
        })
    }

    pub fn miden_network(&self) -> MidenNetwork {
        self.miden_network
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

    pub(crate) fn use_circle_forwarding(&self) -> bool {
        self.use_circle_forwarding
    }

    pub(crate) fn max_withdrawal_fee(&self) -> AssetAmount {
        self.max_withdrawal_fee
    }

    pub(crate) fn withdrawal_limit(&self) -> u64 {
        self.withdrawal_limit
    }

    pub(crate) fn withdrawal_window_ms(&self) -> i64 {
        self.withdrawal_window_ms
    }

    pub(crate) fn withdrawal_cap_error_message(&self) -> Option<&str> {
        self.withdrawal_cap_error_message.as_deref()
    }

    pub(crate) fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    pub(crate) fn faucet_deployment_block(&self) -> BlockNumber {
        self.faucet_deployment_block
    }

    pub(crate) fn trusted_anchor_block(&self) -> BlockNumber {
        self.trusted_anchor_block
    }

    pub(crate) fn trusted_anchor_commitment(&self) -> Word {
        self.trusted_anchor_commitment
    }

    pub(crate) fn minimum_finality_depth_blocks(&self) -> u32 {
        self.minimum_finality_depth_blocks
    }

    pub(crate) fn expected_signing_public_keys_hex(&self) -> &[String] {
        &self.expected_signing_public_keys_hex
    }

    pub(crate) fn store_path(&self) -> &Path {
        &self.store_path
    }
}
