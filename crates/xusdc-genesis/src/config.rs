//! The tool's input-file schema ([`GenesisToolConfig`]).

use std::path::{Path, PathBuf};

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::utils::serde::Deserializable;
use serde::de::{Deserializer, Error as _};
use serde::Deserialize;
use xusdc_encoding::xreserve::encoding::DepositNonce;

// ROLES
// ================================================================================================

/// The five faucet role holders the `XReserveStablecoinBuilder` seeds (`ADMIN`, `ATTEST_ADMIN`,
/// `DOM_PAUSER`, `DOM_UNPAUSER`, `BLK_MANAGER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    AttestAdmin,
    Pauser,
    Unpauser,
    BlocklistManager,
}

impl Role {
    /// Every role, in the stable order the outputs are emitted in.
    pub const ALL: [Role; 5] = [
        Role::Owner,
        Role::AttestAdmin,
        Role::Pauser,
        Role::Unpauser,
        Role::BlocklistManager,
    ];

    /// The role's config-field name, doubling as its name in the stdout listing.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::AttestAdmin => "attest_admin",
            Role::Pauser => "pauser",
            Role::Unpauser => "unpauser",
            Role::BlocklistManager => "blocklist_manager",
        }
    }
}

// CONFIG
// ================================================================================================

/// The tool config: the role holders' account ids, the [`FaucetConfig`], and the optional
/// default output directory (`--out-dir` overrides it). Unknown fields are rejected.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisToolConfig {
    pub accounts: RoleAccounts,
    pub faucet: FaucetConfig,
    pub output_dir: Option<PathBuf>,
}

/// The role holders' account ids, each given as `0x`-prefixed hex or as bech32.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleAccounts {
    #[serde(deserialize_with = "account_id")]
    pub owner: AccountId,
    #[serde(deserialize_with = "account_id")]
    pub attest_admin: AccountId,
    #[serde(deserialize_with = "account_id")]
    pub pauser: AccountId,
    #[serde(deserialize_with = "account_id")]
    pub unpauser: AccountId,
    #[serde(deserialize_with = "account_id")]
    pub blocklist_manager: AccountId,
}

impl RoleAccounts {
    /// Returns the account id configured for `role`.
    pub fn get(&self, role: Role) -> AccountId {
        match role {
            Role::Owner => self.owner,
            Role::AttestAdmin => self.attest_admin,
            Role::Pauser => self.pauser,
            Role::Unpauser => self.unpauser,
            Role::BlocklistManager => self.blocklist_manager,
        }
    }
}

/// The faucet's account seed and the `XReserveStablecoinBuilder` inputs that are not role
/// account ids; amounts are base units.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaucetConfig {
    /// The faucet's 32-byte account seed, as a JSON array of bytes.
    pub seed: [u8; 32],
    /// The initial supply, validated as an [`AssetAmount`] at parse time so it cannot exceed
    /// the hardcoded supply cap.
    #[serde(deserialize_with = "asset_amount")]
    pub token_supply: AssetAmount,
    /// The Circle domain id.
    pub domain: u32,
    pub min_burn_amount: Option<u64>,
    pub verification_base_fee: u32,
    /// The deposit attesters allowlisted at build time, each as a JSON array of the key's 33
    /// compressed SEC1 bytes; empty means the allowlist is seeded later through `set_attester`
    /// notes.
    #[serde(default, deserialize_with = "attesters")]
    pub attesters: Vec<PublicKey>,
    /// The Circle deposit nonces the genesis state already honours, each as a JSON array of its
    /// 32 bytes; each is recorded as consumed at build time so the relayer cannot mint it again.
    #[serde(default, deserialize_with = "used_nonces")]
    pub used_nonces: Vec<DepositNonce>,
}

impl GenesisToolConfig {
    /// Reads and parses the config file at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json(&text)
    }

    /// Parses a config from its JSON text.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(text).map_err(ConfigError::Parse)
    }
}

/// Deserializes an asset amount from its base-unit u64, rejecting out-of-range values.
fn asset_amount<'de, D: Deserializer<'de>>(deserializer: D) -> Result<AssetAmount, D::Error> {
    AssetAmount::new(u64::deserialize(deserializer)?).map_err(D::Error::custom)
}

/// Deserializes an account id from its hex or bech32 string.
fn account_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<AccountId, D::Error> {
    let text = String::deserialize(deserializer)?;
    AccountId::parse(&text)
        .map(|(id, _network)| id)
        .map_err(D::Error::custom)
}

/// Deserializes attester keys from their 33-byte compressed SEC1 form.
fn attesters<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<PublicKey>, D::Error> {
    Vec::<Vec<u8>>::deserialize(deserializer)?
        .iter()
        .map(|bytes| PublicKey::read_from_bytes(bytes).map_err(D::Error::custom))
        .collect()
}

/// Deserializes deposit nonces from their 32 raw bytes.
fn used_nonces<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<DepositNonce>, D::Error> {
    Ok(Vec::<[u8; 32]>::deserialize(deserializer)?
        .into_iter()
        .map(DepositNonce::new)
        .collect())
}

// ERRORS
// ================================================================================================

/// Errors the config loader returns.
#[derive(Debug)]
pub enum ConfigError {
    /// The config file could not be read.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The JSON does not match the schema: a malformed value (an account id, an attester key,
    /// the seed) or an unknown field.
    Parse(serde_json::Error),
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io { path, .. } => write!(f, "reading the config file {}", path.display()),
            Self::Parse(_) => write!(f, "the config JSON does not match the schema"),
        }
    }
}

impl core::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
        }
    }
}
