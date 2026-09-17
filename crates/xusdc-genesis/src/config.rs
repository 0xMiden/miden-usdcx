//! The tool's input-file schema ([`GenesisToolConfig`]) and its validation.
//!
//! The role accounts are given as bare account-id strings (hex or bech32), parsed with the
//! protocol's [`AccountId::parse`]. Parsing is a serde mirror of the raw JSON
//! (`deny_unknown_fields`) followed by a typed conversion, so every rejection surfaces as a
//! specific [`ConfigError`] variant.

use std::path::{Path, PathBuf};

use miden_protocol::account::AccountId;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::errors::AccountIdError;
use miden_protocol::utils::serde::{Deserializable, DeserializationError};
use serde::Deserialize;

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

// TYPED CONFIG
// ================================================================================================

/// The faucet's config: its account seed and the `XReserveStablecoinBuilder` inputs that are
/// not role-account ids.
#[derive(Debug, Clone)]
pub struct FaucetConfig {
    pub seed: [u8; 32],
    pub max_supply: u64,
    pub token_supply: u64,
    pub domain: u32,
    pub min_burn_amount: Option<u64>,
    pub verification_base_fee: u32,
    /// The deposit attesters allowlisted at build time; empty means the allowlist is seeded
    /// later through `set_attester` notes.
    pub attesters: Vec<PublicKey>,
}

/// The validated tool config: one [`AccountId`] per [`Role`], the [`FaucetConfig`], and the
/// optional default output directory (`--out-dir` overrides it).
#[derive(Debug, Clone)]
pub struct GenesisToolConfig {
    pub owner: AccountId,
    pub attest_admin: AccountId,
    pub pauser: AccountId,
    pub unpauser: AccountId,
    pub blocklist_manager: AccountId,
    pub faucet: FaucetConfig,
    pub output_dir: Option<PathBuf>,
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

    /// Parses and validates a config from its JSON text.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = serde_json::from_str(text).map_err(ConfigError::Parse)?;
        let config = Self {
            owner: parse_account_id(Role::Owner, &raw.accounts.owner)?,
            attest_admin: parse_account_id(Role::AttestAdmin, &raw.accounts.attest_admin)?,
            pauser: parse_account_id(Role::Pauser, &raw.accounts.pauser)?,
            unpauser: parse_account_id(Role::Unpauser, &raw.accounts.unpauser)?,
            blocklist_manager: parse_account_id(
                Role::BlocklistManager,
                &raw.accounts.blocklist_manager,
            )?,
            faucet: FaucetConfig {
                seed: raw.faucet.seed,
                max_supply: raw.faucet.max_supply,
                token_supply: raw.faucet.token_supply,
                domain: raw.faucet.domain,
                min_burn_amount: raw.faucet.min_burn_amount,
                verification_base_fee: raw.faucet.verification_base_fee,
                attesters: parse_attesters(&raw.faucet.attesters)?,
            },
            output_dir: raw.output_dir,
        };
        config.validate()?;
        Ok(config)
    }

    /// Returns the account id configured for `role`.
    pub fn account_id(&self, role: Role) -> AccountId {
        match role {
            Role::Owner => self.owner,
            Role::AttestAdmin => self.attest_admin,
            Role::Pauser => self.pauser,
            Role::Unpauser => self.unpauser,
            Role::BlocklistManager => self.blocklist_manager,
        }
    }

    /// Cross-field validation: the initial supply must fit under the cap.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.faucet.token_supply > self.faucet.max_supply {
            return Err(ConfigError::SupplyExceedsMax {
                token_supply: self.faucet.token_supply,
                max_supply: self.faucet.max_supply,
            });
        }
        Ok(())
    }
}

/// Decodes the configured attester keys from their 33-byte compressed SEC1 form; a key that
/// does not decode errors with the index-naming [`ConfigError::AttesterKey`].
fn parse_attesters(raw: &[Vec<u8>]) -> Result<Vec<PublicKey>, ConfigError> {
    raw.iter()
        .enumerate()
        .map(|(index, bytes)| {
            PublicKey::read_from_bytes(bytes)
                .map_err(|source| ConfigError::AttesterKey { index, source })
        })
        .collect()
}

/// Parses one role's account-id string with [`AccountId::parse`] (hex or bech32; the embedded
/// network id, when present, is not checked). A string that parses as neither errors with the
/// role-naming [`ConfigError::AccountId`].
fn parse_account_id(role: Role, id_str: &str) -> Result<AccountId, ConfigError> {
    AccountId::parse(id_str)
        .map(|(id, _network)| id)
        .map_err(|source| ConfigError::AccountId {
            field: role.as_str(),
            source,
        })
}

// RAW (SERDE) MIRROR
// ================================================================================================

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    accounts: RawAccounts,
    faucet: RawFaucet,
    output_dir: Option<PathBuf>,
}

/// Per role, its account id as hex (`0x`-prefixed) or bech32.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccounts {
    owner: String,
    attest_admin: String,
    pauser: String,
    unpauser: String,
    blocklist_manager: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFaucet {
    /// The faucet's 32-byte account seed, as a JSON array of bytes.
    seed: [u8; 32],
    max_supply: u64,
    token_supply: u64,
    domain: u32,
    min_burn_amount: Option<u64>,
    verification_base_fee: u32,
    /// The attester public keys, each as a JSON array of the key's 33 compressed SEC1 bytes.
    #[serde(default)]
    attesters: Vec<Vec<u8>>,
}

// ERRORS
// ================================================================================================

/// Errors the config loader returns. `field` names the offending config field.
#[derive(Debug)]
pub enum ConfigError {
    /// The config file could not be read.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The JSON does not match the schema (including unknown fields, which are rejected).
    Parse(serde_json::Error),
    /// A role's account-id string parses as neither hex nor bech32.
    AccountId {
        field: &'static str,
        source: AccountIdError,
    },
    /// A configured attester key does not decode as a compressed secp256k1 public key.
    AttesterKey {
        index: usize,
        source: DeserializationError,
    },
    /// The initial `token_supply` exceeds `max_supply`.
    SupplyExceedsMax { token_supply: u64, max_supply: u64 },
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io { path, .. } => write!(f, "reading the config file {}", path.display()),
            Self::Parse(_) => write!(f, "the config JSON does not match the schema"),
            Self::AccountId { field, .. } => write!(
                f,
                "the {field} account id is neither valid hex nor valid bech32"
            ),
            Self::AttesterKey { index, .. } => write!(
                f,
                "the faucet.attesters key at index {index} is not a valid 33-byte compressed \
                 secp256k1 public key"
            ),
            Self::SupplyExceedsMax {
                token_supply,
                max_supply,
            } => write!(
                f,
                "token_supply {token_supply} exceeds max_supply {max_supply}"
            ),
        }
    }
}

impl core::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::AccountId { source, .. } => Some(source),
            Self::AttesterKey { source, .. } => Some(source),
            Self::SupplyExceedsMax { .. } => None,
        }
    }
}
