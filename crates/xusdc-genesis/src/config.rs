//! The tool's input-file schema ([`GenesisToolConfig`]) and its validation.
//!
//! This is OUR tool's config, deliberately NOT the node's `GenesisConfig` (no node-crate
//! dependency anywhere: the `genesis.toml` fragment is emitted as plain text and the faucet
//! `.mac` file uses the protocol's `AccountFile`). The role accounts are referenced by BARE
//! account id — this tool neither creates nor reads any account but the faucet it builds.
//! Parsing is two-stage: a serde mirror of the raw JSON (`deny_unknown_fields`) followed by a
//! typed conversion through the protocol's own id and seed parsers, so every rejection surfaces
//! as a specific [`ConfigError`] variant. Role-collision rules are owned and enforced by the
//! `XReserveStablecoinBuilder`, not re-implemented here.

use std::path::{Path, PathBuf};

use miden_protocol::account::AccountId;
use miden_protocol::errors::AccountIdError;
use serde::Deserialize;

/// The number of hex characters in a 32-byte seed (after the mandatory `0x` prefix).
const SEED_HEX_LEN: usize = 64;

// ROLES
// ================================================================================================

/// The six role-account ids the config provides: the network operator plus the five faucet role
/// holders the `XReserveStablecoinBuilder` seeds (`ADMIN`, `ATTEST_ADMIN`, `DOM_PAUSER`,
/// `DOM_UNPAUSER`, `BLK_MANAGER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Operator,
    Owner,
    AttestAdmin,
    Pauser,
    Unpauser,
    BlocklistManager,
}

impl Role {
    /// Every role, in the stable order the outputs are emitted in.
    pub const ALL: [Role; 6] = [
        Role::Operator,
        Role::Owner,
        Role::AttestAdmin,
        Role::Pauser,
        Role::Unpauser,
        Role::BlocklistManager,
    ];

    /// The role's config-field name, doubling as its name in the emitted summary.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Operator => "operator",
            Role::Owner => "owner",
            Role::AttestAdmin => "attest_admin",
            Role::Pauser => "pauser",
            Role::Unpauser => "unpauser",
            Role::BlocklistManager => "blocklist_manager",
        }
    }
}

// NEWTYPES
// ================================================================================================

/// A 32-byte seed parsed from `0x` + 64 hex characters; wrong-length or malformed input is
/// rejected in the constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Seed32([u8; 32]);

impl Seed32 {
    /// Parses a seed from its `0x`-prefixed 64-hex-character form. `field` names the config
    /// field for the error message.
    pub fn from_hex(field: &'static str, hex_str: &str) -> Result<Self, ConfigError> {
        let stripped = hex_str
            .strip_prefix("0x")
            .ok_or(ConfigError::SeedMissingPrefix { field })?;
        if stripped.len() != SEED_HEX_LEN {
            return Err(ConfigError::SeedLength {
                field,
                len: stripped.len(),
            });
        }
        let bytes =
            hex::decode(stripped).map_err(|source| ConfigError::SeedHex { field, source })?;
        Ok(Self(
            bytes.try_into().expect("64 hex chars decode to 32 bytes"),
        ))
    }

    /// Returns the seed bytes.
    pub fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

// TYPED CONFIG
// ================================================================================================

/// The faucet's config: its account seed and the `XReserveStablecoinBuilder` inputs that are not
/// role-account ids.
#[derive(Debug, Clone)]
pub struct FaucetConfig {
    pub seed: Seed32,
    pub max_supply: u64,
    pub token_supply: u64,
    pub domain: u32,
    pub min_burn_amount: Option<u64>,
    pub verification_base_fee: u32,
}

/// The validated tool config: one [`AccountId`] per [`Role`], the [`FaucetConfig`], and the
/// optional default output directory (`--out-dir` overrides it).
#[derive(Debug, Clone)]
pub struct GenesisToolConfig {
    pub operator: AccountId,
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
            operator: parse_account_id(Role::Operator, &raw.accounts.operator)?,
            owner: parse_account_id(Role::Owner, &raw.accounts.owner)?,
            attest_admin: parse_account_id(Role::AttestAdmin, &raw.accounts.attest_admin)?,
            pauser: parse_account_id(Role::Pauser, &raw.accounts.pauser)?,
            unpauser: parse_account_id(Role::Unpauser, &raw.accounts.unpauser)?,
            blocklist_manager: parse_account_id(
                Role::BlocklistManager,
                &raw.accounts.blocklist_manager,
            )?,
            faucet: FaucetConfig {
                seed: Seed32::from_hex("faucet.seed", &raw.faucet.seed)?,
                max_supply: raw.faucet.max_supply,
                token_supply: raw.faucet.token_supply,
                domain: raw.faucet.domain,
                min_burn_amount: raw.faucet.min_burn_amount,
                verification_base_fee: raw.faucet.verification_base_fee,
            },
            output_dir: raw.output_dir,
        };
        config.validate()?;
        Ok(config)
    }

    /// Returns the provided account id for `role`.
    pub fn role_id(&self, role: Role) -> AccountId {
        match role {
            Role::Operator => self.operator,
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

/// Parses one role's account id with the protocol's own parsers: the `0x` form through
/// [`AccountId::from_hex`], anything else through [`AccountId::from_bech32`] (the embedded
/// network id is not checked — the genesis accounts exist on whatever network boots from them).
fn parse_account_id(role: Role, id_str: &str) -> Result<AccountId, ConfigError> {
    let parsed = if id_str.starts_with("0x") {
        AccountId::from_hex(id_str)
    } else {
        AccountId::from_bech32(id_str).map(|(_network, id)| id)
    };
    parsed.map_err(|source| ConfigError::AccountId {
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
    operator: String,
    owner: String,
    attest_admin: String,
    pauser: String,
    unpauser: String,
    blocklist_manager: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFaucet {
    seed: String,
    max_supply: u64,
    token_supply: u64,
    domain: u32,
    min_burn_amount: Option<u64>,
    verification_base_fee: u32,
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
    /// A role's account id parses as neither hex nor bech32.
    AccountId {
        field: &'static str,
        source: AccountIdError,
    },
    /// The seed is missing its mandatory `0x` prefix.
    SeedMissingPrefix { field: &'static str },
    /// The seed's hex part is not exactly 64 characters. Carries the offending length.
    SeedLength { field: &'static str, len: usize },
    /// The seed contains non-hex characters.
    SeedHex {
        field: &'static str,
        source: hex::FromHexError,
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
            Self::SeedMissingPrefix { field } => {
                write!(f, "the {field} seed is missing its 0x prefix")
            }
            Self::SeedLength { field, len } => write!(
                f,
                "the {field} seed must be {SEED_HEX_LEN} hex chars after 0x, got {len}"
            ),
            Self::SeedHex { field, .. } => write!(f, "the {field} seed is not valid hex"),
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
            Self::SeedHex { source, .. } => Some(source),
            _ => None,
        }
    }
}
