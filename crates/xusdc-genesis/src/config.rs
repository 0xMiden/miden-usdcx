//! The tool's input-file schema ([`GenesisToolConfig`]) and its validation.
//!
//! The role accounts are referenced as paths to their `.mac` files (relative paths resolve
//! against the config file's directory); each file is read purely to extract its account id.
//! Parsing is a serde mirror of the raw JSON (`deny_unknown_fields`) followed by a typed
//! conversion, so every rejection surfaces as a specific [`ConfigError`] variant.

use std::path::{Path, PathBuf};

use miden_protocol::account::{AccountFile, AccountId};
use serde::Deserialize;

// ROLES
// ================================================================================================

/// The six role accounts the config references: the mint relayer plus the five faucet role
/// holders the `XReserveStablecoinBuilder` seeds (`ADMIN`, `ATTEST_ADMIN`, `DOM_PAUSER`,
/// `DOM_UNPAUSER`, `BLK_MANAGER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Relayer,
    Owner,
    AttestAdmin,
    Pauser,
    Unpauser,
    BlocklistManager,
}

impl Role {
    /// Every role, in the stable order the outputs are emitted in.
    pub const ALL: [Role; 6] = [
        Role::Relayer,
        Role::Owner,
        Role::AttestAdmin,
        Role::Pauser,
        Role::Unpauser,
        Role::BlocklistManager,
    ];

    /// The role's config-field name, doubling as its name in the stdout listing.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Relayer => "relayer",
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
}

/// The validated tool config: one extracted [`AccountId`] per [`Role`], the [`FaucetConfig`],
/// and the optional default output directory (`--out-dir` overrides it).
#[derive(Debug, Clone)]
pub struct GenesisToolConfig {
    pub relayer: AccountId,
    pub owner: AccountId,
    pub attest_admin: AccountId,
    pub pauser: AccountId,
    pub unpauser: AccountId,
    pub blocklist_manager: AccountId,
    pub faucet: FaucetConfig,
    pub output_dir: Option<PathBuf>,
}

impl GenesisToolConfig {
    /// Reads and parses the config file at `path`; relative account-file paths resolve against
    /// the config file's directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json(&text, path.parent().unwrap_or(Path::new(".")))
    }

    /// Parses and validates a config from its JSON text, extracting each role's account id
    /// from its referenced `.mac` file; relative account-file paths resolve against `base_dir`.
    pub fn from_json(text: &str, base_dir: &Path) -> Result<Self, ConfigError> {
        let raw: RawConfig = serde_json::from_str(text).map_err(ConfigError::Parse)?;
        let config = Self {
            relayer: read_account_id(Role::Relayer, base_dir, &raw.accounts.relayer)?,
            owner: read_account_id(Role::Owner, base_dir, &raw.accounts.owner)?,
            attest_admin: read_account_id(Role::AttestAdmin, base_dir, &raw.accounts.attest_admin)?,
            pauser: read_account_id(Role::Pauser, base_dir, &raw.accounts.pauser)?,
            unpauser: read_account_id(Role::Unpauser, base_dir, &raw.accounts.unpauser)?,
            blocklist_manager: read_account_id(
                Role::BlocklistManager,
                base_dir,
                &raw.accounts.blocklist_manager,
            )?,
            faucet: FaucetConfig {
                seed: raw.faucet.seed,
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

    /// Returns the account id extracted for `role`.
    pub fn account_id(&self, role: Role) -> AccountId {
        match role {
            Role::Relayer => self.relayer,
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

/// Reads one role's `.mac` file purely to extract its account id. An unreadable or undecodable
/// file errors with the role-naming [`ConfigError::AccountFile`].
fn read_account_id(role: Role, base_dir: &Path, raw_path: &str) -> Result<AccountId, ConfigError> {
    let path = base_dir.join(raw_path);
    let file = AccountFile::read(&path).map_err(|source| ConfigError::AccountFile {
        field: role.as_str(),
        path,
        source,
    })?;
    Ok(file.account.id())
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

/// Per role, the path to its protocol `AccountFile` (`.mac`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccounts {
    relayer: String,
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
    /// A referenced account file could not be read or does not decode as a protocol
    /// `AccountFile`.
    AccountFile {
        field: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    /// The initial `token_supply` exceeds `max_supply`.
    SupplyExceedsMax { token_supply: u64, max_supply: u64 },
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io { path, .. } => write!(f, "reading the config file {}", path.display()),
            Self::Parse(_) => write!(f, "the config JSON does not match the schema"),
            Self::AccountFile { field, path, .. } => {
                write!(f, "reading the {field} account file {}", path.display())
            }
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
            Self::Io { source, .. } | Self::AccountFile { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::SupplyExceedsMax { .. } => None,
        }
    }
}
