//! The tool's input-file schema ([`GenesisToolConfig`]) and its validation.
//!
//! This is OUR tool's config, deliberately NOT the node's `GenesisConfig` (no node-crate
//! dependency anywhere: the `genesis.toml` fragment is emitted as plain text and the `.mac`
//! files use the protocol's `AccountFile`). The role wallets are NOT created by this tool: the
//! config references their externally-produced `AccountFile`s by path, and loading decodes them
//! up front. Parsing is two-stage: a serde mirror of the raw JSON (`deny_unknown_fields`)
//! followed by a typed conversion that reads every referenced account file and validates the
//! faucet inputs, so every rejection surfaces as a specific [`ConfigError`] variant.

use std::path::{Path, PathBuf};

use miden_protocol::account::{Account, AccountFile};
use serde::Deserialize;

/// The number of hex characters in a 32-byte seed (after the mandatory `0x` prefix).
const SEED_HEX_LEN: usize = 64;

// ROLES
// ================================================================================================

/// The six genesis wallet roles the config provides accounts for: the network operator plus the
/// five faucet role holders the `XReserveStablecoinBuilder` seeds (`ADMIN`, `ATTEST_ADMIN`,
/// `DOM_PAUSER`, `DOM_UNPAUSER`, `BLK_MANAGER`).
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

    /// The role's config-field name, doubling as its output-file stem.
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

    /// The `.mac` file name this role's account is written to.
    pub fn mac_file_name(self) -> String {
        format!("{}.mac", self.as_str())
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

/// One externally-provided role account: the path the config resolved and the decoded protocol
/// `AccountFile` (the account plus whatever secret keys the file embeds).
#[derive(Debug, Clone)]
pub struct ProvidedAccount {
    pub path: PathBuf,
    pub file: AccountFile,
}

impl ProvidedAccount {
    /// Returns the provided account.
    pub fn account(&self) -> &Account {
        &self.file.account
    }
}

/// The faucet's config: its account seed and the `XReserveStablecoinBuilder` inputs that are not
/// derived from the role wallets.
#[derive(Debug, Clone)]
pub struct FaucetConfig {
    pub seed: Seed32,
    pub max_supply: u64,
    pub token_supply: u64,
    pub domain: u32,
    pub min_burn_amount: Option<u64>,
    pub verification_base_fee: u32,
}

/// The validated tool config: one [`ProvidedAccount`] per [`Role`], the [`FaucetConfig`], and
/// the optional default output directory (`--out-dir` overrides it).
#[derive(Debug, Clone)]
pub struct GenesisToolConfig {
    pub operator: ProvidedAccount,
    pub owner: ProvidedAccount,
    pub attest_admin: ProvidedAccount,
    pub pauser: ProvidedAccount,
    pub unpauser: ProvidedAccount,
    pub blocklist_manager: ProvidedAccount,
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

    /// Parses and validates a config from its JSON text, reading every referenced account file;
    /// relative account-file paths resolve against `base_dir`.
    pub fn from_json(text: &str, base_dir: &Path) -> Result<Self, ConfigError> {
        let raw: RawConfig = serde_json::from_str(text).map_err(ConfigError::Parse)?;
        let config = Self {
            operator: read_account(Role::Operator, base_dir, &raw.accounts.operator)?,
            owner: read_account(Role::Owner, base_dir, &raw.accounts.owner)?,
            attest_admin: read_account(Role::AttestAdmin, base_dir, &raw.accounts.attest_admin)?,
            pauser: read_account(Role::Pauser, base_dir, &raw.accounts.pauser)?,
            unpauser: read_account(Role::Unpauser, base_dir, &raw.accounts.unpauser)?,
            blocklist_manager: read_account(
                Role::BlocklistManager,
                base_dir,
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

    /// Returns the provided account for `role`.
    pub fn provided(&self, role: Role) -> &ProvidedAccount {
        match role {
            Role::Operator => &self.operator,
            Role::Owner => &self.owner,
            Role::AttestAdmin => &self.attest_admin,
            Role::Pauser => &self.pauser,
            Role::Unpauser => &self.unpauser,
            Role::BlocklistManager => &self.blocklist_manager,
        }
    }

    /// Cross-field validation: the initial supply must fit under the cap, and the six provided
    /// accounts must be pairwise distinct (one account cannot hold two roles).
    fn validate(&self) -> Result<(), ConfigError> {
        if self.faucet.token_supply > self.faucet.max_supply {
            return Err(ConfigError::SupplyExceedsMax {
                token_supply: self.faucet.token_supply,
                max_supply: self.faucet.max_supply,
            });
        }
        let ids: Vec<_> = Role::ALL
            .iter()
            .map(|role| (role.as_str(), self.provided(*role).account().id()))
            .collect();
        for (i, (first, first_id)) in ids.iter().enumerate() {
            for (second, second_id) in ids.iter().skip(i + 1) {
                if first_id == second_id {
                    return Err(ConfigError::DuplicateAccount { first, second });
                }
            }
        }
        Ok(())
    }
}

/// Reads the account file for one role: the raw config path resolved against `base_dir`, decoded
/// as a protocol `AccountFile`.
fn read_account(
    role: Role,
    base_dir: &Path,
    raw_path: &str,
) -> Result<ProvidedAccount, ConfigError> {
    let path = base_dir.join(raw_path);
    let file = AccountFile::read(&path).map_err(|source| ConfigError::AccountFile {
        field: role.as_str(),
        path: path.clone(),
        source,
    })?;
    Ok(ProvidedAccount { path, file })
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

/// Per role, the path to its externally-produced protocol `AccountFile`.
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
    /// A referenced account file could not be read or does not decode as a protocol
    /// `AccountFile`.
    AccountFile {
        field: &'static str,
        path: PathBuf,
        source: std::io::Error,
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
    /// Two roles reference the same account.
    DuplicateAccount {
        first: &'static str,
        second: &'static str,
    },
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io { path, .. } => write!(f, "reading the config file {}", path.display()),
            Self::Parse(_) => write!(f, "the config JSON does not match the schema"),
            Self::AccountFile { field, path, .. } => {
                write!(f, "reading the {field} account file {}", path.display())
            }
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
            Self::DuplicateAccount { first, second } => {
                write!(
                    f,
                    "the {first} and {second} roles reference the same account"
                )
            }
        }
    }
}

impl core::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::AccountFile { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::SeedHex { source, .. } => Some(source),
            _ => None,
        }
    }
}
