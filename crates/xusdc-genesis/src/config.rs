//! The tool's input-file schema ([`GenesisToolConfig`]) and its validation.
//!
//! This is OUR tool's config, deliberately NOT the node's `GenesisConfig` (no node-crate
//! dependency anywhere: the `genesis.toml` fragment is emitted as plain text and the faucet
//! `.mac` file uses the protocol's `AccountFile`). The role accounts are referenced as paths to
//! their externally-produced `.mac` files, and the loader reads each file ONLY to extract its
//! account id — reading the id from the actual injectable file keeps the faucet's role slots
//! and the genesis account set consistent by construction, where a hand-copied bare id could
//! not be cross-checked. Nothing but the extracted id (plus the path, reused by reference in
//! the emitted fragment) flows past the loader: no account state and no secret material is ever
//! held or re-serialized. Parsing is two-stage: a serde mirror of the raw JSON
//! (`deny_unknown_fields`) followed by the typed conversion, so every rejection surfaces as a
//! specific [`ConfigError`] variant. Role-collision rules are owned and enforced by the
//! `XReserveStablecoinBuilder`, not re-implemented here.

use std::path::{Path, PathBuf};

use miden_protocol::account::{AccountFile, AccountId};
use serde::Deserialize;

/// The number of hex characters in a 32-byte seed (after the mandatory `0x` prefix).
const SEED_HEX_LEN: usize = 64;

// ROLES
// ================================================================================================

/// The six role accounts the config references: the network operator plus the five faucet role
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

/// One role account's extracted identity: the id (all the faucet build ever consumes) and the
/// resolved path to its `.mac` file (reused ONLY by reference in the emitted `genesis.toml`
/// fragment — the file itself is never copied or re-serialized).
#[derive(Debug, Clone)]
pub struct RoleAccount {
    pub id: AccountId,
    pub path: PathBuf,
}

/// The faucet's config: its account seed and the `XReserveStablecoinBuilder` inputs that are
/// not role-account ids.
#[derive(Debug, Clone)]
pub struct FaucetConfig {
    pub seed: Seed32,
    pub max_supply: u64,
    pub token_supply: u64,
    pub domain: u32,
    pub min_burn_amount: Option<u64>,
    pub verification_base_fee: u32,
}

/// The validated tool config: one [`RoleAccount`] per [`Role`], the [`FaucetConfig`], and the
/// optional default output directory (`--out-dir` overrides it).
#[derive(Debug, Clone)]
pub struct GenesisToolConfig {
    pub operator: RoleAccount,
    pub owner: RoleAccount,
    pub attest_admin: RoleAccount,
    pub pauser: RoleAccount,
    pub unpauser: RoleAccount,
    pub blocklist_manager: RoleAccount,
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
            operator: read_role_account(Role::Operator, base_dir, &raw.accounts.operator)?,
            owner: read_role_account(Role::Owner, base_dir, &raw.accounts.owner)?,
            attest_admin: read_role_account(
                Role::AttestAdmin,
                base_dir,
                &raw.accounts.attest_admin,
            )?,
            pauser: read_role_account(Role::Pauser, base_dir, &raw.accounts.pauser)?,
            unpauser: read_role_account(Role::Unpauser, base_dir, &raw.accounts.unpauser)?,
            blocklist_manager: read_role_account(
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

    /// Returns the role account for `role`.
    pub fn role_account(&self, role: Role) -> &RoleAccount {
        match role {
            Role::Operator => &self.operator,
            Role::Owner => &self.owner,
            Role::AttestAdmin => &self.attest_admin,
            Role::Pauser => &self.pauser,
            Role::Unpauser => &self.unpauser,
            Role::BlocklistManager => &self.blocklist_manager,
        }
    }

    /// Returns the extracted account id for `role` — the only role data the faucet build
    /// consumes.
    pub fn role_id(&self, role: Role) -> AccountId {
        self.role_account(role).id
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

/// Reads one role's `.mac` file and extracts its account id. VALIDATION ONLY, never mutation:
/// the account must already be genesis-injectable — nonce one and no seed — and only the id
/// and the resolved path flow past this point. The seed half of the requirement needs no check
/// of its own: the protocol's `Account` deserialization rejects any nonzero-nonce account that
/// still carries a seed, so a seeded file at nonce one cannot even decode and surfaces as
/// [`ConfigError::AccountFile`], while a ground (nonce-zero, seeded) wallet is caught by the
/// nonce check below.
fn read_role_account(
    role: Role,
    base_dir: &Path,
    raw_path: &str,
) -> Result<RoleAccount, ConfigError> {
    let path = base_dir.join(raw_path);
    let file = AccountFile::read(&path).map_err(|source| ConfigError::AccountFile {
        field: role.as_str(),
        path: path.clone(),
        source,
    })?;
    let account = file.account;
    let nonce = account.nonce().as_canonical_u64();
    if nonce != 1 {
        return Err(ConfigError::AccountNonce {
            field: role.as_str(),
            nonce,
        });
    }
    Ok(RoleAccount {
        id: account.id(),
        path,
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

/// Per role, the path to its externally-produced protocol `AccountFile` (`.mac`).
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
    /// A referenced account is not genesis-injectable: its nonce is not one. (A still-seeded
    /// account at a nonzero nonce cannot even decode — the protocol rejects that shape — so it
    /// surfaces as [`ConfigError::AccountFile`] instead.)
    AccountNonce { field: &'static str, nonce: u64 },
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
            Self::AccountFile { field, path, .. } => {
                write!(f, "reading the {field} account file {}", path.display())
            }
            Self::AccountNonce { field, nonce } => write!(
                f,
                "the {field} account is not genesis-injectable: its nonce is {nonce}, expected 1"
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
            Self::Io { source, .. } | Self::AccountFile { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::SeedHex { source, .. } => Some(source),
            _ => None,
        }
    }
}
