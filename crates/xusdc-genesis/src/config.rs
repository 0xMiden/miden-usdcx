//! The tool's input-file schema ([`GenesisToolConfig`]) and its validation.
//!
//! This is OUR tool's config, deliberately NOT the node's `GenesisConfig` (no node-crate
//! dependency anywhere: the `genesis.toml` fragment is emitted as plain text and the `.mac`
//! files use the protocol's `AccountFile`). Parsing is two-stage: a serde mirror of the raw JSON
//! (`deny_unknown_fields`) followed by a typed conversion whose newtypes validate in their
//! constructors, so every rejection surfaces as a specific [`ConfigError`] variant.

use std::path::{Path, PathBuf};

use miden_protocol::account::auth::{AuthScheme, PublicKey};
use miden_protocol::utils::serde::{Deserializable, DeserializationError};
use serde::Deserialize;

/// The number of hex characters in a 32-byte seed (after the mandatory `0x` prefix).
const SEED_HEX_LEN: usize = 64;

// ROLES
// ================================================================================================

/// The six genesis wallet roles: the network operator plus the five faucet role holders the
/// `XReserveStablecoinBuilder` seeds (`ADMIN`, `ATTEST_ADMIN`, `DOM_PAUSER`, `DOM_UNPAUSER`,
/// `BLK_MANAGER`).
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

/// A supplied authentication public key, restricted to the Falcon512-Poseidon2 scheme the role
/// wallets authenticate with; any other scheme is rejected in the constructor. The hex form is
/// the protocol `PublicKey` serialization (scheme byte followed by the key bytes).
#[derive(Debug, Clone)]
pub struct FalconPublicKey(PublicKey);

impl FalconPublicKey {
    /// Parses a public key from the hex of its protocol serialization. `field` names the config
    /// field for the error message.
    pub fn from_hex(field: &'static str, hex_str: &str) -> Result<Self, ConfigError> {
        let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes =
            hex::decode(stripped).map_err(|source| ConfigError::PublicKeyHex { field, source })?;
        let key = PublicKey::read_from_bytes(&bytes)
            .map_err(|source| ConfigError::PublicKeyDecode { field, source })?;
        if key.auth_scheme() != AuthScheme::Falcon512Poseidon2 {
            return Err(ConfigError::PublicKeyScheme {
                field,
                scheme: key.auth_scheme(),
            });
        }
        Ok(Self(key))
    }

    /// Returns the wrapped protocol public key.
    pub fn as_public_key(&self) -> &PublicKey {
        &self.0
    }
}

// TYPED CONFIG
// ================================================================================================

/// One role account's config: the account seed, plus an optional externally-supplied auth public
/// key. When the key is absent the tool generates one deterministically from the seed and writes
/// the secret into that account's `.mac` file.
#[derive(Debug, Clone)]
pub struct AccountEntry {
    pub seed: Seed32,
    pub public_key: Option<FalconPublicKey>,
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

/// The validated tool config: one [`AccountEntry`] per [`Role`], the [`FaucetConfig`], and the
/// optional default output directory (`--out-dir` overrides it).
#[derive(Debug, Clone)]
pub struct GenesisToolConfig {
    pub operator: AccountEntry,
    pub owner: AccountEntry,
    pub attest_admin: AccountEntry,
    pub pauser: AccountEntry,
    pub unpauser: AccountEntry,
    pub blocklist_manager: AccountEntry,
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
            operator: raw.accounts.operator.into_typed(Role::Operator)?,
            owner: raw.accounts.owner.into_typed(Role::Owner)?,
            attest_admin: raw.accounts.attest_admin.into_typed(Role::AttestAdmin)?,
            pauser: raw.accounts.pauser.into_typed(Role::Pauser)?,
            unpauser: raw.accounts.unpauser.into_typed(Role::Unpauser)?,
            blocklist_manager: raw
                .accounts
                .blocklist_manager
                .into_typed(Role::BlocklistManager)?,
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

    /// Returns the entry for `role`.
    pub fn entry(&self, role: Role) -> &AccountEntry {
        match role {
            Role::Operator => &self.operator,
            Role::Owner => &self.owner,
            Role::AttestAdmin => &self.attest_admin,
            Role::Pauser => &self.pauser,
            Role::Unpauser => &self.unpauser,
            Role::BlocklistManager => &self.blocklist_manager,
        }
    }

    /// Cross-field validation: the initial supply must fit under the cap, and all seven seeds
    /// must be pairwise distinct (a repeated seed would grind the same account id twice).
    fn validate(&self) -> Result<(), ConfigError> {
        if self.faucet.token_supply > self.faucet.max_supply {
            return Err(ConfigError::SupplyExceedsMax {
                token_supply: self.faucet.token_supply,
                max_supply: self.faucet.max_supply,
            });
        }
        let mut seeds: Vec<(&'static str, Seed32)> = Role::ALL
            .iter()
            .map(|role| (role.as_str(), self.entry(*role).seed))
            .collect();
        seeds.push(("faucet", self.faucet.seed));
        for (i, (first, first_seed)) in seeds.iter().enumerate() {
            for (second, second_seed) in seeds.iter().skip(i + 1) {
                if first_seed == second_seed {
                    return Err(ConfigError::DuplicateSeed { first, second });
                }
            }
        }
        Ok(())
    }
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccounts {
    operator: RawAccountEntry,
    owner: RawAccountEntry,
    attest_admin: RawAccountEntry,
    pauser: RawAccountEntry,
    unpauser: RawAccountEntry,
    blocklist_manager: RawAccountEntry,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccountEntry {
    seed: String,
    public_key: Option<String>,
}

impl RawAccountEntry {
    fn into_typed(self, role: Role) -> Result<AccountEntry, ConfigError> {
        Ok(AccountEntry {
            seed: Seed32::from_hex(role.as_str(), &self.seed)?,
            public_key: self
                .public_key
                .map(|hex_str| FalconPublicKey::from_hex(role.as_str(), &hex_str))
                .transpose()?,
        })
    }
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
    /// A seed is missing its mandatory `0x` prefix.
    SeedMissingPrefix { field: &'static str },
    /// A seed's hex part is not exactly 64 characters. Carries the offending length.
    SeedLength { field: &'static str, len: usize },
    /// A seed contains non-hex characters.
    SeedHex {
        field: &'static str,
        source: hex::FromHexError,
    },
    /// A supplied public key contains non-hex characters.
    PublicKeyHex {
        field: &'static str,
        source: hex::FromHexError,
    },
    /// A supplied public key is not a valid protocol `PublicKey` serialization.
    PublicKeyDecode {
        field: &'static str,
        source: DeserializationError,
    },
    /// A supplied public key uses a scheme other than Falcon512-Poseidon2.
    PublicKeyScheme {
        field: &'static str,
        scheme: AuthScheme,
    },
    /// The initial `token_supply` exceeds `max_supply`.
    SupplyExceedsMax { token_supply: u64, max_supply: u64 },
    /// Two config entries share the same seed.
    DuplicateSeed {
        first: &'static str,
        second: &'static str,
    },
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io { path, .. } => write!(f, "reading the config file {}", path.display()),
            Self::Parse(_) => write!(f, "the config JSON does not match the schema"),
            Self::SeedMissingPrefix { field } => {
                write!(f, "the {field} seed is missing its 0x prefix")
            }
            Self::SeedLength { field, len } => write!(
                f,
                "the {field} seed must be {SEED_HEX_LEN} hex chars after 0x, got {len}"
            ),
            Self::SeedHex { field, .. } => write!(f, "the {field} seed is not valid hex"),
            Self::PublicKeyHex { field, .. } => {
                write!(f, "the {field} public key is not valid hex")
            }
            Self::PublicKeyDecode { field, .. } => write!(
                f,
                "the {field} public key is not a valid serialized public key"
            ),
            Self::PublicKeyScheme { field, scheme } => write!(
                f,
                "the {field} public key uses the {scheme} scheme; only Falcon512Poseidon2 is \
                 supported"
            ),
            Self::SupplyExceedsMax {
                token_supply,
                max_supply,
            } => write!(
                f,
                "token_supply {token_supply} exceeds max_supply {max_supply}"
            ),
            Self::DuplicateSeed { first, second } => {
                write!(f, "the {first} and {second} seeds are identical")
            }
        }
    }
}

impl core::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::SeedHex { source, .. } | Self::PublicKeyHex { source, .. } => Some(source),
            Self::PublicKeyDecode { source, .. } => Some(source),
            _ => None,
        }
    }
}
