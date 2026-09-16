//! Shared test fixture: the dev config plus six real role `.mac` files it references,
//! generated deterministically (fixed per-role seeds, seeded ChaCha20 Falcon keys).

// Each test binary compiles its own copy of this module and exercises a different subset of it.
#![allow(dead_code)]

use std::path::Path;

use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{Account, AccountFile, AccountType};
use miden_standards::account::auth::Approver;
use miden_standards::account::wallets::create_basic_wallet;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use xusdc_genesis::config::{ConfigError, GenesisToolConfig, Role};

/// The dev faucet seed (`0x07` repeated), distinct from every wallet seed below.
pub const FAUCET_SEED: [u8; 32] = [7; 32];

/// The fixed per-role wallet seed: the role's 1-based position in [`Role::ALL`], repeated.
pub fn role_seed(role: Role) -> [u8; 32] {
    let byte = match role {
        Role::Relayer => 1,
        Role::Owner => 2,
        Role::AttestAdmin => 3,
        Role::Pauser => 4,
        Role::Unpauser => 5,
        Role::BlocklistManager => 6,
    };
    [byte; 32]
}

/// Generates one role wallet deterministically: a Falcon512-Poseidon2 key pair from seeded
/// ChaCha20, wrapped in a public basic wallet ground from the same seed.
pub fn generate_wallet(role: Role) -> Account {
    let seed = role_seed(role);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let secret = AuthSecretKey::new_falcon512_poseidon2_with_rng(&mut rng);
    create_basic_wallet(
        seed,
        Approver::from(&secret.public_key()),
        AccountType::Public,
    )
    .expect("the fixture wallet must build")
}

/// A materialized dev fixture: the temp directory holding the six generated `.mac` files, and
/// the config JSON referencing them (mutable, so tests can inject malformed values).
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub json: serde_json::Value,
}

impl Fixture {
    /// Generates the six role wallets, writes their `.mac` files, and assembles the dev config.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temp dir is available");
        let mut accounts = serde_json::Map::new();
        for role in Role::ALL {
            let file_name = format!("{}.mac", role.as_str());
            AccountFile::new(generate_wallet(role), Vec::new())
                .write(dir.path().join(&file_name))
                .expect("the fixture .mac must write");
            accounts.insert(
                role.as_str().to_string(),
                serde_json::Value::from(file_name),
            );
        }
        let json = serde_json::json!({
            "accounts": accounts,
            "faucet": {
                "seed": FAUCET_SEED,
                "max_supply": 1_000_000_000_000u64,
                "token_supply": 250_000_000u64,
                "domain": 7,
                "verification_base_fee": 500,
            },
        });
        Self { dir, json }
    }

    /// The directory the config's relative account paths resolve against.
    pub fn base_dir(&self) -> &Path {
        self.dir.path()
    }

    /// Parses the (possibly mutated) config JSON.
    pub fn parse(&self) -> Result<GenesisToolConfig, ConfigError> {
        GenesisToolConfig::from_json(&self.json.to_string(), self.base_dir())
    }

    /// Parses the config JSON, expecting it to be valid.
    pub fn config(&self) -> GenesisToolConfig {
        self.parse().expect("the fixture config must parse")
    }
}
