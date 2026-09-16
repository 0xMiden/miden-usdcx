//! Shared test fixture: the dev config with six fixed dummy role-account ids.
//!
//! The tool consumes role accounts as bare ids, so the fixture needs no accounts at all — just
//! six distinct valid [`AccountId`]s (`AccountId::dummy`, the same pattern the relayer fixtures
//! use) and the fixed faucet parameters.

// Each test binary compiles its own copy of this module and exercises a different subset of it.
#![allow(dead_code)]

use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
use xusdc_genesis::config::{GenesisToolConfig, Role};

/// The dev faucet seed (`0x07` repeated).
pub const FAUCET_SEED_HEX: &str =
    "0x0707070707070707070707070707070707070707070707070707070707070707";

/// The fixed dummy account id for `role`: a public account whose id bytes repeat the role's
/// 1-based position in [`Role::ALL`], so the six ids are pairwise distinct.
pub fn role_id(role: Role) -> AccountId {
    let byte = match role {
        Role::Operator => 1,
        Role::Owner => 2,
        Role::AttestAdmin => 3,
        Role::Pauser => 4,
        Role::Unpauser => 5,
        Role::BlocklistManager => 6,
    };
    AccountId::dummy(
        [byte; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// The dev config JSON: the six fixture role ids (hex form) plus the fixed faucet parameters.
pub fn fixture_json() -> serde_json::Value {
    let mut accounts = serde_json::Map::new();
    for role in Role::ALL {
        accounts.insert(
            role.as_str().to_string(),
            serde_json::Value::from(role_id(role).to_hex()),
        );
    }
    serde_json::json!({
        "accounts": accounts,
        "faucet": {
            "seed": FAUCET_SEED_HEX,
            "max_supply": 1_000_000_000_000u64,
            "token_supply": 250_000_000u64,
            "domain": 7,
            "verification_base_fee": 500,
        },
    })
}

/// The parsed dev config.
pub fn fixture_config() -> GenesisToolConfig {
    GenesisToolConfig::from_json(&fixture_json().to_string())
        .expect("the fixture config must parse")
}
