//! Shared test fixture: the dev config JSON (mutable, so tests can inject malformed values).

// Each test binary compiles its own copy of this module and exercises a different subset of it.
#![allow(dead_code)]

use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::utils::serde::Deserializable;
use xusdc_genesis::config::{ConfigError, GenesisToolConfig, Role};

/// The dev faucet seed (`0x07` repeated).
pub const FAUCET_SEED: [u8; 32] = [7; 32];

/// Two known-valid attester keys in the 33-byte compressed SEC1 form: the secp256k1 generator
/// point and its double.
pub const ATTESTER_KEY_BYTES: [[u8; 33]; 2] = [
    [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ],
    [
        0x02, 0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D, 0x6D, 0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0,
        0x7C, 0xD8, 0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C, 0xA7, 0xAB, 0xAC, 0x09, 0xB9, 0x5C,
        0x70, 0x9E, 0xE5,
    ],
];

/// Two fixture deposit nonces, recorded as consumed at build time.
pub const USED_NONCE_BYTES: [[u8; 32]; 2] = [[0x55; 32], [0x66; 32]];

/// The `0x`-prefixed hex string of `bytes` — the config's byte encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{hex}")
}

/// The fixture attester keys, decoded.
pub fn attester_keys() -> Vec<PublicKey> {
    ATTESTER_KEY_BYTES
        .iter()
        .map(|bytes| PublicKey::read_from_bytes(bytes).expect("the fixture keys are valid"))
        .collect()
}

/// The fixed dev role ids, as hex strings.
pub fn role_id_hex(role: Role) -> &'static str {
    match role {
        Role::Owner => "0x3cd7940c4946bad179675b1d7d8059",
        Role::AttestAdmin => "0x2bb51b585b2a98916aebb827cc5804",
        Role::Pauser => "0x88dc763b163d53513c4ea2c4f5f1f7",
        Role::Unpauser => "0x83b89e07263e3b51799cb3af134d6d",
        Role::BlocklistManager => "0x5cf939821efad05159595966886192",
    }
}

/// A materialized dev fixture: the config JSON, mutable so tests can inject malformed values.
pub struct Fixture {
    pub json: serde_json::Value,
}

impl Fixture {
    /// Assembles the dev config.
    pub fn new() -> Self {
        let mut accounts = serde_json::Map::new();
        for role in Role::ALL {
            accounts.insert(
                role.as_str().to_string(),
                serde_json::Value::from(role_id_hex(role)),
            );
        }
        let json = serde_json::json!({
            "accounts": accounts,
            "faucet": {
                "seed": to_hex(&FAUCET_SEED),
                "token_supply": 250_000_000u64,
                "domain": 7,
                "verification_base_fee": 500,
                "attesters": [to_hex(&ATTESTER_KEY_BYTES[0]), to_hex(&ATTESTER_KEY_BYTES[1])],
                "used_nonces": [to_hex(&USED_NONCE_BYTES[0]), to_hex(&USED_NONCE_BYTES[1])],
            },
        });
        Self { json }
    }

    /// Parses the (possibly mutated) config JSON.
    pub fn parse(&self) -> Result<GenesisToolConfig, ConfigError> {
        GenesisToolConfig::from_json(&self.json.to_string())
    }

    /// Parses the config JSON, expecting it to be valid.
    pub fn config(&self) -> GenesisToolConfig {
        self.parse().expect("the fixture config must parse")
    }
}
