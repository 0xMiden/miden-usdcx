//! Config-schema rejections: every malformed input surfaces as its specific
//! [`ConfigError`] variant.

use std::path::PathBuf;

use assert_matches::assert_matches;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::utils::serde::Serializable;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;
use xusdc_genesis::config::{ConfigError, GenesisToolConfig};

fn fixture_text() -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dev-config.json"),
    )
    .expect("the committed dev fixture is readable")
}

fn fixture_json() -> serde_json::Value {
    serde_json::from_str(&fixture_text()).expect("the fixture is valid JSON")
}

/// The committed fixture parses, and the typed config reflects it.
#[test]
fn the_dev_fixture_round_trips() {
    let config = GenesisToolConfig::from_json(&fixture_text()).expect("the fixture must parse");
    assert_eq!(config.faucet.max_supply, 1_000_000_000_000);
    assert_eq!(config.faucet.token_supply, 250_000_000);
    assert_eq!(config.faucet.domain, 7);
    assert_eq!(config.faucet.verification_base_fee, 500);
    assert!(config.faucet.min_burn_amount.is_none());
    assert!(config.output_dir.is_none());
    assert!(config.operator.public_key.is_none());
}

/// Malformed seeds are rejected with the variant naming the exact defect and field.
#[rstest]
#[case::wrong_length("0x0101", |err: &ConfigError| matches!(err, ConfigError::SeedLength { field: "operator", len: 4 }))]
#[case::missing_prefix(
    "0101010101010101010101010101010101010101010101010101010101010101",
    |err: &ConfigError| matches!(err, ConfigError::SeedMissingPrefix { field: "operator" })
)]
#[case::non_hex(
    "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    |err: &ConfigError| matches!(err, ConfigError::SeedHex { field: "operator", .. })
)]
fn a_malformed_seed_is_rejected(#[case] seed: &str, #[case] is_expected: fn(&ConfigError) -> bool) {
    let mut raw = fixture_json();
    raw["accounts"]["operator"]["seed"] = serde_json::Value::String(seed.to_string());
    let err = GenesisToolConfig::from_json(&raw.to_string())
        .expect_err("a malformed seed must be rejected");
    assert!(is_expected(&err), "unexpected error variant: {err:?}");
}

/// An unknown field anywhere in the document is a schema violation (`deny_unknown_fields`).
#[test]
fn an_unknown_field_is_rejected() {
    let mut raw = fixture_json();
    raw["faucet"]["surprise"] = serde_json::Value::from(1u64);
    let err = GenesisToolConfig::from_json(&raw.to_string())
        .expect_err("an unknown field must be rejected");
    assert_matches!(err, ConfigError::Parse(source) => {
        assert!(
            source.to_string().contains("unknown field"),
            "the parse error must name the unknown field, got: {source}",
        );
    });
}

/// A public key under any scheme other than Falcon512-Poseidon2 is rejected — the role wallets
/// authenticate with Falcon, and a mismatched scheme would build an unauthenticatable account.
#[test]
fn a_non_falcon_public_key_is_rejected() {
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let ecdsa_key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng).public_key();
    let mut raw = fixture_json();
    raw["accounts"]["owner"]["public_key"] =
        serde_json::Value::String(format!("0x{}", hex::encode(ecdsa_key.to_bytes())));
    let err = GenesisToolConfig::from_json(&raw.to_string())
        .expect_err("a non-Falcon public key must be rejected");
    assert_matches!(err, ConfigError::PublicKeyScheme { field: "owner", .. });
}

/// Bytes that do not decode as a protocol `PublicKey` are rejected.
#[test]
fn an_undecodable_public_key_is_rejected() {
    let mut raw = fixture_json();
    raw["accounts"]["owner"]["public_key"] = serde_json::Value::String("0xdead".to_string());
    let err = GenesisToolConfig::from_json(&raw.to_string())
        .expect_err("an undecodable public key must be rejected");
    assert_matches!(err, ConfigError::PublicKeyDecode { field: "owner", .. });
}

/// An initial supply above the cap is rejected before any account is built.
#[test]
fn a_token_supply_above_the_cap_is_rejected() {
    let mut raw = fixture_json();
    raw["faucet"]["token_supply"] = serde_json::Value::from(2_000_000_000_000u64);
    let err = GenesisToolConfig::from_json(&raw.to_string())
        .expect_err("token_supply above max_supply must be rejected");
    assert_matches!(
        err,
        ConfigError::SupplyExceedsMax {
            token_supply: 2_000_000_000_000,
            max_supply: 1_000_000_000_000,
        }
    );
}

/// Two entries sharing a seed are rejected — a repeated seed would grind the same account twice.
#[test]
fn a_duplicate_seed_is_rejected() {
    let mut raw = fixture_json();
    raw["faucet"]["seed"] = raw["accounts"]["operator"]["seed"].clone();
    let err = GenesisToolConfig::from_json(&raw.to_string())
        .expect_err("a duplicate seed must be rejected");
    assert_matches!(
        err,
        ConfigError::DuplicateSeed {
            first: "operator",
            second: "faucet",
        }
    );
}
