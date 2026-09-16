//! Config-schema rejections: every malformed input surfaces as its specific
//! [`ConfigError`] variant.

mod common;

use assert_matches::assert_matches;
use miden_protocol::address::NetworkId;
use rstest::rstest;
use xusdc_genesis::config::{ConfigError, GenesisToolConfig, Role};

use crate::common::{fixture_json, role_id};

/// The dev fixture parses, and the typed config reflects it.
#[test]
fn the_dev_fixture_round_trips() {
    let config =
        GenesisToolConfig::from_json(&fixture_json().to_string()).expect("the fixture must parse");
    assert_eq!(config.faucet.max_supply, 1_000_000_000_000);
    assert_eq!(config.faucet.token_supply, 250_000_000);
    assert_eq!(config.faucet.domain, 7);
    assert_eq!(config.faucet.verification_base_fee, 500);
    assert!(config.faucet.min_burn_amount.is_none());
    assert!(config.output_dir.is_none());
    assert_eq!(
        config.operator,
        role_id(Role::Operator),
        "the operator id must round-trip through the hex form",
    );
}

/// A bech32 account id parses to the same id as its hex form.
#[test]
fn a_bech32_account_id_is_accepted() {
    let mut raw = fixture_json();
    raw["accounts"]["operator"] =
        serde_json::Value::from(role_id(Role::Operator).to_bech32(NetworkId::Testnet));
    let config =
        GenesisToolConfig::from_json(&raw.to_string()).expect("the bech32 form must parse");
    assert_eq!(
        config.operator,
        role_id(Role::Operator),
        "the bech32 form must decode to the same id as the hex form",
    );
}

/// An account id that parses as neither hex nor bech32 is rejected with the variant naming the
/// role.
#[rstest]
#[case::bad_hex("0xnothex")]
#[case::bad_bech32("definitely-not-bech32")]
fn a_malformed_account_id_is_rejected(#[case] id: &str) {
    let mut raw = fixture_json();
    raw["accounts"]["operator"] = serde_json::Value::from(id);
    let err = GenesisToolConfig::from_json(&raw.to_string())
        .expect_err("a malformed account id must be rejected");
    assert_matches!(
        err,
        ConfigError::AccountId {
            field: "operator",
            ..
        }
    );
}

/// A malformed faucet seed is rejected with the variant naming the exact defect.
#[rstest]
#[case::wrong_length("0x0101", |err: &ConfigError| matches!(err, ConfigError::SeedLength { field: "faucet.seed", len: 4 }))]
#[case::missing_prefix(
    "0707070707070707070707070707070707070707070707070707070707070707",
    |err: &ConfigError| matches!(err, ConfigError::SeedMissingPrefix { field: "faucet.seed" })
)]
#[case::non_hex(
    "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    |err: &ConfigError| matches!(err, ConfigError::SeedHex { field: "faucet.seed", .. })
)]
fn a_malformed_faucet_seed_is_rejected(
    #[case] seed: &str,
    #[case] is_expected: fn(&ConfigError) -> bool,
) {
    let mut raw = fixture_json();
    raw["faucet"]["seed"] = serde_json::Value::String(seed.to_string());
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

/// An initial supply above the cap is rejected before the faucet is built.
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
