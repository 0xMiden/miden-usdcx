//! Config-schema rejections: every malformed input surfaces as its specific
//! [`ConfigError`] variant.

mod common;

use assert_matches::assert_matches;
use rstest::rstest;
use xusdc_genesis::config::ConfigError;

use crate::common::Fixture;

/// The dev fixture parses, and the typed config reflects it.
#[test]
fn the_dev_fixture_round_trips() {
    let fixture = Fixture::new();
    let config = fixture.config();
    assert_eq!(config.faucet.max_supply, 1_000_000_000_000);
    assert_eq!(config.faucet.token_supply, 250_000_000);
    assert_eq!(config.faucet.domain, 7);
    assert_eq!(config.faucet.verification_base_fee, 500);
    assert!(config.faucet.min_burn_amount.is_none());
    assert!(config.output_dir.is_none());
    assert_eq!(
        config.operator.account().id(),
        common::generate_wallet(xusdc_genesis::config::Role::Operator)
            .0
            .id(),
        "the provided operator account must be the one the fixture generated",
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
    let mut fixture = Fixture::new();
    fixture.json["faucet"]["seed"] = serde_json::Value::String(seed.to_string());
    let err = fixture
        .parse()
        .expect_err("a malformed seed must be rejected");
    assert!(is_expected(&err), "unexpected error variant: {err:?}");
}

/// An unknown field anywhere in the document is a schema violation (`deny_unknown_fields`).
#[test]
fn an_unknown_field_is_rejected() {
    let mut fixture = Fixture::new();
    fixture.json["faucet"]["surprise"] = serde_json::Value::from(1u64);
    let err = fixture
        .parse()
        .expect_err("an unknown field must be rejected");
    assert_matches!(err, ConfigError::Parse(source) => {
        assert!(
            source.to_string().contains("unknown field"),
            "the parse error must name the unknown field, got: {source}",
        );
    });
}

/// A missing account file is rejected with the variant naming the role and path.
#[test]
fn a_missing_account_file_is_rejected() {
    let mut fixture = Fixture::new();
    fixture.json["accounts"]["operator"] = serde_json::Value::from("missing.mac");
    let err = fixture
        .parse()
        .expect_err("a missing account file must be rejected");
    assert_matches!(err, ConfigError::AccountFile { field: "operator", path, .. } => {
        assert!(path.ends_with("missing.mac"), "the error must carry the resolved path");
    });
}

/// A file that does not decode as a protocol `AccountFile` is rejected.
#[test]
fn an_undecodable_account_file_is_rejected() {
    let fixture = {
        let mut fixture = Fixture::new();
        std::fs::write(
            fixture.base_dir().join("garbage.mac"),
            b"not an account file",
        )
        .expect("the garbage file must write");
        fixture.json["accounts"]["owner"] = serde_json::Value::from("garbage.mac");
        fixture
    };
    let err = fixture
        .parse()
        .expect_err("an undecodable account file must be rejected");
    assert_matches!(err, ConfigError::AccountFile { field: "owner", .. });
}

/// An initial supply above the cap is rejected before any account is built.
#[test]
fn a_token_supply_above_the_cap_is_rejected() {
    let mut fixture = Fixture::new();
    fixture.json["faucet"]["token_supply"] = serde_json::Value::from(2_000_000_000_000u64);
    let err = fixture
        .parse()
        .expect_err("token_supply above max_supply must be rejected");
    assert_matches!(
        err,
        ConfigError::SupplyExceedsMax {
            token_supply: 2_000_000_000_000,
            max_supply: 1_000_000_000_000,
        }
    );
}

/// Two roles referencing the same account are rejected — one account cannot hold two roles.
#[test]
fn a_duplicate_account_is_rejected() {
    let mut fixture = Fixture::new();
    fixture.json["accounts"]["owner"] = fixture.json["accounts"]["operator"].clone();
    let err = fixture
        .parse()
        .expect_err("a duplicate account must be rejected");
    assert_matches!(
        err,
        ConfigError::DuplicateAccount {
            first: "operator",
            second: "owner",
        }
    );
}
