//! Config-schema rejections: every malformed input surfaces as its specific
//! [`ConfigError`] variant.

mod common;

use assert_matches::assert_matches;
use xusdc_genesis::config::{ConfigError, Role};

use crate::common::{generate_wallet, Fixture};

/// The dev fixture parses, and each role's id is extracted from its referenced `.mac` file.
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
    for role in Role::ALL {
        assert_eq!(
            config.account_id(role),
            generate_wallet(role).id(),
            "the {} id must be the one extracted from the referenced .mac file",
            role.as_str(),
        );
    }
}

/// A missing account file is rejected with the variant naming the role and the resolved path.
#[test]
fn a_missing_account_file_is_rejected() {
    let mut fixture = Fixture::new();
    fixture.json["accounts"]["relayer"] = serde_json::Value::from("missing.mac");
    let err = fixture
        .parse()
        .expect_err("a missing account file must be rejected");
    assert_matches!(err, ConfigError::AccountFile { field: "relayer", path, .. } => {
        assert!(path.ends_with("missing.mac"), "the error must carry the resolved path");
    });
}

/// A file that does not decode as a protocol `AccountFile` is rejected.
#[test]
fn a_corrupt_account_file_is_rejected() {
    let mut fixture = Fixture::new();
    std::fs::write(
        fixture.base_dir().join("garbage.mac"),
        b"not an account file",
    )
    .expect("the garbage file must write");
    fixture.json["accounts"]["owner"] = serde_json::Value::from("garbage.mac");
    let err = fixture
        .parse()
        .expect_err("a corrupt account file must be rejected");
    assert_matches!(err, ConfigError::AccountFile { field: "owner", .. });
}

/// A faucet seed that is not exactly 32 bytes is a schema violation.
#[test]
fn a_wrong_length_seed_is_rejected() {
    let mut fixture = Fixture::new();
    fixture.json["faucet"]["seed"] = serde_json::Value::from(vec![7u8; 4]);
    let err = fixture
        .parse()
        .expect_err("a wrong-length seed must be rejected");
    assert_matches!(err, ConfigError::Parse(_));
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

/// An initial supply above the cap is rejected before the faucet is built.
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
