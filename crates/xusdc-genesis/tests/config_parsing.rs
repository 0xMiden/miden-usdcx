//! Config-schema acceptance and rejections.

mod common;

use assert_matches::assert_matches;
use miden_protocol::account::AccountId;
use miden_protocol::address::NetworkId;
use xusdc_encoding::xreserve::encoding::DepositNonce;
use xusdc_genesis::config::{ConfigError, Role};

use crate::common::{attester_keys, role_id_hex, Fixture, USED_NONCE_BYTES};

/// The dev fixture parses, and the typed config reflects it.
#[test]
fn the_dev_fixture_round_trips() {
    let fixture = Fixture::new();
    let config = fixture.config();
    assert_eq!(config.faucet.token_supply.as_u64(), 250_000_000);
    assert_eq!(config.faucet.domain, 7);
    assert_eq!(config.faucet.verification_base_fee, 500);
    assert!(config.faucet.min_burn_amount.is_none());
    assert!(config.output_dir.is_none());
    assert_eq!(
        config
            .faucet
            .attesters
            .iter()
            .map(|key| key.to_commitment())
            .collect::<Vec<_>>(),
        attester_keys()
            .iter()
            .map(|key| key.to_commitment())
            .collect::<Vec<_>>(),
        "the attester keys must decode from their configured SEC1 bytes",
    );
    assert_eq!(
        config.faucet.used_nonces,
        USED_NONCE_BYTES.map(DepositNonce::new),
        "the used nonces must decode from their configured bytes",
    );
    for role in Role::ALL {
        assert_eq!(
            config.accounts.get(role).to_hex(),
            role_id_hex(role),
            "the {} id must round-trip through the hex form",
            role.as_str(),
        );
    }
}

/// A bech32 account id parses to the same id as its hex form.
#[test]
fn a_bech32_account_id_is_accepted() {
    let hex = role_id_hex(Role::Owner);
    let id = AccountId::from_hex(hex).expect("the fixture id is valid hex");
    let mut fixture = Fixture::new();
    fixture.json["accounts"]["owner"] = serde_json::Value::from(id.to_bech32(NetworkId::Testnet));
    assert_eq!(
        fixture.config().accounts.owner,
        id,
        "the bech32 form must decode to the same id as the hex form",
    );
}

/// An account id that parses as neither hex nor bech32 is rejected.
#[test]
fn a_malformed_account_id_is_rejected() {
    for bad_id in ["0xnothex", "definitely-not-bech32"] {
        let mut fixture = Fixture::new();
        fixture.json["accounts"]["owner"] = serde_json::Value::from(bad_id);
        let err = fixture
            .parse()
            .expect_err("a malformed account id must be rejected");
        assert_matches!(err, ConfigError::Parse(_));
    }
}

/// An absent attester list parses as an empty allowlist (seeded later via set_attester).
#[test]
fn an_absent_attester_list_is_an_empty_allowlist() {
    let mut fixture = Fixture::new();
    fixture.json["faucet"]
        .as_object_mut()
        .expect("the faucet section is an object")
        .remove("attesters");
    assert!(
        fixture.config().faucet.attesters.is_empty(),
        "an absent attesters field must parse as an empty allowlist",
    );
}

/// An absent used-nonce list parses as no consumed nonces.
#[test]
fn an_absent_used_nonce_list_is_empty() {
    let mut fixture = Fixture::new();
    fixture.json["faucet"]
        .as_object_mut()
        .expect("the faucet section is an object")
        .remove("used_nonces");
    assert!(
        fixture.config().faucet.used_nonces.is_empty(),
        "an absent used_nonces field must parse as no consumed nonces",
    );
}

/// An attester key that is not a valid 33-byte compressed secp256k1 point is rejected: a
/// wrong-length key, and a key with an invalid SEC1 tag byte.
#[test]
fn a_malformed_attester_key_is_rejected() {
    for bad_key in [vec![2u8; 32], vec![5u8; 33]] {
        let mut fixture = Fixture::new();
        fixture.json["faucet"]["attesters"][0] = serde_json::Value::from(bad_key);
        let err = fixture
            .parse()
            .expect_err("a malformed attester key must be rejected");
        assert_matches!(err, ConfigError::Parse(_));
    }
}

/// A token supply that is not a valid asset amount is rejected at parse time — it could
/// otherwise exceed the hardcoded supply cap.
#[test]
fn an_out_of_range_token_supply_is_rejected() {
    let mut fixture = Fixture::new();
    fixture.json["faucet"]["token_supply"] = serde_json::Value::from(u64::MAX);
    let err = fixture
        .parse()
        .expect_err("an out-of-range token supply must be rejected");
    assert_matches!(err, ConfigError::Parse(_));
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
