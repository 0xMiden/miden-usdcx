//! The config's invariants hold on **every** construction path — the builder *and* serde.
//!
//! Validating only in `ListenerConfigBuilder::build` while deriving `Deserialize` straight onto
//! the struct would leave a hole with teeth: an operator's config file carrying a real API key and
//! an `http://` base URL would be **accepted**, because deserialization populates the private
//! fields without ever passing through the check that would refuse it — and
//! `AuthPosture::from_config` would then hand that credential to the header injector, in the
//! clear. The builder would say no; the config file would say yes; the config file is the path
//! production actually uses.
//!
//! So the property under test is not "the builder validates". It is **"every `ListenerConfig` that
//! exists is valid, however it was made"** — and the parity test below is the one that says so: for
//! each invalid state, the builder and serde must BOTH refuse it.

use assert_matches::assert_matches;
use miden_protocol::asset::AssetAmount;
use rstest::rstest;
use serde_json::{json, Value};
use withdrawal_listener_attester::config::{ListenerConfig, SecretString};
use withdrawal_listener_attester::error::ListenerError;
use xusdc_encoding::xreserve::encoding::CircleDomain;

const OUT_OF_BAND_KEY: &str = "circle-out-of-band-key-Ic4RaK9v";
const FAUCET_ID_HEX: &str = "0xbb405fd9fe431bd1135a292de098cb";

/// A config file that is valid — the baseline each negative perturbs by one field.
fn valid_config_json() -> Value {
    json!({
        "faucet_id": FAUCET_ID_HEX,
        "burn_tag": 3_735_928_559u32,
        "miden_domain": 10_001,
        "max_withdrawal_fee": 1_000u64,
        "circle_base_url": "https://xreserve-api-testnet.circle.com",
        "attester_key_handles": ["kms://attester-a", "kms://attester-b"],
    })
}

#[test]
fn the_baseline_config_file_loads_so_every_negative_below_isolates_one_rule() {
    let config: ListenerConfig =
        serde_json::from_value(valid_config_json()).expect("the baseline must load");

    assert_eq!(config.miden_domain(), CircleDomain::new(10_001));
    assert_eq!(config.max_withdrawal_fee().as_u64(), 1_000);
    assert!(config.api_auth_token().is_none());
}

#[test]
fn the_package_default_refuses_fee_bearing_withdrawals_until_configured() {
    let config = ListenerConfig::default();
    assert_eq!(
        config.max_withdrawal_fee(),
        AssetAmount::ZERO,
        "the default withdrawal fee ceiling is zero"
    );
}

#[test]
fn a_config_file_with_an_unrepresentable_withdrawal_fee_ceiling_is_refused() {
    let mut config = valid_config_json();
    config["max_withdrawal_fee"] = json!(AssetAmount::MAX.as_u64() + 1);

    let error = serde_json::from_value::<ListenerConfig>(config)
        .expect_err("a fee ceiling above AssetAmount::MAX must not load");

    assert_eq!(error.classify(), serde_json::error::Category::Data);
    assert!(
        error.to_string().contains("amount"),
        "the rejection must name the amount bound; got: {error}"
    );
}

// THE HOLE THE AUDIT FOUND: serde must not be a back door around the credential invariant
// ================================================================================================

#[test]
fn a_config_file_carrying_a_credential_over_plaintext_http_is_refused() {
    // THE regression test. Before the fix this deserialized cleanly and the key would have been sent
    // in the clear on the first Circle call.
    let mut config = valid_config_json();
    config["circle_base_url"] = json!("http://xreserve-api-testnet.circle.com");
    config["api_auth_token"] = json!(OUT_OF_BAND_KEY);
    config["api_auth_header"] = json!("X-Circle-Key");

    let error = serde_json::from_value::<ListenerConfig>(config)
        .expect_err("a credential over plaintext http must never load");

    assert_eq!(error.classify(), serde_json::error::Category::Data);
    assert!(
        error.to_string().contains("https"),
        "the rejection must say why; got: {error}"
    );
    // and the message must not leak the thing it is protecting
    assert!(
        !error.to_string().contains(OUT_OF_BAND_KEY),
        "the credential leaked into the error message: {error}"
    );
}

#[rstest]
#[case::plaintext_with_credential(
    json!({"circle_base_url": "http://xreserve-api.circle.com", "api_auth_token": OUT_OF_BAND_KEY, "api_auth_header": "X-Circle-Key"})
)]
#[case::not_a_url(json!({"circle_base_url": "xreserve-api.circle.com"}))]
#[case::empty_url(json!({"circle_base_url": ""}))]
#[case::unsupported_scheme(json!({"circle_base_url": "ftp://xreserve-api.circle.com"}))]
#[case::token_without_a_header_name(json!({"api_auth_token": OUT_OF_BAND_KEY}))]
#[case::malformed_faucet_id(json!({"faucet_id": "0xnot-an-account-id"}))]
fn the_builder_and_serde_refuse_exactly_the_same_invalid_states(#[case] overrides: Value) {
    // The parity property. A config file must never be able to reach a state the builder would have
    // rejected — that is what "valid by construction" has to mean when the config comes from a FILE.
    let mut config = valid_config_json();
    for (key, value) in overrides.as_object().unwrap() {
        config[key] = value.clone();
    }

    assert!(
        serde_json::from_value::<ListenerConfig>(config.clone()).is_err(),
        "serde accepted a state the builder rejects: {config}"
    );
}

#[test]
fn a_plaintext_base_url_without_a_credential_is_still_allowed() {
    // The rule is about the CREDENTIAL, not about http per se: a local dev node over plain http with
    // no key to leak is a legitimate configuration, and refusing it would push operators toward
    // disabling the check entirely.
    let mut config = valid_config_json();
    config["circle_base_url"] = json!("http://localhost:8080");

    assert!(serde_json::from_value::<ListenerConfig>(config).is_ok());
}

// NO AUTH HEADER IS INVENTED — the credential scheme stays OPEN
// ================================================================================================

#[test]
fn the_package_default_names_no_auth_header_at_all() {
    // Defaulting this to `Authorization` would mean that configuring only a token silently
    // SELECTS an undocumented scheme — the exact thing Circle's documentation forbids ("do NOT
    // invent an auth
    // header"). There is no default: the OpenAPI documents no scheme, so neither does this crate.
    let config = ListenerConfig::default();

    assert!(config.api_auth_token().is_none());
    assert_eq!(
        config.api_auth_header(),
        None,
        "no header name may be presumed while Q-API-AUTH is OPEN"
    );
}

#[test]
fn a_token_without_an_explicit_header_name_is_refused_on_both_paths() {
    // If Circle later says "use header X", the operator sets it. Until then, a key with nowhere
    // documented to go is a configuration error — NOT an invitation to guess `Authorization`.
    let from_builder = ListenerConfig::builder()
        .api_auth_token(SecretString::new(OUT_OF_BAND_KEY))
        .build();
    assert_matches!(from_builder, Err(ListenerError::AuthHeaderNameRequired));

    let mut config = valid_config_json();
    config["api_auth_token"] = json!(OUT_OF_BAND_KEY);
    let from_serde = serde_json::from_value::<ListenerConfig>(config);
    assert!(
        from_serde.is_err(),
        "a token with no header name must not load from a config file either"
    );
}

#[test]
fn an_explicitly_named_header_carries_the_key_and_nothing_is_presumed() {
    let mut config = valid_config_json();
    config["api_auth_token"] = json!(OUT_OF_BAND_KEY);
    config["api_auth_header"] = json!("X-Circle-Key");

    let loaded: ListenerConfig = serde_json::from_value(config).expect("https + key + header name");

    assert_eq!(loaded.api_auth_token(), Some(OUT_OF_BAND_KEY));
    assert_eq!(loaded.api_auth_header(), Some("X-Circle-Key"));
}

#[test]
fn a_header_name_without_a_token_is_harmless() {
    // Naming a header but supplying no key sends no header at all — it is a half-finished config, not
    // a dangerous one, and refusing it would serve no purpose.
    let mut config = valid_config_json();
    config["api_auth_header"] = json!("X-Circle-Key");

    let loaded: ListenerConfig =
        serde_json::from_value(config).expect("a name with no key is fine");
    assert!(loaded.api_auth_token().is_none());
}

// THE CREDENTIAL SURVIVES A ROUND TRIP THROUGH THE CONFIG FILE
// ================================================================================================

#[test]
fn a_loaded_config_reserializes_with_its_key_intact_but_never_renders_it() {
    // The redaction is a property of the HUMAN-facing renderings, not of the wire format: a
    // "redaction" that also blanked the serialized form would silently drop the key on the next
    // config reload — turning a security measure into an outage.
    let mut source = valid_config_json();
    source["api_auth_token"] = json!(OUT_OF_BAND_KEY);
    source["api_auth_header"] = json!("X-Circle-Key");

    let loaded: ListenerConfig = serde_json::from_value(source.clone()).unwrap();
    let reserialized = serde_json::to_value(&loaded).unwrap();

    assert_eq!(
        reserialized, source,
        "the config must survive a save/load cycle"
    );
    assert!(
        !format!("{loaded:?}").contains(OUT_OF_BAND_KEY),
        "but Debug must never print it"
    );
}
