//! The auth posture, which stays **OPEN**.
//!
//! The OpenAPI declares **no security scheme at all**: no top-level `security`, no
//! `components.securitySchemes`, no per-operation `security` (verified against the raw 1026-line
//! YAML, `CIRCLE-API-SURFACE.md`). So the contract this crate implements is the one Circle
//! published — *no auth* — and the question of whether production needs an out-of-band key is
//! `REQUIRES CIRCLE CONFIRMATION`, not something to answer by picking a header and hoping.
//!
//! Three properties, each pinned below, and each of them a defect if it fails:
//!
//! 1. **No credential is hardcoded.** The package default carries none, and the default posture
//!    sends no header.
//! 2. **No auth header is invented.** The default posture sends none; a configured key rides under
//!    an operator-supplied header NAME, because presuming `Authorization: Bearer` would presume the
//!    answer to the credential question.
//! 3. **Auth is never mandatory.** A config with no key must be fully usable — the documented
//!    contract works. A client that could only function under an undocumented scheme would be the
//!    defect.
//!
//! Plus the one that makes the other three survive contact with a log file: a credential, once
//! configured, is **never rendered** by `Debug`/`Display`, and never travels over a transport that
//! cannot protect it.

use withdrawal_listener_attester::circle::auth::AuthPosture;
use withdrawal_listener_attester::config::{ListenerConfig, SecretString};
use withdrawal_listener_attester::error::ListenerError;

use assert_matches::assert_matches;

/// A recognisable key, so a leak is unmistakable in any rendered output.
const OUT_OF_BAND_KEY: &str = "circle-out-of-band-key-Ic4RaK9v";

// 1. NO HARDCODED CREDENTIAL
// ================================================================================================

#[test]
fn the_default_config_carries_no_credential_and_the_default_posture_sends_no_header() {
    let config = ListenerConfig::default();

    assert!(
        config.api_auth_token().is_none(),
        "the package default must ship NO credential — Q-API-AUTH is OPEN"
    );

    let posture = AuthPosture::from_config(&config);
    assert_eq!(
        posture,
        AuthPosture::None,
        "with no key configured the client builds requests against the DOCUMENTED no-auth contract"
    );
    assert!(!posture.carries_credential());
    assert_eq!(
        posture.to_header().unwrap(),
        None,
        "no auth header is invented where the OpenAPI documents none"
    );
}

// 2. NO INVENTED HEADER — THE KEY IS CONFIGURABLE, THE HEADER NAME WITH IT
// ================================================================================================

#[test]
fn an_out_of_band_key_is_configurable_without_the_scheme_being_presumed() {
    let config = ListenerConfig::builder()
        .api_auth_token(SecretString::new(OUT_OF_BAND_KEY))
        .api_auth_header("X-Circle-Key")
        .build()
        .expect("an https base url + a key is a valid configuration");

    let posture = AuthPosture::from_config(&config);
    assert!(posture.carries_credential());

    let (name, value) = posture
        .to_header()
        .expect("the header pair must build")
        .expect("a configured key yields a header");

    // the NAME came from config, not from a constant in this crate — that is the whole point
    assert_eq!(name.as_str(), "x-circle-key");
    assert_eq!(value.to_str().unwrap(), OUT_OF_BAND_KEY);
    assert!(
        value.is_sensitive(),
        "the header value must be marked sensitive so it is not echoed by tracing/HPACK"
    );
}

#[test]
fn an_illegal_header_name_or_a_value_carrying_a_control_character_is_refused() {
    // A misconfigured key must not silently degrade into an unauthenticated request stream — and a
    // newline in the value is a header-injection attempt, not a typo.
    let posture = AuthPosture::header("bad header name", OUT_OF_BAND_KEY);
    assert_matches!(
        posture.to_header(),
        Err(ListenerError::BadAuthHeader { ref name, .. }) if name == "bad header name"
    );

    let injected = AuthPosture::header("X-Circle-Key", "value\r\nX-Injected: 1");
    assert_matches!(
        injected.to_header(),
        Err(ListenerError::BadAuthHeader { .. })
    );
}

// 3. AUTH IS NEVER MANDATORY — AND A CREDENTIAL NEVER RIDES A PLAINTEXT TRANSPORT
// ================================================================================================

#[test]
fn the_documented_no_auth_contract_is_a_fully_usable_configuration() {
    // "A config that REQUIRES an undocumented auth scheme to function is rejected" — so the config
    // with NO scheme must build, and must name a real Circle host.
    let config = ListenerConfig::default();

    assert_eq!(
        config.circle_base_url(),
        "https://xreserve-api-testnet.circle.com",
        "the documented testnet host, mirrored — not invented"
    );
    assert!(ListenerConfig::builder()
        .build()
        .is_ok_and(|c| c.api_auth_token().is_none()));
}

#[test]
fn a_configured_credential_over_a_plaintext_base_url_is_refused_at_construction() {
    // Following the relayer's posture: a key that would be sent in the clear is a configuration error,
    // caught when the config is built rather than on the first request. (The serde path enforces the
    // same rule — `tests/config_validation.rs` pins the parity, because a config FILE is the path
    // production actually uses.)
    let attempt = ListenerConfig::builder()
        .circle_base_url("http://xreserve-api-testnet.circle.com")
        .api_auth_token(SecretString::new(OUT_OF_BAND_KEY))
        .api_auth_header("X-Circle-Key")
        .build();

    assert_matches!(attempt, Err(ListenerError::InsecureAuthTransport { .. }));

    // …while the SAME plaintext URL with no credential is merely a local/dev choice, not a leak
    assert!(ListenerConfig::builder()
        .circle_base_url("http://localhost:8080")
        .build()
        .is_ok());
}

// THE CREDENTIAL IS NEVER RENDERED
// ================================================================================================

#[test]
fn no_debug_or_display_rendering_can_print_the_key() {
    let secret = SecretString::new(OUT_OF_BAND_KEY);
    assert_eq!(format!("{secret:?}"), "<redacted>");
    assert_eq!(format!("{secret}"), "<redacted>");
    assert_eq!(secret.expose(), OUT_OF_BAND_KEY, "the one deliberate exit");

    let config = ListenerConfig::builder()
        .api_auth_token(SecretString::new(OUT_OF_BAND_KEY))
        .api_auth_header("X-Circle-Key")
        .build()
        .unwrap();
    let posture = AuthPosture::from_config(&config);

    // a config object is the single most likely thing to be {:?}-logged at startup
    let rendered = format!("{config:?}{posture:?}");
    assert!(
        !rendered.contains(OUT_OF_BAND_KEY),
        "a credential leaked into a Debug rendering: {rendered}"
    );
    // the header NAME is still visible — an operator has to be able to see WHICH header is configured,
    // and it is the one THEY named, never one this crate chose
    assert!(format!("{posture:?}").contains("X-Circle-Key"));
}
