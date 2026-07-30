//! `tests/circle_auth_contract.rs` — the auth posture: a configurable header-injection point, no
//! hardcoded credential, no credential in any human-facing rendering, and no credential over a
//! transport that cannot protect it.
//!
//! the credential scheme is `REQUIRES CIRCLE CONFIRMATION`: the OpenAPI declares no security scheme
//! at all, so the relayer ships an injection point — not a scheme — and these tests pin the
//! properties that must hold whatever Circle answers.
//!
//! No live Circle leg (the mock boundary): every Circle endpoint is `REQUIRES CIRCLE CONFIRMATION`
//! and is exercised against the in-process schema-exact mock ([`mock_circle`]) — the relayer builds
//! a real `reqwest::Request` and the mock's axum router answers it, binding no socket. The
//! attestation wire data is the partner test vector from [`fixtures`] — a real secp256k1 signature
//! over the real raw-keccak digest of a canonical DepositIntent payload — so the keccak binding
//! these tests assert is a genuine binding, not a self-consistent invention.

mod fixtures;
mod mock_circle;

use assert_matches::assert_matches;
use rstest::rstest;
use serde_json::json;

use fixtures::test_vector;
use mock_circle::{
    by_hash_wrapper, client_for, requested_hash, Endpoint, MockCircle, Reply, Script,
};

use xreserve_deposit_relayer::circle::{
    fetch_attestation_by_message_hash, AuthPosture, CircleClient,
};
use xreserve_deposit_relayer::config::RelayerConfig;
use xreserve_deposit_relayer::error::RelayerError;

// auth posture: configurable header injection, no hardcoded credential
// ================================================================================================

/// (3) With NO key configured the client still builds requests against the DOCUMENTED (no-auth)
/// contract — the OpenAPI declares no security scheme — and (2) it sends no credential header of
/// any kind.
#[tokio::test]
async fn t_rly_10_with_no_key_configured_no_auth_header_is_sent_and_the_request_still_succeeds() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(by_hash_wrapper(&vector))]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("the no-auth contract is the documented one — the request must succeed");

    let request = &mock.requests_to(Endpoint::ByHash)[0];
    for header in [
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "x-circle-api-key",
        "x-auth-token",
    ] {
        assert_eq!(
            request.header(header),
            None,
            "no credential header may be sent when none is configured (got `{header}`)"
        );
    }
    // and nothing that smells like a credential rode in on any other header
    for value in request.headers.values() {
        let value = value.to_lowercase();
        assert!(
            !value.contains("bearer ") && !value.contains("sk_live") && !value.contains("sk_test"),
            "a credential-shaped value leaked into a header: {value}"
        );
    }
}

/// (1) The header-injection point exists: an out-of-band key supplied by the operator is attached
/// to every request, under the operator-chosen header name.
#[tokio::test]
async fn t_rly_10_a_configured_out_of_band_key_is_injected_as_a_header() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(by_hash_wrapper(&vector))]));
    let (client, _sink) = client_for(
        &mock,
        AuthPosture::header("Authorization", "Bearer test-only-not-a-real-key"),
    );

    fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("fetch");

    let request = &mock.requests_to(Endpoint::ByHash)[0];
    assert_eq!(
        request.header("authorization"),
        Some("Bearer test-only-not-a-real-key")
    );
}

/// The header NAME is configurable too — the production scheme is still Circle's to confirm, so the
/// client must not presume `Authorization`/`Bearer`.
#[tokio::test]
async fn t_rly_10_the_auth_header_name_is_configurable() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(by_hash_wrapper(&vector))]));
    let (client, _sink) = client_for(&mock, AuthPosture::header("X-Api-Key", "test-only-key"));

    fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("fetch");

    let request = &mock.requests_to(Endpoint::ByHash)[0];
    assert_eq!(request.header("x-api-key"), Some("test-only-key"));
    assert_eq!(request.header("authorization"), None);
}

/// An invalid header name/value is refused at CONSTRUCTION — a misconfigured key can never become a
/// silently header-less (unauthenticated) request stream.
#[rstest]
#[case::bad_name("bad name", "value")]
#[case::empty_name("", "value")]
#[case::newline_in_value("X-Api-Key", "value\nInjected: header")]
fn t_rly_10_an_invalid_auth_header_is_rejected_at_construction(
    #[case] name: &str,
    #[case] value: &str,
) {
    let result = CircleClient::new(
        "https://xreserve-api-testnet.circle.com",
        AuthPosture::header(name, value),
    );
    assert_matches!(
        result.expect_err("invalid header"),
        RelayerError::BadAuthHeader { .. }
    );
}

/// (2) No credential is hardcoded: the default config carries none, the default posture is
/// `AuthPosture::None`, and the shipped source contains no credential literal.
#[test]
fn t_rly_10_no_credential_is_hardcoded_anywhere_in_the_crate() {
    let config = RelayerConfig::default();
    assert_eq!(
        config.api_auth_token(),
        None,
        "the package default holds no key"
    );
    assert_eq!(
        AuthPosture::from_config(&config),
        AuthPosture::None,
        "with no configured token the posture is the documented no-auth contract"
    );

    // a credential literal must not exist in the shipped source
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let markers = [
        "bearer ",
        "sk_live",
        "sk_test",
        "x-api-key:",
        "authorization:",
        "api_key=",
        "apikey=",
    ];
    let mut checked = 0usize;
    for entry in walk_rust_sources(&src) {
        let text = std::fs::read_to_string(&entry)
            .unwrap_or_else(|e| panic!("read {}: {e}", entry.display()))
            .to_lowercase();
        for marker in markers {
            assert!(
                !text.contains(marker),
                "{} contains a credential-shaped literal `{marker}` — Q-API-AUTH is OPEN; the key is \
                 supplied out of band, never baked in",
                entry.display()
            );
        }
        checked += 1;
    }
    assert!(
        checked >= 8,
        "the scan must actually have read the crate's sources"
    );
}

/// The key an OPERATOR configured — the one that actually exists in production — must not leak
/// through `RelayerConfig`'s `Debug` either. A config struct is the single most likely thing to be
/// `{:?}`-logged at startup or dumped into a panic message, and it is the object that HOLDS the
/// credential; redacting only `AuthPosture`/`CircleClient` would leave the front door open.
#[test]
fn t_rly_10_a_configured_key_does_not_leak_through_relayer_config_debug() {
    const OPERATOR_KEY: &str = "operator-supplied-out-of-band-key";

    // exactly how a real config arrives: deserialized from the operator's config source
    let mut value = serde_json::to_value(RelayerConfig::default()).expect("config serializes");
    value["api_auth_token"] = json!(OPERATOR_KEY);
    let config: RelayerConfig = serde_json::from_value(value).expect("config deserializes");

    // the key is USABLE (redaction must not neuter the injection point)...
    assert_eq!(config.api_auth_token(), Some(OPERATOR_KEY));

    //... and yet unprintable
    let rendered = format!("{config:?}");
    assert!(
        !rendered.contains(OPERATOR_KEY),
        "RelayerConfig Debug leaked the credential: {rendered}"
    );
    assert!(
        rendered.contains("redacted"),
        "the token field is still rendered — as a redaction: {rendered}"
    );

    // and the operator's config file round-trips: a redacting Debug must not corrupt what is
    // serialized back out, or reloading a config would silently drop the key
    let reserialized = serde_json::to_string(&config).expect("config serializes");
    assert!(
        reserialized.contains(OPERATOR_KEY),
        "serde must carry the real token; only the human-facing renderings redact it"
    );
    let round_tripped: RelayerConfig =
        serde_json::from_str(&reserialized).expect("config deserializes");
    assert_eq!(round_tripped, config);
}

/// The redaction is not cosmetic: the key a redacted config carries still reaches the wire, under
/// the configured header name. (A "fix" that redacted by dropping the value would pass a Debug
/// assertion and silently unauthenticate the relayer.)
#[tokio::test]
async fn t_rly_10_a_redacted_config_still_injects_the_real_key_on_the_wire() {
    const OPERATOR_KEY: &str = "operator-supplied-out-of-band-key";

    let mut value = serde_json::to_value(RelayerConfig::default()).expect("config serializes");
    value["api_auth_token"] = json!(OPERATOR_KEY);
    value["api_auth_header"] = json!("X-Circle-Api-Key");
    let config: RelayerConfig = serde_json::from_value(value).expect("config deserializes");

    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(by_hash_wrapper(&vector))]));
    let client = CircleClient::from_config(&config)
        .expect("client builds from the operator config")
        .with_transport(mock.transport());

    fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("fetch");

    let request = &mock.requests_to(Endpoint::ByHash)[0];
    assert_eq!(request.header("x-circle-api-key"), Some(OPERATOR_KEY));
    assert!(
        !format!("{client:?}").contains(OPERATOR_KEY),
        "the client built from that config still redacts it"
    );
}

/// The key never reaches a log line: `Debug` (the natural way a client ends up in a log/panic
/// message) redacts the header VALUE while keeping the header NAME visible for diagnosis.
#[test]
fn t_rly_10_debug_redacts_the_configured_key() {
    let posture = AuthPosture::header("X-Api-Key", "super-secret-test-value");
    let rendered = format!("{posture:?}");
    assert!(
        !rendered.contains("super-secret-test-value"),
        "the key must never be rendered: {rendered}"
    );
    assert!(
        rendered.contains("X-Api-Key"),
        "the header NAME stays visible: {rendered}"
    );

    let client = CircleClient::new("https://xreserve-api-testnet.circle.com", posture)
        .expect("client builds");
    let rendered = format!("{client:?}");
    assert!(
        !rendered.contains("super-secret-test-value"),
        "the key must never be rendered through the client either: {rendered}"
    );
}

fn walk_rust_sources(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("src/ is readable") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            out.extend(walk_rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

// (cont.) — a credential may not cross a transport that cannot protect
// it
// ================================================================================================

/// **A configured key requires HTTPS.** With a plaintext base URL the credential would be readable
/// by anything on the path, and no amount of redaction in the logs changes that. The client refuses
/// to be built at all — at CONSTRUCTION, not on the first request, so the misconfiguration surfaces
/// at startup rather than after the key has already been sent.
#[rstest]
#[case::plain_http("http://xreserve-api-testnet.circle.com")]
#[case::plain_http_localhost("http://127.0.0.1:8080")]
fn t_rly_10_a_configured_key_is_refused_over_a_plaintext_base_url(#[case] base_url: &str) {
    let err = CircleClient::new(base_url, AuthPosture::header("X-Api-Key", "test-only-key"))
        .expect_err("a credential must not cross a plaintext transport");

    assert_matches!(err, RelayerError::InsecureAuthTransport { .. });
}

/// The same base URL is fine with NO credential to protect — the relayer does not invent a TLS
/// requirement the documented (no-auth) API does not have; it protects the key it was given.
#[test]
fn t_rly_10_a_plaintext_base_url_is_allowed_when_there_is_no_credential() {
    CircleClient::new("http://127.0.0.1:8080", AuthPosture::None)
        .expect("no credential, nothing to leak — the no-auth contract is the documented one");
}

/// And HTTPS + a key is exactly the supported combination.
#[test]
fn t_rly_10_a_configured_key_is_accepted_over_https() {
    CircleClient::new(
        "https://xreserve-api-testnet.circle.com",
        AuthPosture::header("X-Api-Key", "test-only-key"),
    )
    .expect("https protects the credential in transit");
}

/// The rule holds through `from_config` too — the path an operator's key actually arrives on.
#[test]
fn t_rly_10_a_configured_key_over_a_plaintext_base_url_is_refused_from_config() {
    let mut value = serde_json::to_value(RelayerConfig::default()).expect("serializes");
    value["circle_base_url"] = json!("http://xreserve-api-testnet.circle.com");
    value["api_auth_token"] = json!("operator-key");
    let config: RelayerConfig = serde_json::from_value(value).expect("deserializes");

    assert_matches!(
        CircleClient::from_config(&config).expect_err("plaintext + credential"),
        RelayerError::InsecureAuthTransport { .. }
    );
}
