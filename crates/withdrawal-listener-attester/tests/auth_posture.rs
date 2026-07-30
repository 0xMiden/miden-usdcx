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
//! 1. **No credential is hardcoded** anywhere in the crate — asserted against the source, not just
//!    the API.
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

/// The identifiers that, assigned a string literal, would BE a hardcoded credential. Deliberately
/// not the bare word `token`: `TOKEN_USDC` is the `token: "USDC"` schema enum, and flagging it
/// would train a future reader to ignore this sweep — which is how a real key eventually slips
/// through.
const SECRET_IDENTS: [&str; 6] = [
    "api_auth_token",
    "auth_token",
    "api_key",
    "apikey",
    "password",
    "credential",
];

/// Every credential-shaped literal in one file's source. A line is an offender if it bakes in an
/// auth SCHEME, constructs a non-empty [`SecretString`], hands [`AuthPosture::header`] a literal
/// value, or assigns a secret-named binding a non-empty string literal.
fn scan_for_credentials(source: &str) -> Vec<String> {
    let mut offenders = Vec::new();

    for (n, line) in source.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        let trimmed = lower.trim_start();
        // doc comments and `//` comments are prose, not code
        if trimmed.starts_with("//") {
            continue;
        }

        let bakes_a_scheme = lower.contains("\"bearer ") || lower.contains("\"basic ");
        // the ONE route a credential can enter this crate's config
        let builds_a_secret =
            lower.contains("secretstring::new(\"") && !lower.contains("secretstring::new(\"\")");
        // …and the one route it can reach a header without passing through the config
        let injects_a_literal_key = lower.contains("authposture::header(\"")
            && lower.matches('"').count() >= 4
            && !lower.contains(", \"\")");

        let assigns_a_secret = SECRET_IDENTS.iter().any(|ident| {
            let Some(after) = lower.split_once(ident).map(|(_, rest)| rest.trim_start()) else {
                return false;
            };
            // an assignment (`=` / `:`) whose right-hand side is a NON-EMPTY string literal — as
            // opposed to `api_auth_token: Option<SecretString>` (a type) or
            // `api_auth_token.is_some()` (a read)
            let Some(rhs) = after
                .strip_prefix('=')
                .or_else(|| after.strip_prefix(':'))
                .map(str::trim_start)
            else {
                return false;
            };
            rhs.starts_with('"') && !rhs.starts_with("\"\"")
        });

        if bakes_a_scheme || builds_a_secret || injects_a_literal_key || assigns_a_secret {
            offenders.push(format!("{}: {}", n + 1, line.trim()));
        }
    }

    offenders
}

#[test]
fn the_credential_scanner_catches_a_planted_credential() {
    // The sweep below is only worth running if it can fail. Each of these is a way a key could really
    // be baked in, and each must be caught — otherwise the green sweep means nothing.
    for planted in [
        r#"    let auth = "Bearer sk_live_2Zq7XyPl";"#,
        r#"    let token = SecretString::new("sk_live_2Zq7XyPl");"#,
        r#"    let posture = AuthPosture::header("X-Circle-Key", "sk_live_2Zq7XyPl");"#,
        r#"    let api_key = "sk_live_2Zq7XyPl";"#,
        r#"    api_auth_token: "sk_live_2Zq7XyPl","#,
    ] {
        assert!(
            !scan_for_credentials(planted).is_empty(),
            "the scanner failed to catch a planted credential: {planted}"
        );
    }

    // …and it must NOT fire on the shapes this crate legitimately contains, or it would be silenced
    for innocent in [
        r#"const TOKEN_USDC: &str = "USDC";"#,
        r#"    #[serde(default = "default_api_auth_header")]"#,
        r#"    if config.api_auth_token.is_some() && url.scheme() != "https" {"#,
        r#"    api_auth_token: Option<SecretString>,"#,
        r#"//! the api_key = "example" in a doc comment is prose"#,
    ] {
        assert!(
            scan_for_credentials(innocent).is_empty(),
            "the scanner fired on a legitimate line: {innocent}"
        );
    }
}

#[test]
fn no_credential_literal_is_baked_into_the_crate_source() {
    // The property is about the SOURCE, so the source is what gets read. An API-level assertion
    // ("the default is None") would still pass if a key were spliced in at the request-building layer.
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();

    for entry in walk_rs(&src) {
        let text = std::fs::read_to_string(&entry).unwrap();
        for hit in scan_for_credentials(&text) {
            offenders.push(format!("{}:{hit}", entry.display()));
        }
    }

    assert!(
        offenders.is_empty(),
        "a credential must never be hardcoded in the source; found:\n{}",
        offenders.join("\n")
    );
}

fn walk_rs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(walk_rs(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
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

#[test]
fn no_authorization_scheme_is_named_anywhere_in_the_crate_source() {
    // The strongest form of "no invented header": the string does not appear in the code at all. Round
    // 1 shipped `Authorization` as the package default, so a token-only config silently SELECTED a
    // scheme the OpenAPI does not document. There is now nothing to select — the operator names the
    // header or supplies no key.
    //
    // Prose may still discuss it (that is how the reader learns why there is no default), so comments
    // are excluded; what must not exist is a header name in the code.
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();

    for entry in walk_rs(&src) {
        let text = std::fs::read_to_string(&entry).unwrap();
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            for scheme in ["\"authorization\"", "\"bearer\"", "\"x-api-key\""] {
                if lower.contains(scheme) {
                    offenders.push(format!("{}:{}: {}", entry.display(), n + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "an auth header name must never be baked in while Q-API-AUTH is OPEN; found:\n{}",
        offenders.join("\n")
    );
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

// THE CREDENTIAL SCHEME STAYS OPEN
// ================================================================================================

#[test]
fn the_auth_module_records_q_api_auth_as_open_and_never_as_resolved() {
    // The CDR obligation: this crate parameterizes the question, it does not answer it. A future edit
    // that quietly declares the scheme settled trips this.
    let auth_rs = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/circle/auth.rs"),
    )
    .unwrap();

    assert!(
        auth_rs.contains("Q-API-AUTH"),
        "the OPEN item must be named"
    );
    assert!(
        auth_rs.contains("REQUIRES CIRCLE CONFIRMATION"),
        "its status must be recorded verbatim"
    );
    for settled in [
        "Q-API-AUTH RESOLVED",
        "Q-API-AUTH: RESOLVED",
        "Q-API-AUTH is resolved",
    ] {
        assert!(
            !auth_rs.contains(settled),
            "a Circle-owned open question must never be marked resolved here"
        );
    }
}
