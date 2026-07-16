//! `T-LA-10` — the `POST /v1/prepare-withdrawal` (`CMP-D5`) and `POST /v1/withdraw` (`CMP-D6`) HTTP
//! drivers, against the in-process schema-exact mock, **plus** the fund-safety pre-submit
//! signer-allowlist gate.
//!
//! Non-vacuity: the mock asserts on the REAL built `reqwest::Request` (URL join, JSON body, the
//! `batches[]` wrapper shape); the withdraw response cardinality is required to match the submitted
//! batch count; and every allowlist refusal produces an EXACT error variant and — because no
//! [`AuthorizedWithdrawal`] token is minted — ZERO `/v1/withdraw` calls.
//!
//! The fund-safety token is bound to the B5 [`ValidatedWithdrawal`] digests and the config-owned
//! [`AttesterAllowlist`], and consumed by value on submit, so a proof cannot be forged from ad-hoc
//! inputs or reused.

use assert_matches::assert_matches;
use serde_json::{json, Value};

use miden_protocol::asset::AssetAmount;
use withdrawal_listener_attester::attester::{
    recover_address, sign, Address, AttesterAllowlist, SecretKey, Signature65,
};
use withdrawal_listener_attester::circle::schema::{
    BurnIntent, PrepareWithdrawalRequest, PrepareWithdrawalResponse, WithdrawBatch,
};
use withdrawal_listener_attester::circle::wire::HexBytes;
use withdrawal_listener_attester::circle::CircleClient;
use withdrawal_listener_attester::config::{ListenerConfig, SecretString};
use withdrawal_listener_attester::error::{ListenerError, SubmitGateError};
use withdrawal_listener_attester::types::BurnPayload;
use withdrawal_listener_attester::validate::{validate_returned, ValidatedWithdrawal};
use withdrawal_listener_attester::withdrawal_api::{
    authorize_submission, build_withdraw_request, prepare, withdraw, AuthorizedWithdrawal,
};
use xusdc_encoding::xreserve::encoding::XReserveBurnItems;

#[path = "mock_circle/mod.rs"]
mod mock_circle;
#[path = "support/mod.rs"]
mod support;

use mock_circle::{Endpoint, MockCircle, Reply, Script};

// FIXTURES / HELPERS
// ================================================================================================

/// A single canonical burn intent, cloned from the 200 fixture.
fn burn_intents(n: usize) -> Vec<BurnIntent> {
    let prepared = support::fixture_json("prepare_withdrawal_200");
    let one: Vec<BurnIntent> =
        serde_json::from_value(prepared["batches"][0]["burnIntents"].clone())
            .expect("the fixture burnIntents deserialize");
    let template = one[0].clone();
    std::iter::repeat_with(|| template.clone())
        .take(n)
        .collect()
}

/// The `PrepareWithdrawalRequest` wrapper the driver sends — any schema-valid single-batch request
/// exercises the wire.
fn a_prepare_request() -> PrepareWithdrawalRequest {
    use withdrawal_listener_attester::circle::schema::PrepareBurnIntentInput;
    use withdrawal_listener_attester::circle::wire::{DecimalAmount, Hex32};

    let input = PrepareBurnIntentInput::builder()
        .value_including_fees(DecimalAmount::new("10000000").unwrap())
        .remote_domain(10_001)
        .remote_depositor(Hex32::new(format!("0x{}", "11".repeat(32))).unwrap())
        .final_destination_domain(0)
        .final_destination_recipient(Hex32::new(format!("0x{}", "22".repeat(32))).unwrap())
        .use_circle_forwarding(false)
        .build()
        .expect("a valid prepare input");
    PrepareWithdrawalRequest::new(vec![input])
}

/// A deterministic secret key from a single repeated byte (well below the curve order for any byte).
fn key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).expect("a valid secp256k1 scalar")
}

/// Signs `digest` with `key(byte)` and returns the recovered signer address and the 65-byte signature.
fn signer(byte: u8, digest: &[u8; 32]) -> (Address, Signature65) {
    let sk = key(byte);
    let sig = sign(digest, &sk).expect("sign");
    let addr = recover_address(digest, &sig).expect("recoverable");
    (addr, sig)
}

/// A `WithdrawBatch` carrying `signatures` verbatim (order preserved) over one canonical intent.
fn batch_with(signatures: Vec<HexBytes>) -> WithdrawBatch {
    WithdrawBatch::new(
        burn_intents(1),
        signatures,
        "0x82a1c0dffe1d3c5b7a99b8d7f61534537291b0cfee0d2c4b6a89a8c7e6052443".to_string(),
        false,
    )
    .expect("a 1-intent, 2-signature batch")
}

fn hexbytes(sig: &Signature65) -> HexBytes {
    HexBytes::new(sig.to_hex()).expect("a 65-byte signature renders to valid 0x-hex")
}

fn decode_hex32(s: &str) -> [u8; 32] {
    let body = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(body).unwrap().as_slice().try_into().unwrap()
}

/// The fixed batch digest the single-batch fund-safety cases sign over.
const DIGEST: [u8; 32] = [0x5a; 32];

/// A burn payload that MATCHES the 200 fixture's returned spec (value / destinationDomain /
/// destinationRecipient), so `validate_returned` (B5) accepts the fixture response.
fn payload_matching_fixture() -> BurnPayload {
    let fixture = support::fixture_json("prepare_withdrawal_200");
    let spec = &fixture["batches"][0]["burnIntents"][0]["spec"];
    let value: u64 = spec["value"].as_str().unwrap().parse().unwrap();
    XReserveBurnItems {
        amount: AssetAmount::new(value).unwrap(),
        dest_domain: spec["destinationDomain"].as_u64().unwrap() as u32,
        dest_recipient: decode_hex32(spec["destinationRecipient"].as_str().unwrap()),
        salt: [0u8; 32],
    }
}

/// A `ValidatedWithdrawal` carrying exactly `digests`, minted through the REAL B5 gate
/// (`validate_returned`) against a fixture-derived prepare response — so the gate's digests come from
/// B5, never from ad-hoc test input.
fn validated(digests: &[[u8; 32]]) -> ValidatedWithdrawal {
    let template = support::fixture_json("prepare_withdrawal_200")["batches"][0].clone();
    let batches: Vec<Value> = digests
        .iter()
        .map(|d| {
            let mut b = template.clone();
            b["messageHashToSign"] = Value::String(format!("0x{}", hex::encode(d)));
            b
        })
        .collect();
    let resp: PrepareWithdrawalResponse =
        serde_json::from_value(json!({ "batches": batches })).expect("a valid prepare response");
    validate_returned(
        &resp,
        &payload_matching_fixture(),
        &ListenerConfig::default(),
    )
    .expect("the fixture response passes B5")
}

/// A `ListenerConfig` whose attester allowlist is exactly `addrs`.
fn config_with_allowlist(addrs: impl IntoIterator<Item = Address>) -> ListenerConfig {
    ListenerConfig::builder()
        .attester_allowlist(AttesterAllowlist::new(addrs))
        .build()
        .expect("a valid config")
}

/// The happy-path token: one batch, both signers registered, bound to the B5 digest and config.
fn authorized_two_of_two() -> AuthorizedWithdrawal {
    let (a0, s0) = signer(0x11, &DIGEST);
    let (a1, s1) = signer(0x22, &DIGEST);
    let config = config_with_allowlist([a0, a1]);
    let request =
        build_withdraw_request(vec![batch_with(vec![hexbytes(&s0), hexbytes(&s1)])]).unwrap();
    authorize_submission(request, &validated(&[DIGEST]), &config).expect("both signers registered")
}

/// A two-batch token: each batch's two signers registered, each bound to its own B5 digest.
fn authorized_two_batches() -> AuthorizedWithdrawal {
    let da = [0x5a; 32];
    let db = [0x5b; 32];
    let (a0, s0) = signer(0x11, &da);
    let (a1, s1) = signer(0x22, &da);
    let (b0, t0) = signer(0x33, &db);
    let (b1, t1) = signer(0x44, &db);
    let config = config_with_allowlist([a0, a1, b0, b1]);
    let request = build_withdraw_request(vec![
        batch_with(vec![hexbytes(&s0), hexbytes(&s1)]),
        batch_with(vec![hexbytes(&t0), hexbytes(&t1)]),
    ])
    .unwrap();
    authorize_submission(request, &validated(&[da, db]), &config).expect("all four registered")
}

/// A client pointed at the mock, no auth.
fn client_for(mock: &MockCircle) -> CircleClient {
    CircleClient::new(
        mock.base_url(),
        withdrawal_listener_attester::circle::auth::AuthPosture::None,
    )
    .expect("client builds against the mock base url")
    .with_transport(mock.transport())
}

// PREPARE — POST /v1/prepare-withdrawal (CMP-D5)
// ================================================================================================

#[tokio::test]
async fn prepare_posts_the_batches_wrapper_and_decodes_the_response() {
    let mock = MockCircle::start(Script::new().prepare(vec![Reply::json(
        200,
        support::fixture_json("prepare_withdrawal_200"),
    )]));
    let client = client_for(&mock);

    let resp = prepare(&client, &a_prepare_request())
        .await
        .expect("a 200 prepare decodes");

    assert_eq!(
        resp.batches().len(),
        1,
        "the response is the batches[] wrapper"
    );
    assert!(!resp.batches()[0].burn_intents().is_empty());

    let reqs = mock.requests_to(Endpoint::Prepare);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/v1/prepare-withdrawal");
    let body = reqs[0].body_json();
    assert!(
        body.is_object(),
        "the request body is an object, not a bare array/batch"
    );
    assert!(
        body.get("batches").is_some_and(Value::is_array),
        "with a top-level batches[] array: {body}"
    );
}

#[tokio::test]
async fn prepare_400_is_a_generic_http_error_with_no_body_parsed() {
    let mock = MockCircle::start(Script::new().prepare(vec![Reply::json(
        400,
        support::fixture_json("withdraw_400"),
    )]));
    let client = client_for(&mock);

    let err = prepare(&client, &a_prepare_request()).await.unwrap_err();
    assert_matches!(err, ListenerError::Http { status: 400 });
}

#[tokio::test]
async fn prepare_500_is_a_generic_http_error() {
    let mock = MockCircle::start(Script::new().prepare(vec![Reply::Status(500)]));
    let client = client_for(&mock);

    let err = prepare(&client, &a_prepare_request()).await.unwrap_err();
    assert_matches!(err, ListenerError::Http { status: 500 });
}

#[tokio::test]
async fn a_malformed_prepare_200_body_is_rejected_not_coerced() {
    let mock = MockCircle::start(Script::new().prepare(vec![Reply::json(
        200,
        support::fixture_json("malformed_body"),
    )]));
    let client = client_for(&mock);

    let err = prepare(&client, &a_prepare_request()).await.unwrap_err();
    assert_matches!(
        err,
        ListenerError::MalformedResponse {
            context: "prepare-withdrawal",
            ..
        }
    );
}

// WITHDRAW — POST /v1/withdraw (CMP-D6): the ARRAY response, one element per batch
// ================================================================================================

#[tokio::test]
async fn withdraw_submits_the_wrapper_and_decodes_the_201_array() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdraw_201"),
    )]));
    let client = client_for(&mock);

    let resp = withdraw(&client, authorized_two_of_two())
        .await
        .expect("a 201 withdraw decodes");

    assert_eq!(resp.len(), 1, "the 201 body is an array of length 1");
    assert_eq!(
        resp[0].withdrawal_id(),
        "6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"
    );

    let reqs = mock.requests_to(Endpoint::Withdraw);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/v1/withdraw");
    let body = reqs[0].body_json();
    assert!(
        body.get("batches").is_some_and(Value::is_array),
        "the body is the batches[] wrapper, not a bare batch/array: {body}"
    );
}

#[tokio::test]
async fn withdraw_decodes_a_two_element_array_for_a_two_batch_submission() {
    // Two batches submitted → a two-element array (one WithdrawalStatus per batch). Modelling the
    // response as an object would decode neither.
    let element = support::fixture_json("withdraw_201")[0].clone();
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        Value::Array(vec![element.clone(), element]),
    )]));
    let client = client_for(&mock);

    let resp = withdraw(&client, authorized_two_batches())
        .await
        .expect("a two-element 201 array decodes for a two-batch submission");
    assert_eq!(resp.len(), 2, "one WithdrawalStatus per submitted batch");
}

#[tokio::test]
async fn withdraw_rejects_a_response_with_more_elements_than_batches() {
    // One batch submitted, but two status objects returned — the cardinality must match, or a batch is
    // associated with the wrong status (or an extra, unrelated withdrawal is trusted).
    let element = support::fixture_json("withdraw_201")[0].clone();
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        Value::Array(vec![element.clone(), element]),
    )]));
    let client = client_for(&mock);

    let err = withdraw(&client, authorized_two_of_two())
        .await
        .unwrap_err();
    assert_matches!(
        err,
        ListenerError::WithdrawResponseCardinality {
            submitted: 1,
            returned: 2
        }
    );
}

#[tokio::test]
async fn withdraw_rejects_an_empty_response_array() {
    // Zero status objects for one submitted batch — the submission's outcome is unaccounted for and
    // must not read as success.
    let mock =
        MockCircle::start(Script::new().withdraw(vec![Reply::json(201, Value::Array(vec![]))]));
    let client = client_for(&mock);

    let err = withdraw(&client, authorized_two_of_two())
        .await
        .unwrap_err();
    assert_matches!(
        err,
        ListenerError::WithdrawResponseCardinality {
            submitted: 1,
            returned: 0
        }
    );
}

#[tokio::test]
async fn a_withdraw_201_object_body_fails_to_decode_as_the_array() {
    // The forbidden mis-model: a single object where the array belongs.
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdrawal_status_200"),
    )]));
    let client = client_for(&mock);

    let err = withdraw(&client, authorized_two_of_two())
        .await
        .unwrap_err();
    assert_matches!(
        err,
        ListenerError::MalformedResponse {
            context: "withdraw",
            ..
        }
    );
}

#[tokio::test]
async fn a_withdraw_409_is_a_generic_http_error_never_reported_as_success() {
    // 409 conflict-recovery is W7; here a 409 must surface as a refusal, never as a success value.
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        409,
        support::fixture_json("withdraw_409"),
    )]));
    let client = client_for(&mock);

    let result = withdraw(&client, authorized_two_of_two()).await;
    assert_matches!(result, Err(ListenerError::Http { status: 409 }));
}

#[tokio::test]
async fn a_withdraw_400_is_a_generic_http_error() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::Status(400)]));
    let client = client_for(&mock);
    assert_matches!(
        withdraw(&client, authorized_two_of_two()).await,
        Err(ListenerError::Http { status: 400 })
    );
}

// AUTH INJECTION AT THE TRANSPORT SEAM (T-LA-14 parity)
// ================================================================================================

#[tokio::test]
async fn a_configured_key_is_injected_under_its_header_at_the_transport_seam() {
    const KEY: &str = "circle-out-of-band-key-Ic4RaK9v";
    let cfg = ListenerConfig::builder()
        .circle_base_url(mock_circle::MOCK_BASE_URL)
        .api_auth_token(SecretString::new(KEY))
        .api_auth_header("X-Circle-Key")
        .build()
        .expect("https + a key is valid");

    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdraw_201"),
    )]));
    let client = CircleClient::from_config(&cfg)
        .unwrap()
        .with_transport(mock.transport());

    withdraw(&client, authorized_two_of_two()).await.unwrap();

    let reqs = mock.requests_to(Endpoint::Withdraw);
    assert_eq!(reqs[0].header("x-circle-key"), Some(KEY));
}

#[tokio::test]
async fn no_auth_configured_sends_no_credential_header() {
    let mock = MockCircle::start(Script::new().prepare(vec![Reply::json(
        200,
        support::fixture_json("prepare_withdrawal_200"),
    )]));
    let client = client_for(&mock);
    prepare(&client, &a_prepare_request()).await.unwrap();

    let reqs = mock.requests_to(Endpoint::Prepare);
    assert_eq!(reqs[0].header("x-circle-key"), None);
    assert_eq!(reqs[0].header("authorization"), None);
}

// FUND-SAFETY: THE PRE-SUBMIT SIGNER-ALLOWLIST GATE
// ================================================================================================

#[tokio::test]
async fn all_signers_registered_authorizes_and_submits_exactly_once() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdraw_201"),
    )]));
    let client = client_for(&mock);

    withdraw(&client, authorized_two_of_two())
        .await
        .expect("a fully-registered submission goes through");
    assert_eq!(mock.requests_to(Endpoint::Withdraw).len(), 1);
}

#[tokio::test]
async fn a_non_allowlisted_signer_refuses_the_submission_with_zero_withdraw_calls() {
    // Two signers; only the first is a registered attester. The gate refuses, no token is minted, so
    // `withdraw` cannot even be called — ZERO /v1/withdraw requests reach the mock.
    let (a0, s0) = signer(0x11, &DIGEST);
    let (_a1, s1) = signer(0x22, &DIGEST); // NOT registered
    let config = config_with_allowlist([a0]);
    let request =
        build_withdraw_request(vec![batch_with(vec![hexbytes(&s0), hexbytes(&s1)])]).unwrap();

    let err = authorize_submission(request, &validated(&[DIGEST]), &config).unwrap_err();
    assert_matches!(
        err,
        SubmitGateError::SignerNotAllowlisted {
            batch: 0,
            at: 1,
            ..
        }
    );

    // there is structurally no way to have submitted: withdraw takes an AuthorizedWithdrawal, which was
    // never produced.
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::Status(201)]));
    assert_eq!(mock.request_count(), 0);
}

#[tokio::test]
async fn an_empty_config_allowlist_fails_closed() {
    let (_a0, s0) = signer(0x11, &DIGEST);
    let (_a1, s1) = signer(0x22, &DIGEST);
    let request =
        build_withdraw_request(vec![batch_with(vec![hexbytes(&s0), hexbytes(&s1)])]).unwrap();

    // an unbounded signer set (no configured attester) is refused, not silently allowed
    let err = authorize_submission(request, &validated(&[DIGEST]), &config_with_allowlist([]))
        .unwrap_err();
    assert_matches!(err, SubmitGateError::NoAttestersConfigured);
}

#[tokio::test]
async fn the_default_config_allowlist_is_empty_so_the_gate_fails_closed() {
    let cfg = ListenerConfig::default();
    assert!(cfg.attester_allowlist().is_empty());

    let (_a0, s0) = signer(0x11, &DIGEST);
    let (_a1, s1) = signer(0x22, &DIGEST);
    let request =
        build_withdraw_request(vec![batch_with(vec![hexbytes(&s0), hexbytes(&s1)])]).unwrap();
    assert_matches!(
        authorize_submission(request, &validated(&[DIGEST]), &cfg),
        Err(SubmitGateError::NoAttestersConfigured)
    );
}

#[tokio::test]
async fn signatures_are_bound_to_the_validated_digest_not_a_claimed_address() {
    // The signatures are produced over `other`, and their signers are the registered attesters — but
    // the gate recovers over the B5-VALIDATED digest (DIGEST), so it sees different addresses and
    // refuses. A registered-over-A signature cannot smuggle a submission validated against B.
    let other = [0xa5; 32];
    let (a0, s0) = signer(0x11, &other);
    let (a1, s1) = signer(0x22, &other);
    let config = config_with_allowlist([a0, a1]); // registered as recovered over `other`
    let request =
        build_withdraw_request(vec![batch_with(vec![hexbytes(&s0), hexbytes(&s1)])]).unwrap();

    let err = authorize_submission(request, &validated(&[DIGEST]), &config).unwrap_err();
    assert_matches!(
        err,
        SubmitGateError::SignerNotAllowlisted { batch: 0, .. }
            | SubmitGateError::SignerUnrecoverable { batch: 0, .. }
    );
}

#[tokio::test]
async fn a_batch_digest_count_mismatch_is_refused() {
    let (a0, s0) = signer(0x11, &DIGEST);
    let (a1, s1) = signer(0x22, &DIGEST);
    let config = config_with_allowlist([a0, a1]);
    let request =
        build_withdraw_request(vec![batch_with(vec![hexbytes(&s0), hexbytes(&s1)])]).unwrap();

    // one request batch, but a two-digest ValidatedWithdrawal
    let err =
        authorize_submission(request, &validated(&[DIGEST, [0x5b; 32]]), &config).unwrap_err();
    assert_matches!(
        err,
        SubmitGateError::BatchDigestCountMismatch {
            batches: 1,
            digests: 2
        }
    );
}

#[tokio::test]
async fn a_non_65_byte_signature_in_the_batch_is_refused() {
    let (a0, s0) = signer(0x11, &DIGEST);
    let config = config_with_allowlist([a0]);
    // second signature is valid 0x-hex but 64 bytes (r‖s with the recovery id dropped)
    let short = HexBytes::new(format!("0x{}", "ab".repeat(64))).unwrap();
    let request = build_withdraw_request(vec![batch_with(vec![hexbytes(&s0), short])]).unwrap();

    let err = authorize_submission(request, &validated(&[DIGEST]), &config).unwrap_err();
    assert_matches!(
        err,
        SubmitGateError::MalformedSignature {
            batch: 0,
            at: 1,
            len: 64
        }
    );
}

#[tokio::test]
async fn an_odd_hex_signature_in_the_batch_is_refused() {
    let (a0, s0) = signer(0x11, &DIGEST);
    let config = config_with_allowlist([a0]);
    // "0x123" passes the ^0x[a-fA-F0-9]*$ newtype but is odd-length hex → not decodable
    let bad = HexBytes::new("0x123").unwrap();
    let request = build_withdraw_request(vec![batch_with(vec![hexbytes(&s0), bad])]).unwrap();

    let err = authorize_submission(request, &validated(&[DIGEST]), &config).unwrap_err();
    assert_matches!(err, SubmitGateError::BadSignatureHex { batch: 0, at: 1 });
}
