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
//!
//! # Why the `withdraw` cases drive `submit_withdraw`
//!
//! They used to drive a public raw `withdrawal_api::withdraw` — one POST, `201`-or-`Err`, no ledger.
//! That driver is GONE: it was a public path that could POST a withdrawal without a durable
//! idempotency claim (mint two `AuthorizedWithdrawal`s for one burn — `WithdrawRequest` is `Clone` and
//! `authorize_submission` is public — and submit it twice), and no doc comment naming
//! `submit::submit_withdraw` "the production entry point" made that unrepresentable. Deleting it did.
//!
//! Nothing here lost coverage in the move: `submit_withdraw` builds the request through the same
//! `build_post`, decodes through the same `decode_withdraw_created`, and applies the same `201`
//! cardinality rule — so these cases now assert the wire contract on the path production actually
//! takes. (`submit_withdraw`'s own error handling — the `409` recovery, the retry policy, the ledger —
//! is `T-LA-13`: `conflict_recovery` / `submit_idempotency` / `retry_policy`.)

use assert_matches::assert_matches;
use serde_json::Value;

use withdrawal_listener_attester::circle::wire::HexBytes;
use withdrawal_listener_attester::circle::CircleClient;
use withdrawal_listener_attester::config::{ListenerConfig, SecretString};
use withdrawal_listener_attester::error::{ListenerError, SubmitGateError};
use withdrawal_listener_attester::submit::{submit_withdraw, SubmitError, SubmitOutcome};
use withdrawal_listener_attester::withdrawal_api::{
    authorize_submission, build_withdraw_request, prepare,
};

#[path = "submit_support/mod.rs"]
mod submit_support;

use submit_support::mock_circle::{Endpoint, MockCircle, Reply, Script};
use submit_support::*;

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

    assert_matches!(
        prepare(&client, &a_prepare_request()).await,
        Err(ListenerError::MalformedResponse {
            context: "prepare-withdrawal",
            ..
        })
    );
}

// WITHDRAW — POST /v1/withdraw (CMP-D6), through the production submit path
// ================================================================================================

#[tokio::test]
async fn withdraw_submits_the_wrapper_and_decodes_the_201_array() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdraw_201"),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock);

    let outcome = submit_withdraw(&client, &ledger_in(&dir), authorized_two_of_two())
        .await
        .expect("a 201 withdraw decodes");
    let resp = outcome.submitted().expect("a 201 is a submission");

    assert_eq!(resp.len(), 1, "the 201 body is an array of length 1");
    assert_eq!(resp[0].withdrawal_id(), CONFLICT_WITHDRAWAL_ID);

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
    // response as an object would decode neither. Each element echoes ITS OWN burn, as Circle's would.
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        created_body_for_all(&[BURN_TX_ID, OTHER_BURN_TX_ID]),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock);

    let outcome = submit_withdraw(&client, &ledger_in(&dir), authorized_two_batches())
        .await
        .expect("a two-element 201 array decodes for a two-batch submission");
    let resp = outcome.submitted().expect("a 201 is a submission");
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
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock);

    let err = submit_withdraw(&client, &ledger_in(&dir), authorized_two_of_two())
        .await
        .unwrap_err();
    assert_matches!(
        err,
        SubmitError::Circle(ListenerError::WithdrawResponseCardinality {
            submitted: 1,
            returned: 2
        })
    );
}

#[tokio::test]
async fn withdraw_rejects_an_empty_response_array() {
    // Zero status objects for one submitted batch — the submission's outcome is unaccounted for and
    // must not read as success.
    let mock =
        MockCircle::start(Script::new().withdraw(vec![Reply::json(201, Value::Array(vec![]))]));
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock);

    let err = submit_withdraw(&client, &ledger_in(&dir), authorized_two_of_two())
        .await
        .unwrap_err();
    assert_matches!(
        err,
        SubmitError::Circle(ListenerError::WithdrawResponseCardinality {
            submitted: 1,
            returned: 0
        })
    );
}

#[tokio::test]
async fn a_withdraw_201_object_body_fails_to_decode_as_the_array() {
    // The forbidden mis-model: a single object where the array belongs.
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdrawal_status_200"),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock);

    let err = submit_withdraw(&client, &ledger_in(&dir), authorized_two_of_two())
        .await
        .unwrap_err();
    assert_matches!(
        err,
        SubmitError::Circle(ListenerError::MalformedResponse {
            context: "withdraw",
            ..
        })
    );
}

#[tokio::test]
async fn a_withdraw_409_is_never_reported_as_success() {
    // The 409 conflict-recovery contract itself is T-LA-13 (`conflict_recovery.rs`); what this pins at
    // the driver's own boundary is the floor beneath all of it: whatever else a 409 becomes, it is
    // never a submission.
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(
                409,
                support::fixture_json("withdraw_409"),
            )])
            .status(vec![Reply::json(200, status_body("finalized"))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock);

    let outcome = submit_withdraw(&client, &ledger_in(&dir), authorized_two_of_two())
        .await
        .expect("a 409 is handled, not surfaced as a transport failure");

    assert!(!matches!(outcome, SubmitOutcome::Submitted(_)));
    assert!(outcome.submitted().is_none());
    assert_eq!(withdraw_posts(&mock), 1, "and never re-sent");
}

#[tokio::test]
async fn a_withdraw_400_is_a_generic_http_error() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::Status(400)]));
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock);
    assert_matches!(
        submit_withdraw(&client, &ledger_in(&dir), authorized_two_of_two()).await,
        Err(SubmitError::Circle(ListenerError::Http { status: 400 }))
    );
}

// AUTH INJECTION AT THE TRANSPORT SEAM (T-LA-14 parity)
// ================================================================================================

#[tokio::test]
async fn a_configured_key_is_injected_under_its_header_at_the_transport_seam() {
    const KEY: &str = "circle-out-of-band-key-Ic4RaK9v";
    let cfg = ListenerConfig::builder()
        .circle_base_url(submit_support::mock_circle::MOCK_BASE_URL)
        .api_auth_token(SecretString::new(KEY))
        .api_auth_header("X-Circle-Key")
        .build()
        .expect("https + a key is valid");

    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdraw_201"),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let client = CircleClient::from_config(&cfg)
        .unwrap()
        .with_transport(mock.transport());

    submit_withdraw(&client, &ledger_in(&dir), authorized_two_of_two())
        .await
        .unwrap();

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
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock);

    submit_withdraw(&client, &ledger_in(&dir), authorized_two_of_two())
        .await
        .expect("a fully-registered submission goes through");
    assert_eq!(mock.requests_to(Endpoint::Withdraw).len(), 1);
}

#[tokio::test]
async fn a_non_allowlisted_signer_refuses_the_submission_with_zero_withdraw_calls() {
    // Two signers; only the first is a registered attester. The gate refuses, no token is minted, so
    // the submission cannot even be attempted — ZERO /v1/withdraw requests reach the mock.
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

    // there is structurally no way to have submitted: `submit_withdraw` takes an AuthorizedWithdrawal,
    // which was never produced.
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
