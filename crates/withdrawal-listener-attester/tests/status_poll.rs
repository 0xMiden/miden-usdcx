//! `T-LA-12` — `GET /v1/withdrawal/{withdrawalId}` (`CMP-D7`): the status poll across the FULL status
//! enum, the poll-to-terminal loop, the `404` variant, and the hard refusal of an unknown status.
//!
//! Non-vacuity: each enum value round-trips through the real driver; the loop is proven to STOP at a
//! terminal status (an exact request count, not "eventually"); an unknown status is proven to become an
//! EXACT error, never a default; and the `404` is its own variant, not a generic HTTP refusal.

use std::time::Duration;

use assert_matches::assert_matches;
use serde_json::Value;

use withdrawal_listener_attester::circle::auth::AuthPosture;
use withdrawal_listener_attester::circle::client::PollPolicy;
use withdrawal_listener_attester::circle::schema::WithdrawalStatusKind;
use withdrawal_listener_attester::circle::wire::{SchemaError, Uuid};
use withdrawal_listener_attester::circle::CircleClient;
use withdrawal_listener_attester::error::ListenerError;
use withdrawal_listener_attester::withdrawal_api::{poll_status, poll_status_once};

#[path = "mock_circle/mod.rs"]
mod mock_circle;
#[path = "support/mod.rs"]
mod support;

use mock_circle::{Endpoint, MockCircle, Reply, Script};

const WITHDRAWAL_ID: &str = "6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8";
/// A second, DIFFERENT valid withdrawal id — for the response-binding (mismatch) test.
const OTHER_ID: &str = "11112222-3333-4444-5555-666677778888";

/// The validated withdrawal-id newtype the poll drivers require — a raw string cannot reach them.
fn wid() -> Uuid {
    Uuid::new(WITHDRAWAL_ID).expect("a valid uuid")
}

/// A withdrawal-status body carrying `status`, built by MUTATING the valid 200 fixture — so a
/// scripted body differs from the canonical one in exactly the status field.
fn status_body(status: &str) -> Value {
    let mut body = support::fixture_json("withdrawal_status_200");
    body["status"] = Value::String(status.to_string());
    body
}

/// A client whose poll loop does not actually sleep (interval 0), bounded generously.
fn fast_poll_client(mock: &MockCircle) -> CircleClient {
    CircleClient::new(mock.base_url(), AuthPosture::None)
        .expect("client builds")
        .with_transport(mock.transport())
        .with_poll_policy(PollPolicy::new(Duration::ZERO, 50))
}

// EACH ENUM VALUE ROUND-TRIPS
// ================================================================================================

#[tokio::test]
async fn every_status_enum_value_round_trips_through_a_single_poll() {
    let cases = [
        ("created", WithdrawalStatusKind::Created),
        ("verified", WithdrawalStatusKind::Verified),
        ("confirmed", WithdrawalStatusKind::Confirmed),
        ("finalized", WithdrawalStatusKind::Finalized),
        ("expired", WithdrawalStatusKind::Expired),
        ("failed", WithdrawalStatusKind::Failed),
    ];

    for (wire, kind) in cases {
        let mock =
            MockCircle::start(Script::new().status(vec![Reply::json(200, status_body(wire))]));
        let client = fast_poll_client(&mock);

        let status = poll_status_once(&client, &wid())
            .await
            .unwrap_or_else(|e| panic!("`{wire}` should decode: {e}"));
        assert_eq!(status.status(), kind, "`{wire}` round-trips to its kind");
    }
}

#[tokio::test]
async fn the_poll_object_matches_the_withdraw_response_shape() {
    let mock = MockCircle::start(Script::new().status(vec![Reply::json(
        200,
        support::fixture_json("withdrawal_status_200"),
    )]));
    let client = fast_poll_client(&mock);

    let status = poll_status_once(&client, &wid()).await.unwrap();
    assert_eq!(status.withdrawal_id(), WITHDRAWAL_ID);
    assert!(status.burn_tx_id().starts_with("0x"));
    assert_eq!(status.transfer_spec_hashes().len(), 1);
    assert!(!status.use_circle_forwarding());
}

// THE GET SHAPE — id in the path, no body
// ================================================================================================

#[tokio::test]
async fn the_get_carries_the_withdrawal_id_in_the_path_and_no_body() {
    let mock =
        MockCircle::start(Script::new().status(vec![Reply::json(200, status_body("finalized"))]));
    let client = fast_poll_client(&mock);

    poll_status_once(&client, &wid()).await.unwrap();

    let reqs = mock.requests_to(Endpoint::Status);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, format!("/v1/withdrawal/{WITHDRAWAL_ID}"));
    assert!(reqs[0].body.is_empty(), "a GET carries no body");
}

// POLL-TO-TERMINAL — the loop stops at a terminal status
// ================================================================================================

#[tokio::test]
async fn poll_continues_until_finalized_and_stops_there() {
    let mock = MockCircle::start(Script::new().status(vec![
        Reply::json(200, status_body("created")),
        Reply::json(200, status_body("verified")),
        Reply::json(200, status_body("confirmed")),
        Reply::json(200, status_body("finalized")),
    ]));
    let client = fast_poll_client(&mock);

    let terminal = poll_status(&client, &wid()).await.unwrap();
    assert_eq!(terminal.status(), WithdrawalStatusKind::Finalized);
    // exactly four polls: it stopped at the terminal status, no fifth GET
    assert_eq!(mock.requests_to(Endpoint::Status).len(), 4);
}

#[tokio::test]
async fn poll_stops_at_failed_and_surfaces_the_failure_reason() {
    let mut failed = status_body("failed");
    failed["failureReason"] = Value::String("verification_failed".to_string());
    let mock = MockCircle::start(Script::new().status(vec![
        Reply::json(200, status_body("created")),
        Reply::json(200, failed),
    ]));
    let client = fast_poll_client(&mock);

    let terminal = poll_status(&client, &wid()).await.unwrap();
    assert_eq!(terminal.status(), WithdrawalStatusKind::Failed);
    assert_eq!(terminal.failure_reason(), Some("verification_failed"));
    assert_eq!(mock.requests_to(Endpoint::Status).len(), 2);
}

#[tokio::test]
async fn poll_returns_expired_as_a_retryable_resubmit_outcome_not_a_terminal_success() {
    // §10.10 / T-LA-12: `expired` is RETRYABLE (resubmit a NEW withdrawal), NOT a finalized success
    // and NOT a non-retryable failure. Reading it the wrong way round would strand a recoverable
    // withdrawal or replay a refused one. The poll stops on it (further polling of this id cannot
    // progress), but the outcome must carry the resubmit signal — never be conflated with `finalized`.
    assert!(
        !WithdrawalStatusKind::Expired.is_terminal(),
        "expired is NOT terminal — only finalized/failed are (round-1 forbidden-impl, harness:191-195)"
    );
    assert!(
        WithdrawalStatusKind::Expired.is_retryable(),
        "expired ⇒ the caller must resubmit"
    );
    assert!(
        WithdrawalStatusKind::Finalized.is_terminal(),
        "finalized IS terminal"
    );
    assert!(
        WithdrawalStatusKind::Failed.is_terminal(),
        "failed IS terminal"
    );
    assert!(
        !WithdrawalStatusKind::Failed.is_retryable(),
        "failed is terminal and NEVER retried"
    );
    assert_ne!(
        WithdrawalStatusKind::Expired,
        WithdrawalStatusKind::Finalized,
        "expired is not the finalized success outcome"
    );

    let mock = MockCircle::start(Script::new().status(vec![
        Reply::json(200, status_body("created")),
        Reply::json(200, status_body("expired")),
    ]));
    let client = fast_poll_client(&mock);

    let result = poll_status(&client, &wid()).await.unwrap();
    assert_eq!(result.status(), WithdrawalStatusKind::Expired);
    assert!(
        result.status().is_retryable(),
        "the caller resubmits — expired is not treated as a completed withdrawal"
    );
    assert_ne!(
        result.status(),
        WithdrawalStatusKind::Finalized,
        "an expired poll result must never read as a finalized success"
    );
    assert_eq!(
        mock.requests_to(Endpoint::Status).len(),
        2,
        "polled created then expired, then stopped"
    );
}

// UNKNOWN STATUS — a hard error, never a default
// ================================================================================================

#[tokio::test]
async fn an_unknown_status_string_is_a_hard_error_not_a_default() {
    let mock =
        MockCircle::start(Script::new().status(vec![Reply::json(200, status_body("frozen"))]));
    let client = fast_poll_client(&mock);

    let err = poll_status_once(&client, &wid()).await.unwrap_err();
    assert_matches!(
        err,
        ListenerError::MalformedResponse {
            context: "withdrawal-status",
            ..
        }
    );
}

#[tokio::test]
async fn the_poll_loop_does_not_swallow_an_unknown_status_as_non_terminal() {
    // a defaulted/ignored unknown status would loop forever or return a wrong kind; it must surface as
    // an error on the first poll instead
    let mock =
        MockCircle::start(Script::new().status(vec![Reply::json(200, status_body("frozen"))]));
    let client = fast_poll_client(&mock);

    let err = poll_status(&client, &wid()).await.unwrap_err();
    assert_matches!(err, ListenerError::MalformedResponse { .. });
    assert_eq!(
        mock.requests_to(Endpoint::Status).len(),
        1,
        "it did not loop on the bad body"
    );
}

// 404 — its own variant
// ================================================================================================

#[tokio::test]
async fn a_404_is_its_own_not_found_variant_not_a_generic_http_error() {
    let mock = MockCircle::start(Script::new().status(vec![Reply::json(
        404,
        support::fixture_json("withdrawal_status_404"),
    )]));
    let client = fast_poll_client(&mock);

    let err = poll_status_once(&client, &wid()).await.unwrap_err();
    assert_matches!(
        err,
        ListenerError::WithdrawalNotFound { ref withdrawal_id } if withdrawal_id == WITHDRAWAL_ID
    );
}

#[tokio::test]
async fn the_poll_loop_surfaces_a_404_rather_than_looping() {
    let mock = MockCircle::start(Script::new().status(vec![Reply::Status(404)]));
    let client = fast_poll_client(&mock);

    let err = poll_status(&client, &wid()).await.unwrap_err();
    assert_matches!(err, ListenerError::WithdrawalNotFound { .. });
    assert_eq!(mock.requests_to(Endpoint::Status).len(), 1);
}

// A non-404 non-2xx is a generic HTTP error
// ================================================================================================

#[tokio::test]
async fn a_500_on_a_poll_is_a_generic_http_error() {
    let mock = MockCircle::start(Script::new().status(vec![Reply::Status(500)]));
    let client = fast_poll_client(&mock);
    assert_matches!(
        poll_status_once(&client, &wid()).await,
        Err(ListenerError::Http { status: 500 })
    );
}

// THE ATTEMPT BOUND
// ================================================================================================

#[tokio::test]
async fn the_poll_loop_is_bounded_and_exhausts_on_a_never_terminal_status() {
    // a status that never reaches terminal (the last reply repeats forever) must not loop forever
    let mock =
        MockCircle::start(Script::new().status(vec![Reply::json(200, status_body("created"))]));
    let client = CircleClient::new(mock.base_url(), AuthPosture::None)
        .unwrap()
        .with_transport(mock.transport())
        .with_poll_policy(PollPolicy::new(Duration::ZERO, 3));

    let err = poll_status(&client, &wid()).await.unwrap_err();
    assert_matches!(err, ListenerError::PollExhausted { after: 3 });
    assert_eq!(
        mock.requests_to(Endpoint::Status).len(),
        3,
        "exactly the attempt ceiling"
    );
}

// REPLAY / IDEMPOTENCY
// ================================================================================================

#[tokio::test]
async fn polling_the_same_id_repeatedly_returns_the_current_status() {
    let mock =
        MockCircle::start(Script::new().status(vec![Reply::json(200, status_body("confirmed"))]));
    let client = fast_poll_client(&mock);

    let a = poll_status_once(&client, &wid()).await.unwrap();
    let b = poll_status_once(&client, &wid()).await.unwrap();
    assert_eq!(a.status(), WithdrawalStatusKind::Confirmed);
    assert_eq!(b.status(), WithdrawalStatusKind::Confirmed);
}

// RESPONSE IS BOUND TO THE REQUESTED ID
// ================================================================================================

#[tokio::test]
async fn a_status_for_a_different_withdrawal_id_is_refused_not_reported_as_this_ones() {
    // A schema-valid 200 whose `withdrawalId` is a DIFFERENT withdrawal — its finalized/failed state
    // must never be attributed to the requested id.
    let mut body = status_body("finalized");
    body["withdrawalId"] = Value::String(OTHER_ID.to_string());
    let mock = MockCircle::start(Script::new().status(vec![Reply::json(200, body)]));
    let client = fast_poll_client(&mock);

    let err = poll_status_once(&client, &wid()).await.unwrap_err();
    assert_matches!(
        err,
        ListenerError::WithdrawalIdMismatch { ref requested, ref returned }
            if requested == WITHDRAWAL_ID && returned == OTHER_ID
    );
}

#[tokio::test]
async fn the_poll_loop_surfaces_an_id_mismatch_rather_than_looping() {
    let mut body = status_body("created");
    body["withdrawalId"] = Value::String(OTHER_ID.to_string());
    let mock = MockCircle::start(Script::new().status(vec![Reply::json(200, body)]));
    let client = fast_poll_client(&mock);

    let err = poll_status(&client, &wid()).await.unwrap_err();
    assert_matches!(err, ListenerError::WithdrawalIdMismatch { .. });
    assert_eq!(
        mock.requests_to(Endpoint::Status).len(),
        1,
        "a mismatched response is a hard error, not a retry"
    );
}

// PATH-INJECTION DEFENSE — the id type admits no route-altering characters
// ================================================================================================

#[test]
fn the_withdrawal_id_type_rejects_route_altering_strings() {
    // poll_status_once takes a validated `Uuid`, so a caller cannot pass a dot-segment / query /
    // fragment that would alter the requested route — such strings are rejected at construction.
    for injection in [
        "../../v1/withdraw",
        "6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8/../info",
        "6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8?force=1",
        "6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8#x",
        "not-a-uuid",
        "",
    ] {
        assert_matches!(
            Uuid::new(injection),
            Err(SchemaError::BadUuid(_)),
            "`{injection}` must be rejected as a withdrawal id"
        );
    }

    // …and the canonical id is accepted.
    assert!(Uuid::new(WITHDRAWAL_ID).is_ok());
}
