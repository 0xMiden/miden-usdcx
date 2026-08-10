//! `tests/circle_status_policy_contract.rs` — the HTTP-status policy (the HTTP-status check, the
//! documented policy): 404 → retry with backoff, logged `Pending`, never dropped (400 → reject, NO
//! retry, alert, and no error body ever parsed) (500 → retry, alert after the threshold; plus 429),
//! the classification table itself, and redirects — which are NOT followed.
//!
//! No live Circle leg (the mock boundary): every Circle endpoint is `REQUIRES CIRCLE CONFIRMATION`
//! and is exercised against the in-process schema-exact mock ([`mock_circle`]) — the relayer builds
//! a real `reqwest::Request` and the mock's axum router answers it, binding no socket. The
//! attestation wire data is the partner test vector from [`fixtures`] — a real secp256k1 signature
//! over the real raw-keccak digest of a canonical DepositIntent payload — so the keccak binding
//! these tests assert is a genuine binding, not a self-consistent invention.

mod fixtures;
mod mock_circle;

use std::time::Duration;

use assert_matches::assert_matches;
use rstest::rstest;

use fixtures::test_vector;
use mock_circle::{
    by_hash_wrapper, client_for, requested_hash, Endpoint, MockCircle, Reply, Script,
    FIXTURE_MIDEN_DOMAIN, HASH_PARAM, TEST_ALERT_AFTER, TEST_BACKOFF_BASE_MS, TEST_MAX_ATTEMPTS,
};

use xreserve_deposit_relayer::circle::{
    classify_status, fetch_attestation_by_message_hash, poll_remote_domain_attestations,
    AuthPosture, BatchQuery, StatusClass,
};
use xreserve_deposit_relayer::error::RelayerError;
use xreserve_deposit_relayer::observability::RelayerEvent;

// HTTP 404: retry with backoff, log Pending, never drop
// ================================================================================================

#[tokio::test]
async fn t_rly_07_404_retries_with_exponential_backoff_then_succeeds() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![
        Reply::Status(404),
        Reply::Status(404),
        Reply::ok(by_hash_wrapper(&vector)),
    ]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let fetched = fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("(4) the eventual 200 produces the validated triple");

    assert_eq!(fetched.deposit_intent().as_bytes(), vector.payload());
    assert_eq!(fetched.attestation().len(), 65);

    // (1) the 404s were retried — three attempts reached the wire
    let requests = mock.requests_to(Endpoint::ByHash);
    assert_eq!(requests.len(), 3, "404, 404, 200 → three attempts");

    // and the retries BACKED OFF exponentially: base, then 2×base (observed on the wire, so a
    // no-op/constant backoff cannot pass).
    let gap_1 = requests[1].at.duration_since(requests[0].at);
    let gap_2 = requests[2].at.duration_since(requests[1].at);
    assert!(
        gap_1 >= Duration::from_millis(TEST_BACKOFF_BASE_MS),
        "first retry waits >= base ({TEST_BACKOFF_BASE_MS}ms), got {gap_1:?}"
    );
    assert!(
        gap_2 >= Duration::from_millis(TEST_BACKOFF_BASE_MS * 2),
        "second retry waits >= 2x base, got {gap_2:?}"
    );

    // (3) the attestation was never dropped: each 404 attempt is logged Pending, with no alert
    // (Circle documents 404 alerts only once the attempts are exhausted).
    assert_eq!(sink.pending().len(), 2, "each 404 is logged Pending");
    assert!(
        sink.alerts().is_empty(),
        "a 404 that resolves within the attempt budget does not alert"
    );
    for event in sink.pending() {
        assert_matches!(event, RelayerEvent::Pending { status, .. } => {
            assert_eq!(status, Some(404));
        });
    }
}

/// A 404 that never resolves exhausts the attempt budget and then SURFACES — it is not retried
/// forever, and it is not silently dropped.
#[tokio::test]
async fn t_rly_07_404_that_never_resolves_exhausts_attempts_and_is_surfaced() {
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::Status(404)]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestation_by_message_hash(&client, HASH_PARAM)
        .await
        .expect_err("the attestation is still not published after the last attempt");

    assert_matches!(err, RelayerError::Http { status: 404 });
    assert_eq!(
        mock.requests_to(Endpoint::ByHash).len(),
        TEST_MAX_ATTEMPTS as usize,
        "exactly max_attempts attempts — no unbounded retry"
    );
    assert_eq!(
        sink.pending().len(),
        (TEST_MAX_ATTEMPTS - 1) as usize,
        "every retried attempt is logged Pending"
    );
    assert_eq!(
        sink.alerts().len(),
        1,
        "exhausting the attempt budget alerts (§8.4: 'no alert UNTIL max attempts')"
    );
}

// HTTP 400: reject, NO retry, alert
// ================================================================================================

#[tokio::test]
async fn t_rly_17_400_is_rejected_without_a_retry_and_alerts() {
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::Status(400)]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestation_by_message_hash(&client, HASH_PARAM)
        .await
        .expect_err("400 is a permanent client error");

    // (1) Err(Http(400)); (2) NO retry; (3) logged + alerted
    assert_matches!(err, RelayerError::Http { status: 400 });
    assert_eq!(
        mock.requests_to(Endpoint::ByHash).len(),
        1,
        "a 400 must NOT be retried"
    );
    assert!(
        sink.pending().is_empty(),
        "a 400 is never Pending — it is terminal"
    );
    assert_eq!(sink.rejections().len(), 1);
    assert_eq!(sink.alerts().len(), 1);
}

/// (5) No error-body schema is parsed — the OpenAPI documents status codes only. A 400 whose body
/// is nonsense (or an unrelated JSON object) still yields `Http { status: 400 }`, never a decode
/// error about the body's shape.
#[tokio::test]
async fn t_rly_17_400_error_body_is_never_parsed() {
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::Body {
        status: 400,
        body: "{\"code\":\"whatever\",\"unexpected\":[1,2,3]}".to_string(),
    }]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    assert_matches!(
        fetch_attestation_by_message_hash(&client, HASH_PARAM)
            .await
            .expect_err("400"),
        RelayerError::Http { status: 400 }
    );
}

/// The 400-no-retry rule is a property of the STATUS, not of one endpoint: it holds on the
/// `?txHash=` and batch endpoints too (400 is documented for all three).
#[tokio::test]
async fn t_rly_17_400_is_not_retried_on_the_batch_endpoint_either() {
    let mock = MockCircle::start(Script::new().batch(vec![Reply::Status(400)]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::forward(10, None).expect("valid query");
    let err = poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
        .await
        .expect_err("400");

    assert_matches!(err, RelayerError::Http { status: 400 });
    assert_eq!(mock.requests_to(Endpoint::Batch).len(), 1);
    assert_eq!(sink.alerts().len(), 1);
}

// HTTP 500: retry with backoff, alert after a threshold. Plus 429
// (throttle).
// ================================================================================================

#[tokio::test]
async fn t_rly_18_500_retries_with_backoff_alerts_after_the_threshold_then_succeeds() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![
        Reply::Status(500),
        Reply::Status(500),
        Reply::ok(by_hash_wrapper(&vector)),
    ]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let fetched = fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("(4) the eventual 200 produces the validated triple");
    assert_eq!(fetched.deposit_intent().as_bytes(), vector.payload());

    // (1) retried with exponential backoff
    let requests = mock.requests_to(Endpoint::ByHash);
    assert_eq!(requests.len(), 3);
    let gap_1 = requests[1].at.duration_since(requests[0].at);
    let gap_2 = requests[2].at.duration_since(requests[1].at);
    assert!(gap_1 >= Duration::from_millis(TEST_BACKOFF_BASE_MS));
    assert!(gap_2 >= Duration::from_millis(TEST_BACKOFF_BASE_MS * 2));

    // (3) not dropped: each failed attempt is Pending
    assert_eq!(sink.pending().len(), 2);
    // (2) and — unlike a 404 — a 500 ALERTS once the failed-attempt threshold is crossed
    assert_eq!(
        sink.alerts().len(),
        1,
        "alert_after_attempts = {TEST_ALERT_AFTER}: the 2nd consecutive 500 crosses the threshold"
    );
}

/// Below the threshold, a 500 that resolves on the first retry does NOT alert (an alert on every
/// transient blip is an alert nobody reads).
#[tokio::test]
async fn t_rly_18_a_single_500_below_the_threshold_does_not_alert() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![
        Reply::Status(500),
        Reply::ok(by_hash_wrapper(&vector)),
    ]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("the retry succeeds");
    assert_eq!(sink.pending().len(), 1);
    assert!(
        sink.alerts().is_empty(),
        "one failed attempt is below alert_after_attempts = {TEST_ALERT_AFTER}"
    );
}

#[tokio::test]
async fn t_rly_18_500_that_never_clears_exhausts_attempts_and_alerts() {
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::Status(500)]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestation_by_message_hash(&client, HASH_PARAM)
        .await
        .expect_err("500 forever");

    assert_matches!(err, RelayerError::Http { status: 500 });
    assert_eq!(
        mock.requests_to(Endpoint::ByHash).len(),
        TEST_MAX_ATTEMPTS as usize
    );
    assert!(!sink.alerts().is_empty());
}

/// 429 (rate-limit / throttle) backs off under the SAME ceilings — it is retryable, like a 500.
#[tokio::test]
async fn t_rly_18_429_backs_off_and_retries() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![
        Reply::Status(429),
        Reply::ok(by_hash_wrapper(&vector)),
    ]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("the throttle clears on the retry");

    let requests = mock.requests_to(Endpoint::ByHash);
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1].at.duration_since(requests[0].at)
            >= Duration::from_millis(TEST_BACKOFF_BASE_MS),
        "a 429 waits at least the base backoff before retrying"
    );
    assert_eq!(sink.pending().len(), 1);
}

/// The HTTP-status policy, stated once and asserted directly (the table the HTTP-status check / the
/// documented policy).
#[rstest]
#[case::ok(200, StatusClass::Success)]
#[case::created(201, StatusClass::Success)]
#[case::bad_request(400, StatusClass::Reject)]
#[case::unauthorized(401, StatusClass::Reject)]
#[case::forbidden(403, StatusClass::Reject)]
#[case::not_found(404, StatusClass::RetryPending)]
#[case::conflict(409, StatusClass::Reject)]
#[case::teapot(418, StatusClass::Reject)]
#[case::too_many_requests(429, StatusClass::RetryThrottle)]
#[case::server_error(500, StatusClass::RetryAlert)]
#[case::bad_gateway(502, StatusClass::RetryAlert)]
#[case::unavailable(503, StatusClass::RetryAlert)]
fn status_policy_classifies_every_documented_code(#[case] status: u16, #[case] class: StatusClass) {
    assert_eq!(classify_status(status), class);
    // and the retry decision follows from the class — never from an ad-hoc per-call-site rule
    assert_eq!(
        RelayerError::Http { status }.is_retryable(),
        matches!(
            class,
            StatusClass::RetryPending | StatusClass::RetryThrottle | StatusClass::RetryAlert
        )
    );
}

// REDIRECTS — never followed
// ================================================================================================
//
// A redirect is the cheapest way to move a credential to an origin that should not have it: the
// client re-issues the request at the `Location` the peer chose, and unless the HTTP stack strips the
// auth header, the key goes with it. reqwest strips only a fixed set of standard names
// (`Authorization`, `Cookie`, `Proxy-Authorization`, `WWW-Authenticate`) on a cross-origin redirect —
// and With no documented auth scheme, the relayer's credential header may be called anything at all
// (`X-Circle-Api-Key`, …), which that list does not cover.
//
// So the relayer does not follow redirects AT ALL. The production transport is built with
// `redirect::Policy::none()`, and a 3xx therefore surfaces as an ordinary status: a permanent
// rejection, alerted, not retried. Circle's documented API redirects nowhere, so nothing legitimate
// is lost — and there is no code path on which a key can be re-sent to a peer-chosen origin.

#[rstest]
#[case::moved_permanently(301)]
#[case::found(302)]
#[case::temporary_redirect(307)]
#[case::permanent_redirect(308)]
#[tokio::test]
async fn a_redirect_is_rejected_and_never_followed(#[case] status: u16) {
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::Redirect {
        status,
        location: "https://not-circle.example/v1/attestations".to_string(),
    }]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestation_by_message_hash(&client, HASH_PARAM)
        .await
        .expect_err("a redirect is not a response the relayer follows");

    assert_matches!(err, RelayerError::Http { status: s } if s == status);
    assert_eq!(
        mock.request_count(),
        1,
        "exactly one request: the redirect was NOT followed to the peer's chosen origin"
    );
    assert!(
        sink.pending().is_empty(),
        "a redirect is terminal, not transient"
    );
    assert_eq!(sink.alerts().len(), 1);
}

#[rstest]
#[case::moved_permanently(301, StatusClass::Reject)]
#[case::found(302, StatusClass::Reject)]
#[case::not_modified(304, StatusClass::Reject)]
#[case::temporary_redirect(307, StatusClass::Reject)]
fn the_status_policy_classifies_every_3xx_as_a_permanent_rejection(
    #[case] status: u16,
    #[case] class: StatusClass,
) {
    assert_eq!(classify_status(status), class);
    assert!(
        !RelayerError::Http { status }.is_retryable(),
        "retrying a redirect would just re-issue the request that got redirected"
    );
}
