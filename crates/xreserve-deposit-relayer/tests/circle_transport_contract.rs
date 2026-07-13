//! `tests/circle_transport_contract.rs` — the transport and the policies that bound it: the RATE
//! governor (5 QPS/IP, 35 QPS global — CIR-API-4), the exponential backoff, the request DEADLINE,
//! the response-SIZE ceiling, and the config wiring that supplies all three.
//!
//! The deadline and the size ceiling are availability properties: without them a single peer that
//! accepts a request and never answers — or answers with an endless body — stalls or exhausts the
//! relayer, and no alert is ever raised, because from the relayer's point of view nothing has gone
//! wrong yet.
//!
//! No live Circle leg (§11): every Circle endpoint is `REQUIRES CIRCLE CONFIRMATION` and is
//! exercised against the in-process schema-exact mock ([`mock_circle`]) — the relayer builds a real
//! `reqwest::Request` and the mock's axum router answers it, binding no socket. The attestation wire
//! data is the partner test vector from [`fixtures`] — a real secp256k1 signature over the real
//! raw-keccak digest of a canonical DC-1 DepositIntent payload — so the keccak binding these tests
//! assert is a genuine binding, not a self-consistent invention.

mod fixtures;
mod mock_circle;

use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};

use assert_matches::assert_matches;
use rstest::rstest;
use serde_json::json;

use fixtures::test_vector;
use mock_circle::transports::{AlwaysFailingTransport, HangingTransport};
use mock_circle::{
    by_hash_wrapper, client_with_limits, requested_hash, MockCircle, RecordingSink, Reply, Script,
};

use xreserve_deposit_relayer::circle::{
    fetch_attestation_by_message_hash, fetch_info, with_backoff, AuthPosture, BodyLimit,
    CircleClient, RateGovernor, ReqwestTransport, RetryContext, RetryPolicy, TransportLimits,
};
use xreserve_deposit_relayer::config::RelayerConfig;
use xreserve_deposit_relayer::error::RelayerError;
use xreserve_deposit_relayer::observability::{EventSink, NoopSink, RelayerEvent};

// RATE GOVERNOR — 5 QPS/IP, 35 QPS global (CIR-API-4), and the backoff that runs under it
// ================================================================================================

/// The per-IP ceiling is a real ceiling: with 5 QPS/IP, no 1-second window may ever contain more
/// than 5 acquisitions, and the 6th acquisition must WAIT for the window to roll.
#[tokio::test]
async fn rate_governor_enforces_the_5_qps_per_ip_ceiling() {
    let governor = RateGovernor::new(5, 35).expect("the documented ceilings");
    let started = Instant::now();
    let mut stamps = Vec::new();
    for _ in 0..8 {
        // the instant the GOVERNOR recorded — the same sample it put in its window. Timestamping
        // with a second `Instant::now()` after `acquire` returns would be a different clock sample
        // than the one the ceiling is enforced against, and near a window boundary the two disagree:
        // the governor can legitimately expire its own earlier stamp while the test still counts the
        // later external one, reporting 6-in-5 for a governor that never admitted 6.
        stamps.push(governor.acquire("xreserve-api-testnet.circle.com").await);
    }
    let elapsed = started.elapsed();

    assert_max_in_any_window(&stamps, 5);
    assert!(
        elapsed >= Duration::from_millis(950),
        "the 6th of 8 requests must wait ~1s for the window to roll, took {elapsed:?}"
    );
}

/// The global ceiling binds across DIFFERENT hosts (it is a per-process budget, not a per-host one).
#[tokio::test]
async fn rate_governor_enforces_the_35_qps_global_ceiling_across_hosts() {
    // per-IP set high so ONLY the global ceiling can bind
    let governor = RateGovernor::new(1000, 35).expect("valid");
    let started = Instant::now();
    let mut stamps = Vec::new();
    for i in 0..40 {
        let host = if i % 2 == 0 { "host-a" } else { "host-b" };
        stamps.push(governor.acquire(host).await);
    }
    let elapsed = started.elapsed();

    assert_max_in_any_window(&stamps, 35);
    assert!(
        elapsed >= Duration::from_millis(950),
        "the 36th of 40 requests must wait for the global window to roll, took {elapsed:?}"
    );
}

/// The per-IP window is keyed BY HOST: two requests to two different hosts do not contend, while
/// two to the same host do. (A single shared window would make the ceiling 5 QPS in total — wrong.)
#[tokio::test]
async fn rate_governor_keys_the_per_ip_window_by_host() {
    let governor = RateGovernor::new(1, 1000).expect("valid");

    let started = Instant::now();
    let _ = governor.acquire("host-a").await;
    let _ = governor.acquire("host-b").await;
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "different hosts must not contend for the same per-IP window"
    );

    let started = Instant::now();
    let _ = governor.acquire("host-a").await;
    assert!(
        started.elapsed() >= Duration::from_millis(950),
        "the same host, at 1 QPS, must wait a full window"
    );
}

#[rstest]
#[case::zero_per_ip(0, 35)]
#[case::zero_global(5, 0)]
#[case::both_zero(0, 0)]
fn rate_governor_rejects_a_zero_ceiling(#[case] per_ip: u32, #[case] global: u32) {
    // a 0-QPS window would block forever — refuse it at construction rather than deadlock at runtime
    assert_matches!(
        RateGovernor::new(per_ip, global).expect_err("0 QPS is not a rate"),
        RelayerError::BadRateLimit { .. }
    );
}

/// Asserts the sliding-window invariant directly, on the instants the GOVERNOR recorded: for every
/// acquisition, at most `limit` acquisitions fall inside the 1-second window that starts at it. This
/// is an exact oracle — the governor admits a stamp only when fewer than `limit` of its own stamps
/// lie within the preceding second — so it is deterministic, not a timing race.
fn assert_max_in_any_window(stamps: &[Instant], limit: usize) {
    for (i, start) in stamps.iter().enumerate() {
        let window = Duration::from_millis(1000);
        let count = stamps[i..]
            .iter()
            .take_while(|t| t.duration_since(*start) < window)
            .count();
        assert!(
            count <= limit,
            "{count} acquisitions inside a 1s window (ceiling {limit})"
        );
    }
}

/// `with_backoff` retries a retryable failure, waits base·2^(n-1) between attempts, and stops at
/// `max_attempts` — returning the LAST error rather than looping forever.
#[tokio::test]
async fn with_backoff_retries_exponentially_and_stops_at_max_attempts() {
    let governor = RateGovernor::new(500, 500).expect("permissive");
    let policy = RetryPolicy::new(4, 40, 3).expect("valid");
    let sink = RecordingSink::new();
    let context = RetryContext::new(&governor, "host-a", &policy, sink.as_ref(), "test-endpoint");

    let attempts = std::sync::atomic::AtomicU32::new(0);
    let started = Instant::now();
    let result: Result<(), RelayerError> = with_backoff(&context, || {
        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async { Err(RelayerError::Http { status: 500 }) }
    })
    .await;
    let elapsed = started.elapsed();

    assert_matches!(
        result.expect_err("500 forever"),
        RelayerError::Http { status: 500 }
    );
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        4,
        "exactly max_attempts attempts"
    );
    // waits between the 4 attempts: 40 + 80 + 160 = 280ms
    assert!(
        elapsed >= Duration::from_millis(280),
        "exponential backoff between attempts, got {elapsed:?}"
    );
    assert_eq!(
        sink.pending().len(),
        3,
        "each retried failure is logged Pending"
    );
}

/// A permanent error is NOT retried — `with_backoff` returns it after a single attempt.
#[tokio::test]
async fn with_backoff_does_not_retry_a_permanent_error() {
    let governor = RateGovernor::new(500, 500).expect("permissive");
    let policy = RetryPolicy::new(5, 40, 3).expect("valid");
    let sink = RecordingSink::new();
    let context = RetryContext::new(&governor, "host-a", &policy, sink.as_ref(), "test-endpoint");

    let attempts = std::sync::atomic::AtomicU32::new(0);
    let result: Result<(), RelayerError> = with_backoff(&context, || {
        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async { Err(RelayerError::Http { status: 400 }) }
    })
    .await;

    assert_matches!(result.expect_err("400"), RelayerError::Http { status: 400 });
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a permanent error is never retried"
    );
    assert!(sink.pending().is_empty());
    assert_eq!(sink.alerts().len(), 1, "a permanent failure alerts");
}

#[rstest]
#[case::zero_attempts(0, 100, 1)]
#[case::zero_alert_threshold(3, 100, 0)]
fn retry_policy_rejects_an_impossible_configuration(
    #[case] max_attempts: u32,
    #[case] base_delay_ms: u64,
    #[case] alert_after: u32,
) {
    assert_matches!(
        RetryPolicy::new(max_attempts, base_delay_ms, alert_after)
            .expect_err("an impossible policy"),
        RelayerError::BadRetryPolicy { .. }
    );
}

/// The client wires the DOCUMENTED ceilings out of config: 5 QPS/IP, 35 QPS global, no credential,
/// and the testnet base URL — none of them hardcoded at the call sites.
#[test]
fn client_from_config_wires_the_documented_rate_ceilings_and_no_auth() {
    let config = RelayerConfig::default();
    let client = CircleClient::from_config(&config).expect("the default config builds a client");

    assert_eq!(client.governor().qps_per_ip(), 5, "CIR-API-4: 5 QPS/IP");
    assert_eq!(
        client.governor().qps_global(),
        35,
        "CIR-API-4: 35 QPS global"
    );
    assert_eq!(client.auth(), &AuthPosture::None, "Q-API-AUTH stays OPEN");
    assert_eq!(client.base_url(), config.circle_base_url());
    assert_eq!(
        client.retry_policy().max_attempts(),
        config.max_retry_attempts()
    );
    assert_eq!(
        client.retry_policy().base_delay_ms(),
        config.backoff_base_ms()
    );
}

/// A base URL that is not a URL is refused at construction (not at the first request, deep inside a
/// retry loop).
#[test]
fn client_rejects_a_malformed_base_url() {
    assert_matches!(
        CircleClient::new("not a url", AuthPosture::None).expect_err("malformed base url"),
        RelayerError::BadBaseUrl { .. }
    );
}

/// A transport failure — the request never produced a status — is RETRYABLE and surfaces as
/// `Transport`, never as a bogus HTTP status. Driven through a transport that always fails, so the
/// backoff/Pending path around a dead network is exercised without dialing anything.
#[tokio::test]
async fn a_transport_failure_is_retried_and_surfaces_as_transport() {
    let sink = RecordingSink::new();
    let client = CircleClient::new("http://circle.mock", AuthPosture::None)
        .expect("valid url")
        .with_transport(Arc::new(AlwaysFailingTransport))
        .with_retry_policy(RetryPolicy::new(2, 20, 5).expect("valid"))
        .with_event_sink(
            Arc::clone(&sink) as Arc<dyn xreserve_deposit_relayer::observability::EventSink>
        );

    let err = fetch_info(&client)
        .await
        .expect_err("the transport never reaches Circle");

    assert_matches!(err, RelayerError::Transport(_));
    assert!(err.is_retryable(), "a transport failure is transient");
    assert_eq!(
        sink.pending().len(),
        1,
        "the failed attempt was logged Pending and retried once (max_attempts = 2)"
    );
    assert_eq!(
        sink.alerts().len(),
        1,
        "exhausting the attempts on a dead transport alerts"
    );
}

/// The PRODUCTION transport — the one that actually speaks HTTP — maps a request that never produced
/// a status onto `RelayerError::Transport`, preserving the originating `reqwest::Error` as its
/// source. This is the seam the in-process mock deliberately does not cover, so it is pinned here.
///
/// It dials `127.0.0.1:1` (privileged, nothing listens) with a short timeout: whether the sandbox
/// refuses the connection, denies it, or blackholes it, the request cannot produce an HTTP status —
/// which is exactly the condition under test. It binds no socket, so it runs in the sandbox too.
#[tokio::test]
async fn reqwest_transport_maps_a_failed_request_to_transport() {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("http client builds");
    let client = CircleClient::new("http://127.0.0.1:1", AuthPosture::None)
        .expect("valid url")
        .with_transport(Arc::new(ReqwestTransport::new(http)))
        .with_retry_policy(RetryPolicy::new(1, 10, 1).expect("valid"));

    let err = fetch_info(&client)
        .await
        .expect_err("no HTTP status can come back from a port nothing listens on");

    assert_matches!(err, RelayerError::Transport(_));
    assert!(
        err.source().is_some(),
        "the originating reqwest error is preserved as the cause"
    );
    assert!(err.is_retryable());
}

/// `NoopSink` is the default: a client built without an explicit sink still works (and drops no
/// event on the floor — it simply has no sink wired yet).
#[tokio::test]
async fn the_default_event_sink_is_the_noop_sink() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(by_hash_wrapper(&vector))]));
    let client = CircleClient::new(mock.base_url(), AuthPosture::None)
        .expect("client")
        .with_transport(mock.transport())
        .with_event_sink(Arc::new(NoopSink));

    fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("fetch succeeds with the noop sink");
}

// REQUEST DEADLINE — a peer that never answers must not stall the relayer forever
// ================================================================================================

/// The slowloris shape: the peer accepts the request and simply never responds. Without a deadline
/// the relayer awaits it forever — `max_attempts` is never reached, the attestation is never
/// submitted, and NO alert is ever raised, because from the relayer's point of view nothing has gone
/// wrong yet. One unresponsive peer would take the service down silently.
///
/// With a deadline the hung attempt becomes an ordinary transient failure: bounded, logged
/// `Pending`, retried, and finally surfaced with an alert.
#[tokio::test]
async fn a_hung_request_hits_the_deadline_on_every_attempt_and_is_surfaced() {
    let transport = Arc::new(HangingTransport::default());
    let sink = RecordingSink::new();
    let limits = TransportLimits::new(
        Duration::from_millis(50),
        Duration::from_millis(120),
        1024 * 1024,
    )
    .expect("valid limits");

    let client = CircleClient::new("https://circle.mock", AuthPosture::None)
        .expect("client")
        .with_transport(
            Arc::clone(&transport) as Arc<dyn xreserve_deposit_relayer::circle::HttpTransport>
        )
        .with_transport_limits(limits)
        .with_retry_policy(RetryPolicy::new(3, 10, 2).expect("valid"))
        .with_event_sink(Arc::clone(&sink) as Arc<dyn EventSink>);

    let started = Instant::now();
    // The whole call is wrapped in a test-side deadline of its own, so that a relayer WITHOUT a
    // request deadline FAILS here rather than hanging: an unbounded wait is the bug under test, and a
    // hung test reports it as a stalled suite instead of a red assertion.
    let err = tokio::time::timeout(Duration::from_secs(5), fetch_info(&client))
        .await
        .expect("the relayer must bound its own wait — it hung instead")
        .expect_err("the peer never answers — the relayer must give up, not wait");
    let elapsed = started.elapsed();

    assert_matches!(err, RelayerError::RequestTimeout { .. });
    assert!(err.is_retryable(), "a deadline is a transient condition");
    assert_eq!(
        transport.attempts(),
        3,
        "the deadline fired on EVERY attempt — not once, with the rest inheriting a dead future"
    );
    assert_eq!(
        sink.pending().len(),
        2,
        "each timed-out attempt is logged Pending"
    );
    // a deadline is an alerting failure (unlike a 404), so the operator hears twice: once when the
    // 2nd consecutive failure crosses `alert_after_attempts`, and once when the budget runs out
    let alerts = sink.alerts();
    assert_eq!(alerts.len(), 2, "threshold alert, then give-up alert");
    assert!(
        alerts.iter().any(|event| matches!(
            event,
            RelayerEvent::Alert { reason, .. } if reason.contains("consecutive failed attempts")
        )),
        "the threshold alert names the streak: {alerts:?}"
    );
    assert!(
        alerts.iter().any(|event| matches!(
            event,
            RelayerEvent::Alert { reason, .. } if reason.contains("giving up")
        )),
        "the final alert says the relayer gave up: {alerts:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the whole call is bounded by the deadlines, took {elapsed:?}"
    );
}

// RESPONSE-SIZE CEILING — an endless body must not exhaust memory
// ================================================================================================

/// A peer can answer with an arbitrarily large body. Buffering it whole, unbounded, hands any peer
/// (or anything on the path) a memory-exhaustion lever. The ceiling makes an oversized response a
/// typed rejection instead of an allocation.
#[tokio::test]
async fn an_oversized_response_body_is_rejected_not_buffered() {
    let vector = test_vector();
    // a legitimate body, but far past the (deliberately tiny) ceiling this client is given
    let mut body = by_hash_wrapper(&vector);
    body["padding"] = json!("x".repeat(4096));

    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(body)]));
    let limits = TransportLimits::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        512, // bytes
    )
    .expect("valid limits");
    let (client, sink) = client_with_limits(&mock, limits);

    let err = fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect_err("the body exceeds the configured ceiling");

    assert_matches!(err, RelayerError::ResponseTooLarge { limit: 512, actual } => {
        assert!(actual > 512, "the observed size is reported: {actual}");
    });
    assert!(
        !err.is_retryable(),
        "re-requesting an oversized body just downloads it again"
    );
    assert_eq!(sink.rejections().len(), 1);
    assert_eq!(sink.alerts().len(), 1);
}

/// A body at or under the ceiling is served normally — the ceiling rejects the oversized, not the
/// merely large.
#[tokio::test]
async fn a_response_within_the_size_ceiling_is_accepted() {
    let vector = test_vector();
    let body = by_hash_wrapper(&vector);
    let exact = serde_json::to_vec(&body).expect("serializes").len();

    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(body)]));
    let limits = TransportLimits::new(Duration::from_secs(5), Duration::from_secs(5), exact)
        .expect("valid limits");
    let (client, sink) = client_with_limits(&mock, limits);

    fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("a body of exactly the ceiling's size is within the ceiling");
    assert!(sink.rejections().is_empty());
}

/// [`BodyLimit`] is what stops the production transport from ever BUFFERING an oversized body: it
/// rejects on the advertised `Content-Length` before a single byte is read, and it re-checks every
/// chunk as the body streams in (a lying or absent `Content-Length` must not get past it).
#[test]
fn body_limit_rejects_before_and_during_the_read() {
    // pre-check: an advertised length over the ceiling is refused before reading anything
    let limit = BodyLimit::new(100);
    assert_matches!(
        limit
            .check_content_length(Some(101))
            .expect_err("advertised over the ceiling"),
        RelayerError::ResponseTooLarge {
            limit: 100,
            actual: 101
        }
    );
    assert!(BodyLimit::new(100).check_content_length(Some(100)).is_ok());
    assert!(
        BodyLimit::new(100).check_content_length(None).is_ok(),
        "an absent Content-Length is not a rejection — it is why the streaming check exists"
    );

    // streaming: the ceiling holds even when Content-Length lied (or was absent)
    let mut limit = BodyLimit::new(100);
    assert!(limit.push(60).is_ok());
    assert!(limit.push(40).is_ok(), "exactly at the ceiling is allowed");
    assert_matches!(
        limit.push(1).expect_err("one byte past the ceiling"),
        RelayerError::ResponseTooLarge {
            limit: 100,
            actual: 101
        }
    );
}

#[rstest]
#[case::zero_connect_timeout(0, 1000, 1024)]
#[case::zero_request_timeout(1000, 0, 1024)]
#[case::zero_body_ceiling(1000, 1000, 0)]
fn transport_limits_reject_an_impossible_configuration(
    #[case] connect_ms: u64,
    #[case] request_ms: u64,
    #[case] max_bytes: usize,
) {
    // a zero deadline can never be met and a zero body ceiling rejects every response: refuse them
    // at construction rather than deadlock/reject-everything at runtime
    assert_matches!(
        TransportLimits::new(
            Duration::from_millis(connect_ms),
            Duration::from_millis(request_ms),
            max_bytes
        )
        .expect_err("an impossible limit"),
        RelayerError::BadTransportLimits { .. }
    );
}

/// The limits are CONFIGURATION, not constants buried in the transport — an operator can tighten
/// them, and the defaults are sane rather than absent.
#[test]
fn client_from_config_wires_the_transport_limits() {
    let config = RelayerConfig::default();
    let client = CircleClient::from_config(&config).expect("client builds");

    assert_eq!(
        client.transport_limits().request_timeout(),
        Duration::from_millis(config.request_timeout_ms())
    );
    assert_eq!(
        client.transport_limits().connect_timeout(),
        Duration::from_millis(config.connect_timeout_ms())
    );
    assert_eq!(
        client.transport_limits().max_response_bytes(),
        config.max_response_bytes()
    );

    // and the defaults are actually bounded — the whole point
    assert!(config.request_timeout_ms() > 0 && config.request_timeout_ms() <= 120_000);
    assert!(config.connect_timeout_ms() > 0 && config.connect_timeout_ms() <= 60_000);
    assert!(config.max_response_bytes() > 0 && config.max_response_bytes() <= 64 * 1024 * 1024);
}
