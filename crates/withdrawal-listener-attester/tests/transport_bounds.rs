//! The production response-size ceiling — the streaming `collect_bounded` collector, and its
//! propagation from the [`CircleClient`]'s configured limit into the default production
//! [`ReqwestTransport`].
//!
//! These live in their OWN test file (not inside `transport.rs`), so the response-limit tests are a
//! tests-only artifact and can be run RED against the unmodified transport before the implementation
//! exists — the security fix is proven test-first, not bundled into the code under test.

use std::future::Future;
use std::pin::Pin;

use assert_matches::assert_matches;

use withdrawal_listener_attester::circle::auth::AuthPosture;
use withdrawal_listener_attester::circle::client::DEFAULT_MAX_RESPONSE_BYTES;
use withdrawal_listener_attester::circle::transport::{
    collect_bounded, BodyLimit, ChunkSource, ReqwestTransport,
};
use withdrawal_listener_attester::circle::CircleClient;
use withdrawal_listener_attester::error::ListenerError;

#[path = "mock_circle/mod.rs"]
mod mock_circle;
#[path = "support/mod.rs"]
mod support;

use mock_circle::{Endpoint, MockCircle, Reply, Script};

// THE STREAMING COLLECTOR — the production enforcement, tested without a socket via ChunkSource
// ================================================================================================

/// A body that never ends and declares NO `Content-Length` — exactly the shape a hostile peer sends
/// to make a naive reader buffer without bound.
struct EndlessBody {
    chunk_len: usize,
}

impl ChunkSource for EndlessBody {
    fn advertised_len(&self) -> Option<u64> {
        None
    }

    fn next_chunk(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, ListenerError>> + Send + '_>> {
        let len = self.chunk_len;
        Box::pin(async move { Ok(Some(vec![0u8; len])) })
    }
}

/// A finite body delivered in fixed chunks, advertising its true length.
struct FiniteBody {
    chunks: Vec<Vec<u8>>,
}

impl ChunkSource for FiniteBody {
    fn advertised_len(&self) -> Option<u64> {
        Some(self.chunks.iter().map(|c| c.len() as u64).sum())
    }

    fn next_chunk(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, ListenerError>> + Send + '_>> {
        let next = if self.chunks.is_empty() {
            None
        } else {
            Some(self.chunks.remove(0))
        };
        Box::pin(async move { Ok(next) })
    }
}

#[tokio::test]
async fn collect_bounded_refuses_an_endless_unbounded_body_while_reading() {
    // The ceiling must fire DURING the read, so a body with no Content-Length cannot exhaust memory
    // before it is rejected. With a 4 KiB ceiling and 1 KiB chunks, the buffer never exceeds the
    // ceiling: the chunk that crosses it is dropped.
    let mut body = EndlessBody { chunk_len: 1024 };
    let err = collect_bounded(&mut body, 4096).await.unwrap_err();
    assert_matches!(
        err,
        ListenerError::ResponseTooLarge { limit: 4096, actual } if actual > 4096
    );
}

#[test]
fn a_content_length_over_the_ceiling_is_refused_before_reading_a_byte() {
    let limit = BodyLimit::new(1000);
    assert!(
        limit.check_content_length(Some(5000)).is_err(),
        "an advertised oversized length is refused up front"
    );
    assert!(limit.check_content_length(Some(500)).is_ok());
    assert!(
        limit.check_content_length(None).is_ok(),
        "an absent Content-Length is not itself a rejection — the per-chunk check covers it"
    );
}

#[tokio::test]
async fn collect_bounded_accepts_a_body_within_the_ceiling() {
    let mut body = FiniteBody {
        chunks: vec![vec![1u8; 100], vec![2u8; 100]],
    };
    let collected = collect_bounded(&mut body, 4096).await.unwrap();
    assert_eq!(collected.len(), 200);
}

#[tokio::test]
async fn collect_bounded_enforces_a_ceiling_below_and_accepts_one_above_the_default() {
    // The same 8 KiB body is rejected under a below-default ceiling and accepted under an above-default
    // one — the ceiling VALUE governs the production streaming enforcement, not a fixed constant.
    let below = DEFAULT_MAX_RESPONSE_BYTES / 2;
    let above = DEFAULT_MAX_RESPONSE_BYTES * 2;
    let body_len = DEFAULT_MAX_RESPONSE_BYTES + 8 * 1024; // larger than default, smaller than `above`

    let mut too_big = FiniteBody {
        chunks: vec![vec![7u8; body_len]],
    };
    assert_matches!(
        collect_bounded(&mut too_big, below).await,
        Err(ListenerError::ResponseTooLarge { .. })
    );

    let mut ok = FiniteBody {
        chunks: vec![vec![7u8; body_len]],
    };
    let collected = collect_bounded(&mut ok, above)
        .await
        .expect("a body under the raised ceiling is accepted");
    assert_eq!(collected.len(), body_len);
}

// THE LIMIT IS ONE SOURCE, SHARED WITH THE PRODUCTION TRANSPORT
// ================================================================================================

#[test]
fn the_reqwest_transport_carries_the_ceiling_it_was_built_with() {
    let http = reqwest::Client::new();
    assert_eq!(ReqwestTransport::new(http, 4096).max_response_bytes(), 4096);
}

#[test]
fn a_custom_ceiling_is_propagated_to_the_default_production_transport() {
    // `transport_max_response_bytes` downcasts the ACTUAL installed `Arc<dyn HttpTransport>` and reads
    // the `ReqwestTransport`'s ceiling — it does NOT echo a client field. So if
    // `with_max_response_bytes` stops rebuilding the default transport (e.g. the `if
    // self.transport_is_default {` guard is mutated to `if false {`), the installed transport stays at
    // the DEFAULT ceiling and these assertions fail. This is the non-tautological oracle for the
    // round-3 security fix.
    let default_client = CircleClient::new("https://circle.mock", AuthPosture::None).unwrap();
    assert_eq!(
        default_client.transport_max_response_bytes(),
        Some(DEFAULT_MAX_RESPONSE_BYTES),
        "a fresh client's installed default transport carries the default ceiling"
    );

    let lower = CircleClient::new("https://circle.mock", AuthPosture::None)
        .unwrap()
        .with_max_response_bytes(1000);
    assert_eq!(
        lower.transport_max_response_bytes(),
        Some(1000),
        "a below-default ceiling reaches the INSTALLED production transport (rebuild happened)"
    );
    assert_ne!(
        lower.transport_max_response_bytes(),
        Some(DEFAULT_MAX_RESPONSE_BYTES),
        "if the rebuild were removed the installed transport would still read the default — it must not"
    );
    assert_eq!(lower.max_response_bytes(), 1000);

    let higher = CircleClient::new("https://circle.mock", AuthPosture::None)
        .unwrap()
        .with_max_response_bytes(DEFAULT_MAX_RESPONSE_BYTES * 4);
    assert_eq!(
        higher.transport_max_response_bytes(),
        Some(DEFAULT_MAX_RESPONSE_BYTES * 4),
        "an above-default ceiling reaches the installed transport (not still capped at the default)"
    );
}

#[test]
fn a_caller_supplied_transport_owns_its_own_limits() {
    // With a custom transport installed, the client does not claim to control the transport's ceiling;
    // the client-side post-check still applies its own field.
    let mock = MockCircle::start(Script::new());
    let client = CircleClient::new("https://circle.mock", AuthPosture::None)
        .unwrap()
        .with_transport(mock.transport())
        .with_max_response_bytes(1234);
    assert_eq!(client.transport_max_response_bytes(), None);
    assert_eq!(client.max_response_bytes(), 1234);
}

// THE CLIENT-SIDE CEILING IS THE CONFIGURED VALUE (exercised through a driver + the mock)
// ================================================================================================

fn a_prepare_request() -> withdrawal_listener_attester::circle::schema::PrepareWithdrawalRequest {
    use withdrawal_listener_attester::circle::schema::{
        PrepareBurnIntentInput, PrepareWithdrawalRequest,
    };
    use withdrawal_listener_attester::circle::wire::{DecimalAmount, Hex32};

    let input = PrepareBurnIntentInput::builder()
        .value_including_fees(DecimalAmount::new("10000000").unwrap())
        .remote_domain(10_001)
        .remote_depositor(Hex32::new(format!("0x{}", "11".repeat(32))).unwrap())
        .final_destination_domain(0)
        .final_destination_recipient(Hex32::new(format!("0x{}", "22".repeat(32))).unwrap())
        .use_circle_forwarding(false)
        .build()
        .unwrap();
    PrepareWithdrawalRequest::new(vec![input])
}

#[tokio::test]
async fn a_body_over_the_configured_ceiling_is_refused_and_one_under_a_raised_ceiling_is_not() {
    use withdrawal_listener_attester::withdrawal_api::prepare;

    // A ~2000-byte body, served on a 200.
    let big_body = "x".repeat(2000);
    let mock = MockCircle::start(Script::new().prepare(vec![Reply::Body {
        status: 200,
        body: big_body,
    }]));

    // Below the body size: refused as ResponseTooLarge with the CONFIGURED limit (not the default).
    let strict = CircleClient::new(mock.base_url(), AuthPosture::None)
        .unwrap()
        .with_transport(mock.transport())
        .with_max_response_bytes(1000);
    let err = prepare(&strict, &a_prepare_request()).await.unwrap_err();
    assert_matches!(err, ListenerError::ResponseTooLarge { limit: 1000, .. });

    // Above the body size: it passes the ceiling (and then fails to decode as JSON) — proving the
    // ceiling did NOT reject it.
    let mock2 = MockCircle::start(Script::new().prepare(vec![Reply::Body {
        status: 200,
        body: "x".repeat(2000),
    }]));
    let lax = CircleClient::new(mock2.base_url(), AuthPosture::None)
        .unwrap()
        .with_transport(mock2.transport())
        .with_max_response_bytes(64 * 1024);
    let err = prepare(&lax, &a_prepare_request()).await.unwrap_err();
    assert_matches!(
        err,
        ListenerError::MalformedResponse { .. },
        "a body under the ceiling is read, then rejected by the decoder — not by the ceiling"
    );
    // sanity: the request reached the mock
    assert_eq!(mock2.requests_to(Endpoint::Prepare).len(), 1);
}
