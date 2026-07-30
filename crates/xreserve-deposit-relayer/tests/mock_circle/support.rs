//! Shared test scaffolding: the client under test, and the request parameters the fixtures use.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

use std::sync::Arc;

use xreserve_deposit_relayer::circle::{
    AuthPosture, CircleClient, RateGovernor, RetryPolicy, TransportLimits,
};
use xreserve_deposit_relayer::observability::EventSink;

use crate::fixtures::AttestationVector;
use crate::mock_circle::{MockCircle, RecordingSink};

/// A `depositMessageHash` in the documented `^0x[a-fA-F0-9]{64}$` form that is NOT the fixture's
/// hash — for the paths where the response never gets as far as the requested-hash binding (a 404,
/// a 400, a malformed body). A SUCCESSFUL by-hash fetch must request [`requested_hash`] instead:
/// the endpoint answers a lookup BY that hash, so the relayer refuses a response carrying a
/// different one.
pub const HASH_PARAM: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

/// A source-chain `txHash` in the documented `^0x[a-fA-F0-9]{64}$` form.
pub const TX_HASH: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";

/// Retry base delay used by the HTTP tests: small enough to keep them fast, large enough that the
/// on-the-wire spacing between attempts is unambiguously observable.
pub const TEST_BACKOFF_BASE_MS: u64 = 60;
pub const TEST_MAX_ATTEMPTS: u32 = 3;
pub const TEST_ALERT_AFTER: u32 = 2;

/// The `depositMessageHash` that ACTUALLY identifies this attestation — `keccak256(payload)`. The
/// by-hash endpoint is a lookup by this key, so it is what a successful fetch must ask for.
pub fn requested_hash(vector: &AttestationVector) -> String {
    vector.message_hash_hex()
}

/// A client pointed at the mock, with a fast retry policy and a rate ceiling high enough not to
/// bind (the 5 QPS/IP + 35 QPS global ceilings are asserted by the governor tests, and their wiring
/// from config by the transport suite).
pub fn client_for(mock: &MockCircle, auth: AuthPosture) -> (CircleClient, Arc<RecordingSink>) {
    let sink = RecordingSink::new();
    let client = CircleClient::new(mock.base_url(), auth)
        .expect("client builds against the mock base url")
        // the mock IS the transport: the client builds its real reqwest::Request and the mock's
        // router answers it in process (no socket — see mock_circle::transports)
        .with_transport(mock.transport())
        .with_governor(Arc::new(
            RateGovernor::new(500, 500).expect("permissive governor"),
        ))
        .with_retry_policy(
            RetryPolicy::new(TEST_MAX_ATTEMPTS, TEST_BACKOFF_BASE_MS, TEST_ALERT_AFTER)
                .expect("valid retry policy"),
        )
        .with_event_sink(Arc::clone(&sink) as Arc<dyn EventSink>);
    (client, sink)
}

/// As [`client_for`], with explicit transport limits (deadline + response-size ceiling).
pub fn client_with_limits(
    mock: &MockCircle,
    limits: TransportLimits,
) -> (CircleClient, Arc<RecordingSink>) {
    let (client, sink) = client_for(mock, AuthPosture::None);
    (client.with_transport_limits(limits), sink)
}
