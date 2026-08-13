//! **The two permanent-stranding paths a recovery driver must not have:**
//!
//! 1. **A crashed claim strands forever.** A process death — or a terminal-state write that failed
//!    — between `claim_nonce` and settle leaves a `Pending` record. `claim_nonce` blocks a re-claim
//!    of it (Pending blocks resubmission) and `retryable()` never returns it (it is not `Failed`),
//!    so nothing ever retries it. `reclaim_stale_pending` frees such a record — but only if the
//!    cycle actually calls it. This suite drives the cycle and asserts a stale `Pending` is
//!    reclaimed and retried — and that a YOUNG `Pending` (a submit that may still be in flight) is
//!    left alone.
//!
//! 2. **A persistently-unfetchable head starves the tail.** The bounded retry queue selects the
//!    oldest `retry_batch_size` `Failed` rows by timestamp. If a failed re-fetch left its row's
//!    timestamp unchanged, a full batch of permanently-unfetchable rows would monopolize every
//!    cycle and starve row `batch+1` onward. This suite seeds more than one batch, keeps the head
//!    unfetchable, and asserts the tail still gets a turn — because every retry ATTEMPT re-stamps
//!    the row, rotating it behind the ones not yet tried.
//!
//! Real everywhere except the Miden submit PORT (NON-GATING; the mock boundary). The store runs on
//! a controllable clock so "older than the threshold" and "re-stamped just now" are deterministic.

mod cycle_support;
mod fixtures;
mod mint_support;
mod mock_circle;

use xreserve_deposit_relayer::cycle::{run_relayer_cycle, RelayerCtx};
use xreserve_deposit_relayer::idempotency::{IdempotencyStore, SubmissionStatus};

use cycle_support::{
    cycle_client, cycle_config_with, cycle_identities, cycle_store, cycle_store_with_clock, tx_id,
    ScriptedSubmit, SubmitReply, TestClock,
};
use fixtures::{canonical_payload, AttestationVector, PartnerAttester, TEST_VECTOR_PAYLOAD_ID};
use mint_support::note_rng;
use mock_circle::{
    attestation_page, by_hash_wrapper, Endpoint, MockCircle, RecordingSink, Reply, Script,
};
use xusdc_encoding::xreserve::encoding::DepositIntent;

// STALE-CLAIM RECOVERY — a crashed claim does not strand a deposit forever
// ================================================================================================

/// A `Pending` record older than the stale-claim threshold is RECLAIMED (→ `Failed`) by the cycle
/// and then retried to success. Without the reclaim wiring it would sit `Pending` forever:
/// unreclaimable (`claim_nonce` blocks it) and invisible to `retryable()`.
#[tokio::test]
async fn a_stale_pending_claim_is_reclaimed_and_retried() {
    let stranded = fixtures::test_vector();
    let nonce = nonce_of(&stranded);

    let clock = TestClock::at(1_000);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store_with_clock(&dir, clock.clone());

    // simulate a crash between claim and settle: the nonce is claimed (Pending) and never settled
    store
        .claim_nonce(&nonce, &stranded.message_hash())
        .expect("claim");
    assert_eq!(status(&store, &nonce), SubmissionStatus::Pending);

    // age it past the threshold
    let stale_secs = 100;
    clock.set(1_000 + stale_secs + 1);

    let mock = MockCircle::start(
        Script::new()
            .batch(vec![Reply::ok(attestation_page(&[]))]) // an empty forward page
            .by_hash(vec![Reply::ok(by_hash_wrapper(&stranded))]), // the reclaimed retry re-fetches it
    );
    let config = cycle_config_with(|c| c["stale_claim_secs"] = serde_json::json!(stale_secs));
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let submit = ScriptedSubmit::new(vec![SubmitReply::Accepted(tx_id(0x88))]);
    let identities = cycle_identities();
    let mut rng = note_rng(7);
    let mut ctx = RelayerCtx::new(
        &config,
        &client,
        &store,
        submit.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );

    run_relayer_cycle(&mut ctx).await.expect("cycle runs");

    assert!(
        !mock.requests_to(Endpoint::ByHash).is_empty(),
        "the stale Pending claim was never reclaimed and retried — it is stranded forever"
    );
    assert_eq!(
        status(&store, &nonce),
        SubmissionStatus::Submitted,
        "the reclaimed deposit was not retried to success"
    );
}

/// A `Pending` record YOUNGER than the threshold is NOT reclaimed — its submit may still be in
/// flight, and reclaiming it would race a live attempt. It stays `Pending` and is not re-fetched.
#[tokio::test]
async fn a_young_pending_claim_is_left_in_flight() {
    let in_flight = fixtures::test_vector();
    let nonce = nonce_of(&in_flight);

    let clock = TestClock::at(1_000);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store_with_clock(&dir, clock.clone());
    store
        .claim_nonce(&nonce, &in_flight.message_hash())
        .expect("claim");

    let stale_secs = 100;
    clock.set(1_000 + stale_secs - 1); // younger than the threshold

    let mock = MockCircle::start(
        Script::new()
            .batch(vec![Reply::ok(attestation_page(&[]))])
            .by_hash(vec![Reply::ok(by_hash_wrapper(&in_flight))]),
    );
    let config = cycle_config_with(|c| c["stale_claim_secs"] = serde_json::json!(stale_secs));
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let submit = ScriptedSubmit::always_accepting();
    let identities = cycle_identities();
    let mut rng = note_rng(7);
    let mut ctx = RelayerCtx::new(
        &config,
        &client,
        &store,
        submit.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );

    run_relayer_cycle(&mut ctx).await.expect("cycle runs");

    assert!(
        mock.requests_to(Endpoint::ByHash).is_empty(),
        "a young (possibly in-flight) Pending claim was reclaimed and re-fetched — reclaim raced a \
         live submit"
    );
    assert_eq!(
        status(&store, &nonce),
        SubmissionStatus::Pending,
        "a young claim must be left in flight, not reclaimed"
    );
}

// RETRY-QUEUE FAIRNESS — a persistently-unfetchable head does not starve the tail
// ================================================================================================

/// With `retry_batch_size = 2` and THREE stranded deposits whose re-fetch always fails, the third
/// (tail) deposit still gets a retry attempt within two cycles — because every attempt re-stamps
/// the row it tried, rotating the tried ones behind the untried one.
///
/// Were a re-fetch-failed row's timestamp left unchanged, the first two rows (oldest) would be
/// selected every cycle and the third never reached. The oracle is the by-hash request log: the
/// tail deposit's `messageHash` must appear.
#[tokio::test]
async fn the_retry_queue_rotates_so_a_stuck_head_does_not_starve_the_tail() {
    let a = PartnerAttester::new().attest(&with_distinct_nonce(1));
    let b = PartnerAttester::new().attest(&with_distinct_nonce(2));
    let c = PartnerAttester::new().attest(&with_distinct_nonce(3));

    let clock = TestClock::at(1_000);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store_with_clock(&dir, clock.clone());

    // seed three Failed records at distinct, increasing timestamps: a < b < c
    for (i, vector) in [&a, &b, &c].into_iter().enumerate() {
        clock.set(1_000 + i as u64);
        let nonce = nonce_of(vector);
        store
            .claim_nonce(&nonce, &vector.message_hash())
            .expect("claim");
        store.record_failure(&nonce).expect("-> failed");
    }

    // the re-fetch ALWAYS fails, so nothing succeeds — every attempt only re-stamps (rotates) its row
    let mock = MockCircle::start(
        Script::new()
            .batch(vec![Reply::ok(attestation_page(&[]))])
            .by_hash(vec![Reply::Status(500)]),
    );
    // batch of 2, and a huge stale threshold so reclaim never touches these (they are Failed anyway)
    let config = cycle_config_with(|c| {
        c["retry_batch_size"] = serde_json::json!(2);
        c["stale_claim_secs"] = serde_json::json!(1_000_000);
    });
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let submit = ScriptedSubmit::always_accepting();
    let identities = cycle_identities();
    let mut rng = note_rng(7);
    let mut ctx = RelayerCtx::new(
        &config,
        &client,
        &store,
        submit.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );

    // cycle 1 (t=1003): selects a,b (oldest) → both re-fetch-fail → re-stamped to 1003
    clock.set(1_003);
    run_relayer_cycle(&mut ctx).await.expect("cycle 1 runs");
    // cycle 2 (t=1004): c (t=1002) is now the oldest → it finally gets a turn
    clock.set(1_004);
    run_relayer_cycle(&mut ctx).await.expect("cycle 2 runs");

    let c_hash = format!("0x{}", hex::encode(c.message_hash()));
    let by_hash_paths: Vec<String> = mock
        .requests_to(Endpoint::ByHash)
        .into_iter()
        .map(|r| r.path)
        .collect();
    assert!(
        by_hash_paths.iter().any(|p| p.contains(&c_hash)),
        "the tail deposit {c_hash} was never re-fetched across two cycles — a stuck head starves it. \
         by-hash requests seen: {by_hash_paths:?}"
    );
}

// ORDER — local crash recovery runs BEFORE the fallible discovery fetch
// ================================================================================================

/// Stale-claim reclamation must run BEFORE the optional `/v1/info` discovery, so a broken discovery
/// endpoint cannot prevent local crash recovery. Here the fast-fail is ON and `/v1/info` returns
/// 400 (the cycle will fail on it) — but the stale `Pending` claim must ALREADY have been reclaimed
/// to `Failed` by the time discovery is attempted.
#[tokio::test]
async fn stale_reclamation_runs_before_a_broken_discovery_fetch() {
    let stranded = fixtures::test_vector();
    let nonce = nonce_of(&stranded);

    let clock = TestClock::at(1_000);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store_with_clock(&dir, clock.clone());
    store
        .claim_nonce(&nonce, &stranded.message_hash())
        .expect("claim");

    let stale_secs = 100;
    clock.set(1_000 + stale_secs + 1);

    // fast-fail ON, and /v1/info is broken — discovery will fail the cycle
    let mock = MockCircle::start(
        Script::new()
            .info(vec![Reply::Status(400)])
            .batch(vec![Reply::ok(attestation_page(&[]))]),
    );
    let config = cycle_config_with(|c| {
        c["domain_token_fast_fail"] = serde_json::json!(true);
        c["stale_claim_secs"] = serde_json::json!(stale_secs);
    });
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let submit = ScriptedSubmit::always_accepting();
    let identities = cycle_identities();
    let mut rng = note_rng(7);
    let mut ctx = RelayerCtx::new(
        &config,
        &client,
        &store,
        submit.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );

    // the cycle FAILS on the broken discovery — specifically the HTTP 400 from /v1/info…
    let err = run_relayer_cycle(&mut ctx)
        .await
        .expect_err("a broken /v1/info fails the cycle");
    assert_matches::assert_matches!(
        err,
        xreserve_deposit_relayer::error::RelayerError::Http { status: 400 },
        "the cycle must fail on the discovery 400 specifically, not some other error"
    );

    // …but the stale claim was reclaimed FIRST, so local crash recovery was not blocked by it
    assert_eq!(
        status(&store, &nonce),
        SubmissionStatus::Failed,
        "the stale Pending claim was not reclaimed before discovery — a broken /v1/info blocked local \
         crash recovery"
    );
}

// FAIL-CLOSED — an invalid recovery config fails the cycle rather than running unsafely
// ================================================================================================

/// A cycle built on an INVALID recovery config (a zero retry batch, which would strand every retry)
/// refuses to run — it returns the validation error and reaches neither the store nor the submit
/// port. The binary fails on the same error at startup; this is the belt-and-suspenders for a
/// directly invoked cycle.
#[tokio::test]
async fn an_invalid_recovery_config_fails_the_cycle_closed() {
    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[]))]));
    let config = cycle_config_with(|c| c["retry_batch_size"] = serde_json::json!(0));
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::always_accepting();
    let identities = cycle_identities();
    let mut rng = note_rng(7);
    let mut ctx = RelayerCtx::new(
        &config,
        &client,
        &store,
        submit.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );

    let err = run_relayer_cycle(&mut ctx)
        .await
        .expect_err("an invalid recovery config must fail the cycle closed");
    assert!(
        matches!(
            err,
            xreserve_deposit_relayer::error::RelayerError::BadRecoveryPolicy { .. }
        ),
        "expected BadRecoveryPolicy, got {err:?}"
    );
    assert_eq!(
        submit.call_count(),
        0,
        "no work may happen under an invalid config"
    );
}

// HELPERS
// ================================================================================================

fn status(store: &IdempotencyStore, nonce: &[u8; 32]) -> SubmissionStatus {
    store
        .record(nonce)
        .expect("read")
        .expect("the nonce is claimed")
        .status()
}

fn nonce_of(vector: &AttestationVector) -> [u8; 32] {
    *DepositIntent::try_from(vector.payload())
        .expect("the fixture payload is a valid DepositIntent")
        .header()
        .nonce()
        .as_bytes()
}

/// The canonical payload with its nonce perturbed — a distinct, still-valid deposit. The nonce
/// offset is located by searching for the nonce the decoder reports, so no layout offset is
/// restated.
fn with_distinct_nonce(tweak: u8) -> Vec<u8> {
    let payload = canonical_payload(TEST_VECTOR_PAYLOAD_ID);
    let nonce = nonce_of(&PartnerAttester::new().attest(&payload));
    let offset = payload
        .windows(nonce.len())
        .position(|window| window == nonce)
        .expect("the nonce appears in its own payload");
    let mut tweaked = payload;
    tweaked[offset] ^= tweak;
    tweaked
}
