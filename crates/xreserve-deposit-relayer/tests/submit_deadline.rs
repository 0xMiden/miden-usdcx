//! **The submit deadline bounds a hung node.**
//!
//! The recovery threshold can only be validated to exceed the "longest legitimate submit" if that
//! duration is actually BOUNDED. Awaiting the `MintSubmit` future with no timeout would let a hung
//! node keep a driver `Pending` indefinitely — no finite `stale_claim_secs` would be safe. Each
//! submit attempt is therefore wrapped in the configured `submit_deadline_ms`; a hang becomes a
//! transient failure and is retried, and the whole `submit_with_retry` is bounded by
//! `max_retry_attempts × submit_deadline + backoff`, which is exactly the envelope `RecoveryPolicy`
//! validates against.
//!
//! The deadline is a short 100 ms while the hung submit awaits an hour, so the timeout ALWAYS wins
//! deterministically regardless of machine load (the hung future never completes within the test) —
//! the outcome does not depend on wall-clock timing, only the total runtime does (≈ attempts × 100
//! ms).

mod cycle_support;
mod fixtures;
mod mint_support;
mod mock_circle;

use assert_matches::assert_matches;

use xreserve_deposit_relayer::cycle::{run_relayer_cycle, Disposition, RelayerCtx};
use xreserve_deposit_relayer::idempotency::SubmissionStatus;

use cycle_support::{
    cycle_client, cycle_config_with, cycle_identities, cycle_store, HangingSubmit,
};
use mint_support::note_rng;
use mock_circle::{attestation_page, MockCircle, RecordingSink, Reply, Script};
use xusdc_encoding::xreserve::encoding::DepositIntent;

/// A submit that never completes on its own is bounded by the deadline: each attempt times out
/// (transient), the retry budget is spent, and the attestation ends `Deferred` (retryable next
/// cycle) — never an unbounded `Pending` wait. The submit port is reached exactly
/// `max_retry_attempts` times, each attempt ended by the deadline rather than the hung future.
#[tokio::test]
async fn a_hung_submit_is_bounded_by_the_deadline_and_deferred() {
    let vector = fixtures::test_vector();
    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));

    // short deadline, 3 attempts, no backoff; stale threshold well past the tiny envelope so the
    // recovery policy is valid
    let config = cycle_config_with(|c| {
        c["submit_deadline_ms"] = serde_json::json!(100);
        c["max_retry_attempts"] = serde_json::json!(3);
        c["backoff_base_ms"] = serde_json::json!(0);
        c["stale_claim_secs"] = serde_json::json!(300);
    });
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = HangingSubmit::new();
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

    // an OUTER wall-clock bound: if the submit deadline were removed, the hung submit (a 1-hour sleep)
    // would hang the cycle forever; this fails the test cleanly instead of hanging the whole suite. The
    // bound (10s) is far above the intended 3 × 100ms so it never fires on the correct path.
    let report = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        run_relayer_cycle(&mut ctx),
    )
    .await
    .expect("the cycle must complete — a hung submit was not bounded by its deadline")
    .expect("the cycle runs");

    // the hung submit did not hang the cycle: it was bounded, retried, and deferred
    assert_matches!(report.entries()[0].disposition(), Disposition::Deferred(_));
    assert_eq!(
        submit.call_count(),
        3,
        "each of the 3 attempts must be ended by the deadline, not left awaiting the hung future"
    );
    // the deposit is retryable (Failed), not stranded Pending
    let nonce = *DepositIntent::try_from(vector.payload())
        .expect("valid DI")
        .header()
        .nonce()
        .as_bytes();
    assert_eq!(
        store
            .record(&nonce)
            .expect("read")
            .expect("claimed")
            .status(),
        SubmissionStatus::Failed,
        "a deadline-bounded hung submit leaves the deposit retryable, not an unbounded Pending"
    );
}
