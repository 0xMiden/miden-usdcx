//! **Two drivers at the reclaim boundary.**
//!
//! `retryable()` and `reclaim_stale_pending()` are non-owning reads two relayer processes may run
//! against one store file. The safety property is: while driver A's submit is legitimately in
//! flight (its claim `Pending`, up to the worst-case submit envelope), driver B must NOT reclaim
//! it. That is guaranteed by validating `stale_claim_secs` STRICTLY beyond the backoff-inclusive
//! envelope — so this suite drives TWO store handles on one file and asserts the boundary, with the
//! envelope tied to a NON-ZERO backoff so a mutation that drops the backoff (or the deadline) term
//! is caught.
//!
//! The deterministic case uses a shared controllable clock so "A at its worst-case submit time" is
//! exact; the concurrent case interleaves two handles under a real clock via `tokio::join!` to show
//! the store stays consistent when they overlap for real.

mod cycle_support;
mod fixtures;
mod mint_support;
mod mock_circle;

use assert_matches::assert_matches;

use xreserve_deposit_relayer::cycle::{run_relayer_cycle, Disposition, RelayerCtx};
use xreserve_deposit_relayer::error::RelayerError;
use xreserve_deposit_relayer::idempotency::{IdempotencyStore, SubmissionStatus};

use cycle_support::{
    cycle_client, cycle_config_with, cycle_identities, cycle_store_with_clock, tx_id, HeldSubmit,
    TestClock,
};
use mint_support::note_rng;
use mock_circle::{attestation_page, MockCircle, RecordingSink, Reply, Script};
use xusdc_encoding::xreserve::encoding::DepositIntent;

/// The config knobs whose envelope this suite is built around: 3 attempts × 30 s deadline + 5 s
/// backoff base → a 130 s worst-case submit; the validated stale threshold is one second beyond it.
const ATTEMPTS: u32 = 3;
const DEADLINE_MS: u64 = 30_000;
const BACKOFF_MS: u64 = 5_000;
const ENVELOPE_SECS: u64 = 130; // 3×30 + backoff(2 gaps × 5×2^2 = 40) = 130

fn boundary_config(stale_claim_secs: u64) -> xreserve_deposit_relayer::config::RelayerConfig {
    cycle_config_with(|c| {
        c["max_retry_attempts"] = serde_json::json!(ATTEMPTS);
        c["submit_deadline_ms"] = serde_json::json!(DEADLINE_MS);
        c["backoff_base_ms"] = serde_json::json!(BACKOFF_MS);
        c["stale_claim_secs"] = serde_json::json!(stale_claim_secs);
    })
}

/// **The two-driver boundary, with backoff.** Driver A claims a nonce (models the start of a submit
/// that runs up to the worst-case envelope). At A's worst-case time, driver B's reclaim — using the
/// validated threshold — must NOT free A's live claim. Only well past the threshold does B reclaim
/// it.
///
/// The envelope is asserted exactly (130 s, WITH backoff) and the at-envelope threshold is asserted
/// refused, so dropping either the backoff or the deadline term from the envelope fails this test.
#[tokio::test]
async fn a_live_submit_is_not_reclaimed_within_the_backoff_inclusive_envelope() {
    // the envelope actually includes the backoff term
    assert_eq!(
        boundary_config(ENVELOPE_SECS + 1).submit_worst_case_secs(),
        ENVELOPE_SECS,
        "the submit envelope must be the backoff-inclusive 130s (not the 90s backoff-free value)"
    );
    // a threshold AT the envelope is refused (so a driver can never be reclaimed at its worst case)
    assert_matches!(
        boundary_config(ENVELOPE_SECS).recovery_policy(),
        Err(RelayerError::BadRecoveryPolicy { required_min_stale_secs, .. })
            if required_min_stale_secs == ENVELOPE_SECS + 1
    );

    // the validated, safe threshold
    let policy = boundary_config(ENVELOPE_SECS + 1)
        .recovery_policy()
        .expect("one second beyond the envelope is a valid policy");
    let threshold = policy.stale_claim_secs();
    assert_eq!(threshold, ENVELOPE_SECS + 1);

    let vector = fixtures::test_vector();
    let nonce = nonce_of(&vector);

    let clock = TestClock::at(1_000);
    let dir = tempfile::tempdir().expect("tempdir");
    // TWO handles on ONE file, sharing the clock — two relayer processes
    let driver_a = cycle_store_with_clock(&dir, clock.clone());
    let driver_b = cycle_store_with_clock(&dir, clock.clone());

    // A starts its submit: it claims the nonce (Pending) at t=1000
    driver_a
        .claim_nonce(&nonce, &vector.message_hash())
        .expect("A claims");

    // A's submit runs up to its worst case; at exactly the envelope, it may still be in flight
    clock.set(1_000 + ENVELOPE_SECS);
    driver_b
        .reclaim_stale_pending(threshold)
        .expect("B's reclaim runs");
    assert_eq!(
        status(&driver_b, &nonce),
        SubmissionStatus::Pending,
        "driver B reclaimed A's claim while A's submit was still within its worst-case envelope"
    );

    // well past the threshold — now A's submit has definitely finished (or A has crashed), so reclaim
    // is correct
    clock.set(1_000 + threshold + 5);
    driver_b
        .reclaim_stale_pending(threshold)
        .expect("B's reclaim runs");
    assert_eq!(
        status(&driver_b, &nonce),
        SubmissionStatus::Failed,
        "a claim older than the threshold must be reclaimed — crash recovery must still work"
    );
}

/// **Two drivers overlapping for real.** Under a real clock, driver A holds a fresh claim (a live
/// submit) while driver B repeatedly reclaims, interleaved via `tokio::join!`. Because the claim is
/// far younger than any valid threshold, B never frees it, and A records its submission
/// successfully — two handles on one file do not corrupt each other.
#[tokio::test]
async fn two_concurrent_drivers_do_not_clobber_a_live_claim() {
    let vector = fixtures::test_vector();
    let nonce = nonce_of(&vector);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("shared-store.sqlite3");
    // two independent handles (SystemClock) on one file — genuinely two drivers
    let driver_a = IdempotencyStore::open(&path).expect("A opens");
    let driver_b = IdempotencyStore::open(&path).expect("B opens");

    // B reclaims at the VALIDATED cross-field boundary (131 s), not a hard-coded constant
    let threshold = boundary_config(ENVELOPE_SECS + 1)
        .recovery_policy()
        .expect("valid policy")
        .stale_claim_secs();
    assert_eq!(threshold, ENVELOPE_SECS + 1);

    driver_a
        .claim_nonce(&nonce, &vector.message_hash())
        .expect("A claims");

    // A: holds the claim briefly (a live submit), then records its submission.
    let a = async {
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        driver_a
            .record_submission(&nonce, tx_id(0x7A))
            .expect("A's submission must succeed — its claim was not clobbered");
    };
    // B: hammers reclaim throughout, at the validated threshold. The fresh claim (seconds old at most)
    // is far under it, so B must never free it.
    let b = async {
        for _ in 0..20 {
            let freed = driver_b
                .reclaim_stale_pending(threshold)
                .expect("B's reclaim runs");
            assert!(
                freed.is_empty(),
                "B reclaimed a live, freshly-claimed nonce: {freed:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    };
    tokio::join!(a, b);

    assert_eq!(
        status(&driver_a, &nonce),
        SubmissionStatus::Submitted,
        "A's live claim was overwritten by a concurrent driver's reclaim"
    );
}

// THE REAL LIFECYCLE — driver A runs a live cycle whose submit is held in flight
// ================================================================================================

/// **The requested delayed live-submit boundary.** Driver A runs a REAL `run_relayer_cycle`: it
/// polls Circle, claims its nonce, builds the note, and PARKS inside a held submit — its claim
/// genuinely `Pending` through the real submit/deadline lifecycle. While A is in flight, driver B
/// (a second handle on the same file) advances the shared clock to A's worst-case
/// (backoff-inclusive) envelope and reclaims at the VALIDATED 131 s threshold. B must NOT free A's
/// live claim; A is then released and completes its mint.
///
/// This is the highest-risk overlap the earlier store-only tests did not exercise: a live submit
/// lifecycle in one driver against another driver's reclamation, synchronized so the reclaim lands
/// exactly while A is submitting.
#[tokio::test]
async fn a_live_submit_cycle_is_not_reclaimed_by_a_second_driver_within_the_envelope() {
    let vector = fixtures::test_vector();
    let nonce = nonce_of(&vector);

    // deadline 30 s (real wall-clock) so the held submit is released long before it fires; backoff 5 s
    // so the envelope is the backoff-inclusive 130 s and the validated threshold is 131 s
    let config = boundary_config(ENVELOPE_SECS + 1);
    let threshold = config
        .recovery_policy()
        .expect("valid policy")
        .stale_claim_secs();
    assert_eq!(threshold, ENVELOPE_SECS + 1);

    let clock = TestClock::at(1_000);
    let dir = tempfile::tempdir().expect("tempdir");
    // TWO handles on ONE file, sharing the clock — driver A and driver B are two processes
    let store_a = cycle_store_with_clock(&dir, clock.clone());
    let store_b = cycle_store_with_clock(&dir, clock.clone());

    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let held = HeldSubmit::new(tx_id(0x5A));
    let identities = cycle_identities();
    let mut rng = note_rng(7);
    let mut ctx_a = RelayerCtx::new(
        &config,
        &client,
        &store_a,
        held.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );

    let a_cycle = run_relayer_cycle(&mut ctx_a);
    let coordinator = async {
        // wait until A has actually claimed N and entered the submit (its claim is live)
        held.wait_until_in_flight().await;
        assert_eq!(
            status(&store_b, &nonce),
            SubmissionStatus::Pending,
            "A's claim must be Pending and visible to B while A submits"
        );

        // A is at its worst-case submit time — still legitimately in flight
        clock.set(1_000 + ENVELOPE_SECS);
        let freed = store_b
            .reclaim_stale_pending(threshold)
            .expect("B's reclaim runs");
        assert!(
            freed.is_empty(),
            "driver B reclaimed A's LIVE claim while A's submit was still within its envelope: {freed:?}"
        );
        assert_eq!(status(&store_b, &nonce), SubmissionStatus::Pending);

        // let A finish its mint
        held.release();
    };

    let (report, ()) = tokio::join!(a_cycle, coordinator);
    let report = report.expect("A's cycle completes");

    assert_matches!(
        report.entries()[0].disposition(),
        Disposition::Submitted { .. }
    );
    assert_eq!(held.call_count(), 1, "A submitted exactly once");
    assert_eq!(
        status(&store_b, &nonce),
        SubmissionStatus::Submitted,
        "A's mint was recorded — B did not clobber the live claim"
    );
}

/// **The outside-boundary recovery case, through the real lifecycle.** Driver A runs a real cycle
/// and parks in the submit (claim `Pending`), then CRASHES — its cycle future is dropped
/// mid-submit, so the claim is stranded exactly as a `kill -9` between claim and settle would leave
/// it. Past the validated threshold, driver B reclaims it to `Failed` — crash recovery works, and
/// it is tied to the same backoff-inclusive boundary.
#[tokio::test]
async fn a_crashed_live_submit_is_reclaimed_by_a_second_driver_past_the_boundary() {
    let vector = fixtures::test_vector();
    let nonce = nonce_of(&vector);

    let config = boundary_config(ENVELOPE_SECS + 1);
    let threshold = config
        .recovery_policy()
        .expect("valid policy")
        .stale_claim_secs();

    let clock = TestClock::at(1_000);
    let dir = tempfile::tempdir().expect("tempdir");
    let store_a = cycle_store_with_clock(&dir, clock.clone());
    let store_b = cycle_store_with_clock(&dir, clock.clone());

    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let held = HeldSubmit::new(tx_id(0x5B));
    let identities = cycle_identities();
    let mut rng = note_rng(7);
    let mut ctx_a = RelayerCtx::new(
        &config,
        &client,
        &store_a,
        held.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );

    // drive A until it has claimed N and is parked in the submit, then DROP its cycle — a crash
    // between claim and settle. `select!` polls A's cycle until the held submit signals in-flight.
    {
        let mut a_cycle = Box::pin(run_relayer_cycle(&mut ctx_a));
        tokio::select! {
            _ = &mut a_cycle => panic!("A's cycle must park in the held submit, not complete"),
            () = held.wait_until_in_flight() => {}
        }
        // A "crashes": the cycle future is dropped mid-submit; the committed claim stays Pending
        drop(a_cycle);
    }
    assert_eq!(
        status(&store_b, &nonce),
        SubmissionStatus::Pending,
        "the crashed claim must remain Pending (committed before the submit)"
    );

    // past the validated threshold, a fresh driver reclaims the stranded claim
    clock.set(1_000 + threshold + 5);
    let freed = store_b
        .reclaim_stale_pending(threshold)
        .expect("B's reclaim runs");
    assert!(
        freed.contains(&nonce),
        "the stranded claim past the threshold must be reclaimed — crash recovery must work"
    );
    assert_eq!(status(&store_b, &nonce), SubmissionStatus::Failed);
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

fn nonce_of(vector: &fixtures::AttestationVector) -> [u8; 32] {
    *DepositIntent::try_from(vector.payload())
        .expect("valid DI")
        .header()
        .nonce()
        .as_bytes()
}
