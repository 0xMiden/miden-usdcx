//! **The atomic conditional re-stamp** (`touch_failed_timestamp`) — round-4 finding 2.
//!
//! Round 3 rotated the retry queue by calling `record_failure` unconditionally on a re-fetch failure,
//! and discarded its `Result`. But `retryable()` is a NON-owning read that two drivers may observe, and
//! the status machine permits `Pending → Failed` and `Submitted → Failed`. So if driver A re-fetch-
//! failed a row that driver B had meanwhile CLAIMED (`Pending`) or SUBMITTED (`Submitted`), A's
//! `record_failure` would clobber B's live state back to `Failed` — B could then not record its
//! submission, and the durable log would re-advertise the nonce as retryable. And the discarded
//! `Result` meant a failed re-stamp defeated fairness silently.
//!
//! `touch_failed_timestamp` fixes both: in ONE transaction it re-stamps the timestamp ONLY while the
//! row is still `Failed`, leaves any other state untouched, and returns a `Result` the caller must
//! handle. These tests drive it with a second, independent handle on the same file — the real race —
//! and prove a store read failure propagates rather than being swallowed.

mod idempotency_fixtures;

use assert_matches::assert_matches;
use idempotency_fixtures::{
    claim, fresh_store, message_hash, nonce, open_at, store_path, ManualClock,
};
use rstest::rstest;
use tempfile::TempDir;
use xreserve_deposit_relayer::{error::RelayerError, idempotency::SubmissionStatus};

// THE CONDITIONAL — re-stamp only a Failed row
// ================================================================================================

/// A `Failed` row is re-stamped (timestamp advanced) and reported `true` — this is the rotation the
/// fairness guarantee rides on.
#[test]
fn a_failed_row_is_restamped_and_reported_touched() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    store.record_failure(&nonce(1)).expect("-> failed");
    let before = store.record(&nonce(1)).expect("read").expect("present");
    assert_eq!(before.timestamp(), 1_000);

    clock.advance(7);
    let touched = store
        .touch_failed_timestamp(&nonce(1))
        .expect("touch a failed row");
    assert!(touched, "a Failed row must report touched=true");

    let after = store.record(&nonce(1)).expect("read").expect("present");
    assert_eq!(after.status(), SubmissionStatus::Failed);
    assert_eq!(
        after.timestamp(),
        1_007,
        "the timestamp must be re-stamped to now"
    );
}

/// A row that is NOT `Failed` is left EXACTLY as it was and reported `false` — the touch never
/// transitions a live or settled record. One case per non-Failed status.
#[rstest]
#[case::pending(SubmissionStatus::Pending)]
#[case::submitted(SubmissionStatus::Submitted)]
#[case::committed(SubmissionStatus::Committed)]
#[case::already_minted(SubmissionStatus::AlreadyMinted)]
#[case::rejected(SubmissionStatus::Rejected)]
fn a_non_failed_row_is_left_untouched(#[case] status: SubmissionStatus) {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    idempotency_fixtures::drive_to(&store, &nonce(1), status);
    let before = store.record(&nonce(1)).expect("read").expect("present");

    clock.advance(9);
    let touched = store
        .touch_failed_timestamp(&nonce(1))
        .expect("touch is not an error on a non-failed row");
    assert!(!touched, "a {status} row must report touched=false");

    let after = store.record(&nonce(1)).expect("read").expect("present");
    assert_eq!(
        after, before,
        "touching a {status} row changed it — a live or settled claim was overwritten"
    );
}

/// A nonce the store has never seen is reported `false`, never an error — a work-list row that a
/// concurrent driver settled and pruned is not a crash.
#[test]
fn touching_an_unknown_nonce_reports_false() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);
    assert!(!store
        .touch_failed_timestamp(&nonce(9))
        .expect("an unknown nonce is not an error"));
}

// THE RACE — a second handle's live claim is not clobbered
// ================================================================================================

/// **Two handles on one file.** Handle B wins the retry claim on a `Failed` row (`Failed → Pending`);
/// handle A — which read the same stale work list — then re-fetch-fails and touches the row. The touch
/// must NOT clobber B's `Pending` claim back to `Failed`; B remains free to record its submission.
///
/// With the round-3 unconditional `record_failure`, A would drag the row to `Failed`, B's
/// `record_submission` would then be an illegal `Failed → Submitted`, and the mint would be lost while
/// the log re-advertised the nonce as retryable.
#[test]
fn touch_does_not_overwrite_a_second_handles_live_claim() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    // seed a Failed row through handle A
    let handle_a = open_at(&path, &clock);
    claim(&handle_a, &nonce(1), &message_hash(1));
    handle_a.record_failure(&nonce(1)).expect("-> failed");

    // handle B (a second process) wins the retry claim: Failed -> Pending
    let handle_b = open_at(&path, &clock);
    let outcome = handle_b
        .claim_nonce(&nonce(1), &message_hash(1))
        .expect("B claims the retry");
    assert!(outcome.is_claimed(), "B won the retry claim");
    assert_eq!(
        handle_b
            .record(&nonce(1))
            .expect("read")
            .expect("present")
            .status(),
        SubmissionStatus::Pending
    );

    // handle A, working the same stale work list, re-fetch-fails and touches the row
    let touched = handle_a
        .touch_failed_timestamp(&nonce(1))
        .expect("A's touch is not an error");
    assert!(!touched, "A must not re-stamp a row B has since claimed");

    // B's claim survived — it can still record its submission
    assert_eq!(
        handle_a
            .record(&nonce(1))
            .expect("read")
            .expect("present")
            .status(),
        SubmissionStatus::Pending,
        "A clobbered B's live Pending claim back to Failed"
    );
    handle_b
        .record_submission(&nonce(1), idempotency_fixtures::tx_id(1))
        .expect("B can still record its submission — its claim was not overwritten");
}

/// The same, one step later: B has already SUBMITTED (`Pending → Submitted`) when A's late touch
/// arrives. The touch must not drag a submitted mint back into the retryable pool.
#[test]
fn touch_does_not_overwrite_a_second_handles_submitted_row() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    let handle_a = open_at(&path, &clock);
    claim(&handle_a, &nonce(1), &message_hash(1));
    handle_a.record_failure(&nonce(1)).expect("-> failed");

    let handle_b = open_at(&path, &clock);
    handle_b
        .claim_nonce(&nonce(1), &message_hash(1))
        .expect("B claims");
    handle_b
        .record_submission(&nonce(1), idempotency_fixtures::tx_id(2))
        .expect("B submits");

    let touched = handle_a
        .touch_failed_timestamp(&nonce(1))
        .expect("touch is not an error");
    assert!(!touched);
    assert_eq!(
        handle_a
            .record(&nonce(1))
            .expect("read")
            .expect("present")
            .status(),
        SubmissionStatus::Submitted,
        "A dragged B's submitted mint back to Failed — the mint's record was lost"
    );
}

// PROPAGATION — a store read failure is not swallowed
// ================================================================================================

/// A touch whose read hits a CORRUPT row PROPAGATES the error rather than swallowing it (round 3
/// discarded the `Result`). An unreadable row is corruption, and defaulting it to "not failed" — or to
/// "re-stamp anyway" — would either strand or double-drive the deposit.
#[test]
fn touch_propagates_a_corrupt_row_error() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    {
        let store = open_at(&path, &clock);
        claim(&store, &nonce(1), &message_hash(1));
        store.record_failure(&nonce(1)).expect("-> failed");
    }

    // corrupt the status token directly in the file — a foreign writer / a partial upgrade
    let raw = rusqlite::Connection::open(&path).expect("raw open");
    raw.execute(
        "UPDATE submitted_nonce SET status = 'garbage-token' WHERE nonce_key = ?1",
        rusqlite::params![&nonce(1)[..]],
    )
    .expect("inject corruption");
    drop(raw);

    let store = open_at(&path, &clock);
    let err = store
        .touch_failed_timestamp(&nonce(1))
        .expect_err("a corrupt row must propagate, not be swallowed");
    assert_matches!(err, RelayerError::CorruptStoreRecord { .. });
}
