//! `tests/idempotency_claim.rs` — **the claim**: the store-level portion of `T-RLY-09` (a
//! re-observed nonce yields no second submission) and the atomic acquisition that makes it real.
//!
//! `claim_nonce` is the ONE mint-decision point: a caller mints on [`ClaimOutcome::Claimed`] and on
//! nothing else. Everything this suite asserts follows from that:
//!
//! * a nonce nobody has seen is claimed once, by exactly one observer, and is `Pending` afterwards;
//! * a nonce that is claimed, submitted, committed or already-minted comes back `AlreadySeen` — no
//!   second mint attempt, and the stored record is not touched by the re-observation;
//! * a nonce whose attempt **failed** is RE-claimable, atomically: exactly one observer moves it out
//!   of `Failed` into an owned `Pending` and gets `Claimed`. Without that, a failed mint could only
//!   be retried by reading "not submitted" and then writing — the read-then-write race this module
//!   exists to prevent — or not at all, which strands the deposit;
//! * two attestations claiming one nonce with different `messageHash`es is an anomaly, refused, and
//!   the stored hash is never overwritten.
//!
//! The concurrency tests race real observers through their own store handles on ONE file — the shape
//! of two relayer processes during a deploy overlap. A JSON/bincode store's read-modify-write would
//! fail exactly there, which is the point of the persistence choice.

mod idempotency_fixtures;

use std::{
    sync::{Arc, Barrier},
    thread,
};

use assert_matches::assert_matches;
use idempotency_fixtures::{
    claim, drive_to, fresh_store, message_hash, nonce, open_at, status_of, store_path, tx_id,
    ManualClock,
};
use rstest::rstest;
use tempfile::TempDir;
use xreserve_deposit_relayer::{
    error::RelayerError,
    idempotency::{ClaimOutcome, SubmissionStatus},
};

// -------------------------------------------------------------------------------------------------
// the first observation
// -------------------------------------------------------------------------------------------------

/// The empty store knows nothing: an unseen nonce is not submitted and has no record. (`None`, not a
/// fabricated `Pending` — "never observed" and "mid-flight" are different states, and a caller must
/// be able to tell them apart.)
#[test]
fn an_unseen_nonce_is_not_submitted_and_has_no_record() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    assert!(!store
        .is_nonce_submitted(&nonce(1))
        .expect("lookup succeeds"));
    assert_matches!(store.record(&nonce(1)), Ok(None));
}

/// The first observation CLAIMS the nonce: a `Pending` record, stamped with the observation time,
/// carrying the attestation's `messageHash` and no transaction yet.
#[test]
fn the_first_observation_claims_the_nonce_as_pending() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    let record = claim(&store, &nonce(1), &message_hash(1));

    assert_eq!(record.nonce_key(), &nonce(1));
    assert_eq!(record.attestation_message_hash(), &message_hash(1));
    assert_eq!(record.status(), SubmissionStatus::Pending);
    assert_eq!(record.submitted_tx_id(), None);
    assert_eq!(record.block_num(), None);
    assert_eq!(record.timestamp(), 1_000);

    assert!(store
        .is_nonce_submitted(&nonce(1))
        .expect("lookup succeeds"));
}

// -------------------------------------------------------------------------------------------------
// T-RLY-09 — the re-observation
// -------------------------------------------------------------------------------------------------

/// The SECOND observation of the same nonce — the same attestation on the next poll — is
/// `AlreadySeen`: the caller has its answer without a second mint attempt, and the stored record is
/// exactly the one the first observation wrote. The clock has moved, so a store that re-stamped
/// (i.e. re-claimed) the record would be caught here.
#[test]
fn a_re_observed_nonce_is_already_seen_and_the_record_is_not_rewritten() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    let first = claim(&store, &nonce(1), &message_hash(1));

    clock.advance(3_600);
    let outcome = store
        .claim_nonce(&nonce(1), &message_hash(1))
        .expect("the re-observation is not an error — it is a no-op");

    assert!(
        !outcome.is_claimed(),
        "a re-observed in-flight nonce must not be re-claimed"
    );
    let seen = assert_matches!(outcome, ClaimOutcome::AlreadySeen(record) => record);
    assert_eq!(
        seen.timestamp(),
        first.timestamp(),
        "the re-observation rewrote the record"
    );
    assert_eq!(seen.status(), SubmissionStatus::Pending);
    assert_eq!(seen.attestation_message_hash(), &message_hash(1));
}

/// Re-observing a nonce whose mint is already SUBMITTED hands back the submitted record —
/// transaction id and all — and still refuses to re-claim. This is the steady state of the dedup:
/// Circle keeps serving the attestation until it is minted, and every poll must fall through here.
#[test]
fn a_nonce_re_observed_after_submission_is_already_seen_with_its_transaction() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    clock.advance(5);
    store
        .record_submission(&nonce(1), tx_id(7))
        .expect("pending -> submitted");

    clock.advance(60);
    let seen = assert_matches!(
        store.claim_nonce(&nonce(1), &message_hash(1)),
        Ok(ClaimOutcome::AlreadySeen(record)) => record
    );

    assert_eq!(seen.status(), SubmissionStatus::Submitted);
    assert_eq!(seen.submitted_tx_id(), Some(&tx_id(7)));
    assert_eq!(
        seen.timestamp(),
        1_005,
        "the re-observation rewrote the submission timestamp"
    );
}

/// Which statuses answer `AlreadySeen` to a re-observation, and which one answers `Claimed`.
///
/// The `Failed` row is the whole point: it is the ONE status a re-observation re-claims, because a
/// failed attempt has not minted anything and must be retryable. Everything else — in flight,
/// submitted, committed, already-minted on chain — is a mint that has happened or is happening, and
/// a second attempt could only burn a transaction on the on-chain `usedNonces` assert.
#[rstest]
#[case::pending(SubmissionStatus::Pending, false)]
#[case::submitted(SubmissionStatus::Submitted, false)]
#[case::committed(SubmissionStatus::Committed, false)]
#[case::already_minted(SubmissionStatus::AlreadyMinted, false)]
#[case::failed(SubmissionStatus::Failed, true)]
fn only_a_failed_nonce_is_re_claimed(
    #[case] status: SubmissionStatus,
    #[case] expect_claimed: bool,
) {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    drive_to(&store, &nonce(1), status);

    let outcome = store
        .claim_nonce(&nonce(1), &message_hash(1))
        .expect("the re-observation answers");

    assert_eq!(
        outcome.is_claimed(),
        expect_claimed,
        "a re-observed {status} nonce must {} be re-claimed",
        if expect_claimed { "" } else { "not" }
    );
    // either way the nonce is OWNED once the re-observation returns: freshly re-claimed by this
    // observer, or already in flight for someone else. A third observer arriving now claims nothing.
    assert!(store.is_nonce_submitted(&nonce(1)).expect("lookup"));
}

/// `is_nonce_submitted` — the READ of the same decision. It blocks every status except `Failed` (and
/// answers `false` for a nonce nobody has seen).
#[rstest]
#[case::pending(SubmissionStatus::Pending, true)]
#[case::submitted(SubmissionStatus::Submitted, true)]
#[case::committed(SubmissionStatus::Committed, true)]
#[case::already_minted(SubmissionStatus::AlreadyMinted, true)]
#[case::failed(SubmissionStatus::Failed, false)]
fn is_nonce_submitted_blocks_every_status_except_failed(
    #[case] status: SubmissionStatus,
    #[case] expected: bool,
) {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    drive_to(&store, &nonce(1), status);

    assert_eq!(
        store
            .is_nonce_submitted(&nonce(1))
            .expect("lookup succeeds"),
        expected
    );
    assert_eq!(status.blocks_resubmission(), expected);
}

// -------------------------------------------------------------------------------------------------
// the RETRY claim — a failed attempt is re-acquirable, atomically
// -------------------------------------------------------------------------------------------------

/// The ordinary retry. A submission fails; the next observation of that attestation RE-CLAIMS the
/// nonce — one atomic step, `Claimed`, back in an owned `Pending` — and the retry submits and
/// commits.
///
/// The record's continuity is asserted too: the retry claim keeps the attestation hash it was
/// bound to, and keeps the FAILED transaction's id (the evidence of what was actually sent) until a
/// new submission replaces it.
#[test]
fn a_failed_nonce_is_re_claimed_and_the_retry_can_commit() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    store
        .record_submission(&nonce(1), tx_id(7))
        .expect("pending -> submitted");
    store
        .record_failure(&nonce(1))
        .expect("submitted -> failed");

    clock.advance(30);
    let reclaimed = claim(&store, &nonce(1), &message_hash(1));

    assert_eq!(
        reclaimed.status(),
        SubmissionStatus::Pending,
        "a retry claim must land in an OWNED in-flight state"
    );
    assert_eq!(reclaimed.timestamp(), 1_030);
    assert_eq!(reclaimed.attestation_message_hash(), &message_hash(1));
    assert_eq!(
        reclaimed.submitted_tx_id(),
        Some(&tx_id(7)),
        "the failed attempt's transaction id is the evidence of what was sent — it is not erased"
    );
    assert!(
        store.is_nonce_submitted(&nonce(1)).expect("lookup"),
        "a re-claimed nonce is owned again: a THIRD observer must not also claim it"
    );

    let retried = store
        .record_submission(&nonce(1), tx_id(8))
        .expect("the retry submits");
    assert_eq!(retried.submitted_tx_id(), Some(&tx_id(8)));

    let committed = store
        .record_commit(&nonce(1), 12)
        .expect("the retry commits");
    assert_eq!(committed.status(), SubmissionStatus::Committed);
    assert_eq!(committed.block_num(), Some(12));
}

/// The retry claim is the ONLY way out of `Failed`. Submitting straight from a failed record —
/// "I read that it was not submitted, so I submit" — is the read-then-write race, and it is refused:
/// the caller must go back through the atomic claim.
#[test]
fn a_failed_nonce_cannot_be_submitted_without_re_claiming_it() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    store.record_failure(&nonce(1)).expect("pending -> failed");

    let err = store
        .record_submission(&nonce(1), tx_id(8))
        .expect_err("a submission that skipped the retry claim must be refused");

    assert_matches!(err, RelayerError::IllegalStatusTransition { from, to } => {
        assert_eq!(from, SubmissionStatus::Failed);
        assert_eq!(to, SubmissionStatus::Submitted);
    });
    assert_eq!(
        status_of(&store, &nonce(1)),
        SubmissionStatus::Failed,
        "the refused submission moved the record anyway"
    );
}

/// A nonce freed by [`IdempotencyStore::reclaim_stale_pending`] — the recovery for a claim stranded
/// by a crash — is re-claimable across a RESTART, through the same atomic claim. This is the whole
/// crash-recovery loop: crash mid-submit → the record is stranded `Pending` → the operator's
/// reclaim frees it → the restarted poller re-observes the attestation and re-claims it → the mint
/// finally lands.
#[test]
fn a_stale_reclaimed_nonce_is_re_claimable_after_a_restart() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    {
        let store = open_at(&path, &clock);
        claim(&store, &nonce(1), &message_hash(1));
        // the relayer dies between the claim and the submit: the record is stranded Pending
    }

    {
        let store = open_at(&path, &clock);
        assert_eq!(status_of(&store, &nonce(1)), SubmissionStatus::Pending);
        assert!(
            !store
                .claim_nonce(&nonce(1), &message_hash(1))
                .expect("claim answers")
                .is_claimed(),
            "a stranded Pending must NOT be re-claimed by a bare re-observation — its submit could \
             still be in flight; only the explicit stale reclaim frees it"
        );

        clock.advance(601);
        assert_eq!(
            store.reclaim_stale_pending(600).expect("reclaim"),
            vec![nonce(1)]
        );
        // and the relayer dies again, right after the reclaim
    }

    let restarted = open_at(&path, &clock);
    assert_eq!(
        status_of(&restarted, &nonce(1)),
        SubmissionStatus::Failed,
        "the reclaim did not survive the restart"
    );

    let reclaimed = claim(&restarted, &nonce(1), &message_hash(1));
    assert_eq!(reclaimed.status(), SubmissionStatus::Pending);
    assert_eq!(reclaimed.attestation_message_hash(), &message_hash(1));

    restarted
        .record_submission(&nonce(1), tx_id(3))
        .expect("the recovered nonce submits");
    assert_eq!(
        status_of(&restarted, &nonce(1)),
        SubmissionStatus::Submitted
    );
}

/// The retry driver's work list: the failed records, oldest first. Without it a failed nonce could
/// only be retried if Circle happened to serve its attestation again — but the cursor only moves
/// FORWARD, so an attestation on a page the poll has already passed would never be re-observed, and
/// its deposit would be stranded for good.
#[test]
fn the_retryable_work_list_holds_exactly_the_failed_records_oldest_first() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    // a failure at t=1000
    claim(&store, &nonce(1), &message_hash(1));
    store.record_failure(&nonce(1)).expect("failed");

    // an in-flight one, and a committed one: neither is retryable
    claim(&store, &nonce(2), &message_hash(2));
    claim(&store, &nonce(3), &message_hash(3));
    drive_to(&store, &nonce(3), SubmissionStatus::Committed);

    // a second failure, later
    clock.advance(100);
    claim(&store, &nonce(4), &message_hash(4));
    store.record_failure(&nonce(4)).expect("failed");

    let retryable = store.retryable(10).expect("the work list reads");
    let keys: Vec<[u8; 32]> = retryable.iter().map(|record| *record.nonce_key()).collect();

    assert_eq!(
        keys,
        vec![nonce(1), nonce(4)],
        "the work list must hold exactly the failed records, oldest first"
    );
    assert!(retryable
        .iter()
        .all(|record| record.status() == SubmissionStatus::Failed));
    assert_eq!(
        retryable[0].attestation_message_hash(),
        &message_hash(1),
        "the retry needs the attestation hash to re-fetch the payload it must re-mint"
    );

    assert_eq!(
        store.retryable(1).expect("the work list reads").len(),
        1,
        "the limit bounds the batch"
    );
}

// -------------------------------------------------------------------------------------------------
// the impostor attestation
// -------------------------------------------------------------------------------------------------

/// Two DIFFERENT attestations claiming the SAME nonce is an anomaly — one of them is not what it
/// says it is (a re-issued attestation, a mis-keyed cache, a substitution on the path). The store
/// refuses it with a typed error naming both digests and does NOT overwrite the stored hash: the log
/// must keep saying what was actually claimed and minted.
///
/// It is refused in EVERY status, including `Failed`: the retry claim is not a way in for an
/// impostor.
#[rstest]
#[case::pending(SubmissionStatus::Pending)]
#[case::submitted(SubmissionStatus::Submitted)]
#[case::committed(SubmissionStatus::Committed)]
#[case::already_minted(SubmissionStatus::AlreadyMinted)]
#[case::failed(SubmissionStatus::Failed)]
fn a_second_attestation_for_the_same_nonce_is_refused_in_every_status(
    #[case] status: SubmissionStatus,
) {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    drive_to(&store, &nonce(1), status);

    let err = store
        .claim_nonce(&nonce(1), &message_hash(2))
        .expect_err("a different messageHash for a claimed nonce must be refused");

    assert_matches!(err, RelayerError::NonceMessageHashMismatch { nonce_key, stored, observed } => {
        assert_eq!(nonce_key, nonce(1));
        assert_eq!(stored, message_hash(1));
        assert_eq!(observed, message_hash(2));
    });

    let record = store.record(&nonce(1)).expect("read").expect("still there");
    assert_eq!(
        record.attestation_message_hash(),
        &message_hash(1),
        "the impostor overwrote the stored attestation hash"
    );
    assert_eq!(
        record.status(),
        status,
        "the refused claim moved the record's status"
    );
}

// -------------------------------------------------------------------------------------------------
// the claim is atomic — the property a read-modify-write store cannot give
// -------------------------------------------------------------------------------------------------

/// Many observers race for the same FRESH nonce, each through its own store handle on the same file
/// (the shape of two relayer processes, or two tasks, seeing one attestation at once): exactly ONE
/// gets `Claimed`, so exactly one mint attempt is possible.
#[test]
fn only_one_of_many_concurrent_observers_claims_a_fresh_nonce() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);
    drop(open_at(&path, &clock)); // the schema exists before the racers arrive

    let claims = race_to_claim(&path, &clock, nonce(1));

    assert_eq!(
        claims, 1,
        "{claims} racing observers claimed one fresh nonce — the claim is not atomic"
    );
    let store = open_at(&path, &clock);
    assert_eq!(status_of(&store, &nonce(1)), SubmissionStatus::Pending);
}

/// The same race, on a FAILED nonce — the retry path. Several observers (the poller re-seeing the
/// attestation, the retry driver working its list) reach for the same failed record at once, and
/// exactly ONE re-acquires it. A retry claim that was not atomic would let two of them mint the same
/// deposit again, which is precisely what the seam is for.
#[test]
fn only_one_of_many_concurrent_observers_re_claims_a_failed_nonce() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    {
        let store = open_at(&path, &clock);
        claim(&store, &nonce(1), &message_hash(1));
        store
            .record_submission(&nonce(1), tx_id(7))
            .expect("submitted");
        store.record_failure(&nonce(1)).expect("failed");
    }

    let claims = race_to_claim(&path, &clock, nonce(1));

    assert_eq!(
        claims, 1,
        "{claims} racing observers re-claimed one failed nonce — the retry claim is not atomic"
    );
    let store = open_at(&path, &clock);
    assert_eq!(
        status_of(&store, &nonce(1)),
        SubmissionStatus::Pending,
        "the winner owns the retry"
    );
}

/// Eight observers, eight independent store handles on one file, all claiming `key` at once. Returns
/// how many of them won the claim — which must always be exactly one.
fn race_to_claim(path: &std::path::Path, clock: &Arc<ManualClock>, key: [u8; 32]) -> usize {
    const OBSERVERS: usize = 8;

    let barrier = Arc::new(Barrier::new(OBSERVERS));
    let handles: Vec<_> = (0..OBSERVERS)
        .map(|_| {
            let path = path.to_path_buf();
            let clock = clock.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || -> bool {
                let store = open_at(&path, &clock);
                barrier.wait();
                store
                    .claim_nonce(&key, &message_hash(1))
                    .expect("every racer gets an answer, not an error")
                    .is_claimed()
            })
        })
        .collect();

    handles
        .into_iter()
        .map(|handle| handle.join().expect("no racer panicked"))
        .filter(|claimed| *claimed)
        .count()
}

/// Two live handles on one file share ONE log — a write through either is immediately visible to the
/// other. (A per-process in-memory cache would pass every single-handle test in this suite and fail
/// exactly here.)
#[test]
fn two_handles_on_the_same_file_share_one_log() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    let first = open_at(&path, &clock);
    let second = open_at(&path, &clock);

    claim(&first, &nonce(1), &message_hash(1));

    assert!(
        second.is_nonce_submitted(&nonce(1)).expect("lookup"),
        "the second handle cannot see the first handle's claim"
    );
    assert_matches!(
        second.claim_nonce(&nonce(1), &message_hash(1)),
        Ok(ClaimOutcome::AlreadySeen(_))
    );
}
