//! `tests/idempotency_status_machine.rs` — the `SubmissionStatus` machine: the edges that exist, the
//! edges that do not, and the recovery transition that keeps a crashed claim from stranding a
//! deposit.
//!
//! The machine is the store's whole opinion about what may happen to a mint. Its edges are chosen so
//! that the two failure modes the seam can actually cause stay bounded: a mint attempted twice (no
//! `Submitted → Submitted`, no way out of a settled record, no way to Pending except the atomic
//! claim) and a mint withheld forever (`Failed` is retryable, and a `Pending` stranded by a crash is
//! reclaimable). Every illegal edge is refused with the exact `from → to` it refused — and, just as
//! importantly, leaves the record untouched.

mod idempotency_fixtures;

use assert_matches::assert_matches;
use idempotency_fixtures::{
    claim, drive_to, fresh_store, message_hash, nonce, status_of, tx_id, ManualClock, Transition,
};
use rstest::rstest;
use xreserve_deposit_relayer::{error::RelayerError, idempotency::SubmissionStatus};

// -------------------------------------------------------------------------------------------------
// the edges that exist
// -------------------------------------------------------------------------------------------------

/// The happy path: claim → submit (the transaction id is recorded) → commit (the block number is).
/// Each transition re-stamps the record with the time it happened, and the transaction id survives
/// the commit — it is the mint's evidence, and clearing it on the next transition would erase it.
#[test]
fn the_happy_path_walks_pending_then_submitted_then_committed() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));

    clock.advance(10);
    let submitted = store
        .record_submission(&nonce(1), tx_id(7))
        .expect("pending -> submitted");
    assert_eq!(submitted.status(), SubmissionStatus::Submitted);
    assert_eq!(submitted.submitted_tx_id(), Some(&tx_id(7)));
    assert_eq!(submitted.block_num(), None);
    assert_eq!(submitted.timestamp(), 1_010);

    clock.advance(30);
    let committed = store
        .record_commit(&nonce(1), 8_675_309)
        .expect("submitted -> committed");
    assert_eq!(committed.status(), SubmissionStatus::Committed);
    assert_eq!(
        committed.submitted_tx_id(),
        Some(&tx_id(7)),
        "the commit erased the transaction id it was committing"
    );
    assert_eq!(committed.block_num(), Some(8_675_309));
    assert_eq!(committed.timestamp(), 1_040);
    assert!(committed.status().is_terminal());
}

/// A failure can be recorded whether or not the transaction went out — the submit leg can fail
/// while building the note, or after sending it — and it re-stamps the record without erasing what
/// was sent.
#[rstest]
#[case::before_the_transaction_went_out(SubmissionStatus::Pending, None)]
#[case::after_the_transaction_went_out(SubmissionStatus::Submitted, Some(tx_id(1)))]
fn a_failure_can_be_recorded_from_pending_or_submitted(
    #[case] from: SubmissionStatus,
    #[case] expected_tx: Option<xreserve_deposit_relayer::idempotency::TxId>,
) {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    drive_to(&store, &nonce(1), from);

    clock.advance(7);
    let failed = store.record_failure(&nonce(1)).expect("-> failed");

    assert_eq!(failed.status(), SubmissionStatus::Failed);
    assert_eq!(failed.timestamp(), 1_007);
    assert_eq!(failed.submitted_tx_id(), expected_tx.as_ref());
    assert!(
        !store.is_nonce_submitted(&nonce(1)).expect("lookup"),
        "a failed submission must be retryable — treating it as submitted strands the deposit"
    );
    assert!(!failed.status().is_terminal());
}

/// `AlreadyMinted` — the chain answered "this nonce is already in `usedNonces`" — is TERMINAL. It is
/// the store learning that the on-chain safety backstop already fired; another attempt could only
/// burn a transaction on an assert that must fail. It is reachable from every pre-terminal status,
/// because the chain can tell us at any point.
#[rstest]
#[case::from_pending(SubmissionStatus::Pending)]
#[case::from_submitted(SubmissionStatus::Submitted)]
#[case::from_failed(SubmissionStatus::Failed)]
fn already_minted_is_reachable_from_any_live_status_and_is_terminal(
    #[case] from: SubmissionStatus,
) {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    drive_to(&store, &nonce(1), from);

    let settled = store
        .record_already_minted(&nonce(1))
        .expect("-> already minted");

    assert_eq!(settled.status(), SubmissionStatus::AlreadyMinted);
    assert!(settled.status().is_terminal());
    assert!(store.is_nonce_submitted(&nonce(1)).expect("lookup"));
}

// -------------------------------------------------------------------------------------------------
// the edges that do not exist
// -------------------------------------------------------------------------------------------------

/// Every illegal edge, refused by the EXACT `from → to` it refused — and the record left untouched
/// (no half-written status, no bumped timestamp, no stray transaction id).
///
/// Why each is illegal:
/// * a settled record (`Committed` / `AlreadyMinted`) has no outgoing edge — resurrecting one
///   re-opens a nonce whose mint already happened;
/// * a commit without a submission would record a block for a transaction that was never sent;
/// * `Submitted → Submitted` is the double-submit the seam exists to prevent;
/// * `Failed → Submitted` is the read-then-write retry race: the way out of `Failed` is the atomic
///   re-claim (`claim_nonce`), never a bare submission.
#[rstest]
#[case::committed_to_submitted(SubmissionStatus::Committed, Transition::Submit)]
#[case::committed_to_failed(SubmissionStatus::Committed, Transition::Fail)]
#[case::committed_to_already_minted(SubmissionStatus::Committed, Transition::AlreadyMinted)]
#[case::already_minted_to_submitted(SubmissionStatus::AlreadyMinted, Transition::Submit)]
#[case::already_minted_to_failed(SubmissionStatus::AlreadyMinted, Transition::Fail)]
#[case::already_minted_to_committed(SubmissionStatus::AlreadyMinted, Transition::Commit)]
#[case::pending_to_committed(SubmissionStatus::Pending, Transition::Commit)]
#[case::submitted_to_submitted(SubmissionStatus::Submitted, Transition::Submit)]
#[case::failed_to_submitted(SubmissionStatus::Failed, Transition::Submit)]
#[case::failed_to_committed(SubmissionStatus::Failed, Transition::Commit)]
fn an_illegal_transition_is_refused_and_leaves_the_record_untouched(
    #[case] from: SubmissionStatus,
    #[case] attempt: Transition,
) {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    drive_to(&store, &nonce(1), from);
    let before = store.record(&nonce(1)).expect("read").expect("exists");

    clock.advance(1_234);
    let err = attempt
        .apply(&store, &nonce(1))
        .expect_err("an illegal transition must be refused");

    assert_matches!(err, RelayerError::IllegalStatusTransition { from: f, to: t } => {
        assert_eq!(f, from);
        assert_eq!(t, attempt.target());
    });

    let after = store.record(&nonce(1)).expect("read").expect("exists");
    assert_eq!(
        after, before,
        "the refused transition still changed the record"
    );
}

/// A transition on a nonce that was never claimed is a caller bug, not a silent insert: recording a
/// submission for an unknown nonce would create a log row with no attestation behind it (there is no
/// `messageHash` to put in it) — exactly the row an audit would later have to explain.
#[rstest]
#[case::submit(Transition::Submit)]
#[case::commit(Transition::Commit)]
#[case::already_minted(Transition::AlreadyMinted)]
#[case::fail(Transition::Fail)]
fn a_transition_on_an_unclaimed_nonce_is_refused(#[case] attempt: Transition) {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    let err = attempt
        .apply(&store, &nonce(3))
        .expect_err("a transition without a claim must be refused");

    assert_matches!(err, RelayerError::UnknownNonce { nonce_key } => {
        assert_eq!(nonce_key, nonce(3));
    });
    assert_matches!(
        store.record(&nonce(3)),
        Ok(None),
        "the refused transition inserted a record"
    );
}

// -------------------------------------------------------------------------------------------------
// recovery — the stranded claim
// -------------------------------------------------------------------------------------------------

/// The liveness escape hatch, and its bounds. A relayer that dies between the claim and the submit
/// leaves a `Pending` record that nothing retries — the deposit is stranded, which is the worst
/// thing this store can do. `reclaim_stale_pending` is the explicit recovery: `Pending` records
/// older than the threshold become `Failed` (i.e. re-claimable).
///
/// It touches NOTHING else — not a young `Pending` (its submit may be in flight this second) and not
/// a `Submitted` (its transaction may still land; whether to abandon it is the submit leg's call,
/// made against the chain, not this store's against a clock).
#[test]
fn reclaim_stale_pending_frees_only_stranded_claims() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1)); // stranded
    claim(&store, &nonce(2), &message_hash(2));
    store
        .record_submission(&nonce(2), tx_id(2))
        .expect("pending -> submitted"); // in flight

    clock.advance(601);
    claim(&store, &nonce(3), &message_hash(3)); // young

    let reclaimed = store.reclaim_stale_pending(600).expect("reclaim succeeds");

    assert_eq!(
        reclaimed,
        vec![nonce(1)],
        "exactly the stranded claim is freed"
    );
    assert_eq!(status_of(&store, &nonce(1)), SubmissionStatus::Failed);
    assert!(!store.is_nonce_submitted(&nonce(1)).expect("lookup"));

    assert_eq!(
        status_of(&store, &nonce(2)),
        SubmissionStatus::Submitted,
        "a submitted transaction was reclaimed out from under the submit leg"
    );
    assert_eq!(
        status_of(&store, &nonce(3)),
        SubmissionStatus::Pending,
        "a young claim was reclaimed while its submit was still in flight"
    );
}

/// The reclaim is re-runnable and idempotent-in-effect: a second pass over an already-freed record
/// finds nothing to free (it is `Failed` now, not `Pending`), so an operator can run it on a timer
/// without churning the log.
#[test]
fn a_second_reclaim_pass_finds_nothing_to_free() {
    let clock = ManualClock::at(1_000);
    let (_dir, store) = fresh_store(&clock);

    claim(&store, &nonce(1), &message_hash(1));
    clock.advance(601);

    assert_eq!(
        store.reclaim_stale_pending(600).expect("first pass"),
        vec![nonce(1)]
    );
    let after_first = store.record(&nonce(1)).expect("read").expect("exists");

    clock.advance(601);
    assert!(
        store
            .reclaim_stale_pending(600)
            .expect("second pass")
            .is_empty(),
        "the second pass freed a record that was already failed"
    );
    assert_eq!(
        store.record(&nonce(1)).expect("read").expect("exists"),
        after_first,
        "the second pass re-stamped a record it did not free"
    );
}
