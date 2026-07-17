//! The `SubmitLedger` tests that drive its `pub(crate)` transitions directly.
//!
//! `claim_burns` and `record_failure` are `pub(crate)` — a fund-safety boundary (see
//! [`SubmitLedger::claim_burns`]), so `tests/`, which is a separate crate, cannot call them. These
//! tests therefore live inside the crate; they live in this FILE, and not at the bottom of
//! `store.rs`, because BUILDER-GATES G3 requires tests in their own module/file rather than inline
//! with the implementation. A sibling test module gets `pub(crate)` access without putting tests in
//! the implementation file, and `crate_posture.rs` pins that structure mechanically.
//!
//! Everything reachable through the ledger's PUBLIC surface stays in `tests/submit_idempotency.rs`,
//! driven through `submit_withdraw`.
//!
//! Each test opens a REAL ledger on a REAL file, exactly as those do: durability is only provable
//! against a file a second handle can reopen, which is why [`SubmitLedger::open`] refuses an
//! in-memory database.

use std::slice;

use assert_matches::assert_matches;

use super::*;

const BURN_TX_ID: &str = "0x82a1c0dffe1d3c5b7a99b8d7f61534537291b0cfee0d2c4b6a89a8c7e6052443";
const OTHER_BURN_TX_ID: &str = "0x1d4b7e2a90c3f5681bb4e0d29a7c3f5e8d1a6b04c9e2f7358a0d5c1b6e93a247";
const CONFLICT_WITHDRAWAL_ID: &str = "6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8";

fn ledger_in(dir: &tempfile::TempDir) -> SubmitLedger {
    SubmitLedger::open(dir.path().join("submitted_burns.sqlite3")).expect("the ledger opens")
}

/// The claim is the decision point, and it is atomic: of two claims on the same burn exactly one is
/// `Claimed`.
#[test]
fn claiming_the_same_burn_twice_yields_claimed_then_already_seen() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let key = BurnKey::new(BURN_TX_ID);

    assert_matches!(
        ledger.claim_burns(slice::from_ref(&key)).unwrap(),
        ClaimOutcome::Claimed(_)
    );
    assert_matches!(
        ledger.claim_burns(&[key]).unwrap(),
        ClaimOutcome::AlreadySeen(r) if r.status() == SubmissionStatus::Pending
    );
}

/// An all-or-nothing multi-key claim: if ANY key in the set is already seen, NOTHING is claimed.
/// Otherwise a partial claim would strand the other burns in `Pending` forever.
#[test]
fn a_multi_burn_claim_that_hits_an_already_seen_burn_claims_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let taken = BurnKey::new(BURN_TX_ID);
    let fresh = BurnKey::new(OTHER_BURN_TX_ID);

    ledger.claim_burns(slice::from_ref(&taken)).unwrap();
    let outcome = ledger.claim_burns(&[fresh.clone(), taken]).unwrap();

    assert_matches!(outcome, ClaimOutcome::AlreadySeen(_));
    assert_eq!(
        ledger.record(&fresh).unwrap().map(|r| r.status()),
        None,
        "the fresh burn must NOT be left claimed by a rolled-back attempt"
    );
}

#[test]
fn a_submitted_burn_cannot_be_walked_back_to_failed() {
    // Failed is the RE-CLAIMABLE state. If a submitted burn could reach it, a retry driver would
    // re-POST a burn Circle may already be releasing — the exact double-withdrawal this ledger exists
    // to prevent.
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let key = BurnKey::new(BURN_TX_ID);
    ledger.claim_burns(slice::from_ref(&key)).unwrap();
    ledger
        .record_submission(&key, Some(CONFLICT_WITHDRAWAL_ID))
        .unwrap();

    assert_matches!(
        ledger.record_failure(&key),
        Err(LedgerError::IllegalStatusTransition {
            from: SubmissionStatus::Submitted,
            to: SubmissionStatus::Failed
        })
    );
}
