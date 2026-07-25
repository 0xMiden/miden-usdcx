//! `T-LA-13` — **which burn each piece of Circle evidence is durably attached to.**
//!
//! `conflict_recovery` pins what a `409` RETURNS and what it does on the wire. This file pins what it
//! WRITES DOWN, which is a separate question with its own way of going wrong.
//!
//! # Why a `withdrawalId` in the wrong record is a fund-safety defect, not untidiness
//!
//! [`SubmissionRecord::withdrawal_id`] is the handle an operator polls. It is the answer to "this burn
//! is blocked — what happened to it?", and reconciliation starts from it. So writing burn A's
//! `withdrawalId` into burn B's record is not a cosmetic slip: it is **durable false evidence**. An
//! operator reconciling B would poll A's withdrawal, read A's `finalized`, and conclude that B was
//! released — a conclusion Circle never supported, reached through a record this service fabricated.
//!
//! The rule this file enforces, on every branch:
//!
//! * a `withdrawalId` is stored **only** on a burn the conflict evidence actually binds it to — the
//!   ONE burn the `409` named;
//! * every other burn is blocked with **`None`**: no claim, because there is no evidence;
//! * a conflict that echoes a burn we never submitted binds its id to **nothing at all** — it is about
//!   someone else's withdrawal entirely.
//!
//! Blocking and attributing are different acts. Every burn here ends up blocked either way; what
//! separates a correct implementation from a dishonest one is what it CLAIMS about each of them, and
//! only an assertion on the stored id can tell the two apart.

use assert_matches::assert_matches;
use serde_json::json;

use withdrawal_listener_attester::idempotency::SubmissionStatus;
use withdrawal_listener_attester::submit::{submit_withdraw, SubmitOutcome};

#[path = "submit_support/mod.rs"]
mod submit_support;

use submit_support::mock_circle::{MockCircle, Reply, Script};
use submit_support::*;

/// Every burn is blocked, and NONE of them claims a withdrawal — asserted together, because "blocked"
/// is the easy half and the ledger is only honest if both hold.
fn assert_blocked_with_no_withdrawal(
    ledger: &withdrawal_listener_attester::idempotency::SubmitLedger,
    burns: &[&str],
) {
    for burn in burns {
        assert_eq!(
            status_of(ledger, burn),
            Some(SubmissionStatus::ReconciliationRequired),
            "{burn} must be blocked"
        );
        assert_eq!(
            withdrawal_id_of(ledger, burn),
            None,
            "{burn} must claim NO withdrawal id — nothing binds one to it, and a stored id is what an \
             operator would poll"
        );
    }
}

// ================================================================================================
// A CONFLICT THAT NAMES A BURN WE NEVER SUBMITTED BINDS ITS ID TO NOTHING
// ================================================================================================

/// The `409` echoes a `burnTxId` this request never sent, and carries a `withdrawalId`. That id
/// describes a withdrawal of **someone else's burn** — it is bound to none of ours, so it must be
/// written against none of ours.
#[tokio::test]
async fn a_conflict_echo_mismatch_binds_its_withdrawal_id_to_no_burn() {
    let mock = MockCircle::start(
        Script::new().withdraw(vec![Reply::json(409, conflict_body_for(THIRD_BURN_TX_ID))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let outcome = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("handled");

    assert_matches!(outcome, SubmitOutcome::ConflictEchoMismatch { .. });
    assert_blocked_with_no_withdrawal(&ledger, &[BURN_TX_ID]);
}

/// The same, multi-burn: an unrelated conflict must not stamp its id across the whole request.
#[tokio::test]
async fn a_multi_burn_conflict_echo_mismatch_binds_its_withdrawal_id_to_no_burn() {
    let mock = MockCircle::start(
        Script::new().withdraw(vec![Reply::json(409, conflict_body_for(THIRD_BURN_TX_ID))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    submit_withdraw(
        &client_for(&mock),
        &ledger,
        authorized_for_burns(&[BURN_TX_ID, OTHER_BURN_TX_ID]),
    )
    .await
    .expect("handled");

    assert_blocked_with_no_withdrawal(&ledger, &[BURN_TX_ID, OTHER_BURN_TX_ID]);
}

/// A `409` with no `withdrawalId` at all has nothing to bind: every burn blocked, none claiming one.
#[tokio::test]
async fn a_conflict_without_a_withdrawal_id_binds_none_to_any_burn() {
    let mock = MockCircle::start(
        Script::new().withdraw(vec![Reply::json(409, json!({ "burnTxId": BURN_TX_ID }))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    submit_withdraw(
        &client_for(&mock),
        &ledger,
        authorized_for_burns(&[BURN_TX_ID, OTHER_BURN_TX_ID]),
    )
    .await
    .expect("handled");

    assert_blocked_with_no_withdrawal(&ledger, &[BURN_TX_ID, OTHER_BURN_TX_ID]);
}

// ================================================================================================
// THE ID GOES ON THE NAMED BURN — AND NOWHERE ELSE
// ================================================================================================

/// **A failed recovery poll must not smear the id across the neighbours.**
///
/// The `409` bound `CONFLICT_WITHDRAWAL_ID` to `BURN_TX_ID` and said nothing whatsoever about the
/// others. The poll then failed, so every burn stays blocked — but the id is evidence about ONE of
/// them, and only that one may carry it.
#[tokio::test]
async fn a_failed_recovery_poll_binds_the_id_only_to_the_conflict_named_burn() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_for(BURN_TX_ID))])
            .status(vec![Reply::json(
                404,
                support::fixture_json("withdrawal_status_404"),
            )]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    submit_withdraw(
        &client_for(&mock),
        &ledger,
        authorized_for_burns(&[BURN_TX_ID, OTHER_BURN_TX_ID, THIRD_BURN_TX_ID]),
    )
    .await
    .expect_err("an unresolvable recovery is surfaced");

    // the burn Circle actually named: it keeps the lead an operator needs
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired)
    );
    assert_eq!(
        withdrawal_id_of(&ledger, BURN_TX_ID).as_deref(),
        Some(CONFLICT_WITHDRAWAL_ID),
        "the conflict bound this id to THIS burn — that is the one true fact here"
    );

    // the neighbours: blocked, but claiming nothing
    assert_blocked_with_no_withdrawal(&ledger, &[OTHER_BURN_TX_ID, THIRD_BURN_TX_ID]);
}

/// **A recovered-status burn mismatch must not smear the id either.**
///
/// The conflict named `BURN_TX_ID`; the status came back about a different burn, so the recovery is a
/// defect. Everything is blocked — but the neighbours were never mentioned by anything, so they must
/// claim nothing.
#[tokio::test]
async fn a_recovered_status_mismatch_binds_the_id_only_to_the_conflict_named_burn() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_for(BURN_TX_ID))])
            .status(vec![Reply::json(
                200,
                status_body_for(THIRD_BURN_TX_ID, "finalized"),
            )]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let outcome = submit_withdraw(
        &client_for(&mock),
        &ledger,
        authorized_for_burns(&[BURN_TX_ID, OTHER_BURN_TX_ID]),
    )
    .await
    .expect("handled");

    assert_matches!(outcome, SubmitOutcome::ConflictEchoMismatch { .. });
    assert_eq!(
        withdrawal_id_of(&ledger, BURN_TX_ID).as_deref(),
        Some(CONFLICT_WITHDRAWAL_ID),
        "the 409 itself still bound this id to this burn, even though the status was incoherent"
    );
    assert_blocked_with_no_withdrawal(&ledger, &[OTHER_BURN_TX_ID]);
}

/// The successful recovery, checked the same way: `finalized` settles the named burn WITH its id, and
/// the neighbours are blocked claiming nothing.
#[tokio::test]
async fn a_successful_recovery_binds_the_id_only_to_the_named_burn() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_for(BURN_TX_ID))])
            .status(vec![Reply::json(
                200,
                status_body_for(BURN_TX_ID, "finalized"),
            )]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    submit_withdraw(
        &client_for(&mock),
        &ledger,
        authorized_for_burns(&[BURN_TX_ID, OTHER_BURN_TX_ID]),
    )
    .await
    .expect("recovered");

    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::Finalized)
    );
    assert_eq!(
        withdrawal_id_of(&ledger, BURN_TX_ID).as_deref(),
        Some(CONFLICT_WITHDRAWAL_ID)
    );
    assert_blocked_with_no_withdrawal(&ledger, &[OTHER_BURN_TX_ID]);
}

/// A non-`finalized` recovery: the named burn keeps the id (it is real evidence, and the operator will
/// need it), the neighbours still claim nothing.
#[tokio::test]
async fn a_non_finalized_recovery_binds_the_id_only_to_the_named_burn() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_for(OTHER_BURN_TX_ID))])
            .status(vec![Reply::json(
                200,
                status_body_for(OTHER_BURN_TX_ID, "failed"),
            )]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    submit_withdraw(
        &client_for(&mock),
        &ledger,
        authorized_for_burns(&[BURN_TX_ID, OTHER_BURN_TX_ID]),
    )
    .await
    .expect("handled");

    assert_eq!(
        withdrawal_id_of(&ledger, OTHER_BURN_TX_ID).as_deref(),
        Some(CONFLICT_WITHDRAWAL_ID),
        "the conflict named this burn"
    );
    assert_blocked_with_no_withdrawal(&ledger, &[BURN_TX_ID]);
}

// ================================================================================================
// THE NON-CONFLICT PATHS CLAIM NOTHING EITHER
// ================================================================================================

/// An exhausted `5xx` budget blocks the burn, but Circle never named a withdrawal — so no id is
/// invented for it.
#[tokio::test]
async fn an_exhausted_retry_budget_binds_no_withdrawal_id() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::Status(500)]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect_err("surfaced");

    assert_blocked_with_no_withdrawal(&ledger, &[BURN_TX_ID]);
}

/// A `201` binds each burn to ITS OWN returned withdrawal — never to a neighbour's.
#[tokio::test]
async fn a_201_binds_each_burn_to_its_own_returned_withdrawal_id() {
    let other_withdrawal = "aaaabbbb-cccc-dddd-eeee-ffff00001111";
    let mut second = created_body_for(OTHER_BURN_TX_ID)[0].clone();
    second["withdrawalId"] = json!(other_withdrawal);
    let body = json!([created_body_for(BURN_TX_ID)[0].clone(), second]);

    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(201, body)]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    submit_withdraw(&client_for(&mock), &ledger, authorized_two_batches())
        .await
        .expect("submitted");

    assert_eq!(
        withdrawal_id_of(&ledger, BURN_TX_ID).as_deref(),
        Some(CONFLICT_WITHDRAWAL_ID),
        "each burn carries the withdrawal Circle returned FOR IT"
    );
    assert_eq!(
        withdrawal_id_of(&ledger, OTHER_BURN_TX_ID).as_deref(),
        Some(other_withdrawal),
        "not the other batch's — the array is paired by burnTxId, not by luck"
    );
}
