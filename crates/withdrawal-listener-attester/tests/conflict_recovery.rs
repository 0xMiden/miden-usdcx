//! `T-LA-13` — the **`409` conflict-recovery** contract on `POST /v1/withdraw` (§10.10).
//!
//! A duplicate `burnTxId` must NEVER be reported as a success, and must NEVER be blindly re-sent —
//! either mistake releases native USDC twice.
//!
//! # Non-vacuity: the mock's CALL LOG is the oracle
//!
//! An outcome assertion alone proves nothing about what went on the wire — a driver that re-POSTed and
//! then returned a tidy outcome would pass it. So every case asserts on the call log: the exact number
//! of `POST /v1/withdraw` attempts, and the exact number (and path) of `GET /v1/withdrawal/{id}`
//! recoveries. The mock's reply queue REPEATS its last element forever, so a blind re-send genuinely
//! could happen and genuinely would be counted.
//!
//! # The binding is per-burn, and that is what the multi-burn cases are for
//!
//! A `POST /v1/withdraw` carries 1-5 batches; a `409` names ONE `burnTxId`. So "which burn does this
//! conflict bind to?" is a real question the moment a request carries more than one — and answering it
//! "any of them" would let a conflict about burn A settle burn B with no Circle evidence for B at all.
//! Every recovery case below is therefore run multi-burn as well as single-burn.

use assert_matches::assert_matches;
use rstest::rstest;
use serde_json::{json, Value};

use withdrawal_listener_attester::circle::schema::WithdrawalStatusKind;
use withdrawal_listener_attester::error::ListenerError;
use withdrawal_listener_attester::idempotency::SubmissionStatus;
use withdrawal_listener_attester::submit::{submit_withdraw, SubmitError, SubmitOutcome};

#[path = "submit_support/mod.rs"]
mod submit_support;

use submit_support::mock_circle::{Endpoint, MockCircle, Reply, Script};
use submit_support::*;

// ================================================================================================
// THE 409 CONTRACT — never success, never a blind re-send (§10.10)
// ================================================================================================

/// The recovery path: a 409 carrying `conflict.withdrawalId` is resolved by POLLING
/// `GET /v1/withdrawal/{withdrawalId}` — and the POST is issued exactly ONCE.
#[tokio::test]
async fn a_409_with_a_withdrawal_id_recovers_by_polling_and_never_reposts() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_full())])
            .status(vec![Reply::json(200, status_body("finalized"))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let outcome = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("a 409 with a withdrawal id recovers");

    assert_matches!(
        &outcome,
        SubmitOutcome::ConflictRecovered { withdrawal_id, status }
            if withdrawal_id.as_str() == CONFLICT_WITHDRAWAL_ID
                && status.status() == WithdrawalStatusKind::Finalized
    );

    // THE call-log oracle: exactly one POST — the 409 was recovered, not re-sent.
    assert_eq!(
        withdraw_posts(&mock),
        1,
        "a 409 must never trigger a second POST /v1/withdraw"
    );
    assert!(status_gets(&mock) >= 1, "the recovery must actually poll");
    assert_eq!(
        mock.requests_to(Endpoint::Status)[0].path,
        format!("/v1/withdrawal/{CONFLICT_WITHDRAWAL_ID}"),
        "the poll must be keyed on the CONFLICT's withdrawalId"
    );
}

/// A 409 can NEVER produce the success variant — for EITHER conflict-body shape. This is the
/// forbidden-implementation test: "409 mapped to success".
#[rstest]
#[case::with_withdrawal_id(conflict_body_full())]
#[case::burn_tx_id_only(conflict_body_burn_only())]
#[tokio::test]
async fn a_409_never_yields_the_submitted_success_variant(#[case] body: Value) {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, body)])
            .status(vec![Reply::json(200, status_body("finalized"))]),
    );
    let dir = tempfile::tempdir().unwrap();

    let outcome = submit_withdraw(
        &client_for(&mock),
        &ledger_in(&dir),
        authorized_for(BURN_TX_ID),
    )
    .await
    .expect("the 409 is handled, not surfaced as a transport failure");

    assert!(
        !matches!(outcome, SubmitOutcome::Submitted(_)),
        "a 409 is a duplicate conflict, NEVER a success: {outcome:?}"
    );
    assert!(
        outcome.submitted().is_none(),
        "and it carries no submission response"
    );
}

/// Only `conflict.burnTxId` → stop resubmission and mark reconciliation required. No poll (there is no
/// id to poll), no second POST.
#[tokio::test]
async fn a_409_with_only_a_burn_tx_id_stops_and_marks_reconciliation_required() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_burn_only())])
            .status(vec![Reply::json(200, status_body("finalized"))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let outcome = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("the 409 is handled");

    assert_matches!(
        &outcome,
        SubmitOutcome::ReconciliationRequired { burn_tx_id, .. } if burn_tx_id == BURN_TX_ID
    );
    assert_eq!(withdraw_posts(&mock), 1, "submission stopped");
    assert_eq!(
        status_gets(&mock),
        0,
        "there is no withdrawalId to poll — nothing may be invented"
    );
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired),
        "the burn is recorded as needing reconciliation, and is therefore blocked"
    );
}

/// A 409 body echoing a DIFFERENT `burnTxId` is a DEFECT — the idempotency key must match. It is not a
/// recovery (no poll), not a success, and it does not resubmit.
#[tokio::test]
async fn a_409_echoing_a_different_burn_tx_id_is_a_defect_not_a_recovery() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_echoing_another_burn())])
            .status(vec![Reply::json(200, status_body("finalized"))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let outcome = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("the 409 is handled");

    assert_matches!(
        &outcome,
        SubmitOutcome::ConflictEchoMismatch { submitted, echoed }
            if submitted.iter().any(|s| s == BURN_TX_ID) && echoed == OTHER_BURN_TX_ID
    );
    assert_eq!(withdraw_posts(&mock), 1);
    assert_eq!(
        status_gets(&mock),
        0,
        "a mismatched echo must not be chased — that id is not this burn's"
    );
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired),
        "a defect fails closed"
    );
}

/// The recovered status is reported HONESTLY. Only `finalized` is done: a `failed` / `expired` /
/// still-pending recovery is NOT a success and does NOT settle the ledger as finalized.
#[rstest]
#[case::failed("failed", WithdrawalStatusKind::Failed)]
#[case::expired("expired", WithdrawalStatusKind::Expired)]
#[tokio::test]
async fn a_409_recovered_to_a_non_finalized_status_is_not_success(
    #[case] wire: &str,
    #[case] kind: WithdrawalStatusKind,
) {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_full())])
            .status(vec![Reply::json(200, status_body(wire))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let outcome = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("the 409 recovers to a real status");

    assert_matches!(&outcome, SubmitOutcome::ConflictRecovered { status, .. } if status.status() == kind);
    assert!(!matches!(outcome, SubmitOutcome::Submitted(_)));
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired),
        "only `finalized` settles a burn; {wire} does not"
    );
    assert_eq!(withdraw_posts(&mock), 1, "and nothing is re-sent");
}

/// `finalized` — the ONE terminal success — settles the ledger, and still is not `Submitted`.
#[tokio::test]
async fn a_409_recovered_to_finalized_settles_the_burn_as_finalized() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_full())])
            .status(vec![Reply::json(200, status_body("finalized"))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("recovered");

    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::Finalized)
    );
    assert_eq!(
        withdrawal_id_of(&ledger, BURN_TX_ID).as_deref(),
        Some(CONFLICT_WITHDRAWAL_ID),
        "the id an operator would poll is recorded with it"
    );
}

/// The recovered STATUS is bound to this burn too: a schema-valid status object for a different
/// `burnTxId` is a defect, not this withdrawal's outcome.
#[tokio::test]
async fn a_recovered_status_for_another_burn_tx_id_is_a_defect() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_full())])
            .status(vec![Reply::json(
                200,
                status_body_for(OTHER_BURN_TX_ID, "finalized"),
            )]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let outcome = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("handled");

    assert_matches!(
        &outcome,
        SubmitOutcome::ConflictEchoMismatch { echoed, .. } if echoed == OTHER_BURN_TX_ID
    );
    assert!(!matches!(outcome, SubmitOutcome::Submitted(_)));
    assert_eq!(withdraw_posts(&mock), 1);
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired)
    );
}

/// A 409 body that does not decode (no `burnTxId` to echo-check against) is an EXACT `Err` — nothing
/// is acted on, nothing is re-sent, and the burn is left blocked.
#[rstest]
#[case::no_burn_tx_id(json!({ "withdrawalId": CONFLICT_WITHDRAWAL_ID }))]
#[case::burn_tx_id_not_hex(json!({ "burnTxId": "not-hex-at-all" }))]
#[case::not_an_object(json!(["conflict"]))]
#[tokio::test]
async fn a_409_with_an_undecodable_body_is_an_exact_err_and_never_resubmits(#[case] body: Value) {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, body)])
            .status(vec![Reply::json(200, status_body("finalized"))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let err = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect_err("an unreadable conflict body is not a success");

    assert_matches!(
        err,
        SubmitError::Circle(ListenerError::MalformedResponse {
            context: "withdraw-conflict",
            ..
        })
    );
    assert_eq!(withdraw_posts(&mock), 1, "never a blind re-send");
    assert_eq!(status_gets(&mock), 0, "and nothing to poll");
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired),
        "an ambiguous conflict fails closed"
    );
}

/// A poll that cannot answer (the conflict's id 404s) leaves the burn BLOCKED and surfaces the error.
/// "We asked what happened and did not find out" is the definition of ambiguous — and must never
/// become a re-send.
#[tokio::test]
async fn a_recovery_poll_that_fails_leaves_the_burn_blocked_and_surfaces() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_full())])
            .status(vec![Reply::json(
                404,
                support::fixture_json("withdrawal_status_404"),
            )]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let err = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect_err("an unresolvable recovery is not a success");

    assert_matches!(
        err,
        SubmitError::Circle(ListenerError::WithdrawalNotFound { .. })
    );
    assert_eq!(withdraw_posts(&mock), 1, "still exactly one POST");
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired)
    );
}

// ================================================================================================
// PER-BURN BINDING — a conflict names ONE burn, and settles ONLY that burn
// ================================================================================================

/// **A recovered conflict for burn A must never finalize burn B.**
///
/// The 409 names A and A alone. Recording B as `Finalized` off the back of it would be a durable claim
/// that Circle released B — with NO Circle evidence for B whatsoever — permanently blocking B behind a
/// dishonest record. B's real state is unknown, so B fails closed instead.
#[tokio::test]
async fn a_409_naming_one_burn_never_finalizes_the_other_burns() {
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

    let outcome = submit_withdraw(
        &client_for(&mock),
        &ledger,
        authorized_for_burns(&[BURN_TX_ID, OTHER_BURN_TX_ID, THIRD_BURN_TX_ID]),
    )
    .await
    .expect("the conflict recovers for the burn it names");

    assert_matches!(outcome, SubmitOutcome::ConflictRecovered { .. });

    // the named burn: settled by the evidence that names it
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::Finalized),
        "the burn the conflict actually named is settled by it"
    );
    // every OTHER burn: no evidence, so no claim
    for unnamed in [OTHER_BURN_TX_ID, THIRD_BURN_TX_ID] {
        assert_eq!(
            status_of(&ledger, unnamed),
            Some(SubmissionStatus::ReconciliationRequired),
            "{unnamed} was never named by the conflict — it must NOT inherit the other burn's outcome"
        );
        assert_ne!(
            status_of(&ledger, unnamed),
            Some(SubmissionStatus::Finalized),
            "{unnamed} must never be recorded finalized without Circle evidence for {unnamed}"
        );
    }
    assert_eq!(withdraw_posts(&mock), 1);
}

/// The same per-burn binding for the non-`finalized` recovery: the named burn takes the recovered
/// state, the rest fail closed. Nothing is inherited in either direction.
#[tokio::test]
async fn a_409_naming_one_burn_of_many_blocks_the_rest_without_claiming_their_state() {
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

    for burn in [BURN_TX_ID, OTHER_BURN_TX_ID] {
        assert_eq!(
            status_of(&ledger, burn),
            Some(SubmissionStatus::ReconciliationRequired),
            "{burn}: a failed recovery settles nothing"
        );
    }
}

/// A `409` with only `conflict.burnTxId` in a multi-burn request blocks EVERY burn: the request was
/// refused as a whole, and the named burn cannot even be recovered.
#[tokio::test]
async fn a_409_without_a_withdrawal_id_blocks_every_burn_in_the_request() {
    let mock = MockCircle::start(
        Script::new().withdraw(vec![Reply::json(409, json!({ "burnTxId": BURN_TX_ID }))]),
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

    assert_matches!(outcome, SubmitOutcome::ReconciliationRequired { .. });
    for burn in [BURN_TX_ID, OTHER_BURN_TX_ID] {
        assert_eq!(
            status_of(&ledger, burn),
            Some(SubmissionStatus::ReconciliationRequired),
            "{burn} must be blocked"
        );
    }
    assert_eq!(status_gets(&mock), 0);
}

/// **The recovered status must echo the burn the CONFLICT named — not merely some burn in the
/// request.** Both burns here were submitted, so an "echoes any of ours" check would wave this
/// through and attribute burn B's withdrawal to burn A.
#[tokio::test]
async fn a_recovered_status_must_echo_the_burn_the_conflict_named_not_merely_any_submitted_burn() {
    let mock = MockCircle::start(
        Script::new()
            // the conflict names BURN_TX_ID …
            .withdraw(vec![Reply::json(409, conflict_body_for(BURN_TX_ID))])
            // … but the recovered status is about OTHER_BURN_TX_ID, which this request also carries
            .status(vec![Reply::json(
                200,
                status_body_for(OTHER_BURN_TX_ID, "finalized"),
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

    assert_matches!(
        &outcome,
        SubmitOutcome::ConflictEchoMismatch { echoed, .. } if echoed == OTHER_BURN_TX_ID
    );
    for burn in [BURN_TX_ID, OTHER_BURN_TX_ID] {
        assert_ne!(
            status_of(&ledger, burn),
            Some(SubmissionStatus::Finalized),
            "{burn} must not be settled by a status the conflict never pointed at"
        );
    }
}
