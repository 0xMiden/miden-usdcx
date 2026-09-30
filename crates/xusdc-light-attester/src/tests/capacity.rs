//! Local queue rules.

use std::time::{Duration, UNIX_EPOCH};

use miden_protocol::asset::FungibleAsset;
use miden_protocol::utils::serde::Serializable;
use reqwest::StatusCode;
use serde_json::json;

use crate::attester::{burn_hold, Attester};
use crate::circle::CircleError;
use crate::store::BurnHoldReason;
use crate::submission::{SubmissionStatus, SubmitError};
use crate::verify::VerifyError;

use super::submit::{poll, recover, reply, Ledger};
use super::support::{read_store, CircleState, ObservedRequest};

const WINDOW: i64 = 86_400_000;
const ENDPOINT: &str = "https://circle.example.invalid/v1/withdraw";

fn at(attester: &mut Attester, millis: i64) {
    attester.now = Some(UNIX_EPOCH + Duration::from_millis(millis as u64));
}

fn admission(ledger: &Ledger, index: usize) -> i64 {
    ledger.stored(&format!(
        "SELECT admitted_at_ms FROM burns WHERE note_id = x'{}'",
        hex::encode(ledger.burns[index].note_id().to_bytes())
    ))
}

/// One column of a burn's history rows of one kind, oldest first.
fn recorded<T: rusqlite::types::FromSql>(
    ledger: &Ledger,
    index: usize,
    kind: &str,
    column: &str,
) -> Vec<T> {
    read_store(&ledger.path())
        .prepare(&format!(
            "SELECT {column} FROM submission_events WHERE note_id = ?1 AND kind = ?2 ORDER BY seq"
        ))
        .unwrap()
        .query_map(
            rusqlite::params![ledger.burns[index].note_id().to_bytes(), kind],
            |row| row.get(0),
        )
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[tokio::test]
async fn smaller_burns_continue_while_large_burns_wait() {
    let ledger = Ledger::with_amounts([2_000, 300, 700]).await;
    ledger.configure(1_000);
    let fitting: Vec<_> = ledger
        .fresh_indices
        .iter()
        .copied()
        .filter(|&i| i != 0)
        .collect();
    let replies = fitting
        .iter()
        .flat_map(|&i| {
            [
                reply(200, ledger.prepared_response(i)),
                CircleState::TransportError,
            ]
        })
        .collect();
    let (mut attester, requests) = ledger.start(replies).await;
    assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        4,
        "only fitting burns reach prepare and POST"
    );
    assert!(attester
        .store
        .submission(ledger.burns[0].note_id())
        .unwrap()
        .is_none());
    assert_eq!(attester.store.submissions_to_recover().unwrap().len(), 2);
}

#[tokio::test]
async fn reservations_use_the_rolling_boundary_and_never_move_backwards() {
    let ledger = Ledger::new().await;
    let (saved, amount) = ledger
        .signed_with_max_height(0, None)
        .await
        .submission(ENDPOINT.parse().unwrap())
        .unwrap();
    let (mut attester, _) = ledger.start(vec![]).await;
    assert!(attester
        .store
        .admit_submission(&saved, amount, WINDOW, WINDOW, 1_000)
        .unwrap());
    let next = ledger.burns[1].note_id();
    for (time, fits) in [
        (WINDOW - 1, false),
        (2 * WINDOW - 1, false),
        (2 * WINDOW, true),
    ] {
        assert_eq!(
            attester
                .store
                .can_submit_burn(next, 1_000, time, WINDOW, 1_000)
                .unwrap(),
            fits
        );
    }
    // Renewal replaces this note's charge, rather than adding another 1,000.
    assert!(attester
        .store
        .renew_submission(saved.note_id, WINDOW + 100, WINDOW, 1_000)
        .unwrap());
    assert!(attester
        .store
        .renew_submission(saved.note_id, WINDOW - 100, WINDOW, 1_000)
        .unwrap());
    assert_eq!(admission(&ledger, 0), WINDOW + 100);
    assert!(!attester
        .store
        .can_submit_burn(next, 1_000, 2 * WINDOW, WINDOW, 1_000)
        .unwrap());
}

#[tokio::test]
async fn summing_large_reservations_does_not_overflow() {
    let amount = FungibleAsset::MAX_AMOUNT.as_u64();
    let ledger = Ledger::with_amounts([amount; 3]).await;
    ledger.configure(u64::MAX);
    let (mut attester, requests) = ledger
        .start(vec![
            CircleState::TransportError,
            CircleState::TransportError,
        ])
        .await;
    for index in 0..3 {
        ledger.submit(&mut attester, index).await.unwrap();
    }
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| matches!(
        request,
        ObservedRequest::Submit { endpoint, .. } if endpoint == ENDPOINT
    )));
    assert!(attester
        .store
        .submission(ledger.burns[2].note_id())
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn retries_recheck_capacity_without_changing_signed_bytes() {
    let ledger = Ledger::new().await;
    ledger.configure(1_000);
    let (mut attester, requests) = ledger
        .start(vec![
            CircleState::TransportError,
            reply(201, json!([ledger.response(1, "created")])),
            reply(200, ledger.response(1, "finalized")),
            CircleState::TransportError,
        ])
        .await;
    at(&mut attester, WINDOW);
    ledger.submit(&mut attester, 0).await.unwrap();
    let body = ledger.record(&attester, 0).body;
    at(&mut attester, 2 * WINDOW);
    ledger.submit(&mut attester, 1).await.unwrap();
    recover(&mut attester).await.unwrap();
    assert_eq!(
        requests.lock().unwrap().len(),
        2,
        "retry cannot overbook the new window"
    );
    poll(&mut attester).await.unwrap();
    assert_eq!(
        ledger.record(&attester, 1).status,
        SubmissionStatus::Finalized,
        "GET is not capacity-gated"
    );
    at(&mut attester, 3 * WINDOW);
    recover(&mut attester).await.unwrap();
    assert_eq!(
        requests.lock().unwrap()[3],
        ObservedRequest::Submit {
            endpoint: ENDPOINT.into(),
            body,
        }
    );
    assert_eq!(admission(&ledger, 0), 3 * WINDOW);
    // Only the resend that fit renewed the reservation, and the history records when.
    assert_eq!(
        recorded::<i64>(&ledger, 0, "RESERVATION_RENEWED", "admitted_at_ms"),
        [3 * WINDOW]
    );
}

/// Lowering the limit below an in-flight burn's amount must not strand its uncertain POST.
#[tokio::test]
async fn recovery_is_not_gated_by_the_per_burn_cap() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![CircleState::TransportError]).await;
    at(&mut attester, WINDOW);
    ledger.submit(&mut attester, 0).await.unwrap();
    drop(attester);

    ledger.configure(500);
    let (mut attester, requests) = ledger
        .start(vec![reply(201, json!([ledger.response(0, "created")]))])
        .await;
    at(&mut attester, WINDOW);
    recover(&mut attester).await.unwrap();
    assert_eq!(
        requests.lock().unwrap().len(),
        1,
        "the saved request is re-sent"
    );
    assert_eq!(
        ledger.record(&attester, 0).status,
        SubmissionStatus::Submitted
    );
}

/// Lowering the limit, even to zero, must not strand requests Circle may already hold: a
/// reservation still inside the window is renewed and its request sent again without the limit
/// check. An expired one is checked again, so only one of the two fits beside the other's renewed
/// reservation.
#[tokio::test]
async fn live_reservations_are_resent_after_the_limit_drops() {
    for (restart_at, resent, admissions) in [
        (2 * WINDOW - 1, 2, [2 * WINDOW - 1, 2 * WINDOW - 1]),
        (2 * WINDOW, 1, [WINDOW, 2 * WINDOW]),
    ] {
        let ledger = Ledger::new().await;
        let (mut attester, _) = ledger
            .start(vec![
                CircleState::TransportError,
                CircleState::TransportError,
            ])
            .await;
        at(&mut attester, WINDOW);
        ledger.submit(&mut attester, 0).await.unwrap();
        ledger.submit(&mut attester, 1).await.unwrap();
        drop(attester);

        ledger.configure(0);
        let (mut attester, requests) = ledger
            .start(vec![
                CircleState::TransportError,
                CircleState::TransportError,
            ])
            .await;
        at(&mut attester, restart_at);
        recover(&mut attester).await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), resent, "{restart_at}");
        let mut stored = [admission(&ledger, 0), admission(&ledger, 1)];
        stored.sort();
        assert_eq!(stored, admissions, "{restart_at}");
    }
}

/// A burn authorized again after its withdrawal expired holds one reservation, not one for each
/// authorization.
#[tokio::test]
async fn a_new_authorization_replaces_the_burns_reservation() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![
            reply(201, json!([ledger.response(0, "created")])),
            reply(200, ledger.response(0, "expired")),
            CircleState::TransportError,
        ])
        .await;
    at(&mut attester, WINDOW);
    ledger.submit(&mut attester, 0).await.unwrap();
    poll(&mut attester).await.unwrap();
    ledger.submit(&mut attester, 0).await.unwrap();
    assert_eq!(
        recorded::<i64>(&ledger, 0, "AUTHORIZED", "reservation_amount"),
        [1_000, 1_000]
    );
    let next = ledger.burns[1].note_id();
    assert!(attester
        .store
        .can_submit_burn(next, 1_000, WINDOW, WINDOW, 2_000)
        .unwrap());
    assert!(!attester
        .store
        .can_submit_burn(next, 1_001, WINDOW, WINDOW, 2_000)
        .unwrap());
}

#[tokio::test]
async fn prepare_400_holds_survive_restart_until_released() {
    let ledger = Ledger::new().await;
    let order = &ledger.fresh_indices;
    let mut bad = ledger.prepared_response(order[2]);
    bad["batches"][0]["messageHashToSign"] = json!(format!("0x{}", "00".repeat(32)));
    let (mut attester, _) = ledger
        .start(vec![
            reply(201, json!([ledger.response(order[0], "expired")])),
            reply(400, json!({"message": "rejected"})),
            reply(200, json!({})),
            reply(200, bad),
        ])
        .await;
    // Circle can refuse the fresh prepare for a burn whose earlier withdrawal expired.
    ledger.submit(&mut attester, order[0]).await.unwrap();
    assert!(matches!(
        attester.run_one_cycle().await.unwrap().submit,
        Err(SubmitError::Prepare(
            CircleError::UnexpectedPrepareStatus { .. }
        ))
    ));
    drop(attester);
    // Neither the malformed reply nor the failed check held its burn: both are prepared again.
    let replies = order[1..]
        .iter()
        .flat_map(|&i| {
            [
                reply(200, ledger.prepared_response(i)),
                reply(201, json!([ledger.response(i, "finalized")])),
            ]
        })
        .chain([
            reply(200, ledger.prepared_response(order[0])),
            CircleState::TransportError,
        ])
        .collect();
    let (mut attester, requests) = ledger.start(replies).await;
    assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
    assert_eq!(requests.lock().unwrap().len(), 4);
    assert_eq!(
        ledger.record(&attester, order[0]).status,
        SubmissionStatus::Expired
    );
    assert!(
        admission(&ledger, order[0]) > 0,
        "the hold keeps its existing reservation"
    );
    attester
        .release_burn_hold(ledger.burns[order[0]].note_id())
        .unwrap();
    assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 6);
    assert_eq!(requests[4], ObservedRequest::Prepare);
}

#[tokio::test]
async fn transient_prepare_failures_retry_next_cycle() {
    // Only a 400 from prepare holds a burn; every other failure is tried again next cycle.
    let failures: [fn(&Ledger) -> CircleState; 7] = [
        |_| CircleState::TransportError,
        |_| reply(503, json!({})),
        |_| reply(429, json!({})),
        |_| reply(408, json!({})),
        |_| reply(403, json!({})),
        |_| reply(200, json!({})),
        |ledger| {
            let mut bad = ledger.prepared_response(ledger.fresh_indices[0]);
            bad["batches"][0]["messageHashToSign"] = json!(format!("0x{}", "00".repeat(32)));
            reply(200, bad)
        },
    ];
    for failure in failures {
        let ledger = Ledger::new().await;
        let order = &ledger.fresh_indices;
        let (mut attester, requests) = ledger
            .start(vec![
                failure(&ledger),
                reply(200, ledger.prepared_response(order[0])),
                CircleState::TransportError,
            ])
            .await;
        for &i in &order[1..] {
            attester
                .store
                .hold_burn(
                    ledger.burns[i].note_id(),
                    BurnHoldReason::PrepareRejected,
                )
                .unwrap();
        }
        assert!(attester.run_one_cycle().await.unwrap().submit.is_err());
        assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
        assert_eq!(requests.lock().unwrap().len(), 3);
    }
}

/// A burn's hold and its release both record the hold's reason in the burn's history, also for a
/// burn that has no saved request.
#[tokio::test]
async fn burn_hold_and_release_record_the_reason() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![]).await;
    let note_id = ledger.burns[0].note_id();
    attester
        .store
        .hold_burn(note_id, BurnHoldReason::PrepareRejected)
        .unwrap();
    attester.release_burn_hold(note_id).unwrap();
    for kind in ["BURN_HELD", "BURN_RELEASED"] {
        assert_eq!(
            recorded::<String>(&ledger, 0, kind, "burn_hold_reason"),
            ["prepare_rejected"],
            "{kind}"
        );
    }
}

/// Without a usable clock the withdrawal limit cannot be applied, so the cycle stops before any
/// Circle request, as it does after a store failure.
#[tokio::test]
async fn unusable_clock_stops_the_cycle() {
    let ledger = Ledger::new().await;
    let (mut attester, requests) = ledger.start(vec![]).await;
    attester.now = Some(UNIX_EPOCH - Duration::from_millis(1));
    let error = attester.run_one_cycle().await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<SubmitError>(),
        Some(SubmitError::Clock)
    ));
    assert!(requests.lock().unwrap().is_empty());
}

/// Only a 400 from prepare holds a burn; any other failure before submission is tried again.
#[test]
fn failures_that_hold_a_burn() {
    let prepare = |status: u16| {
        SubmitError::Prepare(CircleError::UnexpectedPrepareStatus {
            status: StatusCode::from_u16(status).unwrap(),
            body: br#"{"message":"rejected"}"#.to_vec(),
        })
    };
    let malformed = serde_json::from_slice::<serde_json::Value>(b"not JSON").unwrap_err();
    for (name, error, hold) in [
        (
            "prepare 400",
            prepare(400),
            Some(BurnHoldReason::PrepareRejected),
        ),
        ("prepare 503", prepare(503), None),
        ("prepare 429", prepare(429), None),
        ("prepare 408", prepare(408), None),
        ("prepare 403", prepare(403), None),
        (
            "malformed reply",
            SubmitError::Prepare(CircleError::InvalidResponse(malformed)),
            None,
        ),
        (
            "Circle unavailable",
            SubmitError::Prepare(CircleError::Unavailable),
            None,
        ),
        (
            "failed verification",
            SubmitError::Verification(VerifyError::DigestMismatch),
            None,
        ),
    ] {
        assert_eq!(burn_hold(&error), hold, "{name}");
    }
}
