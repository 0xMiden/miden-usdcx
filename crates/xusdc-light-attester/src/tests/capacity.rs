//! Local queue rules. The cap-error text here is synthetic, not a claimed Circle message.

use std::time::{Duration, UNIX_EPOCH};

use miden_protocol::asset::FungibleAsset;
use miden_protocol::utils::serde::Serializable;
use reqwest::StatusCode;
use serde_json::json;

use crate::attester::{burn_hold, Attester};
use crate::circle::{CircleError, RawResponse};
use crate::store::BurnHoldReason;
use crate::submission::{is_limit_rejection, SubmissionStatus, SubmitError};
use crate::verify::VerifyError;

use super::submit::{poll, recover, reply, Ledger};
use super::support::{CircleState, ObservedRequest};

const WINDOW: i64 = 86_400_000;
const ENDPOINT: &str = "https://circle.example.invalid/v1/withdraw";

fn at(attester: &mut Attester, millis: i64) {
    attester.now = Box::new(move || UNIX_EPOCH + Duration::from_millis(millis as u64));
}

fn admission(ledger: &Ledger, index: usize) -> i64 {
    ledger.stored(&format!(
        "SELECT admitted_at_ms FROM burns WHERE note_id = x'{}'",
        hex::encode(ledger.burns[index].burn.note_id().to_bytes())
    ))
}

#[tokio::test]
async fn smaller_burns_continue_while_large_burns_wait() {
    let ledger = Ledger::with_amounts([2_000, 300, 700]).await;
    ledger.configure(1_000, false);
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
        .submission(ledger.burns[0].burn.note_id())
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
        .submission(ENDPOINT.into())
        .unwrap();
    let (mut attester, _) = ledger.start(vec![]).await;
    assert!(attester
        .store
        .admit_submission(&saved, amount, WINDOW, WINDOW, 1_000)
        .unwrap());
    let next = ledger.burns[1].burn.note_id();
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
    ledger.configure(u64::MAX, false);
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
        .submission(ledger.burns[2].burn.note_id())
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn retries_recheck_capacity_without_changing_signed_bytes() {
    let ledger = Ledger::new().await;
    ledger.configure(1_000, false);
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
}

/// Lowering the limit below an in-flight burn's amount must not strand its uncertain POST.
#[tokio::test]
async fn recovery_is_not_gated_by_the_per_burn_cap() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![CircleState::TransportError]).await;
    at(&mut attester, WINDOW);
    ledger.submit(&mut attester, 0).await.unwrap();
    drop(attester);

    ledger.configure(500, false);
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

        ledger.configure(0, false);
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

#[tokio::test]
async fn cap_rejection_releases_capacity_but_waits_for_fresh_signing() {
    let ledger = Ledger::new().await;
    ledger.configure(1_000, true);
    let order = &ledger.fresh_indices;
    let (mut attester, requests) = ledger
        .start(vec![
            reply(200, ledger.prepared_response(order[0])),
            reply(400, json!({"message": "synthetic cap rejection"})),
            reply(200, ledger.prepared_response(order[1])),
            CircleState::TransportError,
        ])
        .await;
    at(&mut attester, WINDOW);
    attester.run_one_cycle().await.unwrap();
    let rejected = ledger.burns[order[0]].burn.note_id();
    assert!(
        attester.store.submission(rejected).unwrap().is_none(),
        "discard rejected signed bytes"
    );
    assert_eq!(admission(&ledger, order[0]), WINDOW);
    assert_eq!(
        requests.lock().unwrap().len(),
        4,
        "released capacity serves another burn"
    );
    attester
        .store
        .hold_burn(rejected, BurnHoldReason::PrepareRejected)
        .unwrap();
    attester
        .store
        .hold_burn(
            ledger.burns[order[2]].burn.note_id(),
            BurnHoldReason::PrepareRejected,
        )
        .unwrap();
    drop(attester);

    // A restart and manual hold release must not erase the cap cooldown.
    ledger.sql("UPDATE submissions SET status = 'HELD', hold_reason = 'http_rejected'");
    let (mut attester, requests) = ledger
        .start(vec![
            reply(200, ledger.prepared_response(order[0])),
            CircleState::TransportError,
        ])
        .await;
    attester.release_burn_hold(rejected).unwrap();
    assert!(!attester
        .store
        .can_submit_burn(rejected, 1_000, 2 * WINDOW - 1, WINDOW, 2_000)
        .unwrap());
    at(&mut attester, 2 * WINDOW);
    assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert_eq!(requests.lock().unwrap()[0], ObservedRequest::Prepare);
    assert_eq!(admission(&ledger, order[0]), 2 * WINDOW);
}

#[tokio::test]
async fn only_the_configured_post_400_releases_capacity() {
    // Only a POST 400 whose message starts with the configured text releases capacity.
    let numbered =
        "synthetic cap rejection for USDC. Current total: 900000. Limit: 1000000 per 24-hour window";
    for (configured, status, message, lookup, released) in [
        (false, 400, "synthetic cap rejection", false, false),
        (true, 400, " synthetic cap rejection", false, false),
        (true, 503, "synthetic cap rejection", false, false),
        (true, 400, "synthetic cap rejection", true, false),
        (true, 400, numbered, false, true),
    ] {
        let ledger = Ledger::new().await;
        ledger.configure(1_000, configured);
        let rejection = reply(status, json!({"message": message}));
        let replies = if lookup {
            vec![
                reply(201, json!([ledger.response(0, "created")])),
                rejection,
            ]
        } else {
            vec![rejection]
        };
        let (mut attester, _) = ledger.start(replies).await;
        at(&mut attester, WINDOW);
        ledger.submit(&mut attester, 0).await.unwrap();
        if lookup {
            poll(&mut attester).await.unwrap();
        }
        let kept = attester
            .store
            .submission(ledger.burns[0].burn.note_id())
            .unwrap()
            .is_some_and(|saved| !saved.body.is_empty());
        assert_eq!(kept, !released, "{message}");
        assert_eq!(
            attester
                .store
                .can_submit_burn(ledger.burns[1].burn.note_id(), 1_000, WINDOW, WINDOW, 1_000)
                .unwrap(),
            released,
            "{message}"
        );
    }

    // The reply to the first POST is lost, so Circle may have accepted it. The limit 400 on the
    // resend then keeps the signed request queued, and the burn is never signed a second time.
    let ledger = Ledger::new().await;
    ledger.configure(1_000, true);
    let (mut attester, _) = ledger
        .start(vec![
            CircleState::TransportError,
            reply(400, json!({"message": "synthetic cap rejection"})),
        ])
        .await;
    at(&mut attester, WINDOW);
    ledger.submit(&mut attester, 0).await.unwrap();
    let sent = ledger.record(&attester, 0);
    recover(&mut attester).await.unwrap();
    let saved = ledger.record(&attester, 0);
    assert_eq!(
        (saved.status, saved.body, saved.last_error.as_deref()),
        (
            SubmissionStatus::Submitting,
            sent.body,
            Some("Circle's withdrawal limit is reached")
        )
    );
    assert!(!attester
        .store
        .can_submit_burn(ledger.burns[1].burn.note_id(), 1_000, WINDOW, WINDOW, 1_000)
        .unwrap());
    assert!(!attester
        .store
        .burns_ready_for_withdrawal(3u32.into(), 1)
        .unwrap()
        .iter()
        .any(|burn| burn.note_id() == saved.note_id));
}

#[tokio::test]
async fn failed_cap_cleanup_keeps_the_request_and_reservation() {
    let ledger = Ledger::new().await;
    ledger.configure(1_000, true);
    ledger.sql("CREATE TRIGGER fail_cap BEFORE UPDATE ON burns WHEN NEW.status = 'CAP_REJECTED' BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
    let (mut attester, _) = ledger
        .start(vec![reply(
            400,
            json!({"message": "synthetic cap rejection"}),
        )])
        .await;
    at(&mut attester, WINDOW);
    assert!(matches!(
        ledger.submit(&mut attester, 0).await,
        Err(SubmitError::Store(_))
    ));
    assert_eq!(
        ledger.record(&attester, 0).status,
        SubmissionStatus::Submitting
    );
    assert!(!attester
        .store
        .can_submit_burn(ledger.burns[1].burn.note_id(), 1_000, WINDOW, WINDOW, 1_000)
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
    drop(attester);
    ledger.config.lock().unwrap().switch("--release-holds");
    let (mut attester, requests) = ledger
        .start(vec![
            reply(200, ledger.prepared_response(order[0])),
            CircleState::TransportError,
        ])
        .await;
    assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], ObservedRequest::Prepare);
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
                    ledger.burns[i].burn.note_id(),
                    BurnHoldReason::PrepareRejected,
                )
                .unwrap();
        }
        assert!(attester.run_one_cycle().await.unwrap().submit.is_err());
        assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
        assert_eq!(requests.lock().unwrap().len(), 3);
    }
}

/// Without a usable clock the withdrawal limit cannot be applied, so the cycle stops before any
/// Circle request, as it does after a store failure.
#[tokio::test]
async fn unusable_clock_stops_the_cycle() {
    let ledger = Ledger::new().await;
    let (mut attester, requests) = ledger.start(vec![]).await;
    attester.now = Box::new(|| UNIX_EPOCH - Duration::from_millis(1));
    let error = attester.run_one_cycle().await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<SubmitError>(),
        Some(SubmitError::Clock)
    ));
    assert!(requests.lock().unwrap().is_empty());
}

/// Circle's limit message is recognised by its configured start, and only in a 400.
#[test]
fn limit_message_is_recognised_by_its_start() {
    let start = Some("synthetic cap rejection");
    let numbered =
        "synthetic cap rejection for USDC. Current total: 900000. Limit: 1000000 per 24-hour window";
    let message = |value| serde_json::to_vec(&json!({ "message": value })).unwrap();
    for (name, configured, status, body, expected) in [
        ("not configured", None, 400, message(json!(numbered)), false),
        (
            "the exact start",
            start,
            400,
            message(json!("synthetic cap rejection")),
            true,
        ),
        (
            "the numbered message",
            start,
            400,
            message(json!(numbered)),
            true,
        ),
        (
            "a leading space",
            start,
            400,
            message(json!(" synthetic cap rejection")),
            false,
        ),
        ("a 503", start, 503, message(json!(numbered)), false),
        (
            "a body that is not JSON",
            start,
            400,
            b"synthetic cap rejection".to_vec(),
            false,
        ),
        (
            "a message that is not text",
            start,
            400,
            message(json!(7)),
            false,
        ),
    ] {
        let response = RawResponse::new(StatusCode::from_u16(status).unwrap(), body);
        assert_eq!(
            is_limit_rejection(&response, configured),
            expected,
            "{name}"
        );
    }
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
            (Some(BurnHoldReason::PrepareRejected), Some("rejected")),
        ),
        ("prepare 503", prepare(503), (None, None)),
        ("prepare 429", prepare(429), (None, None)),
        ("prepare 408", prepare(408), (None, None)),
        ("prepare 403", prepare(403), (None, None)),
        (
            "malformed reply",
            SubmitError::Prepare(CircleError::InvalidResponse(malformed)),
            (None, None),
        ),
        (
            "Circle unavailable",
            SubmitError::Prepare(CircleError::Unavailable),
            (None, None),
        ),
        (
            "failed verification",
            SubmitError::Verification(Box::new(VerifyError::DigestMismatch)),
            (None, None),
        ),
    ] {
        let (reason, message) = burn_hold(&error);
        assert_eq!((reason, message.as_deref()), hold, "{name}");
    }
}
