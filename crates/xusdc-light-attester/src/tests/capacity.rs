//! Local queue rules. The cap-error text here is synthetic, not a claimed Circle message.

use std::time::{Duration, UNIX_EPOCH};

use miden_protocol::asset::FungibleAsset;
use miden_protocol::utils::serde::Serializable;
use serde_json::json;

use crate::attester::Attester;
use crate::circle::CircleError;
use crate::store::BurnHoldReason;
use crate::submission::{SubmissionStatus, SubmitError};

use super::submit::{poll, recover, reply, Ledger};
use super::support::CircleState;

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
    assert!(requests
        .iter()
        .all(|request| request.method == reqwest::Method::POST && request.url == ENDPOINT));
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
    assert_eq!(requests.lock().unwrap()[3].body, body);
    assert_eq!(admission(&ledger, 0), 3 * WINDOW);
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
    assert!(requests.lock().unwrap()[0]
        .url
        .ends_with("/v1/prepare-withdrawal"));
    assert_eq!(admission(&ledger, order[0]), 2 * WINDOW);
}

#[tokio::test]
async fn only_the_configured_post_400_releases_capacity() {
    for (configured, status, message, lookup) in [
        (false, 400, "synthetic cap rejection", false),
        (true, 400, "synthetic cap rejection ", false),
        (true, 503, "synthetic cap rejection", false),
        (true, 400, "synthetic cap rejection", true),
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
        assert!(!ledger.record(&attester, 0).body.is_empty());
        assert!(!attester
            .store
            .can_submit_burn(ledger.burns[1].burn.note_id(), 1_000, WINDOW, WINDOW, 1_000)
            .unwrap());
    }
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
        Err(SubmitError::InvalidStore)
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
async fn prepare_and_verify_holds_survive_restart_until_released() {
    let ledger = Ledger::new().await;
    let order = &ledger.fresh_indices;
    let mut bad = ledger.prepared_response(order[2]);
    bad["batches"][0]["messageHashToSign"] = json!(format!("0x{}", "00".repeat(32)));
    let (mut attester, _) = ledger
        .start(vec![
            reply(201, json!([ledger.response(order[2], "expired")])),
            reply(400, json!({"message": "rejected"})),
            reply(200, json!({})),
            reply(200, bad),
        ])
        .await;
    // Verification can fail on a fresh authorization for an expired attempt too.
    ledger.submit(&mut attester, order[2]).await.unwrap();
    assert!(matches!(
        attester.run_one_cycle().await.unwrap().submit,
        Err(SubmitError::Prepare(
            CircleError::UnexpectedPrepareStatus { .. }
        ))
    ));
    drop(attester);
    let replies = order
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
    assert!(requests.lock().unwrap().is_empty());
    assert_eq!(
        ledger.record(&attester, order[2]).status,
        SubmissionStatus::Expired
    );
    assert!(
        admission(&ledger, order[2]) > 0,
        "the hold keeps its existing reservation"
    );
    for &i in order {
        attester
            .release_burn_hold(ledger.burns[i].burn.note_id())
            .unwrap();
    }
    assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
    assert_eq!(requests.lock().unwrap().len(), 6);
}

#[tokio::test]
async fn transient_prepare_failures_retry_next_cycle() {
    for failure in [CircleState::TransportError, reply(503, json!({}))] {
        let ledger = Ledger::new().await;
        let order = &ledger.fresh_indices;
        let (mut attester, requests) = ledger
            .start(vec![
                failure,
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
