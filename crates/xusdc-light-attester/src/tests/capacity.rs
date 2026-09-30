//! Local queue rules.

use miden_protocol::block::BlockNumber;
use miden_protocol::utils::serde::Serializable;
use reqwest::StatusCode;
use serde_json::json;

use crate::attester::{burn_hold, release_holds};
use crate::circle::CircleError;
use crate::store::BurnHoldReason;
use crate::submission::{SubmissionStatus, SubmitError};
use crate::verify::VerifyError;

use super::submit::{reply, Ledger};
use super::support::{faucet_account_id, read_store, CircleState, ObservedRequest};

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
            rusqlite::params![ledger.burns[index].burn.note_id().to_bytes(), kind],
            |row| row.get(0),
        )
        .unwrap()
        .map(Result::unwrap)
        .collect()
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
    drop(attester);
    assert_eq!(
        release_holds(
            &ledger.path(),
            faucet_account_id(),
            BlockNumber::GENESIS,
            ledger.blocks[0].header().commitment(),
        )
        .unwrap(),
        (1, 0)
    );
    let mut store = ledger.open_store().unwrap();
    store
        .hold_burn(
            ledger.burns[order[0]].burn.note_id(),
            BurnHoldReason::PrepareRejected,
        )
        .unwrap();
    drop(store);
    let (attester, requests) = ledger.start(vec![]).await;
    assert!(attester
        .store
        .burns_ready_for_withdrawal(3u32.into(), 1)
        .unwrap()
        .iter()
        .all(|burn| burn.note_id() != ledger.burns[order[0]].burn.note_id()));
    assert!(requests.lock().unwrap().is_empty());
    drop(attester);
    assert_eq!(
        release_holds(
            &ledger.path(),
            faucet_account_id(),
            BlockNumber::GENESIS,
            ledger.blocks[0].header().commitment(),
        )
        .unwrap(),
        (1, 0)
    );
    let (mut attester, requests) = ledger
        .start(vec![
            reply(200, ledger.prepared_response(order[0])),
            CircleState::TransportError,
        ])
        .await;
    assert_eq!(
        recorded::<i64>(&ledger, order[0], "BURN_RELEASED", "burn_hold_reason"),
        [BurnHoldReason::PrepareRejected.code(); 2]
    );
    assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], ObservedRequest::Prepare);
}

/// Releasing every hold is all or nothing: when a history row cannot be written, no hold is
/// cleared, no held request is deleted and no history row is kept.
#[tokio::test]
async fn failed_release_keeps_every_hold() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![reply(400, json!({"message": "rejected"}))])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    attester
        .store
        .hold_burn(
            ledger.burns[1].burn.note_id(),
            BurnHoldReason::PrepareRejected,
        )
        .unwrap();
    drop(attester);
    ledger.sql(
        "CREATE TRIGGER fail_release BEFORE INSERT ON submission_events
         WHEN NEW.kind = 'OPERATOR_RELEASE' BEGIN SELECT RAISE(FAIL, 'disk full'); END;",
    );
    let before = std::fs::read(ledger.path()).unwrap();
    let mut store = ledger.open_store().unwrap();
    assert!(store.release_all_holds().is_err());
    drop(store);
    assert_eq!(std::fs::read(ledger.path()).unwrap(), before);
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

/// A burn's hold and its release both record the hold's reason in the burn's history, also for a
/// burn that has no saved request.
#[tokio::test]
async fn burn_hold_and_release_record_the_reason() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![]).await;
    let note_id = ledger.burns[0].burn.note_id();
    attester
        .store
        .hold_burn(note_id, BurnHoldReason::PrepareRejected)
        .unwrap();
    attester.release_burn_hold(note_id).unwrap();
    for kind in ["BURN_HELD", "BURN_RELEASED"] {
        assert_eq!(
            recorded::<i64>(&ledger, 0, kind, "burn_hold_reason"),
            [BurnHoldReason::PrepareRejected.code()],
            "{kind}"
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
            SubmitError::Verification(VerifyError::DigestMismatch),
            (None, None),
        ),
    ] {
        let (reason, message) = burn_hold(&error);
        assert_eq!((reason, message.as_deref()), hold, "{name}");
    }
}
