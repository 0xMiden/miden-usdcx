//! Burn holds: which failures hold a burn, and how a hold is recorded and released.

use miden_protocol::utils::serde::Serializable;
use reqwest::StatusCode;
use serde_json::json;

use crate::attester::burn_hold;
use crate::circle::CircleError;
use crate::store::BurnHoldReason;
use crate::submission::{SubmissionStatus, SubmitError};
use crate::verify::VerifyError;

use super::submit::{reply, Ledger};
use super::support::{read_store, CircleState, ObservedRequest};

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
    let refusal = json!({"message": "rejected"});
    let refusal_body = serde_json::to_vec(&refusal).unwrap();
    let mut bad = ledger.prepared_response(order[2]);
    bad["batches"][0]["messageHashToSign"] = json!(format!("0x{}", "00".repeat(32)));
    let (mut attester, _) = ledger
        .start(vec![
            reply(201, json!([ledger.response(order[0], "expired")])),
            reply(400, refusal),
            reply(200, json!({})),
            reply(200, bad),
        ])
        .await;
    // Circle can refuse the fresh prepare for a burn whose earlier withdrawal expired.
    ledger.submit(&mut attester, order[0]).await.unwrap();
    let expired = ledger.record(&attester, order[0]);
    let earlier_history = ledger.history(order[0]);
    assert!(matches!(
        attester.run_one_cycle().await.unwrap().submit,
        Err(SubmitError::Prepare(
            CircleError::UnexpectedPrepareStatus { .. }
        ))
    ));
    assert_eq!(ledger.record(&attester, order[0]), expired);
    let history = ledger.history(order[0]);
    assert_eq!(&history[..earlier_history.len()], earlier_history);
    assert_eq!(history.last(), Some(&("BURN_HELD".into(), None)));
    assert_eq!(
        recorded::<Option<i64>>(&ledger, order[0], "BURN_HELD", "http_status"),
        [Some(400)]
    );
    assert_eq!(
        recorded::<Option<Vec<u8>>>(&ledger, order[0], "BURN_HELD", "response"),
        [Some(refusal_body)]
    );
    for column in [
        "status",
        "withdrawal_id",
        "error",
        "endpoint",
        "hold_reason",
    ] {
        assert_eq!(
            recorded::<Option<String>>(&ledger, order[0], "BURN_HELD", column),
            [None],
            "{column}"
        );
    }
    for column in ["body", "transfer_spec_hash"] {
        assert_eq!(
            recorded::<Option<Vec<u8>>>(&ledger, order[0], "BURN_HELD", column),
            [None],
            "{column}"
        );
    }
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
    attester
        .release_burn_hold(ledger.burns[order[0]].burn.note_id())
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
                    ledger.burns[i].burn.note_id(),
                    BurnHoldReason::PrepareRejected,
                    None,
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
    let order = &ledger.fresh_indices;
    let note_id = ledger.burns[order[0]].burn.note_id();
    let refusal = json!({"message": "first refusal"});
    let refusal_body = serde_json::to_vec(&refusal).unwrap();
    let (mut attester, _) = ledger.start(vec![reply(400, refusal)]).await;
    for &index in &order[1..] {
        attester
            .store
            .hold_burn(
                ledger.burns[index].burn.note_id(),
                BurnHoldReason::PrepareRejected,
                None,
            )
            .unwrap();
    }
    assert!(matches!(
        attester.run_one_cycle().await.unwrap().submit,
        Err(SubmitError::Prepare(
            CircleError::UnexpectedPrepareStatus { .. }
        ))
    ));
    assert_eq!(
        recorded::<Option<i64>>(&ledger, order[0], "BURN_HELD", "http_status"),
        [Some(400)]
    );
    assert_eq!(
        recorded::<Option<Vec<u8>>>(&ledger, order[0], "BURN_HELD", "response"),
        [Some(refusal_body)]
    );
    drop(attester);

    let (mut attester, _) = ledger.start(vec![]).await;
    assert_eq!(
        recorded::<Option<i64>>(&ledger, order[0], "BURN_HELD", "http_status"),
        [Some(400)]
    );
    attester.release_burn_hold(note_id).unwrap();
    for kind in ["BURN_HELD", "BURN_RELEASED"] {
        assert_eq!(
            recorded::<i64>(&ledger, order[0], kind, "burn_hold_reason"),
            [BurnHoldReason::PrepareRejected.code()],
            "{kind}"
        );
    }
    drop(attester);

    ledger.sql(
        "CREATE TRIGGER fail_burn_hold BEFORE INSERT ON submission_events
         WHEN NEW.kind = 'BURN_HELD'
         BEGIN SELECT RAISE(FAIL, 'disk full'); END;",
    );
    let (mut attester, _) = ledger
        .start(vec![reply(400, json!({"message": "rejected again"}))])
        .await;
    assert!(attester.run_one_cycle().await.is_err());
    drop(attester);
    let connection = read_store(&ledger.path());
    let hold: Option<i64> = connection
        .query_row(
            "SELECT hold_reason FROM burns WHERE note_id = ?1",
            [note_id.to_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(hold, None);
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
            Some((
                BurnHoldReason::PrepareRejected,
                Some((400, br#"{"message":"rejected"}"#.to_vec())),
            )),
        ),
        ("prepare 503", prepare(503), None),
        (
            "prepare 429",
            SubmitError::Prepare(CircleError::RateLimited {
                body: None,
                read_error: None,
            }),
            None,
        ),
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
        let actual = burn_hold(&error).map(|(reason, response)| {
            (
                reason,
                response.map(|(status, body)| (status, body.to_vec())),
            )
        });
        assert_eq!(actual, hold, "{name}");
    }
}
