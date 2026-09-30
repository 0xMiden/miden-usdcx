//! Burn holds: which failures hold a burn, and how a hold is recorded and released.

use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteId;
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
            rusqlite::params![ledger.burns[index].note_id().to_bytes(), kind],
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
            &[ledger.burns[order[0]].burn.note_id()],
        )
        .unwrap(),
        (1, 0)
    );
    let mut store = ledger.open_store().unwrap();
    store
        .hold_burn(
            ledger.burns[order[0]].burn.note_id(),
            BurnHoldReason::PrepareRejected,
            None,
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
            &[ledger.burns[order[0]].burn.note_id()],
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

/// Releasing the named holds is all or nothing: when a history row cannot be written, no hold is
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
            None,
        )
        .unwrap();
    drop(attester);
    ledger.sql(
        "CREATE TRIGGER fail_release BEFORE INSERT ON submission_events
         WHEN NEW.kind = 'OPERATOR_RELEASE' BEGIN SELECT RAISE(FAIL, 'disk full'); END;",
    );
    let before = std::fs::read(ledger.path()).unwrap();
    let mut store = ledger.open_store().unwrap();
    assert!(store
        .release_holds(&[
            ledger.burns[0].burn.note_id(),
            ledger.burns[1].burn.note_id()
        ])
        .is_err());
    drop(store);
    assert_eq!(std::fs::read(ledger.path()).unwrap(), before);
}

/// Only the named burns are released: other holds stay, a held withdrawal keeps its saved request
/// until it is named, and naming a burn without a hold releases nothing.
#[tokio::test]
async fn only_named_holds_are_released() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![reply(400, json!({"message": "rejected"}))])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let [withdrawal, first, second] = [0, 1, 2].map(|index| ledger.burns[index].burn.note_id());
    for burn in [first, second] {
        attester
            .store
            .hold_burn(burn, BurnHoldReason::PrepareRejected, None)
            .unwrap();
    }
    drop(attester);
    let mut store = ledger.open_store().unwrap();
    assert_eq!(store.release_holds(&[first]).unwrap(), (1, 0));
    let ready: Vec<_> = store
        .burns_ready_for_withdrawal(3u32.into(), 1)
        .unwrap()
        .iter()
        .map(|burn| burn.note_id())
        .collect();
    assert_eq!(ready, [first], "only the named burn is released");
    let unknown = NoteId::try_from_hex(&format!("0x{}", "11".repeat(32))).unwrap();
    for named in [[withdrawal, first], [withdrawal, unknown]] {
        assert!(
            store.release_holds(&named).is_err(),
            "a named burn that is not held, or unknown, fails the whole release"
        );
    }
    assert!(
        store.submission(withdrawal).unwrap().is_some(),
        "a held withdrawal keeps its saved request until it is released"
    );
    assert_eq!(store.release_holds(&[withdrawal]).unwrap(), (0, 1));
    assert!(store.submission(withdrawal).unwrap().is_none());
}

/// Each hold is listed on one line with the note ID first: a held burn with its reason, and a held
/// withdrawal with Circle's message on that line too.
#[tokio::test]
async fn holds_are_listed() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![reply(400, json!({"message": "limit\n  reached"}))])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let [withdrawal, burn] = [0, 1].map(|index| ledger.burns[index].burn.note_id());
    attester
        .store
        .hold_burn(burn, BurnHoldReason::PrepareRejected, None)
        .unwrap();
    let lines: Vec<_> = attester
        .store
        .holds()
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        lines,
        [
            format!("{burn}\tburn\tPrepareRejected\t-"),
            format!("{withdrawal}\twithdrawal\tHttpRejected\tlimit reached"),
        ]
    );
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
    let note_id = ledger.burns[order[0]].note_id();
    let refusal = json!({"message": "first refusal"});
    let refusal_body = serde_json::to_vec(&refusal).unwrap();
    let (mut attester, _) = ledger.start(vec![reply(400, refusal)]).await;
    for &index in &order[1..] {
        attester
            .store
            .hold_burn(
                ledger.burns[index].note_id(),
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
            (
                Some(BurnHoldReason::PrepareRejected),
                Some((400, br#"{"message":"rejected"}"#.to_vec())),
                Some("rejected"),
            ),
        ),
        ("prepare 503", prepare(503), (None, None, None)),
        (
            "prepare 429",
            SubmitError::Prepare(CircleError::RateLimited {
                body: None,
                read_error: None,
            }),
            (None, None, None),
        ),
        ("prepare 408", prepare(408), (None, None, None)),
        ("prepare 403", prepare(403), (None, None, None)),
        (
            "malformed reply",
            SubmitError::Prepare(CircleError::InvalidResponse(malformed)),
            (None, None, None),
        ),
        (
            "Circle unavailable",
            SubmitError::Prepare(CircleError::Unavailable),
            (None, None, None),
        ),
        (
            "failed verification",
            SubmitError::Verification(VerifyError::DigestMismatch),
            (None, None, None),
        ),
    ] {
        let (reason, response, message) = burn_hold(&error);
        assert_eq!(
            (
                reason,
                response.map(|(status, body)| (status, body.to_vec())),
                message.as_deref(),
            ),
            hold,
            "{name}"
        );
    }
}
