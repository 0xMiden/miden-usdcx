use miden_protocol::note::NoteId;
use miden_protocol::utils::serde::Serializable;
use serde_json::json;

use crate::attester::Attester;
use crate::circle::CircleError;
use crate::submission::{HoldReason, SavedSubmission, SubmissionStatus::*, SubmitError};

use super::submit::{reply, Ledger};
use super::support::{CircleState, ObservedRequest};

async fn submitted(ledger: &Ledger, indices: &[usize]) {
    let replies = indices
        .iter()
        .map(|&i| reply(201, json!([ledger.response(i, "created")])))
        .collect();
    let (mut attester, _) = ledger.start(replies).await;
    for &index in indices {
        ledger.submit(&mut attester, index).await.unwrap();
    }
}

async fn pending_pair() -> (Ledger, [usize; 2]) {
    let ledger = Ledger::new().await;
    let mut indices = [0, 1];
    // SQLite orders the serialized note-ID BLOB, not the fixture's insertion order.
    indices.sort_by_key(|&i| ledger.burns[i].burn.note_id().to_bytes());
    submitted(&ledger, &indices).await;
    (ledger, indices)
}

fn ready(attester: &Attester) -> Vec<NoteId> {
    attester
        .store
        .burns_ready_for_withdrawal(3u32.into(), 1)
        .unwrap()
        .into_iter()
        .map(|burn| burn.note_id())
        .collect()
}

#[tokio::test]
async fn expired_is_saved() {
    let ledger = Ledger::new().await;
    submitted(&ledger, &[0]).await;
    let (mut attester, _) = ledger
        .start(vec![reply(200, ledger.response(0, "expired"))])
        .await;
    attester.poll_withdrawal_statuses().await.unwrap();
    assert_eq!(ledger.record(&attester, 0).status, Expired);
}

#[tokio::test]
async fn only_submitted_withdrawals_are_polled() {
    for status in ["finalized", "expired", "failed", "unknown"] {
        let ledger = Ledger::new().await;
        let (mut attester, requests) = ledger
            .start(vec![
                reply(201, json!([ledger.response(0, "created")])),
                reply(201, json!([ledger.response(1, status)])),
                CircleState::TransportError,
                reply(200, ledger.response(0, "finalized")),
            ])
            .await;
        for index in 0..3 {
            ledger.submit(&mut attester, index).await.unwrap();
        }
        let excluded = [ledger.record(&attester, 1), ledger.record(&attester, 2)];
        attester.poll_withdrawal_statuses().await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), 4, "{status}");
        assert!(matches!(
            requests.lock().unwrap()[3],
            ObservedRequest::Lookup { .. }
        ));
        assert_eq!(ledger.record(&attester, 0).status, Finalized);
        assert_eq!(ledger.record(&attester, 1), excluded[0]);
        assert_eq!(ledger.record(&attester, 2), excluded[1]);
    }
}

#[tokio::test]
async fn each_withdrawal_is_polled_once_per_pass() {
    let (ledger, [first, second]) = pending_pair().await;
    let replies = vec![
        reply(200, ledger.response(first, "created")),
        reply(200, ledger.response(second, "verified")),
    ];
    let (mut attester, requests) = ledger.start([replies.clone(), replies].concat()).await;
    attester.poll_withdrawal_statuses().await.unwrap();
    assert_eq!(requests.lock().unwrap().len(), 2);
    attester.poll_withdrawal_statuses().await.unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests
        .iter()
        .all(|request| matches!(request, ObservedRequest::Lookup { .. })));
    assert_eq!(requests[0], requests[2]);
    assert_eq!(requests[1], requests[3]);
    let (
        ObservedRequest::Lookup { id: first_id, .. },
        ObservedRequest::Lookup { id: second_id, .. },
    ) = (&requests[0], &requests[1])
    else {
        panic!("expected two status checks: {requests:?}");
    };
    assert_ne!(first_id, second_id);
    assert_eq!(ledger.record(&attester, first).status, Submitted);
    assert_eq!(ledger.record(&attester, second).status, Submitted);
}

#[tokio::test]
async fn only_expired_submissions_allow_fresh_work() {
    let ledger = Ledger::new().await;
    let (mut attester, requests) = ledger
        .start(vec![
            reply(201, json!([ledger.response(0, "expired")])),
            reply(201, json!([ledger.response(1, "failed")])),
            reply(201, json!([ledger.response(2, "created")])),
            CircleState::TransportError,
        ])
        .await;
    assert_eq!(ready(&attester).len(), 3);
    for index in 0..3 {
        ledger.submit(&mut attester, index).await.unwrap();
    }
    let expired = ledger.record(&attester, 0);
    assert_eq!(ready(&attester), vec![expired.note_id]);
    assert_eq!(ledger.record(&attester, 0), expired);
    let fresh = ledger
        .signed_with_max_height(0, Some("184467440737095516170001"))
        .await;
    attester.submit_signed_withdrawal(&fresh).await.unwrap();
    assert!(ready(&attester).is_empty());
    assert_ne!(ledger.record(&attester, 0).body, expired.body);
    assert_eq!(ledger.record(&attester, 0).status, Submitting);
    assert_eq!(requests.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn failed_without_a_reason_is_saved() {
    let ledger = Ledger::new().await;
    submitted(&ledger, &[0]).await;
    let (mut attester, _) = ledger
        .start(vec![reply(200, ledger.response(0, "failed"))])
        .await;
    attester.poll_withdrawal_statuses().await.unwrap();
    let saved = ledger.record(&attester, 0);
    assert_eq!(saved.status, Failed);
    assert_eq!(saved.last_error, None);
    assert_eq!(saved.last_http_status, Some(200));
}

#[tokio::test]
async fn transport_failure_does_not_block_others() {
    let (ledger, [first, second]) = pending_pair().await;
    let (mut attester, requests) = ledger
        .start(vec![
            CircleState::TransportError,
            reply(200, ledger.response(second, "finalized")),
        ])
        .await;
    let before = ledger.record(&attester, first);
    attester.poll_withdrawal_statuses().await.unwrap();
    assert_eq!(
        ledger.record(&attester, first),
        SavedSubmission {
            last_http_status: None,
            last_response: None,
            last_error: Some(CircleError::Unavailable.to_string()),
            ..before
        }
    );
    assert_eq!(ledger.record(&attester, second).status, Finalized);
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn missing_lookup_does_not_block_others() {
    let (ledger, [first, second]) = pending_pair().await;
    let (mut attester, requests) = ledger
        .start(vec![
            reply(404, json!({})),
            reply(200, ledger.response(second, "finalized")),
            reply(200, ledger.response(first, "created")),
        ])
        .await;
    let before = ledger.record(&attester, first);
    attester.poll_withdrawal_statuses().await.unwrap();
    assert_eq!(
        ledger.record(&attester, first),
        SavedSubmission {
            status: Held,
            hold_reason: Some(HoldReason::HttpRejected),
            last_http_status: Some(404),
            last_response: Some(b"{}".to_vec()),
            last_error: Some("HTTP response needs operator review".into()),
            ..before
        }
    );
    assert_eq!(ledger.record(&attester, second).status, Finalized);
    assert_eq!(requests.lock().unwrap().len(), 2);
    attester.poll_withdrawal_statuses().await.unwrap();
    assert_eq!(requests.lock().unwrap().len(), 2);
    let held = ledger.record(&attester, first);
    attester.retry_held_submission(held.note_id).unwrap();
    attester.recover_submissions().await.unwrap();
    assert_eq!(ledger.record(&attester, first).status, Submitted);
    assert_eq!(ledger.record(&attester, first).body, held.body);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0], requests[2]);
    assert!(matches!(requests[2], ObservedRequest::Lookup { .. }));
}

#[tokio::test]
async fn wrong_response_is_held_without_blocking_others() {
    let (ledger, [first, second]) = pending_pair().await;
    let mut response = ledger.response(first, "finalized");
    response["transferSpecHashes"] = json!([format!("0x{}", "ff".repeat(32))]);
    let (mut attester, requests) = ledger
        .start(vec![
            reply(200, response),
            reply(200, ledger.response(second, "finalized")),
        ])
        .await;
    attester.poll_withdrawal_statuses().await.unwrap();
    assert_eq!(ledger.record(&attester, first).status, Held);
    assert_eq!(
        ledger.record(&attester, first).hold_reason,
        Some(HoldReason::ResponseMismatch)
    );
    assert_eq!(ledger.record(&attester, second).status, Finalized);
    attester.poll_withdrawal_statuses().await.unwrap();
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn failed_store_write_preserves_the_old_row() {
    let (ledger, [first, second]) = pending_pair().await;
    ledger.sql("CREATE TRIGGER fail_poll BEFORE UPDATE ON submissions BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
    let (mut attester, requests) = ledger
        .start(vec![
            reply(200, ledger.response(first, "expired")),
            reply(200, ledger.response(second, "finalized")),
        ])
        .await;
    let old = [
        ledger.record(&attester, first),
        ledger.record(&attester, second),
    ];
    let old_ready = ready(&attester);
    let error = attester.poll_withdrawal_statuses().await.unwrap_err();
    assert!(matches!(error, SubmitError::Store(_)));
    assert_eq!(ledger.record(&attester, first), old[0]);
    assert_eq!(ledger.record(&attester, second), old[1]);
    assert_eq!(ready(&attester), old_ready);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn saved_poll_result_survives_restart() {
    let ledger = Ledger::new().await;
    submitted(&ledger, &[0]).await;
    let (mut attester, first) = ledger
        .start(vec![reply(200, ledger.response(0, "verified"))])
        .await;
    attester.poll_withdrawal_statuses().await.unwrap();
    let saved = ledger.record(&attester, 0);
    assert_eq!(saved.last_http_status, Some(200));
    drop(attester);
    let (mut attester, resumed) = ledger
        .start(vec![reply(200, ledger.response(0, "finalized"))])
        .await;
    assert_eq!(ledger.record(&attester, 0), saved);
    attester.poll_withdrawal_statuses().await.unwrap();
    assert_eq!(*first.lock().unwrap(), *resumed.lock().unwrap());
    assert_eq!(ledger.record(&attester, 0).status, Finalized);
}
