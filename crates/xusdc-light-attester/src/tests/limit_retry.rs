use std::time::{Duration, UNIX_EPOCH};

use miden_protocol::utils::serde::Serializable;
use reqwest::StatusCode;
use serde_json::json;

use crate::attester::Attester;
use crate::circle::is_withdrawal_limit;
use crate::config::WithdrawalLimit;
use crate::submission::SubmissionStatus;

use super::service_map::{counts, fresh_replies, signers};
use super::submit::{reply, Ledger, ScriptedCircle};
use super::support::{development_pair, scan_limits, CircleState, ObservedRequest, TestChain};

const PREFIX: &str = "Withdrawal limit reached";

async fn ledger() -> Ledger {
    let ledger = Ledger::new().await;
    {
        let mut args = ledger.config.lock().unwrap();
        args.append("--withdrawal-limit-message-prefix", PREFIX);
        args.append("--withdrawal-limit-retry-interval", "5m");
    }
    ledger
}

fn limit() -> CircleState {
    reply(400, json!({"message": format!("{PREFIX}: try later")}))
}

fn make_due(ledger: &Ledger) {
    ledger.sql("UPDATE burns SET withdrawal_limit_retry_at = 0 WHERE withdrawal_limit_retry_at IS NOT NULL");
}

#[test]
fn limit_matching_and_deadlines_are_exact() {
    let policy = WithdrawalLimit {
        message_prefix: PREFIX.into(),
        retry_interval: Duration::from_millis(1),
    };
    assert_eq!(policy.retry_at(UNIX_EPOCH).unwrap(), 1);
    assert_eq!(
        policy
            .retry_at(UNIX_EPOCH + Duration::from_millis(999))
            .unwrap(),
        1
    );
    assert!(policy
        .retry_at(UNIX_EPOCH - Duration::from_secs(1))
        .is_err());
    let overflow = WithdrawalLimit {
        retry_interval: Duration::MAX,
        ..policy
    };
    assert!(overflow.retry_at(UNIX_EPOCH).is_err());
    for body in [
        json!({}),
        json!({"message": 7}),
        json!({"message": "Other rejection"}),
        json!({"message": PREFIX.to_lowercase()}),
    ] {
        assert!(!is_withdrawal_limit(
            StatusCode::BAD_REQUEST,
            &serde_json::to_vec(&body).unwrap(),
            PREFIX
        ));
    }
    assert!(!is_withdrawal_limit(
        StatusCode::BAD_REQUEST,
        b"invalid json",
        PREFIX
    ));
    let long_prefix = format!("{PREFIX}{}", "x".repeat(250));
    let body = serde_json::to_vec(&json!({"message": format!("{long_prefix}: details")})).unwrap();
    assert!(is_withdrawal_limit(
        StatusCode::BAD_REQUEST,
        &body,
        &long_prefix
    ));
    assert!(!is_withdrawal_limit(
        StatusCode::TOO_MANY_REQUESTS,
        &body,
        &long_prefix
    ));
}

#[tokio::test]
async fn prepare_limit_survives_restart_without_stopping_polling() {
    let ledger = ledger().await;
    let [a, b, c] = ledger.fresh_indices.clone().try_into().unwrap();
    let (mut attester, _) = ledger
        .start(vec![reply(201, json!([ledger.response(c, "created")]))])
        .await;
    ledger.submit(&mut attester, c).await.unwrap();
    drop(attester);
    let (pair, calls) = signers(None).await;
    let (mut attester, requests, _) = ledger
        .runtime(
            vec![limit(), reply(200, ledger.response(c, "confirmed"))],
            pair,
        )
        .await;
    assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
    let wait = attester.store.first_limit_wait().unwrap().unwrap();
    assert_eq!(wait.note_id, ledger.burns[a].note_id());
    assert_eq!(counts(&calls), [0, 0]);
    assert!(attester.store.holds().unwrap().is_empty());
    assert_eq!(requests.lock().unwrap().len(), 2);
    drop(attester);
    ledger
        .config
        .lock()
        .unwrap()
        .replace("--withdrawal-limit-retry-interval", "1ms");
    let (mut attester, requests) = ledger
        .start(vec![reply(200, ledger.response(c, "finalized"))])
        .await;
    attester.run_one_cycle().await.unwrap();
    assert_eq!(
        attester.store.first_limit_wait().unwrap().unwrap().retry_at,
        wait.retry_at
    );
    assert!(matches!(
        requests.lock().unwrap().as_slice(),
        [ObservedRequest::Lookup { .. }]
    ));
    drop(attester);

    let mut disabled = ledger.config.lock().unwrap().clone();
    disabled.remove("--withdrawal-limit-message-prefix");
    disabled.remove("--withdrawal-limit-retry-interval");
    let (circle, requests) = ScriptedCircle::new(ledger.path(), vec![]);
    let result = Attester::start(
        disabled.load(),
        Box::new(TestChain::new(ledger.blocks.clone(), scan_limits(3, 3)).0),
        Box::new(circle),
        development_pair().await,
    )
    .await;
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("saved withdrawal-limit waits"));
    assert!(requests.lock().unwrap().is_empty());
    make_due(&ledger);
    let (mut attester, requests) = ledger.start(fresh_replies(&ledger, &[a, b])).await;
    attester.run_one_cycle().await.unwrap();
    assert!(attester.store.first_limit_wait().unwrap().is_none());
    assert_eq!(requests.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn a_first_post_rejection_can_prepare_and_sign_again() {
    let ledger = ledger().await;
    let a = ledger.fresh_indices[0];
    let (pair, calls) = signers(None).await;
    let (mut attester, requests, _) = ledger
        .runtime(vec![reply(200, ledger.prepared_response(a)), limit()], pair)
        .await;
    attester.run_one_cycle().await.unwrap();
    assert!(attester
        .store
        .submission(ledger.burns[a].note_id())
        .unwrap()
        .is_none());
    assert_eq!(
        ledger.history(a),
        [
            ("AUTHORIZED".into(), Some("SUBMITTING".into())),
            ("WITHDRAWAL_LIMIT".into(), None)
        ]
    );
    assert_eq!(counts(&calls), [1, 1]);
    assert_eq!(requests.lock().unwrap().len(), 2);
    drop(attester);
    make_due(&ledger);
    let (pair, calls) = signers(None).await;
    let (mut attester, _, _) = ledger
        .runtime(fresh_replies(&ledger, &ledger.fresh_indices), pair)
        .await;
    attester.run_one_cycle().await.unwrap();
    assert_eq!(counts(&calls), [3, 3]);
    assert_eq!(
        ledger
            .history(a)
            .iter()
            .filter(|(kind, _)| kind == "AUTHORIZED")
            .count(),
        2
    );
}

#[tokio::test]
async fn uncertain_posts_keep_their_authorization_and_poll_known_ids_during_wait() {
    let ledger = ledger().await;
    let a = ledger.fresh_indices[0];
    let (mut attester, _) = ledger.start(vec![CircleState::TransportError]).await;
    ledger.submit(&mut attester, a).await.unwrap();
    let original = ledger.record(&attester, a);
    drop(attester);
    let (pair, calls) = signers(None).await;
    let (mut attester, requests, _) = ledger.runtime(vec![limit()], pair).await;
    attester.run_one_cycle().await.unwrap();
    assert_eq!(counts(&calls), [0, 0]);
    assert_eq!(ledger.record(&attester, a).body, original.body);
    assert_eq!(requests.lock().unwrap().len(), 1);
    drop(attester);
    make_due(&ledger);
    let id = ledger.response(a, "created")["withdrawalId"]
        .as_str()
        .unwrap()
        .to_owned();
    let (mut attester, requests) = ledger
        .start(vec![
            reply(409, json!({"conflict": {"withdrawalId": id}})),
            reply(200, ledger.response(ledger.fresh_indices[1], "confirmed")),
        ])
        .await;
    attester.run_one_cycle().await.unwrap();
    assert!(attester.store.first_limit_wait().unwrap().is_some());
    assert_eq!(
        ledger.record(&attester, a).withdrawal_id.as_deref(),
        Some(id.as_str())
    );
    assert_eq!(
        requests.lock().unwrap()[0],
        ObservedRequest::Submit {
            endpoint: original.endpoint.to_string(),
            body: original.body.clone()
        }
    );
    drop(attester);
    let (pair, calls) = signers(None).await;
    let (mut attester, requests, _) = ledger
        .runtime(
            vec![limit(), reply(200, ledger.response(a, "confirmed"))],
            pair,
        )
        .await;
    // A GET 400 must neither replace the request nor postpone its existing deadline.
    let deadline = attester.store.first_limit_wait().unwrap().unwrap().retry_at;
    attester.run_one_cycle().await.unwrap();
    assert_eq!(
        attester.store.first_limit_wait().unwrap().unwrap().retry_at,
        deadline
    );
    attester.run_one_cycle().await.unwrap();
    assert!(attester.store.first_limit_wait().unwrap().is_none());
    assert_eq!(counts(&calls), [0, 0]);
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert_eq!(
        ledger.record(&attester, a).transfer_spec_hash,
        original.transfer_spec_hash
    );
}

#[tokio::test]
async fn fresh_and_recovery_posts_share_byte_order_and_a_durable_barrier() {
    for recover_first in [false, true] {
        let ledger = ledger().await;
        let [a, b, _] = ledger.fresh_indices.clone().try_into().unwrap();
        let recovered = if recover_first { a } else { b };
        let (mut attester, _) = ledger.start(vec![CircleState::TransportError]).await;
        ledger.submit(&mut attester, recovered).await.unwrap();
        drop(attester);
        let (pair, calls) = signers(None).await;
        let (mut attester, requests, chain) = ledger.runtime(vec![limit()], pair).await;
        let expected = if recover_first {
            ObservedRequest::Submit {
                endpoint: ledger.record(&attester, a).endpoint.to_string(),
                body: ledger.record(&attester, a).body,
            }
        } else {
            ObservedRequest::Prepare
        };
        attester.run_one_cycle().await.unwrap();
        assert_eq!(*requests.lock().unwrap(), [expected]);
        assert_eq!(
            attester.store.first_limit_wait().unwrap().unwrap().note_id,
            ledger.burns[a].note_id()
        );
        *chain.invalid_scan_limits.lock().unwrap() = true;
        attester.run_one_cycle().await.unwrap();
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "a failed discovery cannot let recovered B pass A"
        );
        assert_eq!(counts(&calls), [0, 0]);
        let mut by_bytes = ledger
            .burns
            .iter()
            .map(|burn| burn.note_id())
            .collect::<Vec<_>>();
        by_bytes.sort_by_key(|id| id.to_bytes());
        assert_eq!(by_bytes[0], ledger.burns[a].note_id());
        let mut by_value = by_bytes.clone();
        by_value.sort();
        assert_ne!(
            by_bytes, by_value,
            "fixture must distinguish Word ordering from stored bytes"
        );
    }
    let ledger = ledger().await;
    let older = ledger.fresh_indices[2];
    ledger.sql(&format!(
        "UPDATE burns SET creation_block = 0 WHERE note_id = x'{}'",
        hex::encode(ledger.burns[older].note_id().to_bytes())
    ));
    let (mut attester, _) = ledger.start(vec![limit()]).await;
    attester.run_one_cycle().await.unwrap();
    assert_eq!(
        attester.store.first_limit_wait().unwrap().unwrap().note_id,
        ledger.burns[older].note_id(),
        "creation block takes precedence over note-ID bytes"
    );
}

#[tokio::test]
async fn waiting_ends_only_on_a_qualifying_outcome() {
    for outcome in [
        "hold",
        "transport",
        "verification",
        "expired",
        "failed",
        "429",
    ] {
        let ledger = ledger().await;
        let a = ledger.fresh_indices[0];
        let (mut attester, _) = ledger.start(vec![limit()]).await;
        attester.run_one_cycle().await.unwrap();
        drop(attester);
        make_due(&ledger);
        let mut replies = match outcome {
            "hold" => vec![reply(400, json!({"message": "different rejection"}))],
            "transport" => vec![CircleState::TransportError],
            "verification" => {
                let mut bad = ledger.prepared_response(a);
                bad["batches"][0]["messageHashToSign"] = json!(format!("0x{}", "00".repeat(32)));
                vec![reply(200, bad)]
            }
            "429" => vec![reply(429, json!({"message": "slow down"}))],
            status => vec![
                reply(200, ledger.prepared_response(a)),
                reply(201, json!([ledger.response(a, status)])),
            ],
        };
        let cleared = matches!(outcome, "hold" | "failed");
        if cleared {
            replies.extend(fresh_replies(&ledger, &ledger.fresh_indices[1..]));
        }
        let (mut attester, requests) = ledger.start(replies).await;
        attester.run_one_cycle().await.unwrap();
        assert_eq!(
            attester.store.first_limit_wait().unwrap().is_none(),
            cleared,
            "{outcome}"
        );
        let call_count = requests.lock().unwrap().len();
        if !cleared {
            attester.run_one_cycle().await.unwrap();
            assert_eq!(requests.lock().unwrap().len(), call_count, "{outcome}");
        }
        if outcome == "expired" {
            assert_eq!(
                ledger.record(&attester, a).status,
                SubmissionStatus::Expired
            );
            drop(attester);
            make_due(&ledger);
            let (mut attester, _) = ledger
                .start(fresh_replies(&ledger, &ledger.fresh_indices))
                .await;
            attester.run_one_cycle().await.unwrap();
            assert!(attester.store.first_limit_wait().unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn limit_history_failure_rolls_back_request_and_deadline() {
    let ledger = ledger().await;
    ledger.sql(
        "CREATE TRIGGER fail_limit BEFORE INSERT ON submission_events
        WHEN NEW.kind = 'WITHDRAWAL_LIMIT' BEGIN SELECT RAISE(FAIL, 'disk full'); END;",
    );
    let a = ledger.fresh_indices[0];
    let (mut attester, requests) = ledger
        .start(vec![reply(200, ledger.prepared_response(a)), limit()])
        .await;
    assert!(attester.run_one_cycle().await.is_err());
    let saved = ledger.record(&attester, a);
    assert_eq!(saved.status, SubmissionStatus::Submitting);
    assert_eq!(saved.last_http_status, None);
    assert!(attester.store.first_limit_wait().unwrap().is_none());
    assert_eq!(
        ledger.history(a),
        [("AUTHORIZED".into(), Some("SUBMITTING".into()))]
    );
    assert_eq!(requests.lock().unwrap().len(), 2);
}
