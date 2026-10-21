//! S3 must not participate in withdrawal, FIFO or admin progress.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;

use crate::export::tests::{PreparedS3, Reply};
use crate::export::{ExportConfig, Exporter};
use crate::store::BurnHoldReason;

use super::admin::list_command;
use super::submit::{poll, reply, Ledger};

#[tokio::test(start_paused = true)]
async fn blocked_s3_does_not_block_cycles_admin_or_withdrawal_limit_waits() {
    let ledger = Ledger::new().await;
    {
        let mut args = ledger.config.lock().unwrap();
        args.append(
            "--withdrawal-limit-message-prefix",
            "Withdrawal limit reached",
        );
        args.append("--withdrawal-limit-retry-interval", "5m");
    }
    let [a, b, c] = ledger.fresh_indices.clone().try_into().unwrap();
    let (signers, calls) = super::service_map::signers(None).await;
    let (mut attester, requests, chain) = ledger
        .runtime(
            vec![
                reply(201, json!([ledger.response(c, "created")])),
                reply(200, ledger.response(c, "finalized")),
                reply(
                    400,
                    json!({"message": "Withdrawal limit reached: try later"}),
                ),
            ],
            signers,
        )
        .await;
    ledger.submit(&mut attester, c).await.unwrap();
    poll(&mut attester).await.unwrap();
    attester
        .store
        .hold_burn(
            ledger.burns[a].note_id(),
            BurnHoldReason::PrepareRejected,
            None,
        )
        .unwrap();
    let config =
        ExportConfig::new("withdrawal-lookups".into(), None, Some("eu-north-1".into())).unwrap();
    let destination = config.destination_key();
    let sink = PreparedS3::answering([Reply::Block(Arc::new(Notify::new()))]);
    let exporter = Exporter::with_client(config.clone(), sink.client());
    let shutdown = CancellationToken::new();
    let (sender, receiver) = mpsc::channel(16);
    attester.attach_admin(receiver, shutdown.clone());
    let run = attester.run_with_exporter(shutdown.clone(), config, exporter);
    let operator = async {
        for _ in 0..1000 {
            if sink.active_count() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(sink.active_count(), 1);
        assert_eq!(list_command(&sender).await.unwrap().unwrap().holds.len(), 1);
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(2)).await;
        for _ in 0..1000 {
            if *chain.scan_limit_requests.lock().unwrap() >= 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(list_command(&sender).await.unwrap().unwrap().holds.len(), 1);
        assert!(*chain.scan_limit_requests.lock().unwrap() >= 2);
        assert_eq!(sink.count(), 1);
        shutdown.cancel();
    };
    let (result, _) = tokio::join!(run, operator);
    result.unwrap();
    assert_eq!(sink.active_count(), 0, "shutdown cancels the blocked PUT");
    assert_eq!(
        attester.store.first_limit_wait().unwrap().unwrap().note_id,
        ledger.burns[b].note_id()
    );
    assert_eq!(
        requests.lock().unwrap().len(),
        3,
        "no retry before the persisted limit deadline"
    );
    assert_eq!(super::service_map::counts(&calls), [0, 0]);
    let replay = attester.store.export_batch(&destination, 100).unwrap();
    assert_eq!(
        replay.after, 0,
        "cancellation must leave unacknowledged mappings for restart"
    );
    assert!(!replay.records.is_empty());
}
