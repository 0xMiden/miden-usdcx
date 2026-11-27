//! S3 must not participate in withdrawal, FIFO or admin progress.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::{mpsc, Notify};
use tokio::time::{sleep_until, timeout, Instant};
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
        args.replace("--poll-interval", "15s");
        args.append(
            "--withdrawal-limit-message-prefix",
            "Withdrawal limit reached",
        );
        args.append("--withdrawal-limit-retry-interval", "5m");
    }
    let [held, limit_waiting, finalized] = ledger.fresh_indices.clone().try_into().unwrap();
    let (signers, calls) = super::service_map::signers(None).await;
    let (mut attester, requests, chain) = ledger
        .runtime(
            vec![
                reply(201, json!([ledger.response(finalized, "created")])),
                reply(200, ledger.response(finalized, "finalized")),
                reply(
                    400,
                    json!({"message": "Withdrawal limit reached: try later"}),
                ),
            ],
            signers,
        )
        .await;
    ledger.submit(&mut attester, finalized).await.unwrap();
    poll(&mut attester).await.unwrap();
    attester
        .store
        .hold_burn(
            ledger.burns[held].note_id(),
            BurnHoldReason::PrepareRejected,
            None,
        )
        .unwrap();
    let config = ExportConfig::from_url("s3://withdrawal-lookups/withdrawals/").unwrap();
    let destination = config.destination_key();
    let pending_before_run = attester.store.export_batch(&destination, 100).unwrap();
    assert!(!pending_before_run.is_empty());
    let sink = PreparedS3::answering([Reply::Denied, Reply::Block(Arc::new(Notify::new()))]);
    let exporter = Exporter::with_client(config.clone(), sink.client());
    let shutdown = CancellationToken::new();
    let (sender, receiver) = mpsc::channel(16);
    attester.attach_admin(receiver, shutdown.clone());
    let started = Instant::now();
    let run = attester.run_with_exporter(shutdown.clone(), config, exporter);
    let operator = async {
        // The 10-second export retry falls between the two 15-second attester cycles.
        for (elapsed, cycles) in [(11, 1), (16, 2)] {
            sleep_until(started + Duration::from_secs(elapsed)).await;
            assert_eq!(*chain.scan_limit_requests.lock().unwrap(), cycles);
            assert_eq!(sink.count(), 2, "the export retries during the idle period");
            assert_eq!(sink.active_count(), 1);
            let page = timeout(Duration::from_secs(1), list_command(&sender))
                .await
                .expect("the blocked PUT delayed the admin response")
                .unwrap()
                .unwrap();
            assert_eq!(page.holds.len(), 1);
        }
        shutdown.cancel();
    };
    // Shutdown must finish before the blocked PUT would time out at 20 seconds.
    let (result, _) = timeout(Duration::from_secs(19), async {
        tokio::join!(run, operator)
    })
    .await
    .expect("the attester did not stop with a blocked PUT");
    result.unwrap();
    assert_eq!(sink.active_count(), 0, "shutdown cancels the blocked PUT");
    assert_eq!(
        attester.store.first_limit_wait().unwrap().unwrap().note_id,
        ledger.burns[limit_waiting].note_id()
    );
    assert_eq!(
        requests.lock().unwrap().len(),
        3,
        "no retry before the persisted limit deadline"
    );
    assert_eq!(super::service_map::counts(&calls), [0, 0]);
    let replay = attester.store.export_batch(&destination, 100).unwrap();
    for record in pending_before_run {
        assert!(
            replay.contains(&record),
            "cancellation must leave unacknowledged mappings for restart"
        );
    }
}
