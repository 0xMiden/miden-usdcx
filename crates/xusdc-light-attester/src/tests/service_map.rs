use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Signature, B256};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteType;
use miden_protocol::transaction::OutputNote;
use miden_standards::note::BurnNote;
use serde_json::json;

use crate::attester::{Attester, CycleError, DiscoverError, SubmitError};
use crate::signer::{Signer, SignerError, SigningPublicKey};
use crate::submission::SubmissionStatus::{Expired, Finalized, Submitted};
use crate::verify::VerifyError;

use super::discovery::write_config;
use super::submit::{reply, Ledger, ScriptedCircle};
use super::support::{
    development_signers, faucet_account_id, note, scan_limits, transaction, BlockFactory,
    CircleState, TestChain,
};
use super::validation::validated_burn;
use super::verify::serial;

type Counts = [Arc<AtomicUsize>; 2];

struct CountedSigner {
    inner: Box<dyn Signer>,
    calls: Arc<AtomicUsize>,
    shutdown: Option<Arc<AtomicBool>>,
}

impl Signer for CountedSigner {
    fn public_key(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, SignerError>> + Send + '_>> {
        self.inner.public_key()
    }

    fn sign_digest(
        &self,
        digest: B256,
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignerError>> + Send + '_>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if let Some(shutdown) = &self.shutdown {
                shutdown.store(true, Ordering::Release);
            }
            self.inner.sign_digest(digest).await
        })
    }
}

fn signers(shutdown: Option<Arc<AtomicBool>>) -> ([Box<dyn Signer>; 2], Counts) {
    let calls = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let mut index = 0;
    let signers = development_signers().map(|inner| {
        let signer = Box::new(CountedSigner {
            inner,
            calls: calls[index].clone(),
            shutdown: shutdown.clone(),
        }) as Box<dyn Signer>;
        index += 1;
        signer
    });
    (signers, calls)
}

fn counts(calls: &Counts) -> [usize; 2] {
    calls.each_ref().map(|count| count.load(Ordering::Relaxed))
}

fn accepted(ledger: &Ledger, index: usize, status: &str) -> CircleState {
    reply(201, json!([ledger.response(index, status)]))
}

fn fresh_replies(ledger: &Ledger, indices: &[usize]) -> Vec<CircleState> {
    indices
        .iter()
        .flat_map(|&i| {
            [
                reply(200, ledger.prepared_response(i)),
                accepted(ledger, i, "created"),
            ]
        })
        .collect()
}

async fn seed(ledger: &Ledger, outcomes: &[(usize, Option<&str>)]) {
    let replies = outcomes
        .iter()
        .map(|&(i, status)| status.map_or(CircleState::TransportError, |s| accepted(ledger, i, s)))
        .collect();
    let (mut attester, _) = ledger.start(replies).await;
    for &(index, _) in outcomes {
        ledger.submit(&mut attester, index).await.unwrap();
    }
}

#[tokio::test]
async fn cycle_runs_in_order() {
    let ledger = Ledger::new().await;
    seed(&ledger, &[(0, None), (1, Some("created"))]).await;
    let mut replies = vec![accepted(&ledger, 0, "created")];
    replies.extend(fresh_replies(&ledger, &[2]));
    replies.push(reply(200, ledger.response(1, "finalized")));
    let (signers, calls) = signers(None);
    let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
    let saved = ledger.record(&attester, 0);
    let report = attester.run_one_cycle().await.unwrap();
    assert!(report.discover.is_ok() && report.submit.is_ok());
    assert_eq!(counts(&calls), [1, 1]);
    assert_eq!(*chain.scan_limit_requests.lock().unwrap(), 1);
    assert_eq!(*chain.requests.lock().unwrap(), [BlockNumber::GENESIS]);
    let requests = requests.lock().unwrap();
    let paths: Vec<_> = requests
        .iter()
        .map(|r| {
            r.url
                .strip_prefix("https://circle.example.invalid")
                .unwrap()
        })
        .collect();
    assert_eq!(
        paths,
        [
            "/v1/withdraw",
            "/v1/prepare-withdrawal",
            "/v1/withdraw",
            "/v1/withdrawal/6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e71",
        ]
    );
    assert_eq!(requests[0].body, saved.body);
    assert_eq!(ledger.record(&attester, 0).status, Submitted);
    assert_eq!(ledger.record(&attester, 1).status, Finalized);
    assert_eq!(ledger.record(&attester, 2).status, Submitted);
}

#[tokio::test]
async fn invalid_burns_are_not_signed() {
    let invalid = note(BurnNote::script(), NoteType::Public, 7, 1);
    let young = validated_burn(1_000, serial(8), 9);
    let mut blocks = BlockFactory::new(faucet_account_id());
    blocks.push(vec![invalid.output], vec![]);
    blocks.push(
        vec![OutputNote::Public(young.burn.note.clone())],
        vec![transaction(faucet_account_id(), &[invalid.nullifier])],
    );
    blocks.push(
        vec![],
        vec![transaction(faucet_account_id(), &[young.burn.nullifier()])],
    );
    blocks.push(vec![], vec![]);
    let directory = tempfile::tempdir().unwrap();
    let config = write_config(&directory, 0, &blocks.blocks()[0], 1);
    let (circle, requests) = ScriptedCircle::new(directory.path().join("state.sqlite3"), vec![]);
    let (chain, _) = TestChain::new(blocks.blocks(), scan_limits(3, 1));
    let (signers, calls) = signers(None);
    let mut attester = Attester::start(config, Box::new(chain), Box::new(circle), signers)
        .await
        .unwrap();
    let report = attester.run_one_cycle().await.unwrap();
    assert!(report.discover.is_ok() && report.submit.is_ok());
    assert_eq!(counts(&calls), [0, 0]);
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn circle_response_is_checked_before_signing() {
    let ledger = Ledger::new().await;
    let order = &ledger.fresh_indices;
    seed(&ledger, &[(order[2], Some("created"))]).await;
    let mut response = ledger.prepared_response(order[0]);
    response["batches"][0]["messageHashToSign"] = json!(format!("0x{}", "00".repeat(32)));
    let mut replies = vec![reply(200, response)];
    replies.extend(fresh_replies(&ledger, &order[1..2]));
    replies.push(reply(200, ledger.response(order[2], "finalized")));
    let (signers, calls) = signers(None);
    let (mut attester, requests, _) = ledger.runtime(replies, signers).await;
    let report = attester.run_one_cycle().await.unwrap();
    assert!(report.discover.is_ok());
    assert_eq!(counts(&calls), [1, 1]);
    assert_eq!(requests.lock().unwrap().len(), 4);
    assert!(attester
        .store
        .submission(ledger.burns[order[0]].burn.note_id())
        .unwrap()
        .is_none());
    let pending = attester
        .store
        .burns_ready_for_withdrawal(3u32.into(), 1)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].note_id(), ledger.burns[order[0]].burn.note_id());
    assert_eq!(ledger.record(&attester, order[1]).status, Submitted);
    assert_eq!(ledger.record(&attester, order[2]).status, Finalized);
    let error = report.submit.unwrap_err();
    assert!(
        matches!(error, SubmitError::Verification(cause) if cause.downcast_ref::<VerifyError>() == Some(&VerifyError::DigestMismatch))
    );
}

#[tokio::test]
async fn expiry_waits_for_the_next_cycle() {
    let ledger = Ledger::new().await;
    seed(
        &ledger,
        &[(0, None), (1, Some("created")), (2, Some("created"))],
    )
    .await;
    let id = ledger.response(0, "expired")["withdrawalId"].clone();
    let mut replies = vec![
        reply(409, json!({"conflict": {"withdrawalId": id}})),
        reply(200, ledger.response(0, "expired")),
    ];
    replies.extend(
        ledger
            .ordered_indices()
            .into_iter()
            .filter(|i| *i != 0)
            .map(|i| reply(200, ledger.response(i, "finalized"))),
    );
    replies.extend(fresh_replies(&ledger, &[0]));
    let (signers, calls) = signers(None);
    let (mut attester, requests, _) = ledger.runtime(replies, signers).await;
    let report = attester.run_one_cycle().await.unwrap();
    assert!(report.discover.is_ok() && report.submit.is_ok());
    assert_eq!(ledger.record(&attester, 0).status, Expired);
    assert_eq!(ledger.record(&attester, 1).status, Finalized);
    assert_eq!(ledger.record(&attester, 2).status, Finalized);
    assert_eq!(counts(&calls), [0, 0]);
    assert_eq!(requests.lock().unwrap().len(), 4);
    attester.run_one_cycle().await.unwrap();
    assert_eq!(counts(&calls), [1, 1]);
    assert_eq!(requests.lock().unwrap().len(), 6);
    assert_eq!(ledger.record(&attester, 0).status, Submitted);
}

#[tokio::test]
async fn discovery_failure_still_recovers_and_polls() {
    let ledger = Ledger::new().await;
    seed(&ledger, &[(0, None), (1, Some("created"))]).await;
    let (signers, calls) = signers(None);
    let replies = vec![
        accepted(&ledger, 0, "created"),
        reply(200, ledger.response(1, "finalized")),
    ];
    let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
    *chain.scan_limits.lock().unwrap() = scan_limits(4, 3);
    let checkpoint = attester.store.scan_state().unwrap();
    let report = attester.run_one_cycle().await.unwrap();
    assert!(matches!(report.discover, Err(DiscoverError::Chain(_))));
    assert!(report.submit.is_ok());
    assert_eq!(counts(&calls), [0, 0]);
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert_eq!(ledger.record(&attester, 0).status, Submitted);
    assert_eq!(ledger.record(&attester, 1).status, Finalized);
    assert!(attester
        .store
        .submission(ledger.burns[2].burn.note_id())
        .unwrap()
        .is_none());
    assert_eq!(attester.store.scan_state().unwrap(), checkpoint);
}

#[tokio::test]
async fn submission_store_failure_stops_remaining_work() {
    for recovering in [true, false] {
        let ledger = Ledger::new().await;
        let [first, second, polled] = [0, 1, 2].map(|i| ledger.fresh_indices[i]);
        seed(&ledger, &[(polled, Some("created"))]).await;
        let first_reply = if recovering {
            seed(&ledger, &[(first, None)]).await;
            ledger.sql("CREATE TRIGGER fail_outcome BEFORE UPDATE ON submissions BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
            accepted(&ledger, first, "created")
        } else {
            ledger.sql("CREATE TRIGGER fail_insert BEFORE INSERT ON submissions BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
            reply(200, ledger.prepared_response(first))
        };
        let replies = vec![
            first_reply,
            reply(200, ledger.prepared_response(second)),
            reply(200, ledger.response(polled, "finalized")),
        ];
        let (signers, calls) = signers(None);
        let (mut attester, requests, _) = ledger.runtime(replies, signers).await;
        let before = [first, second, polled].map(|i| {
            attester
                .store
                .submission(ledger.burns[i].burn.note_id())
                .unwrap()
        });
        let error = attester.run_one_cycle().await.unwrap_err();
        assert!(matches!(
            error,
            CycleError::Submission(SubmitError::InvalidStore)
        ));
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(counts(&calls), [usize::from(!recovering); 2]);
        assert_eq!(
            requests.lock().unwrap().len(),
            1,
            "stop after failed persistence"
        );
        for (i, saved) in [first, second, polled].into_iter().zip(before) {
            assert_eq!(
                attester
                    .store
                    .submission(ledger.burns[i].burn.note_id())
                    .unwrap(),
                saved
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn discovery_store_failure_stops_work_but_retries() {
    let ledger = Ledger::new().await;
    seed(&ledger, &[(0, None), (1, Some("created"))]).await;
    ledger.rewind_empty_block();
    ledger.sql("CREATE TRIGGER fail_scan BEFORE UPDATE ON attester_state BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
    let replies = vec![
        accepted(&ledger, 0, "created"),
        reply(200, ledger.response(1, "finalized")),
    ];
    let (signers, calls) = signers(None);
    let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
    let checkpoint = attester.store.scan_state().unwrap();
    let before = [ledger.record(&attester, 0), ledger.record(&attester, 1)];
    assert!(matches!(
        attester.run_one_cycle().await,
        Err(CycleError::Discovery(DiscoverError::Store(_)))
    ));
    assert_eq!(counts(&calls), [0, 0]);
    assert!(requests.lock().unwrap().is_empty());
    assert_eq!(
        *chain.requests.lock().unwrap(),
        [BlockNumber::GENESIS, 3u32.into()]
    );
    assert_eq!(attester.store.scan_state().unwrap(), checkpoint);
    assert_eq!(ledger.record(&attester, 0), before[0]);
    assert_eq!(ledger.record(&attester, 1), before[1]);

    let shutdown = Arc::new(AtomicBool::new(false));
    let mut run = Box::pin(attester.run(shutdown.clone()));
    // Two failed cycles, separated by the configured 100 ms delay; neither ends the service.
    assert!(tokio::time::timeout(Duration::from_millis(150), &mut run)
        .await
        .is_err());
    assert_eq!(*chain.scan_limit_requests.lock().unwrap(), 3);
    assert!(requests.lock().unwrap().is_empty());
    shutdown.store(true, Ordering::Release);
    run.await;
}

#[tokio::test(start_paused = true)]
async fn restart_and_shutdown_do_not_lose_work() {
    let ledger = Ledger::new().await;
    seed(&ledger, &[(1, Some("created"))]).await;
    let fresh: Vec<_> = ledger
        .fresh_indices
        .iter()
        .copied()
        .filter(|i| *i != 1)
        .collect();
    let mut replies = fresh_replies(&ledger, &fresh);
    replies.push(reply(200, ledger.response(1, "finalized")));
    let shutdown = Arc::new(AtomicBool::new(false));
    let (signers, calls) = signers(Some(shutdown.clone()));
    let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
    let started = tokio::time::Instant::now();
    attester.run(shutdown.clone()).await;
    assert_eq!(
        started.elapsed(),
        Duration::from_millis(100),
        "sleep the full interval"
    );
    assert!(shutdown.load(Ordering::Acquire));
    assert_eq!(
        counts(&calls),
        [2, 2],
        "finish the second burn after shutdown"
    );
    assert_eq!(
        requests.lock().unwrap().len(),
        5,
        "finish submissions and polling"
    );
    assert_eq!(*chain.scan_limit_requests.lock().unwrap(), 1);
    assert_eq!(ledger.record(&attester, 1).status, Finalized);
    for index in fresh {
        assert_eq!(ledger.record(&attester, index).status, Submitted);
    }
}
