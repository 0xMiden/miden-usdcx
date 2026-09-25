use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Signature, B256, U256};
use alloy_sol_types::SolCall;
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::Felt;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::attester::{Attester, DiscoverError, SubmitError};
use crate::signer::{Signer, SignerError, SigningPublicKey};
use crate::submission::SubmissionStatus::{Expired, Finalized, Submitted};
use crate::verify::VerifyError;

use super::discovery::test_config;
use super::submit::{reply, Ledger, ScriptedCircle};
use super::support::{
    development_signers, faucet_account_id, scan_limits, test_note, transaction, BlockFactory,
    CircleState, ObservedRequest, TestChain,
};
use super::validation::{validated_burn, NoteFixture};
use super::verify::{captured, decode_call, serial, with_calldata, FORWARDED_FIXTURE};

type Counts = [Arc<AtomicUsize>; 2];

struct CountedSigner {
    inner: Box<dyn Signer>,
    calls: Arc<AtomicUsize>,
    shutdown: Option<CancellationToken>,
    fail: bool,
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
                shutdown.cancel();
            }
            if self.fail {
                return Err(SignerError);
            }
            self.inner.sign_digest(digest).await
        })
    }
}

pub(super) fn signers(shutdown: Option<CancellationToken>) -> ([Box<dyn Signer>; 2], Counts) {
    let calls = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let mut index = 0;
    let signers = development_signers().map(|inner| {
        let signer = Box::new(CountedSigner {
            inner,
            calls: calls[index].clone(),
            shutdown: shutdown.clone(),
            fail: false,
        }) as Box<dyn Signer>;
        index += 1;
        signer
    });
    (signers, calls)
}

pub(super) fn counts(calls: &Counts) -> [usize; 2] {
    calls.each_ref().map(|count| count.load(Ordering::Relaxed))
}

fn accepted(ledger: &Ledger, index: usize, status: &str) -> CircleState {
    reply(201, json!([ledger.response(index, status)]))
}

#[tokio::test]
async fn either_signer_failure_leaves_burns_retryable_without_submitting() {
    for failed_index in 0..2 {
        let ledger = Ledger::new().await;
        let calls = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        let mut index = 0;
        let signers = development_signers().map(|inner| {
            let signer = Box::new(CountedSigner {
                inner,
                calls: calls[index].clone(),
                shutdown: None,
                fail: index == failed_index,
            }) as Box<dyn Signer>;
            index += 1;
            signer
        });
        let replies = (0..2)
            .flat_map(|_| {
                ledger
                    .fresh_indices
                    .iter()
                    .map(|&i| reply(200, ledger.prepared_response(i)))
            })
            .collect();
        let (mut attester, requests, _) = ledger.runtime(replies, signers).await;
        for cycle in 1..=2 {
            let report = attester.run_one_cycle().await.unwrap();
            assert!(matches!(report.submit, Err(SubmitError::Signing(_))));
            assert_eq!(ledger.stored("SELECT count(*) FROM submissions"), 0);
            assert_eq!(
                ledger.stored("SELECT count(*) FROM burns WHERE hold_reason IS NOT NULL"),
                0
            );
            assert_eq!(requests.lock().unwrap().len(), cycle * 3);
        }
        assert!(requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| matches!(r, ObservedRequest::Prepare)));
        // The second configured key has the lower address and is called first.
        assert_eq!(
            counts(&calls),
            if failed_index == 1 { [0, 6] } else { [6, 6] }
        );
    }
}

pub(super) fn fresh_replies(ledger: &Ledger, indices: &[usize]) -> Vec<CircleState> {
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
    assert!(
        matches!(
            requests.as_slice(),
            [
                ObservedRequest::Submit { .. },
                ObservedRequest::Prepare,
                ObservedRequest::Submit { .. },
                ObservedRequest::Lookup { id, .. },
            ] if id == "6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e71"
        ),
        "{requests:?}"
    );
    assert!(matches!(&requests[0], ObservedRequest::Submit { body, .. } if *body == saved.body));
    assert_eq!(ledger.record(&attester, 0).status, Submitted);
    assert_eq!(ledger.record(&attester, 1).status, Finalized);
    assert_eq!(ledger.record(&attester, 2).status, Submitted);
}

#[tokio::test]
async fn invalid_burns_are_not_signed() {
    let mut invalid = NoteFixture::new();
    invalid.edit_attachment(1, |w| w[0][0] = Felt::new(u64::from(u32::MAX) + 1).unwrap());
    let invalid = test_note(invalid.note(7));
    let young = validated_burn(1_000, serial(8), 9);
    let mut blocks = BlockFactory::new();
    blocks.push(vec![invalid.output], vec![]);
    blocks.push(
        vec![OutputNote::Public(young.burn.note().clone())],
        vec![transaction(faucet_account_id(), &[invalid.nullifier])],
    );
    blocks.push(
        vec![],
        vec![transaction(faucet_account_id(), &[young.burn.nullifier()])],
    );
    blocks.push(vec![], vec![]);
    let directory = tempfile::tempdir().unwrap();
    let config = test_config(&directory, 0, &blocks.blocks()[0], 1);
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
    // A failed check leaves the burn ready for the next cycle, except a forwarded burn too small
    // to pay the configured CCTP fee: that fails the same way every cycle, so it is held. The fee
    // ceiling is checked first, so a small forwarded burn during a fee spike is retried instead.
    for (expected, held) in [
        (VerifyError::DigestMismatch, false),
        (VerifyError::TooSmallToForward, true),
        (VerifyError::FeeTooHigh, false),
    ] {
        let ledger = Ledger::new().await;
        let order = &ledger.fresh_indices;
        {
            let mut config = ledger.config.lock().unwrap();
            config.replace("--max-withdrawal-fee", "1500");
            config.replace("--cctp-forwarding-max-fee", "1000");
        }
        seed(&ledger, &[(order[2], Some("created"))]).await;
        let burn = &ledger.burns[order[0]];
        // Circle's forwarded Linea reply, scaled to this burn and the configured CCTP fee of 1000.
        let forwarded = |payout: u64, fee: u64| {
            let mut batch = captured(FORWARDED_FIXTURE);
            let spec = &mut batch.burn_intents[0].spec;
            spec.salt = burn.burn.note().as_note().serial_num().to_hex();
            spec.value = payout.to_string();
            batch.burn_intents[0].max_fee = fee.to_string();
            let mut call = decode_call(&batch);
            call.amount = U256::from(payout);
            call.destinationDomain = 9;
            call.mintRecipient = B256::from_slice(burn.items.dest_recipient.as_bytes());
            call.maxFee = U256::from(1000);
            let batch = with_calldata(batch, call.abi_encode());
            json!({"batches": [{"burnIntents": batch.burn_intents,
                "encoded": batch.encoded, "messageHashToSign": batch.message_hash_to_sign}]})
        };
        let response = match expected {
            VerifyError::DigestMismatch => {
                let mut response = ledger.prepared_response(order[0]);
                response["batches"][0]["messageHashToSign"] =
                    json!(format!("0x{}", "00".repeat(32)));
                response
            }
            // Nothing else is wrong with this reply: the payout of 1000 cannot pay the CCTP fee.
            VerifyError::TooSmallToForward => forwarded(1000, 0),
            // Just as small, but Circle's fee of 600 plus the CCTP fee exceeds the ceiling of 1500.
            _ => forwarded(400, 600),
        };
        let mut replies = vec![reply(200, response)];
        replies.extend(fresh_replies(&ledger, &order[1..2]));
        replies.push(reply(200, ledger.response(order[2], "finalized")));
        let (signers, calls) = signers(None);
        let (mut attester, requests, _) = ledger.runtime(replies, signers).await;
        let report = attester.run_one_cycle().await.unwrap();
        assert!(report.discover.is_ok());
        assert_eq!(counts(&calls), [1, 1], "{expected}");
        assert_eq!(requests.lock().unwrap().len(), 4);
        assert!(attester
            .store
            .submission(burn.burn.note_id())
            .unwrap()
            .is_none());
        let pending: Vec<_> = attester
            .store
            .burns_ready_for_withdrawal(3u32.into(), 1)
            .unwrap()
            .iter()
            .map(|burn| burn.note_id())
            .collect();
        if held {
            assert!(pending.is_empty(), "the burn is held");
            assert_eq!(
                ledger.stored(&format!(
                    "SELECT count(*) FROM burns WHERE note_id = x'{}'
                        AND hold_reason = 'too_small_to_forward'",
                    hex::encode(burn.burn.note_id().to_bytes())
                )),
                1
            );
        } else {
            assert_eq!(
                pending,
                [burn.burn.note_id()],
                "a failed check leaves the burn unsigned and ready for the next cycle"
            );
        }
        assert_eq!(ledger.record(&attester, order[1]).status, Submitted);
        assert_eq!(ledger.record(&attester, order[2]).status, Finalized);
        let error = report.submit.unwrap_err();
        assert!(
            matches!(error, SubmitError::Verification(cause) if cause.downcast_ref::<VerifyError>() == Some(&expected))
        );
    }
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
    assert_eq!(
        ledger.stored("SELECT count(*) FROM burns WHERE reservation_amount = 1000"),
        3,
        "expiry and finalization keep their capacity charges"
    );
    attester.run_one_cycle().await.unwrap();
    assert_eq!(counts(&calls), [1, 1]);
    assert_eq!(requests.lock().unwrap().len(), 6);
    assert_eq!(ledger.record(&attester, 0).status, Submitted);
    assert_eq!(
        ledger.stored("SELECT count(*) FROM burns WHERE reservation_amount = 1000"),
        3,
        "a replacement must not add or remove a burn's reservation"
    );
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
            error.downcast_ref::<SubmitError>(),
            Some(SubmitError::Store(_))
        ));
        assert!(format!("{error:#}").contains("disk full"));
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

/// A chain that moved behind the verified checkpoint stops the cycle before any Circle traffic.
#[tokio::test]
async fn diverged_chain_stops_the_cycle() {
    let ledger = Ledger::new().await;
    seed(&ledger, &[(0, None), (1, Some("created"))]).await;
    let replies = vec![
        accepted(&ledger, 0, "created"),
        reply(200, ledger.response(1, "finalized")),
    ];
    let (signers, calls) = signers(None);
    let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
    *chain.scan_limits.lock().unwrap() = scan_limits(2, 2);
    let before = [ledger.record(&attester, 0), ledger.record(&attester, 1)];

    let error = attester.run_one_cycle().await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<DiscoverError>(),
        Some(DiscoverError::ChainDiverged)
    ));
    assert_eq!(counts(&calls), [0, 0]);
    assert!(requests.lock().unwrap().is_empty());
    assert_eq!(ledger.record(&attester, 0), before[0]);
    assert_eq!(ledger.record(&attester, 1), before[1]);
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
    let error = attester.run_one_cycle().await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<DiscoverError>(),
        Some(DiscoverError::Store(_))
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

    let shutdown = CancellationToken::new();
    let mut run = Box::pin(attester.run(shutdown.clone()));
    // Two failed cycles, separated by the configured 100 ms delay; neither ends the service.
    assert!(tokio::time::timeout(Duration::from_millis(150), &mut run)
        .await
        .is_err());
    assert_eq!(*chain.scan_limit_requests.lock().unwrap(), 3);
    assert!(requests.lock().unwrap().is_empty());
    shutdown.cancel();
    run.await;
}

/// After a 429 the rest of the cycle leaves Circle alone and the pause before the next cycle
/// doubles; the first cycle without a 429 returns to the poll interval.
#[tokio::test(start_paused = true)]
async fn rate_limit_backs_off_until_a_clean_cycle() {
    let ledger = Ledger::new().await;
    seed(&ledger, &[(0, None), (1, Some("created"))]).await;
    let slow_down = || reply(429, json!({"message": "slow down"}));
    let replies = vec![
        slow_down(),
        slow_down(),
        accepted(&ledger, 0, "finalized"),
        reply(200, ledger.prepared_response(2)),
        accepted(&ledger, 2, "finalized"),
        reply(200, ledger.response(1, "finalized")),
    ];
    let (signers, _) = signers(None);
    let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
    let shutdown = CancellationToken::new();
    let mut run = Box::pin(attester.run(shutdown.clone()));
    // With a 100 ms poll interval the cycles start at 0, 200, 600 and 700 ms.
    for (wait_ms, cycles, requests_sent) in [
        (1, 1, 1),
        (198, 1, 1),
        (2, 2, 2),
        (398, 2, 2),
        (2, 3, 6),
        (97, 3, 6),
        (3, 4, 6),
    ] {
        assert!(
            tokio::time::timeout(Duration::from_millis(wait_ms), &mut run)
                .await
                .is_err()
        );
        assert_eq!(*chain.scan_limit_requests.lock().unwrap(), cycles);
        assert_eq!(requests.lock().unwrap().len(), requests_sent);
    }
    shutdown.cancel();
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
    let shutdown = CancellationToken::new();
    let (signers, calls) = signers(Some(shutdown.clone()));
    let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
    let started = tokio::time::Instant::now();
    attester.run(shutdown.clone()).await;
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "a cancellation cuts the sleep short"
    );
    assert!(shutdown.is_cancelled());
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
