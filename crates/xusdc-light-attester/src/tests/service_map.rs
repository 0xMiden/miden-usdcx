use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Signature, B256};
use miden_protocol::block::BlockNumber;
use miden_protocol::transaction::OutputNote;
use miden_protocol::Felt;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::attester::{Attester, DiscoverError, SubmitError};
use crate::chain::ChainError;
use crate::circle::CircleError;
use crate::signer::{Signer, SignerError, SignerPair, SigningPublicKey};
use crate::submission::SubmissionStatus::{Expired, Finalized, Submitted, Submitting};
use crate::verify::VerifyError;

use super::discovery::test_config;
use super::submit::{reply, Ledger, ScriptedCircle};
use super::support::{
    development_signers, faucet_account_id, scan_limits, test_note, transaction, BlockFactory,
    ChainControls, CircleState, ObservedRequest, TestChain,
};
use super::validation::{validated_burn, NoteFixture};
use super::verify::serial;

type Counts = [Arc<AtomicUsize>; 2];

struct CountedSigner {
    inner: Box<dyn Signer>,
    calls: Arc<AtomicUsize>,
    shutdown: Option<CancellationToken>,
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
            self.inner.sign_digest(digest).await
        })
    }
}

pub(super) async fn signers(shutdown: Option<CancellationToken>) -> (SignerPair, Counts) {
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
    (SignerPair::new(signers).await.unwrap(), calls)
}

pub(super) fn counts(calls: &Counts) -> [usize; 2] {
    calls.each_ref().map(|count| count.load(Ordering::Relaxed))
}

fn accepted(ledger: &Ledger, index: usize, status: &str) -> CircleState {
    reply(201, json!([ledger.response(index, status)]))
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
    let (pair, calls) = signers(None).await;
    let (mut attester, requests, chain) = ledger.runtime(replies, pair).await;
    let saved = ledger.record(&attester, 0);
    let report = attester.run_one_cycle().await.unwrap();
    assert!(report.discover.is_ok() && report.submit.is_ok());
    assert_eq!(counts(&calls), [1, 1]);
    assert_eq!(*chain.scan_limit_requests.lock().unwrap(), 1);
    assert_eq!(
        *chain.requests.lock().unwrap(),
        [BlockNumber::GENESIS, 3u32.into(), 3u32.into()]
    );
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
    let (signers, calls) = signers(None).await;
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
    let (signers, calls) = signers(None).await;
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
    let pending: Vec<_> = attester
        .store
        .burns_ready_for_withdrawal(3u32.into(), 1)
        .unwrap()
        .iter()
        .map(|burn| burn.note_id())
        .collect();
    assert_eq!(
        pending,
        [ledger.burns[order[0]].burn.note_id()],
        "a failed check leaves the burn unsigned and ready for the next cycle"
    );
    assert_eq!(ledger.record(&attester, order[1]).status, Submitted);
    assert_eq!(ledger.record(&attester, order[2]).status, Finalized);
    let error = report.submit.unwrap_err();
    assert!(matches!(
        error,
        SubmitError::Verification(VerifyError::DigestMismatch)
    ));
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
    let (signers, calls) = signers(None).await;
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

/// Any failed chain read, an unreachable node or an answer it cannot decode, still lets the
/// saved submissions be recovered and polled.
#[tokio::test]
async fn discovery_failure_still_recovers_and_polls() {
    for invalid_answer in [false, true] {
        let ledger = Ledger::new().await;
        seed(&ledger, &[(0, None), (1, Some("created"))]).await;
        let (signers, calls) = signers(None).await;
        let replies = vec![
            accepted(&ledger, 0, "created"),
            reply(200, ledger.response(1, "finalized")),
        ];
        let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
        if invalid_answer {
            *chain.invalid_scan_limits.lock().unwrap() = true;
        } else {
            *chain.scan_limits.lock().unwrap() = scan_limits(4, 3);
        }
        let checkpoint = attester.store.scan_state().unwrap();
        let report = attester.run_one_cycle().await.unwrap();
        if invalid_answer {
            assert!(matches!(
                report.discover,
                Err(DiscoverError::Chain(ChainError::Rpc(_)))
            ));
        } else {
            assert!(matches!(
                report.discover,
                Err(DiscoverError::Chain(ChainError::Unavailable))
            ));
        }
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
        let (signers, calls) = signers(None).await;
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
        let stage = if recovering {
            "recovery stopped"
        } else {
            "submission stopped"
        };
        assert!(format!("{error:#}").starts_with(stage), "{error:#}");
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
    let (pair, calls) = signers(None).await;
    let (mut attester, requests, chain) = ledger.runtime(replies, pair).await;
    *chain.scan_limits.lock().unwrap() = scan_limits(2, 2);
    let before = [ledger.record(&attester, 0), ledger.record(&attester, 1)];

    let error = attester.run_one_cycle().await.unwrap_err();
    assert!(
        matches!(
            error.downcast_ref::<DiscoverError>(),
            Some(DiscoverError::ChainDiverged)
        ),
        "{error:#}"
    );
    assert_eq!(counts(&calls), [0, 0]);
    assert!(requests.lock().unwrap().is_empty());
    assert_eq!(ledger.record(&attester, 0), before[0]);
    assert_eq!(ledger.record(&attester, 1), before[1]);

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        attester.run(CancellationToken::new()),
    )
    .await
    .expect("a diverged chain ends the run")
    .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<DiscoverError>(),
        Some(DiscoverError::ChainDiverged)
    ));
    assert_eq!(counts(&calls), [0, 0]);
    assert!(requests.lock().unwrap().is_empty());
    drop(attester);

    let config = test_config(&ledger.directory, 1, &ledger.blocks[0], 1);
    let (circle, fork_requests) = ScriptedCircle::new(ledger.path(), vec![]);
    let (chain, _) = TestChain::new(ledger.fork_blocks.clone(), scan_limits(3, 3));
    let (pair, _) = signers(None).await;
    let error = Attester::start(config, Box::new(chain), Box::new(circle), pair)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            error.downcast_ref::<DiscoverError>(),
            Some(DiscoverError::ChainDiverged)
        ),
        "{error:#}"
    );
    assert!(fork_requests.lock().unwrap().is_empty());

    let config = test_config(&ledger.directory, 1, &ledger.blocks[0], 1);
    let (circle, missing_requests) = ScriptedCircle::new(ledger.path(), vec![]);
    let (chain, _) = TestChain::new(ledger.blocks.clone(), scan_limits(3, 3));
    let (pair, _) = signers(None).await;
    let error = Attester::start(
        config,
        Box::new(chain.missing_at(3)),
        Box::new(circle),
        pair,
    )
    .await
    .err()
    .unwrap();
    assert!(
        matches!(
            error.downcast_ref::<DiscoverError>(),
            Some(DiscoverError::Chain(_))
        ),
        "{error:#}"
    );
    assert!(missing_requests.lock().unwrap().is_empty());

    let replies = vec![
        accepted(&ledger, 0, "created"),
        reply(200, ledger.response(1, "finalized")),
    ];
    let (pair, calls) = signers(None).await;
    let (mut attester, requests, chain) = ledger.runtime(replies, pair).await;
    *chain.scan_limits.lock().unwrap() = scan_limits(3, 1);
    let report = attester.run_one_cycle().await.unwrap();
    assert!(report.discover.is_ok() && report.submit.is_ok());
    assert_eq!(counts(&calls), [0, 0]);
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert_eq!(ledger.record(&attester, 0).status, Submitted);
    assert_eq!(ledger.record(&attester, 1).status, Finalized);
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
    let (signers, calls) = signers(None).await;
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
        [BlockNumber::GENESIS, 2u32.into(), 3u32.into()]
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
    run.await.unwrap();
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
    let (signers, _) = signers(None).await;
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
    run.await.unwrap();
}

/// A 429 anywhere in a cycle ends its Circle traffic: nothing more is prepared, signed, sent or
/// polled. The row keeps Circle's reply when it could be read, and the next direct cycle starts
/// without the 429.
#[tokio::test]
async fn rate_limit_ends_the_cycle_where_it_comes() {
    let slow_down = || reply(429, json!({"message": "slow down"}));
    let reply_body = Some(br#"{"message":"slow down"}"#.to_vec());
    for case in ["recovery", "lookup", "prepare", "submission"] {
        let ledger = Ledger::new().await;
        seed(&ledger, &[(0, None), (1, Some("created"))]).await;
        let id = ledger.response(0, "created")["withdrawalId"].clone();
        let (mut replies, signed, limited) = match case {
            "recovery" => (vec![slow_down()], false, Some((0, reply_body.clone()))),
            "lookup" => (
                vec![
                    reply(409, json!({"conflict": {"withdrawalId": id}})),
                    CircleState::RateLimitedUnread,
                ],
                false,
                Some((0, None)),
            ),
            "prepare" => (
                vec![accepted(&ledger, 0, "created"), slow_down()],
                false,
                None,
            ),
            _ => (
                vec![
                    accepted(&ledger, 0, "created"),
                    reply(200, ledger.prepared_response(2)),
                    slow_down(),
                ],
                true,
                Some((2, reply_body.clone())),
            ),
        };
        let sent = replies.len();
        replies.push(slow_down());
        let (signers, calls) = signers(None).await;
        let (mut attester, requests, _) = ledger.runtime(replies, signers).await;
        let polled = ledger.record(&attester, 1);

        let report = attester.run_one_cycle().await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), sent, "{case}");
        assert_eq!(counts(&calls), [usize::from(signed); 2], "{case}");
        assert_eq!(ledger.record(&attester, 1), polled, "{case}");
        match limited {
            Some((index, body)) => {
                let saved = ledger.record(&attester, index);
                assert_eq!(saved.status, Submitting, "{case}");
                assert_eq!(saved.withdrawal_id.is_some(), case == "lookup", "{case}");
                assert_eq!(
                    (saved.last_http_status, saved.last_response),
                    (body.as_ref().map(|_| 429), body),
                    "{case}"
                );
            }
            None => {
                assert!(matches!(
                    report.submit,
                    Err(SubmitError::Prepare(CircleError::RateLimited { .. }))
                ));
                assert!(attester
                    .store
                    .submission(ledger.burns[2].burn.note_id())
                    .unwrap()
                    .is_none());
            }
        }

        attester.run_one_cycle().await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), sent + 1, "{case}");
    }
}

/// Advances paused time around each expected cycle start and checks that the cycle started then,
/// and not before.
async fn assert_cycle_starts(
    run: &mut Pin<Box<impl Future<Output = anyhow::Result<()>>>>,
    chain: &ChainControls,
    starts_ms: &[u64],
) {
    let mut elapsed = 0;
    for (started, &start) in starts_ms.iter().enumerate() {
        if start > 0 {
            let early = Duration::from_millis(start - 1 - elapsed);
            assert!(tokio::time::timeout(early, &mut *run).await.is_err());
            assert_eq!(*chain.scan_limit_requests.lock().unwrap(), started);
            elapsed = start - 1;
        }
        let due = Duration::from_millis(start + 1 - elapsed);
        assert!(tokio::time::timeout(due, &mut *run).await.is_err());
        assert_eq!(*chain.scan_limit_requests.lock().unwrap(), started + 1);
        elapsed = start + 1;
    }
}

/// Only a 429 lengthens the pause, even when the cycle then stops on a store failure; a cycle that
/// fails without one goes back to the poll interval.
#[tokio::test(start_paused = true)]
async fn only_a_rate_limit_lengthens_the_pause() {
    // (the Circle status whose saved outcome fails to write, Circle's answers, cycle starts)
    for (failing, statuses, starts_ms) in [
        (429, [429, 429, 429], [0, 200, 600]),
        (201, [429, 201, 201], [0, 200, 300]),
    ] {
        let ledger = Ledger::new().await;
        seed(&ledger, &[(0, None)]).await;
        ledger.sql(&format!(
            "CREATE TRIGGER fail_outcome BEFORE UPDATE ON submissions \
             WHEN NEW.last_http_status = {failing} BEGIN SELECT RAISE(FAIL, 'disk full'); END;"
        ));
        let replies = statuses
            .map(|status| match status {
                429 => reply(429, json!({"message": "slow down"})),
                _ => accepted(&ledger, 0, "created"),
            })
            .to_vec();
        let (signers, _) = signers(None).await;
        let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
        let shutdown = CancellationToken::new();
        let mut run = Box::pin(attester.run(shutdown.clone()));
        assert_cycle_starts(&mut run, &chain, &starts_ms).await;
        assert_eq!(requests.lock().unwrap().len(), 3);
        shutdown.cancel();
        run.await.unwrap();
    }
}

/// A poll interval above the one-minute cap is still the least pause after a 429.
#[tokio::test(start_paused = true)]
async fn long_poll_interval_is_kept_after_a_rate_limit() {
    let ledger = Ledger::new().await;
    seed(&ledger, &[(0, None)]).await;
    ledger
        .config
        .lock()
        .unwrap()
        .replace("--poll-interval", "90s");
    let replies = vec![reply(429, json!({"message": "slow down"})); 3];
    let (signers, _) = signers(None).await;
    let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
    let shutdown = CancellationToken::new();
    let mut run = Box::pin(attester.run(shutdown.clone()));
    assert_cycle_starts(&mut run, &chain, &[0, 90_000, 180_000]).await;
    assert_eq!(requests.lock().unwrap().len(), 3);
    shutdown.cancel();
    run.await.unwrap();
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
    let (signers, calls) = signers(Some(shutdown.clone())).await;
    let (mut attester, requests, chain) = ledger.runtime(replies, signers).await;
    let started = tokio::time::Instant::now();
    attester.run(shutdown.clone()).await.unwrap();
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
