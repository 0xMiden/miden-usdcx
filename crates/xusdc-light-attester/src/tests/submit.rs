//! Durable submission and recovery, using synthetic responses rather than claiming live proof.

use std::collections::VecDeque;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::{keccak256, Signature, B256, U256};
use miden_objects::prost::Message;
use miden_objects::proto;
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::serde::Serializable;
use reqwest::{header::CONTENT_TYPE, Method, StatusCode};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

use crate::attester::{release_holds, Attester};
use crate::burn::{DiscoveredBurn, ValidatedBurn};
use crate::circle::{
    read_prepared, CircleApi, CircleClient, CircleError, RawResponse, UnverifiedPrepareResponse,
};
use crate::signer::{Signer, SignerError, SignerPair, SigningPublicKey};
use crate::store::{ScanCursor, Store, TrustedAnchor, CONFLICT, INVALID};
use crate::submission::{HoldReason, SavedSubmission, SubmissionStatus, SubmitError};
use crate::verify::{rebuild_for_test, SignedWithdrawal};

use super::discovery;
use super::service_map::{counts, fresh_replies, signers};
use super::startup::TestArgs;
use super::support::{
    development_pair, faucet_account_id, history, read_store, scan_limits, transaction,
    BlockFactory, ChainControls, CircleState, ObservedRequest, TestChain,
};
use super::validation::validated_burn;
use super::verify::{batch, serial};

const ID: &str = "6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e70";
const ENDPOINT: &str = "https://circle.example.invalid/v1/withdraw";
pub(super) type Requests = Arc<Mutex<Vec<ObservedRequest>>>;

pub(super) async fn recover(attester: &mut Attester) -> Result<(), SubmitError> {
    let queue = attester.store.submissions_to_recover()?;
    attester.advance_submissions(queue, &mut false).await
}

pub(super) async fn poll(attester: &mut Attester) -> Result<(), SubmitError> {
    let queue = attester.store.submissions_to_poll().unwrap();
    attester.advance_submissions(queue, &mut false).await
}

struct TestSigner(u8);
impl Signer for TestSigner {
    fn public_key(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, SignerError>> + Send + '_>> {
        // Signer 1 holds the key with the lower Ethereum address, so ids follow address order.
        let key = match self.0 {
            1 => alloy_primitives::hex!(
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
            ),
            _ => alloy_primitives::hex!(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ),
        };
        Box::pin(async move { Ok(SigningPublicKey(key)) })
    }
    fn sign_digest(
        &self,
        _: B256,
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignerError>> + Send + '_>> {
        Box::pin(async move {
            Ok(Signature::new(
                U256::from(self.0),
                U256::from(self.0),
                false,
            ))
        })
    }
}

pub(super) struct ScriptedCircle {
    replies: Mutex<VecDeque<CircleState>>,
    requests: Requests,
    store_path: PathBuf,
}

impl ScriptedCircle {
    pub(super) fn new(store_path: PathBuf, replies: Vec<CircleState>) -> (Self, Requests) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                replies: Mutex::new(replies.into()),
                requests: requests.clone(),
                store_path,
            },
            requests,
        )
    }

    /// Checks that the store already holds what is about to be sent, then records the call and
    /// hands out the next scripted reply.
    fn reply_after_save(
        &self,
        request: ObservedRequest,
        sql: &str,
        value: impl rusqlite::ToSql,
    ) -> Result<RawResponse, CircleError> {
        // Inspect committed disk bytes while the writer is idle at its Circle boundary.
        // An immutable reader avoids the store's intentional exclusive connection lock.
        let disk = Connection::open_with_flags(
            format!("file:{}?immutable=1", self.store_path.display()),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .unwrap();
        let saved: i64 = disk.query_row(sql, [value], |r| r.get(0)).unwrap();
        assert_eq!(
            saved, 1,
            "request and any recovery ID must be durable before they are sent to Circle"
        );
        self.next_reply(request)
    }

    fn next_reply(&self, request: ObservedRequest) -> Result<RawResponse, CircleError> {
        self.requests.lock().unwrap().push(request);
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected extra Circle request")
            .answer()
    }
}

impl CircleApi for ScriptedCircle {
    fn check_connection(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircleError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }

    fn prepare_withdrawal<'a>(
        &'a self,
        _burn: &'a ValidatedBurn,
        _cctp_forwarding_max_fee: u64,
    ) -> Pin<Box<dyn Future<Output = Result<UnverifiedPrepareResponse, CircleError>> + Send + 'a>>
    {
        Box::pin(async move { read_prepared(self.next_reply(ObservedRequest::Prepare)?) })
    }

    fn post_submission<'a>(
        &'a self,
        saved: &'a SavedSubmission,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + 'a>> {
        Box::pin(async move {
            self.reply_after_save(
                ObservedRequest::Submit {
                    endpoint: saved.endpoint.to_string(),
                    body: saved.body.clone(),
                },
                "SELECT count(*) FROM submissions WHERE status = 'SUBMITTING' AND body = ?1 AND withdrawal_id IS NULL",
                &saved.body,
            )
        })
    }

    fn get_withdrawal<'a>(
        &'a self,
        saved: &'a SavedSubmission,
        id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + 'a>> {
        Box::pin(async move {
            self.reply_after_save(
                ObservedRequest::Lookup {
                    endpoint: saved.endpoint.to_string(),
                    id: id.to_owned(),
                },
                "SELECT count(*) FROM submissions WHERE status IN ('SUBMITTING', 'SUBMITTED') AND withdrawal_id = ?1",
                id,
            )
        })
    }
}

pub(super) struct Ledger {
    pub(super) directory: tempfile::TempDir,
    pub(super) blocks: Vec<SignedBlock>,
    pub(super) fork_blocks: Vec<SignedBlock>,
    pub(super) config: Mutex<TestArgs>,
    pub(super) burns: Vec<ValidatedBurn>,
    pub(super) fresh_indices: Vec<usize>,
}

impl Ledger {
    pub(super) async fn new() -> Self {
        let mut burns: Vec<_> = (0..3)
            .map(|i| validated_burn(1_000, serial(0x3132_3334_3536_3738 + i), 9))
            .collect();
        let mut factory = BlockFactory::new();
        factory.push(vec![], vec![]);
        factory.push(
            burns
                .iter()
                .map(|b| OutputNote::Public(b.burn.note().clone()))
                .collect(),
            vec![],
        );
        let shared = transaction(
            faucet_account_id(),
            &[burns[0].burn.nullifier(), burns[1].burn.nullifier()],
        );
        for burn in &mut burns[..2] {
            burn.burn = DiscoveredBurn::new(
                burn.burn.note().clone(),
                burn.burn.creation_block(),
                burn.burn.consumption_block(),
                shared.id(),
                faucet_account_id(),
            )
            .unwrap();
        }
        let transactions = vec![
            shared,
            transaction(faucet_account_id(), &[burns[2].burn.nullifier()]),
        ];
        factory.push(vec![], transactions);
        let mut fork_factory = factory.clone();
        factory.push(vec![], vec![]);
        fork_factory.push(
            vec![OutputNote::Public(burns[0].burn.note().clone())],
            vec![],
        );
        let directory = tempfile::tempdir().unwrap();
        let blocks = factory.blocks();
        let (mut attester, _) =
            discovery::start(&directory, 1, blocks.clone(), scan_limits(3, 3)).await;
        attester.discover_burns().await.unwrap();
        let fresh_indices = attester
            .store
            .burns_ready_for_withdrawal(3u32.into(), 1)
            .unwrap()
            .iter()
            .map(|saved| {
                burns
                    .iter()
                    .position(|burn| burn.burn.note_id() == saved.note_id())
                    .unwrap()
            })
            .collect();
        let config = discovery::test_args(&directory, 1, &blocks[0], 1);
        Self {
            directory,
            blocks,
            fork_blocks: fork_factory.blocks(),
            config: Mutex::new(config),
            burns,
            fresh_indices,
        }
    }

    pub(super) fn path(&self) -> PathBuf {
        self.directory.path().join("state.sqlite3")
    }

    pub(super) async fn start(&self, replies: Vec<CircleState>) -> (Attester, Requests) {
        let (attester, requests, _) = self.runtime(replies, development_pair().await).await;
        (attester, requests)
    }

    pub(super) async fn runtime(
        &self,
        replies: Vec<CircleState>,
        signers: SignerPair,
    ) -> (Attester, Requests, ChainControls) {
        let (circle, requests) = ScriptedCircle::new(self.path(), replies);
        let config = self.config.lock().unwrap().load();
        let (chain, controls) = TestChain::new(self.blocks.clone(), scan_limits(3, 3));
        let attester = Attester::start(config, Box::new(chain), Box::new(circle), signers)
            .await
            .unwrap();
        (attester, requests, controls)
    }

    pub(super) fn ordered_indices(&self) -> Vec<usize> {
        let mut indices: Vec<_> = (0..self.burns.len()).collect();
        indices.sort_by_key(|&i| self.burns[i].burn.note_id().to_bytes());
        indices
    }

    pub(super) fn prepared_response(&self, index: usize) -> Value {
        let burn = &self.burns[index];
        let prepared = batch(
            &burn.burn.note_id().to_hex(),
            burn.amount,
            burn.items.dest_domain.as_u32(),
        );
        json!({"batches": [{"burnIntents": prepared.burn_intents,
            "encoded": prepared.encoded, "messageHashToSign": prepared.message_hash_to_sign}]})
    }

    async fn signed(&self, index: usize) -> SignedWithdrawal {
        self.signed_with_max_height(index, None).await
    }

    pub(super) async fn signed_with_max_height(
        &self,
        index: usize,
        height: Option<&str>,
    ) -> SignedWithdrawal {
        let burn = &self.burns[index];
        let mut prepared = batch(&burn.burn.note_id().to_hex(), 1_000, 9);
        if let Some(height) = height {
            prepared.burn_intents[0].max_block_height = height.into();
            rebuild_for_test(&mut prepared).unwrap();
        }
        let signers = SignerPair::new([
            Box::new(TestSigner(1)) as Box<dyn Signer>,
            Box::new(TestSigner(2)) as Box<dyn Signer>,
        ])
        .await
        .unwrap();
        let config = self.config.lock().unwrap().load();
        UnverifiedPrepareResponse {
            batches: vec![prepared],
        }
        .verify(burn, &config)
        .unwrap()
        .sign(&signers)
        .await
        .unwrap()
    }

    pub(super) async fn submit(
        &self,
        attester: &mut Attester,
        index: usize,
    ) -> Result<(), SubmitError> {
        attester
            .submit_signed_withdrawal(&self.signed(index).await, &mut false)
            .await
    }

    pub(super) fn record(&self, attester: &Attester, index: usize) -> SavedSubmission {
        attester
            .store
            .submission(self.burns[index].burn.note_id())
            .unwrap()
            .unwrap()
    }

    /// The burn's history, oldest first: each row's kind and the submission status it recorded.
    pub(super) fn history(&self, index: usize) -> Vec<(String, Option<String>)> {
        history(&self.path(), self.burns[index].burn.note_id())
    }

    pub(super) fn stored(&self, sql: &str) -> i64 {
        let disk = Connection::open_with_flags(
            format!("file:{}?immutable=1", self.path().display()),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .unwrap();
        disk.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    /// Opens the ledger's store directly, as a starting attester would.
    pub(super) fn open_store(&self) -> anyhow::Result<Store> {
        Store::open_or_create(
            &self.path(),
            faucet_account_id(),
            ScanCursor {
                next_block: BlockNumber::from(1u32),
            },
            TrustedAnchor {
                block_num: BlockNumber::GENESIS,
                commitment: self.blocks[0].header().commitment(),
            },
        )
    }

    pub(super) fn sql(&self, sql: &str) {
        Connection::open(self.path())
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }

    pub(super) fn rewind_empty_block(&self) {
        let header = proto::blockchain::BlockHeader::from(self.blocks[2].header()).encode_to_vec();
        self.sql(&format!(
            "UPDATE attester_state SET next_block = 3, authenticated_parent = x'{}'",
            hex::encode(header),
        ));
    }

    pub(super) fn response(&self, index: usize, status: &str) -> Value {
        json!({"withdrawalId": format!("6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e{:02}", 70 + index), "burnTxId": self.burns[index].burn.note_id().to_hex(),
            "status": status, "useCircleForwarding": true, "transferSpecHashes": [reference_hash(&self.burns[index])]})
    }
}

pub(super) async fn submission_store() -> (tempfile::TempDir, Vec<SignedBlock>, TestArgs) {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![CircleState::TransportError]).await;
    ledger.submit(&mut attester, 0).await.unwrap();
    drop(attester);
    let config = ledger.config.into_inner().unwrap();
    (ledger.directory, ledger.blocks, config)
}

#[tokio::test]
async fn malformed_saved_submission_is_rejected_when_loaded() {
    let (directory, blocks, config) = submission_store().await;
    Connection::open(directory.path().join("state.sqlite3"))
        .unwrap()
        .execute("UPDATE submissions SET body = X'00'", [])
        .unwrap();

    let requests = Arc::new(Mutex::new(Vec::new()));
    let circle = ScriptedCircle {
        replies: Mutex::new(VecDeque::new()),
        requests: requests.clone(),
        store_path: directory.path().join("state.sqlite3"),
    };
    let chain = TestChain::new(blocks, scan_limits(3, 3)).0;
    let mut attester = Attester::start(
        config.load(),
        Box::new(chain),
        Box::new(circle),
        development_pair().await,
    )
    .await
    .expect("startup checks structure, not submission contents");

    assert!(matches!(
        recover(&mut attester).await,
        Err(SubmitError::Store(_))
    ));
    assert!(requests.lock().unwrap().is_empty());
}

/// The stored status names never change, and any other name is refused when a row is read.
#[test]
fn submission_status_names_are_fixed() {
    use SubmissionStatus::*;
    for (status, name) in [
        (Submitting, "SUBMITTING"),
        (Submitted, "SUBMITTED"),
        (Finalized, "FINALIZED"),
        (Expired, "EXPIRED"),
        (Failed, "FAILED"),
        (Held, "HELD"),
    ] {
        assert_eq!(status.as_ref(), name);
        assert_eq!(name.parse::<SubmissionStatus>(), Ok(status));
    }
    assert!("submitting".parse::<SubmissionStatus>().is_err());
}

// Synthetic packed TransferSpec vector, independently transcribed from Circle's Solidity layout.
// This tests our encoder, not the still-unobserved correspondence to REST transferSpecHashes.
fn reference_hash(burn: &ValidatedBurn) -> String {
    let packed = format!(
        concat!(
            "ca85def7000000010000000600000009",
            "{0}{1}{2}{3}{4}",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "{4}{5}",
            "00000000000000000000000000000000000000000000000000000000000003e8",
            "{6}",
            "00000070",
            "6b20f62a0000000100002717",
            "00000000000000000000000000000000bb405fd9fe431bd1135a292de098cb00",
            "00000000000000000000000000000000ba0000000000ca110000dd000000ef00",
            "{5}00000000"
        ),
        "11".repeat(32),
        "22".repeat(32),
        "0000000000000000000000003600000000000000000000000000000000000000",
        "44".repeat(32),
        "55".repeat(32),
        "00".repeat(32),
        hex::encode(burn.burn.note_id().as_bytes())
    );
    keccak256(hex::decode(packed).unwrap()).to_string()
}

/// A history row's kind and the submission status it recorded.
pub(super) fn event(kind: &str, status: SubmissionStatus) -> (String, Option<String>) {
    (kind.into(), Some(status.as_ref().into()))
}

pub(super) fn reply(status: u16, value: Value) -> CircleState {
    CircleState::ResponseBody(
        StatusCode::from_u16(status).unwrap(),
        serde_json::to_vec(&value).unwrap(),
    )
}
fn conflict() -> CircleState {
    reply(
        409,
        json!({"success": false, "message": "already associated", "conflict": {"withdrawalId": ID}}),
    )
}

/// Sends the checked intent and both signatures; binds every successful status to that request.
#[tokio::test]
async fn submit_sends_checked_request() {
    use SubmissionStatus::*;
    for (status, expected) in [
        ("created", Submitted),
        ("verified", Submitted),
        ("confirmed", Submitted),
        ("finalized", Finalized),
        ("expired", Expired),
        ("failed", Failed),
        ("new_status", Submitting),
    ] {
        let ledger = Ledger::new().await;
        let mut response = ledger.response(0, status);
        if status == "failed" {
            response["failureReason"] = json!("Circle's reported failure");
        }
        let (mut attester, requests) = ledger.start(vec![reply(201, json!([response]))]).await;
        ledger.submit(&mut attester, 0).await.unwrap();
        let saved = ledger.record(&attester, 0);
        assert_eq!(saved.status, expected, "{status}");
        assert_eq!(saved.withdrawal_id.as_deref(), Some(ID));
        assert_eq!(
            saved.transfer_spec_hash.to_string(),
            reference_hash(&ledger.burns[0])
        );
        if status == "failed" {
            assert_eq!(
                saved.last_error.as_deref(),
                Some("Circle's reported failure")
            );
        }
        if status == "new_status" {
            assert_eq!(
                saved.last_error.as_deref(),
                Some("Circle returned an unknown withdrawal status")
            );
        }
        assert!(attester.retry_held_submission(saved.note_id).is_err());
        if matches!(status, "created" | "finalized" | "failed" | "new_status") {
            let history = ledger.history(0);
            let fresh = ledger
                .signed_with_max_height(0, Some("184467440737095516170001"))
                .await;
            assert!(
                matches!(
                    attester.submit_signed_withdrawal(&fresh, &mut false).await,
                    Err(SubmitError::Store(error)) if error.to_string() == CONFLICT
                ),
                "{status}"
            );
            assert_eq!(ledger.record(&attester, 0), saved);
            assert_eq!(ledger.history(0), history, "{status}");
        }
        {
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            let ObservedRequest::Submit { endpoint, body } = &requests[0] else {
                panic!("expected the withdraw request, got {:?}", requests[0]);
            };
            assert_eq!(endpoint, ENDPOINT);
            let body: Value = serde_json::from_slice(body).unwrap();
            let expected_intent = serde_json::to_value(
                batch(&ledger.burns[0].burn.note_id().to_hex(), 1_000, 9)
                    .burn_intents
                    .remove(0),
            )
            .unwrap();
            assert_eq!(
                body,
                json!({"batches": [{"burnIntents": [expected_intent], "burnSignatures": [
            format!("0x{}{}1b", "00".repeat(31) + "01", "00".repeat(31) + "01"),
            format!("0x{}{}1b", "00".repeat(31) + "02", "00".repeat(31) + "02")],
            "burnTxId": ledger.burns[0].burn.note_id().to_hex(), "useCircleForwarding": true}]})
            );
        }
        if expected == Expired {
            let fresh = ledger
                .signed_with_max_height(0, Some("184467440737095516170001"))
                .await;
            let fresh_body = fresh.submission(ENDPOINT.parse().unwrap()).unwrap().body;
            assert_ne!(fresh_body, saved.body);
            drop(attester);

            ledger.sql("CREATE TRIGGER fail_replacement BEFORE UPDATE OF body ON submissions BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
            let (mut attester, requests) = ledger.start(vec![]).await;
            assert!(
                matches!(
                    attester.submit_signed_withdrawal(&fresh, &mut false).await,
                    Err(SubmitError::Store(_))
                ),
                "{status}"
            );
            assert!(requests.lock().unwrap().is_empty());
            assert_eq!(ledger.record(&attester, 0), saved);
            drop(attester);

            // The fresh request must replace the old outcome atomically, before its POST.
            ledger.sql("DROP TRIGGER fail_replacement;
                CREATE TRIGGER clean_replacement BEFORE UPDATE OF body ON submissions
                WHEN NEW.status != 'SUBMITTING' OR NEW.withdrawal_id IS NOT NULL OR NEW.hold_reason IS NOT NULL
                    OR NEW.last_http_status IS NOT NULL OR NEW.last_response IS NOT NULL OR NEW.last_error IS NOT NULL
                BEGIN SELECT RAISE(FAIL, 'replacement retained old outcome'); END;");
            let (mut attester, requests) = ledger
                .start(vec![reply(201, json!([ledger.response(0, "created")]))])
                .await;
            attester
                .submit_signed_withdrawal(&fresh, &mut false)
                .await
                .unwrap();
            assert_eq!(
                requests.lock().unwrap()[0],
                ObservedRequest::Submit {
                    endpoint: ENDPOINT.into(),
                    body: fresh_body,
                }
            );
            assert_eq!(ledger.record(&attester, 0).status, Submitted);
            // The replaced request's authorization and outcome stay in the history.
            assert_eq!(
                ledger.history(0),
                [
                    event("AUTHORIZED", Submitting),
                    event("OUTCOME", expected),
                    event("AUTHORIZED", Submitting),
                    event("OUTCOME", Submitted),
                ],
                "{status}"
            );
        }
    }
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![reply(200, json!([ledger.response(0, "created")]))])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    assert_eq!(
        ledger.record(&attester, 0).status,
        Submitting,
        "only 201 creates a submission"
    );
}

/// A history row is written with the change it records: when the row cannot be written, the
/// change is not made either. An operator retry is recorded without a new authorization, and an
/// answer that changes nothing the history records adds no row.
#[tokio::test]
async fn failed_history_write_changes_nothing() {
    use SubmissionStatus::*;
    let ledger = Ledger::new().await;
    let fail_history = "CREATE TRIGGER fail_history BEFORE INSERT ON submission_events
        BEGIN SELECT RAISE(FAIL, 'disk full'); END;";
    ledger.sql(fail_history);
    let (mut attester, requests) = ledger.start(vec![]).await;
    assert!(matches!(
        ledger.submit(&mut attester, 0).await,
        Err(SubmitError::Store(_))
    ));
    assert!(attester
        .store
        .submission(ledger.burns[0].burn.note_id())
        .unwrap()
        .is_none());
    assert!(requests.lock().unwrap().is_empty());
    drop(attester);

    ledger.sql("DROP TRIGGER fail_history;");
    let (mut attester, _) = ledger
        .start(vec![reply(400, json!({"message": "rejected"}))])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    drop(attester);
    ledger.sql(fail_history);
    let (mut attester, _) = ledger.start(vec![]).await;
    let held = ledger.record(&attester, 0);
    assert!(attester.retry_held_submission(held.note_id).is_err());
    assert_eq!(ledger.record(&attester, 0), held);
    drop(attester);

    ledger.sql("DROP TRIGGER fail_history;");
    let (mut attester, _) = ledger.start(vec![]).await;
    attester.retry_held_submission(held.note_id).unwrap();
    let retried = ledger.record(&attester, 0);
    drop(attester);
    ledger.sql(
        "CREATE TRIGGER fail_outcome BEFORE INSERT ON submission_events WHEN NEW.kind = 'OUTCOME'
        BEGIN SELECT RAISE(FAIL, 'disk full'); END;",
    );
    let (mut attester, _) = ledger
        .start(vec![reply(201, json!([ledger.response(0, "created")]))])
        .await;
    assert!(recover(&mut attester).await.is_err());
    assert_eq!(ledger.record(&attester, 0), retried);
    drop(attester);

    ledger.sql("DROP TRIGGER fail_outcome;");
    let (mut attester, _) = ledger
        .start(vec![
            reply(201, json!([ledger.response(0, "created")])),
            reply(200, ledger.response(0, "confirmed")),
            reply(200, ledger.response(0, "confirmed")),
            reply(200, ledger.response(0, "finalized")),
        ])
        .await;
    recover(&mut attester).await.unwrap();
    assert_eq!(
        ledger.history(0),
        [
            event("AUTHORIZED", Submitting),
            event("OUTCOME", Held),
            event("OPERATOR_RETRY", Submitting),
            event("OUTCOME", Submitted),
        ]
    );

    // Two polls with the same answer add one row between them (the status check answers 200, the
    // POST answered 201); a new status adds another.
    let recorded = ledger.history(0).len();
    poll(&mut attester).await.unwrap();
    poll(&mut attester).await.unwrap();
    assert_eq!(ledger.history(0).len(), recorded + 1);
    poll(&mut attester).await.unwrap();
    assert_eq!(
        ledger.history(0)[recorded..],
        [event("OUTCOME", Submitted), event("OUTCOME", Finalized)]
    );
}

/// An operator retry puts a held request back without recording an outcome, so when the request is
/// sent again and Circle gives the same answer as before the retry, the history records it again.
#[tokio::test]
async fn retried_request_records_the_same_answer_again() {
    let ledger = Ledger::new().await;
    let rejected = json!({"message": "rejected"});
    let (mut attester, _) = ledger
        .start(vec![reply(400, rejected.clone()), reply(400, rejected)])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let held = ledger.record(&attester, 0);
    attester.retry_held_submission(held.note_id).unwrap();
    recover(&mut attester).await.unwrap();
    assert_eq!(ledger.record(&attester, 0), held);
    assert_eq!(
        ledger.history(0).last(),
        Some(&event("OUTCOME", SubmissionStatus::Held))
    );
}

/// A history row belongs to a burn the store knows. It is written from the burn's row, so a change
/// to a request whose burn is gone writes no history row and is refused, and the request is left
/// as it was.
#[tokio::test]
async fn history_needs_a_known_burn() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![reply(400, json!({"message": "rejected"}))])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    drop(attester);
    // With the history table's foreign key, a burn can only go missing while foreign keys are off.
    ledger.sql(
        "PRAGMA foreign_keys = OFF;
        DELETE FROM burns WHERE note_id IN (SELECT note_id FROM submissions);",
    );
    let request = || -> (String, Option<String>) {
        read_store(&ledger.path())
            .query_row("SELECT status, hold_reason FROM submissions", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap()
    };
    let held = ("HELD".to_owned(), Some("http_rejected".to_owned()));

    let (mut attester, _) = ledger.start(vec![]).await;
    assert_eq!(request(), held);
    let error = attester
        .store
        .retry_held_submission(ledger.burns[0].burn.note_id())
        .unwrap_err();
    assert_eq!(error.to_string(), CONFLICT);
    assert_eq!(request(), held);
}

/// Persist before sending; an uncertain request cannot be replaced by a fresh authorization.
#[tokio::test]
async fn submit_saves_before_sending() {
    let ledger = Ledger::new().await;
    ledger.sql("CREATE TRIGGER fail_insert BEFORE INSERT ON submissions BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
    let (mut attester, requests) = ledger.start(vec![]).await;
    assert!(matches!(
        ledger.submit(&mut attester, 0).await,
        Err(SubmitError::Store(_))
    ));
    assert!(requests.lock().unwrap().is_empty());
    assert!(attester
        .store
        .submission(ledger.burns[0].burn.note_id())
        .unwrap()
        .is_none());
    drop(attester);
    ledger.sql("DROP TRIGGER fail_insert;");
    let (mut attester, requests) = ledger.start(vec![CircleState::TransportError]).await;
    let signed = ledger.signed(0).await;
    attester
        .submit_signed_withdrawal(&signed, &mut false)
        .await
        .unwrap();
    let original = ledger.record(&attester, 0);
    assert_eq!(
        attester
            .store
            .burns_ready_for_withdrawal(3u32.into(), 1)
            .unwrap()
            .len(),
        2,
        "a saved request leaves the fresh-work queue but retains its burn evidence"
    );
    let fresh = ledger
        .signed_with_max_height(0, Some("184467440737095516170001"))
        .await;
    assert!(matches!(
        attester.submit_signed_withdrawal(&fresh, &mut false).await,
        Err(SubmitError::Store(error)) if error.to_string() == CONFLICT
    ));
    assert_eq!(ledger.record(&attester, 0), original);
    assert_eq!(
        requests.lock().unwrap().len(),
        1,
        "uncertain requests must be recovered, not replaced"
    );
}

/// Ambiguous POST results and lost outcome writes retry the saved bytes, even after restart.
#[tokio::test]
async fn retries_use_saved_request() {
    for (name, first) in [
        ("transport loss", CircleState::TransportError),
        (
            "server error",
            reply(503, json!({"message": "unavailable"})),
        ),
        ("rate limited", reply(429, json!({"message": "slow down"}))),
        ("rate limited, reply unread", CircleState::RateLimitedUnread),
        (
            "request timeout",
            reply(408, json!({"message": "request timeout"})),
        ),
        ("forbidden", reply(403, json!({"message": "forbidden"}))),
        (
            "truncated success",
            CircleState::ResponseBody(StatusCode::CREATED, b"[{".to_vec()),
        ),
        ("empty body", CircleState::Response(StatusCode::CREATED)),
        ("empty result", reply(201, json!([]))),
        (
            "conflict without ID",
            CircleState::Response(StatusCode::CONFLICT),
        ),
    ] {
        let ledger = Ledger::new().await;
        let first = if name == "conflict without ID" {
            reply(
                409,
                json!({"success": false, "message": "already associated",
                "conflict": {"burnTxId": ledger.burns[0].burn.note_id().to_hex()}}),
            )
        } else {
            first
        };
        let (mut attester, first_requests) = ledger.start(vec![first]).await;
        let mut rate_limited = false;
        attester
            .submit_signed_withdrawal(&ledger.signed(0).await, &mut rate_limited)
            .await
            .unwrap();
        assert_eq!(
            first_requests.lock().unwrap().len(),
            1,
            "{name}: wait for the next explicit recovery pass"
        );
        let saved = ledger.record(&attester, 0);
        assert_eq!(saved.withdrawal_id, None);
        assert_eq!(saved.status, SubmissionStatus::Submitting, "{name}");
        // Only a 429 stops the rest of the cycle; a 408 is retried like any other status.
        assert_eq!(rate_limited, name.starts_with("rate limited"), "{name}");
        if rate_limited {
            // Circle's reply is saved when it was read, and never made up when it was not.
            let reply = (name == "rate limited").then(|| br#"{"message":"slow down"}"#.to_vec());
            assert_eq!(
                (saved.last_http_status, saved.last_response),
                (reply.as_ref().map(|_| 429), reply),
                "{name}"
            );
            let queue = attester.store.submissions_to_recover().unwrap();
            attester
                .advance_submissions(queue, &mut rate_limited)
                .await
                .unwrap();
            assert_eq!(
                first_requests.lock().unwrap().len(),
                1,
                "{name}: no request until the next cycle"
            );
        }
        drop(attester);
        ledger
            .config
            .lock()
            .unwrap()
            .replace("--circle-url", "https://new-circle.example.invalid");
        let (mut attester, retried) = ledger
            .start(vec![reply(201, json!([ledger.response(0, "created")]))])
            .await;
        recover(&mut attester).await.unwrap();
        assert_eq!(
            *first_requests.lock().unwrap(),
            *retried.lock().unwrap(),
            "{name}"
        );
        assert_eq!(
            ledger.record(&attester, 0).status,
            SubmissionStatus::Submitted
        );
    }
    let ledger = Ledger::new().await;
    ledger.sql("CREATE TRIGGER fail_outcome BEFORE UPDATE ON submissions BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
    let (mut attester, first) = ledger
        .start(vec![reply(201, json!([ledger.response(0, "created")]))])
        .await;
    assert!(matches!(
        ledger.submit(&mut attester, 0).await,
        Err(SubmitError::Store(_))
    ));
    assert_eq!(
        ledger.record(&attester, 0).status,
        SubmissionStatus::Submitting
    );
    drop(attester);
    ledger.sql("DROP TRIGGER fail_outcome;");
    let (mut attester, retry) = ledger
        .start(vec![
            conflict(),
            reply(200, ledger.response(0, "finalized")),
        ])
        .await;
    recover(&mut attester).await.unwrap();
    assert_eq!(first.lock().unwrap()[0], retry.lock().unwrap()[0]);
    assert_eq!(
        ledger.record(&attester, 0).status,
        SubmissionStatus::Finalized
    );
}

/// A saved endpoint that no longer parses is refused when loaded, and the refusal keeps the parse
/// error that says why.
#[tokio::test]
async fn malformed_saved_endpoint_keeps_its_cause() {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![CircleState::TransportError]).await;
    ledger.submit(&mut attester, 0).await.unwrap();
    drop(attester);
    ledger.sql("UPDATE submissions SET endpoint = 'circle.example.invalid/v1/withdraw'");
    let error = ledger
        .open_store()
        .unwrap()
        .submissions_to_recover()
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("relative URL without a base"),
        "{error:#}"
    );
}

/// A malformed withdrawal ID is never accepted from a creation or a conflict because it would be
/// sent back as a URL path segment. The request stays queued instead.
#[tokio::test]
async fn malformed_withdrawal_ids_are_retried() {
    let ledger = Ledger::new().await;
    let mut response = ledger.response(0, "created");
    response["withdrawalId"] = json!("../v1/info");
    let (mut attester, _) = ledger.start(vec![reply(201, json!([response]))]).await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let saved = ledger.record(&attester, 0);
    assert_eq!(
        (saved.status, saved.hold_reason, saved.withdrawal_id),
        (SubmissionStatus::Submitting, None, None)
    );

    let ledger = Ledger::new().await;
    let (mut attester, requests) = ledger
        .start(vec![reply(
            409,
            json!({"conflict": {"withdrawalId": "../v1/info"}}),
        )])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let saved = ledger.record(&attester, 0);
    assert_eq!(
        (saved.status, saved.hold_reason, saved.withdrawal_id),
        (SubmissionStatus::Submitting, None, None)
    );
    assert_eq!(requests.lock().unwrap().len(), 1, "no lookup with a bad ID");

    let ledger = Ledger::new().await;
    let response = ledger.response(0, "finalized");
    let (mut attester, _) = ledger.start(vec![reply(201, json!([response]))]).await;
    ledger.submit(&mut attester, 0).await.unwrap();
    assert_eq!(
        ledger.record(&attester, 0).status,
        SubmissionStatus::Finalized
    );
    drop(attester);
    ledger.sql("UPDATE submissions SET withdrawal_id = 'abc' WHERE status = 'FINALIZED'");
    assert_eq!(ledger.open_store().err().unwrap().to_string(), INVALID);
    let connection = Connection::open(ledger.path()).unwrap();
    let row = connection
        .query_row("SELECT status, withdrawal_id FROM submissions", [], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap();
    assert_eq!(row, ("FINALIZED".into(), "abc".into()));
}

/// A conflict ID is only a lookup handle: GET must prove the saved withdrawal's identity.
#[tokio::test]
async fn conflicts_are_checked() {
    use SubmissionStatus::*;
    for (name, unavailable) in [
        ("server error", reply(503, json!({}))),
        ("not found", reply(404, json!({}))),
        ("malformed", reply(200, json!({}))),
        ("rate limited", reply(429, json!({}))),
    ] {
        let ledger = Ledger::new().await;
        let (mut attester, requests) = ledger.start(vec![conflict(), unavailable]).await;
        let mut rate_limited = false;
        attester
            .submit_signed_withdrawal(&ledger.signed(0).await, &mut rate_limited)
            .await
            .unwrap();
        let saved = ledger.record(&attester, 0);
        assert_eq!(saved.status, Submitting, "{name}");
        assert_eq!(saved.withdrawal_id.as_deref(), Some(ID));
        assert_eq!(requests.lock().unwrap().len(), 2);
        assert_eq!(rate_limited, name == "rate limited", "{name}");
        drop(attester);
        let (mut attester, requests) = ledger
            .start(vec![reply(200, ledger.response(0, "created"))])
            .await;
        recover(&mut attester).await.unwrap();
        assert_eq!(
            requests.lock().unwrap()[0],
            ObservedRequest::Lookup {
                endpoint: ENDPOINT.into(),
                id: ID.into(),
            },
            "{name}: do not POST again after saving the ID"
        );
        assert_eq!(ledger.record(&attester, 0).status, Submitted);
    }
    type Mutation = (&'static str, fn(&mut Value));
    let mismatches: &[Mutation] = &[
        ("empty ID", |v| v["withdrawalId"] = json!("")),
        ("burn note", |v| {
            v["burnTxId"] = json!(format!("0x{}", "ff".repeat(32)))
        }),
        ("missing hash", |v| v["transferSpecHashes"] = json!([])),
        ("extra hash", |v| {
            let hash = v["transferSpecHashes"][0].clone();
            v["transferSpecHashes"].as_array_mut().unwrap().push(hash);
        }),
        ("wrong hash", |v| {
            v["transferSpecHashes"][0] = json!(format!("0x{}", "ff".repeat(32)))
        }),
        ("forwarding", |v| v["useCircleForwarding"] = json!(false)),
    ];
    for (name, change) in mismatches {
        let ledger = Ledger::new().await;
        let mut response = ledger.response(0, "created");
        change(&mut response);
        // POST and GET share the identity predicate; keep one GET field mismatch as well.
        let replies = if *name == "wrong hash" {
            vec![conflict(), reply(200, response)]
        } else {
            vec![reply(201, json!([response]))]
        };
        let (mut attester, _) = ledger.start(replies).await;
        ledger.submit(&mut attester, 0).await.unwrap();
        let saved = ledger.record(&attester, 0);
        assert_eq!(
            (saved.status, saved.hold_reason, saved.last_error.as_deref()),
            (
                Submitting,
                None,
                Some("response does not identify the saved withdrawal")
            ),
            "{name}"
        );
    }
    let ledger = Ledger::new().await;
    let mut other_id = ledger.response(0, "created");
    other_id["withdrawalId"] = json!("6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e71");
    for (name, replies, error) in [
        (
            "wrong lookup ID",
            vec![conflict(), reply(200, other_id)],
            "response does not identify the saved withdrawal",
        ),
        (
            "extra success",
            vec![reply(
                201,
                json!([ledger.response(0, "created"), ledger.response(0, "created")]),
            )],
            "response contains extra withdrawals",
        ),
        (
            "conflict wrong burn note",
            vec![reply(
                409,
                json!({"success": false, "message": "already associated", "conflict": {"withdrawalId": ID, "burnTxId": "0x00"}}),
            )],
            "conflict names another burn note",
        ),
    ] {
        let ledger = Ledger::new().await;
        let (mut attester, _) = ledger.start(replies).await;
        ledger.submit(&mut attester, 0).await.unwrap();
        let saved = ledger.record(&attester, 0);
        assert_eq!(
            (saved.status, saved.hold_reason, saved.last_error.as_deref()),
            (Submitting, None, Some(error)),
            "{name}"
        );
        assert!(attester
            .retry_held_submission(ledger.burns[0].burn.note_id())
            .is_err());
    }
    let ledger = Ledger::new().await;
    ledger.sql("CREATE TRIGGER fail_id BEFORE UPDATE ON submissions WHEN NEW.withdrawal_id IS NOT NULL BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
    let (mut attester, requests) = ledger.start(vec![conflict()]).await;
    assert!(matches!(
        ledger.submit(&mut attester, 0).await,
        Err(SubmitError::Store(_))
    ));
    assert_eq!(
        requests.lock().unwrap().len(),
        1,
        "no GET until its ID has been saved"
    );
    assert_eq!(ledger.record(&attester, 0).withdrawal_id, None);
}

/// A held withdrawal cannot poison unrelated work; only reviewed HTTP rejections can be requeued.
#[tokio::test]
async fn held_submissions_do_not_block_others() {
    let ledger = Ledger::new().await;
    assert_eq!(
        ledger.burns[0].burn.burn_tx_id(),
        ledger.burns[1].burn.burn_tx_id()
    );
    let rejected = json!({"message": "operator must investigate", "code": "unrecognized"});
    let (mut attester, requests) = ledger
        .start(vec![
            reply(400, rejected.clone()),
            reply(201, json!([ledger.response(1, "created")])),
        ])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let held = ledger.record(&attester, 0);
    assert_eq!(held.hold_reason, Some(HoldReason::HttpRejected));
    assert_eq!(
        serde_json::from_slice::<Value>(held.last_response.as_ref().unwrap()).unwrap(),
        rejected
    );
    ledger.submit(&mut attester, 1).await.unwrap();
    recover(&mut attester).await.unwrap();
    assert_eq!(
        requests.lock().unwrap().len(),
        2,
        "holds do not retry automatically"
    );

    // Releasing the hold starts the withdrawal over: the burn is prepared and signed again, and
    // the old signed request is never sent.
    drop(attester);
    assert_eq!(
        release_holds(
            &ledger.path(),
            faucet_account_id(),
            BlockNumber::GENESIS,
            ledger.blocks[0].header().commitment(),
            &[held.note_id],
        )
        .unwrap(),
        (0, 1)
    );
    let ready: Vec<_> = ledger
        .fresh_indices
        .iter()
        .copied()
        .filter(|&index| index != 1)
        .collect();
    let mut replies = fresh_replies(&ledger, &ready);
    replies.push(reply(200, ledger.response(1, "created")));
    let (signers, calls) = signers(None).await;
    let (mut attester, released, _) = ledger.runtime(replies, signers).await;
    assert!(attester.store.submission(held.note_id).unwrap().is_none());
    assert!(attester
        .store
        .burns_ready_for_withdrawal(3u32.into(), 1)
        .unwrap()
        .iter()
        .any(|burn| burn.note_id() == held.note_id));
    attester.run_one_cycle().await.unwrap();
    assert_eq!(counts(&calls), [2, 2], "both ready burns are signed");
    {
        let released = released.lock().unwrap();
        let position = 2 * ready.iter().position(|&index| index == 0).unwrap();
        assert_eq!(released[position], ObservedRequest::Prepare);
        let ObservedRequest::Submit { body, .. } = &released[position + 1] else {
            panic!(
                "expected the withdraw request, got {:?}",
                released[position + 1]
            );
        };
        let body: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(
            body["batches"][0]["burnTxId"],
            ledger.burns[0].burn.note_id().to_hex()
        );
    }
    for index in 0..2 {
        assert_eq!(
            ledger.record(&attester, index).status,
            SubmissionStatus::Submitted
        );
    }
    // The history keeps the released request before the burn's new authorization.
    assert_eq!(
        ledger.history(0),
        [
            event("AUTHORIZED", SubmissionStatus::Submitting),
            event("OUTCOME", SubmissionStatus::Held),
            event("OPERATOR_RELEASE", SubmissionStatus::Held),
            event("AUTHORIZED", SubmissionStatus::Submitting),
            event("OUTCOME", SubmissionStatus::Submitted),
        ]
    );

    // A status lookup never holds: after a 400 to the GET the saved ID stays queued.
    let ledger = Ledger::new().await;
    let (mut attester, requests) = ledger.start(vec![conflict(), reply(400, rejected)]).await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let queued = ledger.record(&attester, 0);
    assert_eq!(queued.hold_reason, None);
    assert_eq!(queued.withdrawal_id.as_deref(), Some(ID));
    drop(attester);
    ledger
        .config
        .lock()
        .unwrap()
        .replace("--circle-url", "https://new-circle.example.invalid");
    let (mut attester, retry) = ledger
        .start(vec![reply(200, ledger.response(0, "created"))])
        .await;
    recover(&mut attester).await.unwrap();
    assert_eq!(*retry.lock().unwrap(), requests.lock().unwrap()[1..]);
    assert_eq!(
        ledger.record(&attester, 0).status,
        SubmissionStatus::Submitted
    );
}

/// The withdraw and status requests are built from the saved row: its endpoint's host, its exact
/// bytes and the configured timeout, whatever today's configured URL is.
#[tokio::test]
async fn submission_requests_use_the_saved_request() {
    let ledger = Ledger::new().await;
    let saved = ledger
        .signed(0)
        .await
        .submission("https://saved.example.invalid/v1/withdraw".parse().unwrap())
        .unwrap();
    let config = ledger.config.lock().unwrap().load();
    let client = CircleClient::start(&config).unwrap().0;

    let post = client.submission_request(&saved).unwrap();
    assert_eq!(post.method(), Method::POST);
    assert_eq!(
        post.url().as_str(),
        "https://saved.example.invalid/v1/withdraw"
    );
    assert_eq!(post.timeout(), Some(&Duration::from_millis(100)));
    assert_eq!(
        post.headers().len(),
        1,
        "no auth or invented idempotency headers"
    );
    assert_eq!(post.headers()[CONTENT_TYPE], "application/json");
    assert_eq!(
        post.body().and_then(|body| body.as_bytes()),
        Some(saved.body.as_slice())
    );

    let get = client.status_request(&saved, ID).unwrap();
    assert_eq!(get.method(), Method::GET);
    assert_eq!(
        get.url().as_str(),
        format!("https://saved.example.invalid/v1/withdrawal/{ID}")
    );
    assert_eq!(get.timeout(), Some(&Duration::from_millis(100)));
    assert!(get.headers().is_empty());
    assert!(get.body().is_none());
}

/// Circle's answers are read into the saved row: only a 400 to the POST holds it, other unexpected
/// answers leave it queued, and an answer counts only if it names the saved withdrawal.
#[tokio::test]
async fn circle_answers_are_read_into_the_saved_row() {
    use SubmissionStatus::*;
    let ledger = Ledger::new().await;
    let queued = ledger
        .signed(0)
        .await
        .submission(ENDPOINT.parse().unwrap())
        .unwrap();
    let body = |value: Value| serde_json::to_vec(&value).unwrap();
    let created = ledger.response(0, "created");
    let mut failed = ledger.response(0, "failed");
    failed["failureReason"] = json!("Circle's reported failure");
    let mut wrong_hash = ledger.response(0, "created");
    wrong_hash["transferSpecHashes"] = json!([reference_hash(&ledger.burns[1])]);
    let mut short_id = ledger.response(0, "created");
    short_id["withdrawalId"] = json!("abc");
    let mut braced_id = ledger.response(0, "created");
    braced_id["withdrawalId"] = json!("{6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e70}");
    let mut other_id = ledger.response(0, "finalized");
    other_id["withdrawalId"] = json!("6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e71");
    let not_named = Some("response does not identify the saved withdrawal");
    // Each row: the reply to a POST, or with `lookup` to a GET for the saved ID, then the row's
    // status, hold, withdrawal ID and error afterwards.
    for (name, lookup, status, reply, expected) in [
        (
            "created",
            false,
            201,
            body(json!([created])),
            (Submitted, None, Some(ID), None),
        ),
        (
            "failed",
            false,
            201,
            body(json!([failed])),
            (Failed, None, Some(ID), Some("Circle's reported failure")),
        ),
        (
            "unknown status",
            false,
            201,
            body(json!([ledger.response(0, "new_status")])),
            (
                Submitting,
                None,
                Some(ID),
                Some("Circle returned an unknown withdrawal status"),
            ),
        ),
        (
            "rejected",
            false,
            400,
            body(json!({"message": "rejected"})),
            (
                Held,
                Some(HoldReason::HttpRejected),
                None,
                Some("HTTP response needs operator review"),
            ),
        ),
        (
            "timeout",
            false,
            408,
            Vec::new(),
            (
                Submitting,
                None,
                None,
                Some("Circle returned HTTP 408 Request Timeout"),
            ),
        ),
        (
            "rate limited",
            false,
            429,
            Vec::new(),
            (
                Submitting,
                None,
                None,
                Some("Circle returned HTTP 429 Too Many Requests"),
            ),
        ),
        (
            "answered 200",
            false,
            200,
            body(json!([created])),
            (Submitting, None, None, Some("Circle returned HTTP 200 OK")),
        ),
        (
            "malformed",
            false,
            201,
            body(json!({})),
            (
                Submitting,
                None,
                None,
                Some("Circle returned an incomplete or malformed response"),
            ),
        ),
        (
            "two withdrawals",
            false,
            201,
            body(json!([created, created])),
            (
                Submitting,
                None,
                None,
                Some("response contains extra withdrawals"),
            ),
        ),
        (
            "wrong hash",
            false,
            201,
            body(json!([wrong_hash])),
            (Submitting, None, None, not_named),
        ),
        (
            "short withdrawal ID",
            false,
            201,
            body(json!([short_id])),
            (Submitting, None, None, not_named),
        ),
        (
            "braced withdrawal ID",
            false,
            201,
            body(json!([braced_id])),
            (Submitting, None, None, not_named),
        ),
        (
            "lookup finalized",
            true,
            200,
            body(ledger.response(0, "finalized")),
            (Finalized, None, Some(ID), None),
        ),
        (
            "lookup rejected",
            true,
            400,
            Vec::new(),
            (
                Submitting,
                None,
                Some(ID),
                Some("Circle returned HTTP 400 Bad Request"),
            ),
        ),
        (
            "lookup names another ID",
            true,
            200,
            body(other_id),
            (Submitting, None, Some(ID), not_named),
        ),
    ] {
        let mut saved = queued.clone();
        if lookup {
            saved.withdrawal_id = Some(ID.into());
        }
        saved.read_response(RawResponse::new(
            StatusCode::from_u16(status).unwrap(),
            reply,
        ));
        assert_eq!(
            (
                saved.status,
                saved.hold_reason,
                saved.withdrawal_id.as_deref(),
                saved.last_error.as_deref()
            ),
            expected,
            "{name}"
        );
    }

    for (name, conflict, id, error) in [
        ("an ID", json!({"withdrawalId": ID}), Some(ID), None),
        (
            "no ID yet",
            json!({}),
            None,
            Some("conflict has no withdrawal ID yet"),
        ),
        (
            "another burn note",
            json!({"withdrawalId": ID, "burnTxId": format!("0x{}", "ff".repeat(32))}),
            None,
            Some("conflict names another burn note"),
        ),
        (
            "a malformed ID",
            json!({"withdrawalId": "6149dc3d/../withdraw"}),
            None,
            Some("conflict names a malformed withdrawal ID"),
        ),
        (
            "a short ID",
            json!({"withdrawalId": "abc"}),
            None,
            Some("conflict names a malformed withdrawal ID"),
        ),
        (
            "a braced ID",
            json!({"withdrawalId": "{6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e70}"}),
            None,
            Some("conflict names a malformed withdrawal ID"),
        ),
    ] {
        let mut saved = queued.clone();
        saved.last_response = Some(body(
            json!({"success": false, "message": "already associated", "conflict": conflict}),
        ));
        assert_eq!(saved.read_conflict(), id.is_some(), "{name}");
        assert_eq!(
            (saved.withdrawal_id.as_deref(), saved.last_error.as_deref()),
            (id, error),
            "{name}"
        );
    }
}
