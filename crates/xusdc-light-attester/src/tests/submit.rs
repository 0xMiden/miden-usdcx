//! Durable submission and recovery, using synthetic responses rather than claiming live proof.

use std::collections::VecDeque;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::{keccak256, Signature, B256, U256};
use miden_protocol::block::SignedBlock;
use miden_protocol::transaction::OutputNote;
use reqwest::{header::CONTENT_TYPE, Method, StatusCode};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

use crate::attester::Attester;
use crate::burn::{DiscoveredBurn, ValidatedBurn};
use crate::circle::{
    read_prepared, CircleApi, CircleClient, CircleError, RawResponse, UnverifiedPrepareResponse,
};
use crate::config::Config;
use crate::signer::{Signer, SignerError, SigningPublicKey};
use crate::store::CONFLICT;
use crate::submission::{HoldReason, SavedSubmission, SubmissionStatus, SubmitError};
use crate::verify::{rebuild_for_test, SignedWithdrawal};

use super::discovery;
use super::support::{
    faucet_account_id, scan_limits, transaction, BlockFactory, CircleState, ObservedRequest,
    TestChain,
};
use super::validation::validated_burn;
use super::verify::{batch, serial};

const ID: &str = "6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e70";
const ENDPOINT: &str = "https://circle.example.invalid/v1/withdraw";
type Requests = Arc<Mutex<Vec<ObservedRequest>>>;

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

struct ScriptedCircle {
    replies: Mutex<VecDeque<CircleState>>,
    requests: Requests,
    store_path: PathBuf,
    rate_limited: AtomicBool,
}

impl ScriptedCircle {
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
        let answer = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected extra Circle request")
            .answer();
        // Like the real client, a 429 pauses the rest of the cycle.
        if matches!(&answer, Ok(response) if response.status == StatusCode::TOO_MANY_REQUESTS) {
            self.rate_limited.store(true, Ordering::Relaxed);
        }
        answer
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
        _use_circle_forwarding: bool,
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
                    endpoint: saved.endpoint.clone(),
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
                    endpoint: saved.endpoint.clone(),
                    id: id.to_owned(),
                },
                "SELECT count(*) FROM submissions WHERE status = 'SUBMITTING' AND withdrawal_id = ?1",
                id,
            )
        })
    }

    fn rate_limited(&self) -> bool {
        self.rate_limited.load(Ordering::Relaxed)
    }
}

struct Ledger {
    directory: tempfile::TempDir,
    blocks: Vec<SignedBlock>,
    burns: Vec<ValidatedBurn>,
}

impl Ledger {
    async fn new() -> Self {
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
        factory.push(vec![], vec![]);
        let directory = tempfile::tempdir().unwrap();
        let blocks = factory.blocks();
        let (mut attester, _) =
            discovery::start(&directory, 1, blocks.clone(), scan_limits(3, 3)).await;
        attester.discover_burns().await.unwrap();
        Self {
            directory,
            blocks,
            burns,
        }
    }

    fn path(&self) -> PathBuf {
        self.directory.path().join("state.sqlite3")
    }

    async fn start(&self, replies: Vec<CircleState>) -> (Attester, Requests) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let circle = ScriptedCircle {
            replies: Mutex::new(replies.into()),
            requests: requests.clone(),
            store_path: self.path(),
            rate_limited: AtomicBool::new(false),
        };
        let config = Config::load(&self.directory.path().join("attester.toml")).unwrap();
        let chain = TestChain::new(self.blocks.clone(), scan_limits(3, 3)).0;
        let attester = Attester::start(config, Box::new(chain), Box::new(circle))
            .await
            .unwrap();
        (attester, requests)
    }

    async fn signed(&self, index: usize) -> SignedWithdrawal {
        self.signed_with_max_height(index, None).await
    }

    async fn signed_with_max_height(&self, index: usize, height: Option<&str>) -> SignedWithdrawal {
        let burn = &self.burns[index];
        let mut prepared = batch(&burn.burn.note().as_note().serial_num().to_hex(), 1_000, 9);
        if let Some(height) = height {
            prepared.burn_intents[0].max_block_height = height.into();
            rebuild_for_test(&mut prepared).unwrap();
        }
        UnverifiedPrepareResponse {
            batches: vec![prepared],
        }
        .verify(
            burn,
            &Config::load(&self.directory.path().join("attester.toml")).unwrap(),
        )
        .unwrap()
        .sign([&TestSigner(1), &TestSigner(2)])
        .await
        .unwrap()
    }

    async fn submit(&self, attester: &mut Attester, index: usize) -> Result<(), SubmitError> {
        attester
            .submit_signed_withdrawal(&self.signed(index).await)
            .await
    }

    fn record(&self, attester: &Attester, index: usize) -> SavedSubmission {
        attester
            .store
            .submission(self.burns[index].burn.note_id())
            .unwrap()
            .unwrap()
    }

    fn sql(&self, sql: &str) {
        Connection::open(self.path())
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }

    fn response(&self, index: usize, status: &str) -> Value {
        json!({"withdrawalId": format!("6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e{:02}", 70 + index), "burnTxId": self.burns[index].burn.note_id().to_hex(),
            "status": status, "useCircleForwarding": false, "transferSpecHashes": [reference_hash(index)]})
    }
}

pub(super) async fn submission_store() -> (tempfile::TempDir, Vec<SignedBlock>) {
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger.start(vec![CircleState::TransportError]).await;
    ledger.submit(&mut attester, 0).await.unwrap();
    drop(attester);
    (ledger.directory, ledger.blocks)
}

#[tokio::test]
async fn malformed_saved_submission_is_rejected_when_loaded() {
    let (directory, blocks) = submission_store().await;
    Connection::open(directory.path().join("state.sqlite3"))
        .unwrap()
        .execute("UPDATE submissions SET body = X'00'", [])
        .unwrap();

    let requests = Arc::new(Mutex::new(Vec::new()));
    let circle = ScriptedCircle {
        replies: Mutex::new(VecDeque::new()),
        requests: requests.clone(),
        store_path: directory.path().join("state.sqlite3"),
        rate_limited: AtomicBool::new(false),
    };
    let config = Config::load(&directory.path().join("attester.toml")).unwrap();
    let chain = TestChain::new(blocks, scan_limits(3, 3)).0;
    let mut attester = Attester::start(config, Box::new(chain), Box::new(circle))
        .await
        .expect("startup checks structure, not submission contents");

    assert!(matches!(
        attester.recover_submissions().await,
        Err(SubmitError::Store(_))
    ));
    assert!(requests.lock().unwrap().is_empty());
}

// Synthetic packed TransferSpec vector, independently transcribed from Circle's Solidity layout.
// This tests our encoder, not the still-unobserved correspondence to REST transferSpecHashes.
fn reference_hash(index: usize) -> String {
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
        "33".repeat(32),
        "44".repeat(32),
        "55".repeat(32),
        "00".repeat(32),
        hex::encode(serial(0x3132_3334_3536_3738 + index as u64).as_bytes())
    );
    keccak256(hex::decode(packed).unwrap()).to_string()
}

fn reply(status: u16, value: Value) -> CircleState {
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
        assert_eq!(saved.transfer_spec_hash.to_string(), reference_hash(0));
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
        if matches!(status, "created" | "finalized" | "new_status") {
            let fresh = ledger
                .signed_with_max_height(0, Some("184467440737095516170001"))
                .await;
            assert!(
                matches!(
                    attester.submit_signed_withdrawal(&fresh).await,
                    Err(SubmitError::Store(error)) if error.to_string() == CONFLICT
                ),
                "{status}"
            );
            assert_eq!(ledger.record(&attester, 0), saved);
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
                batch(
                    &ledger.burns[0].burn.note().as_note().serial_num().to_hex(),
                    1_000,
                    9,
                )
                .burn_intents
                .remove(0),
            )
            .unwrap();
            assert_eq!(
                body,
                json!({"batches": [{"burnIntents": [expected_intent], "burnSignatures": [
            format!("0x{}{}1b", "00".repeat(31) + "01", "00".repeat(31) + "01"),
            format!("0x{}{}1b", "00".repeat(31) + "02", "00".repeat(31) + "02")],
            "burnTxId": ledger.burns[0].burn.note_id().to_hex(), "useCircleForwarding": false}]})
            );
        }
        if matches!(expected, Failed | Expired) {
            let fresh = ledger
                .signed_with_max_height(0, Some("184467440737095516170001"))
                .await;
            let fresh_body = fresh.submission(ENDPOINT.into()).unwrap().body;
            assert_ne!(fresh_body, saved.body);
            drop(attester);

            ledger.sql("CREATE TRIGGER fail_replacement BEFORE UPDATE OF body ON submissions BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
            let (mut attester, requests) = ledger.start(vec![]).await;
            assert!(
                matches!(
                    attester.submit_signed_withdrawal(&fresh).await,
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
            attester.submit_signed_withdrawal(&fresh).await.unwrap();
            assert_eq!(
                requests.lock().unwrap()[0],
                ObservedRequest::Submit {
                    endpoint: ENDPOINT.into(),
                    body: fresh_body,
                }
            );
            assert_eq!(ledger.record(&attester, 0).status, Submitted);
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

    let ledger = Ledger::new().await;
    let mut response = ledger.response(0, "created");
    response["useCircleForwarding"] = json!(true);
    let path = ledger.directory.path().join("attester.toml");
    let text = std::fs::read_to_string(&path).unwrap().replace(
        "use_circle_forwarding = false",
        "use_circle_forwarding = true",
    );
    std::fs::write(path, text).unwrap();
    let (mut attester, requests) = ledger.start(vec![reply(201, json!([response]))]).await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let body: Value = match &requests.lock().unwrap()[0] {
        ObservedRequest::Submit { body, .. } => serde_json::from_slice(body).unwrap(),
        other => panic!("expected the withdraw request, got {other:?}"),
    };
    assert_eq!(body["batches"][0]["useCircleForwarding"], true);
    assert_eq!(ledger.record(&attester, 0).status, Submitted);
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
    attester.submit_signed_withdrawal(&signed).await.unwrap();
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
        attester.submit_signed_withdrawal(&fresh).await,
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
        ledger.submit(&mut attester, 0).await.unwrap();
        assert_eq!(
            first_requests.lock().unwrap().len(),
            1,
            "{name}: wait for the next explicit recovery pass"
        );
        assert_eq!(ledger.record(&attester, 0).withdrawal_id, None);
        assert_eq!(
            ledger.record(&attester, 0).status,
            SubmissionStatus::Submitting,
            "{name}"
        );
        if name == "rate limited" {
            attester.recover_submissions().await.unwrap();
            assert_eq!(
                first_requests.lock().unwrap().len(),
                1,
                "{name}: no request until the next cycle"
            );
        }
        drop(attester);
        let config_path = ledger.directory.path().join("attester.toml");
        let text = std::fs::read_to_string(&config_path)
            .unwrap()
            .replace("circle.example.invalid", "new-circle.example.invalid");
        std::fs::write(config_path, text).unwrap();
        let (mut attester, retried) = ledger
            .start(vec![reply(201, json!([ledger.response(0, "created")]))])
            .await;
        attester.recover_submissions().await.unwrap();
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
    attester.recover_submissions().await.unwrap();
    assert_eq!(first.lock().unwrap()[0], retry.lock().unwrap()[0]);
    assert_eq!(
        ledger.record(&attester, 0).status,
        SubmissionStatus::Finalized
    );
}

/// A withdrawal ID outside Circle's UUID charset is never accepted from a creation or a conflict,
/// because it would be sent back as a URL path segment. The request stays queued instead.
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
}

/// A conflict ID is only a lookup handle: GET must prove the saved withdrawal's identity.
#[tokio::test]
async fn conflicts_are_checked() {
    use SubmissionStatus::*;
    for (name, unavailable) in [
        ("server error", reply(503, json!({}))),
        ("not found", reply(404, json!({}))),
        ("malformed", reply(200, json!({}))),
    ] {
        let ledger = Ledger::new().await;
        let (mut attester, requests) = ledger.start(vec![conflict(), unavailable]).await;
        ledger.submit(&mut attester, 0).await.unwrap();
        let saved = ledger.record(&attester, 0);
        assert_eq!(saved.status, Submitting, "{name}");
        assert_eq!(saved.withdrawal_id.as_deref(), Some(ID));
        assert_eq!(requests.lock().unwrap().len(), 2);
        drop(attester);
        let (mut attester, requests) = ledger
            .start(vec![reply(200, ledger.response(0, "created"))])
            .await;
        attester.recover_submissions().await.unwrap();
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
        ("forwarding", |v| v["useCircleForwarding"] = json!(true)),
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

/// A held burn cannot poison unrelated work; only reviewed HTTP rejections can be requeued.
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
            reply(201, json!([ledger.response(0, "created")])),
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
    attester.recover_submissions().await.unwrap();
    assert_eq!(
        requests.lock().unwrap().len(),
        2,
        "holds do not retry automatically"
    );
    attester.retry_held_submission(held.note_id).unwrap();
    attester.recover_submissions().await.unwrap();
    {
        let observed = requests.lock().unwrap();
        assert_eq!(observed.len(), 3);
        assert_eq!(observed[0], observed[2]);
        for (index, request) in observed[..2].iter().enumerate() {
            assert_eq!(
                ledger.record(&attester, index).status,
                SubmissionStatus::Submitted
            );
            let ObservedRequest::Submit { body, .. } = request else {
                panic!("expected the withdraw request, got {request:?}");
            };
            let body: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(
                body["batches"][0]["burnTxId"],
                ledger.burns[index].burn.note_id().to_hex()
            );
        }
    }

    // A status lookup never holds: after a 400 to the GET the saved ID stays queued.
    let ledger = Ledger::new().await;
    let (mut attester, requests) = ledger.start(vec![conflict(), reply(400, rejected)]).await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let queued = ledger.record(&attester, 0);
    assert_eq!(queued.hold_reason, None);
    assert_eq!(queued.withdrawal_id.as_deref(), Some(ID));
    drop(attester);
    let path = ledger.directory.path().join("attester.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("circle.example.invalid", "new-circle.example.invalid");
    std::fs::write(path, text).unwrap();
    let (mut attester, retry) = ledger
        .start(vec![reply(200, ledger.response(0, "created"))])
        .await;
    attester.recover_submissions().await.unwrap();
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
        .submission("https://saved.example.invalid/v1/withdraw".into())
        .unwrap();
    let config = Config::load(&ledger.directory.path().join("attester.toml")).unwrap();
    let client = CircleClient::new(&config).unwrap();

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
    let queued = ledger.signed(0).await.submission(ENDPOINT.into()).unwrap();
    let body = |value: Value| serde_json::to_vec(&value).unwrap();
    let created = ledger.response(0, "created");
    let mut failed = ledger.response(0, "failed");
    failed["failureReason"] = json!("Circle's reported failure");
    let mut wrong_hash = ledger.response(0, "created");
    wrong_hash["transferSpecHashes"] = json!([reference_hash(1)]);
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
