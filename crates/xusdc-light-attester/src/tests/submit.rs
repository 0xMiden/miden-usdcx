//! Durable submission and recovery, using synthetic responses rather than claiming live proof.

use std::collections::VecDeque;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::{keccak256, Signature, B256, U256};
use miden_protocol::block::ProvenBlock;
use miden_protocol::transaction::OutputNote;
use miden_protocol::utils::serde::Serializable;
use reqwest::{Method, StatusCode};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

use crate::attester::Attester;
use crate::burn::{DiscoveredBurn, ValidatedBurn};
use crate::circle::{CircleError, HttpTransport, RawResponse, UnverifiedPrepareResponse};
use crate::config::Config;
use crate::signer::{Signer, SignerError, SigningPublicKey};
use crate::submission::{HoldReason, SavedSubmission, SubmissionStatus, SubmitError};
use crate::verify::{rebuild_for_test, verify_prepared_response, SignedWithdrawal};

use super::discovery;
use super::support::{
    development_signers, faucet_account_id, scan_limits, transaction, BlockFactory, ChainControls,
    CircleState, ObservedRequest, TestChain,
};
use super::validation::validated_burn;
use super::verify::{batch, serial};

const ID: &str = "6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e70";
const ENDPOINT: &str = "https://circle.example.invalid/v1/withdraw";
pub(super) type Requests = Arc<Mutex<Vec<ObservedRequest>>>;

pub(super) async fn recover(attester: &mut Attester) -> Result<(), SubmitError> {
    let queue = attester.store.submissions_to_recover()?;
    attester.recover_submissions(queue).await
}

pub(super) async fn poll(attester: &mut Attester) -> Result<(), SubmitError> {
    let queue = attester.store.submissions_to_poll().unwrap();
    attester.poll_withdrawal_statuses(queue).await
}

struct TestSigner(u8);
impl Signer for TestSigner {
    fn public_key(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, SignerError>> + Send + '_>> {
        Box::pin(async { panic!("provider keys are not part of submission") })
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
}

impl HttpTransport for ScriptedCircle {
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + '_>> {
        Box::pin(async move {
            if request.url().path() == "/v1/info" {
                return Ok(RawResponse::new(StatusCode::OK, vec![]));
            }
            let body = request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .unwrap_or_default()
                .to_vec();
            if request.url().path() != "/v1/prepare-withdrawal" {
                // Inspect committed disk bytes while the writer is idle at its HTTP boundary.
                // An immutable reader avoids the store's intentional exclusive connection lock.
                let disk = Connection::open_with_flags(
                    format!("file:{}?immutable=1", self.store_path.display()),
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
                )
                .unwrap();
                let saved: i64 = if request.method() == Method::POST {
                    disk.query_row(
                        "SELECT count(*) FROM submissions JOIN burns USING (note_id) WHERE submissions.status = 'SUBMITTING' AND body = ?1 AND withdrawal_id IS NULL AND reservation_amount IS NOT NULL AND admitted_at_ms IS NOT NULL",
                        [&body],
                        |r| r.get(0),
                    )
                    .unwrap()
                } else {
                    let id = request.url().path().rsplit('/').next().unwrap();
                    disk.query_row("SELECT count(*) FROM submissions WHERE status IN ('SUBMITTING', 'SUBMITTED') AND withdrawal_id = ?1", [id], |r| r.get(0)).unwrap()
                };
                assert_eq!(
                    saved, 1,
                    "request and any recovery ID must be durable before HTTP"
                );
            }
            self.requests.lock().unwrap().push(ObservedRequest {
                method: request.method().clone(),
                url: request.url().to_string(),
                timeout: request.timeout().copied(),
                headers: request.headers().clone(),
                body,
            });
            match self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected extra HTTP request")
            {
                CircleState::Response(status) => Ok(RawResponse::new(status, vec![])),
                CircleState::ResponseBody(status, body) => Ok(RawResponse::new(status, body)),
                CircleState::TransportError => Err(CircleError::Unavailable),
            }
        })
    }
}

pub(super) struct Ledger {
    directory: tempfile::TempDir,
    blocks: Vec<ProvenBlock>,
    pub(super) burns: Vec<ValidatedBurn>,
    pub(super) fresh_indices: Vec<usize>,
}

impl Ledger {
    pub(super) async fn new() -> Self {
        Self::with_amounts([1_000; 3]).await
    }

    pub(super) async fn with_amounts(amounts: [u64; 3]) -> Self {
        let mut burns: Vec<_> = amounts
            .into_iter()
            .enumerate()
            .map(|(i, amount)| validated_burn(amount, serial(0x3132_3334_3536_3738 + i as u64), 9))
            .collect();
        let mut factory = BlockFactory::new(faucet_account_id());
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
            burn.burn = DiscoveredBurn::try_new(
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
        Self {
            directory,
            blocks,
            burns,
            fresh_indices,
        }
    }

    fn path(&self) -> PathBuf {
        self.directory.path().join("state.sqlite3")
    }

    pub(super) fn configure(&self, limit: u64, cap_message: bool) {
        let path = self.directory.path().join("attester.toml");
        let text = std::fs::read_to_string(&path).unwrap().replace(
            "withdrawal_limit = 10_000_000_000_000",
            &format!("withdrawal_limit = {limit}"),
        );
        let extra = if cap_message {
            "\nwithdrawal_cap_error_message = 'synthetic cap rejection'\n"
        } else {
            ""
        };
        std::fs::write(path, format!("{text}{extra}")).unwrap();
    }

    pub(super) fn stored(&self, sql: &str) -> i64 {
        let disk = Connection::open_with_flags(
            format!("file:{}?immutable=1", self.path().display()),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .unwrap();
        disk.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    pub(super) async fn start(&self, replies: Vec<CircleState>) -> (Attester, Requests) {
        let (attester, requests, _) = self.runtime(replies, development_signers()).await;
        (attester, requests)
    }

    pub(super) async fn runtime(
        &self,
        replies: Vec<CircleState>,
        signers: [Box<dyn Signer>; 2],
    ) -> (Attester, Requests, ChainControls) {
        let (circle, requests) = ScriptedCircle::new(self.path(), replies);
        let config = Config::load(&self.directory.path().join("attester.toml")).unwrap();
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
            &burn.burn.note().as_note().serial_num().to_hex(),
            burn.amount,
            burn.items.dest_domain,
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
        let mut prepared = batch(
            &burn.burn.note().as_note().serial_num().to_hex(),
            burn.amount,
            9,
        );
        if let Some(height) = height {
            prepared.burn_intents[0].max_block_height = height.into();
            rebuild_for_test(&mut prepared, false).unwrap();
        }
        verify_prepared_response(
            burn,
            UnverifiedPrepareResponse {
                batches: vec![prepared],
            },
            &Config::load(&self.directory.path().join("attester.toml")).unwrap(),
        )
        .unwrap()
        .sign([&TestSigner(1), &TestSigner(2)])
        .await
        .unwrap()
    }

    pub(super) async fn submit(
        &self,
        attester: &mut Attester,
        index: usize,
    ) -> Result<(), SubmitError> {
        attester
            .submit_signed_withdrawal(&self.signed(index).await)
            .await
    }

    pub(super) fn record(&self, attester: &Attester, index: usize) -> SavedSubmission {
        attester
            .store
            .submission(self.burns[index].burn.note_id())
            .unwrap()
            .unwrap()
    }

    pub(super) fn sql(&self, sql: &str) {
        Connection::open(self.path())
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }

    pub(super) fn rewind_empty_block(&self) {
        self.sql(&format!(
            "UPDATE attester_state SET next_block = 3, authenticated_parent = x'{}'",
            hex::encode(self.blocks[2].header().to_bytes()),
        ));
    }

    pub(super) fn response(&self, index: usize, status: &str) -> Value {
        json!({"withdrawalId": format!("6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e{:02}", 70 + index), "burnTxId": self.burns[index].burn.note_id().to_hex(),
            "status": status, "useCircleForwarding": false, "transferSpecHashes": [reference_hash(index)]})
    }
}

pub(super) async fn submission_store() -> (tempfile::TempDir, Vec<ProvenBlock>) {
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
    };
    let config = Config::load(&directory.path().join("attester.toml")).unwrap();
    let chain = TestChain::new(blocks, scan_limits(3, 3)).0;
    let mut attester = Attester::start(
        config,
        Box::new(chain),
        Box::new(circle),
        development_signers(),
    )
    .await
    .expect("startup checks structure, not submission contents");

    assert!(matches!(
        recover(&mut attester).await,
        Err(SubmitError::InvalidStore)
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
        ("new_status", Held),
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
        assert!(attester.retry_held_submission(saved.note_id).is_err());
        if matches!(status, "created" | "finalized" | "new_status") {
            let fresh = ledger
                .signed_with_max_height(0, Some("184467440737095516170001"))
                .await;
            assert!(
                matches!(
                    attester.submit_signed_withdrawal(&fresh).await,
                    Err(SubmitError::Conflict)
                ),
                "{status}"
            );
            assert_eq!(ledger.record(&attester, 0), saved);
        }
        {
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            let request = &requests[0];
            assert_eq!(request.method, Method::POST);
            assert_eq!(request.url, ENDPOINT);
            assert_eq!(request.timeout, Some(Duration::from_millis(100)));
            assert_eq!(
                request.headers.len(),
                1,
                "no auth or invented idempotency headers"
            );
            assert_eq!(request.headers["content-type"], "application/json");
            let body: Value = serde_json::from_slice(&request.body).unwrap();
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
            let fresh_body = fresh.submission(ENDPOINT.into()).unwrap().0.body;
            assert_ne!(fresh_body, saved.body);
            drop(attester);

            ledger.sql("CREATE TRIGGER fail_replacement BEFORE UPDATE OF body ON submissions BEGIN SELECT RAISE(FAIL, 'disk full'); END;");
            let (mut attester, requests) = ledger.start(vec![]).await;
            assert!(
                matches!(
                    attester.submit_signed_withdrawal(&fresh).await,
                    Err(SubmitError::InvalidStore)
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
            assert_eq!(requests.lock().unwrap()[0].body, fresh_body);
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
        Held,
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
    let body: Value = serde_json::from_slice(&requests.lock().unwrap()[0].body).unwrap();
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
        Err(SubmitError::InvalidStore)
    ));
    assert!(requests.lock().unwrap().is_empty());
    assert!(attester
        .store
        .submission(ledger.burns[0].burn.note_id())
        .unwrap()
        .is_none());
    assert_eq!(
        ledger.stored("SELECT count(*) FROM burns WHERE reservation_amount IS NOT NULL"),
        0,
        "a failed saved request rolls back its reservation too"
    );
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
        Err(SubmitError::Conflict)
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
        drop(attester);
        let config_path = ledger.directory.path().join("attester.toml");
        let text = std::fs::read_to_string(&config_path)
            .unwrap()
            .replace("circle.example.invalid", "new-circle.example.invalid");
        std::fs::write(config_path, text).unwrap();
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
        Err(SubmitError::InvalidStore)
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
        let held = name == "not found";
        assert_eq!(saved.status, if held { Held } else { Submitting }, "{name}");
        assert_eq!(saved.withdrawal_id.as_deref(), Some(ID));
        assert_eq!(requests.lock().unwrap().len(), 2);
        drop(attester);
        let (mut attester, requests) = ledger
            .start(vec![reply(200, ledger.response(0, "created"))])
            .await;
        if held {
            assert_eq!(saved.hold_reason, Some(HoldReason::HttpRejected));
            recover(&mut attester).await.unwrap();
            assert!(requests.lock().unwrap().is_empty());
            attester.retry_held_submission(saved.note_id).unwrap();
        }
        recover(&mut attester).await.unwrap();
        assert_eq!(
            requests.lock().unwrap()[0].method,
            Method::GET,
            "{name}: do not POST again after saving the ID"
        );
        assert_eq!(ledger.record(&attester, 0).status, Submitted);
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests[0].url,
            format!("https://circle.example.invalid/v1/withdrawal/{ID}")
        );
        assert_eq!(requests[0].timeout, Some(Duration::from_millis(100)));
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
        assert_eq!(
            ledger.record(&attester, 0).hold_reason,
            Some(HoldReason::ResponseMismatch),
            "{name}"
        );
    }
    let ledger = Ledger::new().await;
    let mut other_id = ledger.response(0, "created");
    other_id["withdrawalId"] = json!("6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e71");
    for (name, replies, reason) in [
        (
            "wrong lookup ID",
            vec![conflict(), reply(200, other_id)],
            HoldReason::ResponseMismatch,
        ),
        (
            "extra success",
            vec![reply(
                201,
                json!([ledger.response(0, "created"), ledger.response(0, "created")]),
            )],
            HoldReason::ResponseMismatch,
        ),
        (
            "conflict wrong burn note",
            vec![reply(
                409,
                json!({"success": false, "message": "already associated", "conflict": {"withdrawalId": ID, "burnTxId": "0x00"}}),
            )],
            HoldReason::ResponseMismatch,
        ),
    ] {
        let ledger = Ledger::new().await;
        let (mut attester, _) = ledger.start(replies).await;
        ledger.submit(&mut attester, 0).await.unwrap();
        assert_eq!(
            ledger.record(&attester, 0).hold_reason,
            Some(reason),
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
        Err(SubmitError::InvalidStore)
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
    recover(&mut attester).await.unwrap();
    assert_eq!(
        requests.lock().unwrap().len(),
        2,
        "holds do not retry automatically"
    );
    attester.retry_held_submission(held.note_id).unwrap();
    recover(&mut attester).await.unwrap();
    {
        let observed = requests.lock().unwrap();
        assert_eq!(observed.len(), 3);
        assert_eq!(observed[0], observed[2]);
        for (index, request) in observed[..2].iter().enumerate() {
            assert_eq!(
                ledger.record(&attester, index).status,
                SubmissionStatus::Submitted
            );
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(
                body["batches"][0]["burnTxId"],
                ledger.burns[index].burn.note_id().to_hex()
            );
        }
    }

    let ledger = Ledger::new().await;
    let (mut attester, requests) = ledger.start(vec![conflict(), reply(400, rejected)]).await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let held = ledger.record(&attester, 0);
    assert_eq!(held.hold_reason, Some(HoldReason::HttpRejected));
    assert_eq!(held.withdrawal_id.as_deref(), Some(ID));
    drop(attester);
    let path = ledger.directory.path().join("attester.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("circle.example.invalid", "new-circle.example.invalid");
    std::fs::write(path, text).unwrap();
    let (mut attester, retry) = ledger
        .start(vec![reply(200, ledger.response(0, "created"))])
        .await;
    attester.retry_held_submission(held.note_id).unwrap();
    let queued = ledger.record(&attester, 0);
    assert_eq!(queued.withdrawal_id, held.withdrawal_id);
    assert_eq!(queued.body, held.body);
    recover(&mut attester).await.unwrap();
    assert_eq!(*retry.lock().unwrap(), requests.lock().unwrap()[1..]);
    assert_eq!(
        ledger.record(&attester, 0).status,
        SubmissionStatus::Submitted
    );
}
