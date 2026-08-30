//! Shared test fixtures for Circle response decoding.

#![allow(dead_code)] // Each test binary uses only a subset of the shared fixtures.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use xreserve_deposit_relayer_lite::circle::{Attestation, CircleFeed, Page};

/// One answer from the domain-level Circle feed fake.
#[derive(Debug)]
pub enum FeedAnswer {
    Page(Page),
    Error(String),
}

/// A fake Circle feed answering scripted pages and recording requested cursors.
#[derive(Debug, Default)]
pub struct MockCircle {
    answers: Mutex<VecDeque<FeedAnswer>>,
    requests: Mutex<Vec<(u32, Option<String>)>>,
}

impl MockCircle {
    /// Answers these pages or failures in order.
    pub fn new(answers: Vec<FeedAnswer>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into()),
            requests: Mutex::new(Vec::new()),
        })
    }

    /// Every domain and cursor requested, in order.
    pub fn requests(&self) -> Vec<(u32, Option<String>)> {
        self.requests.lock().unwrap().clone()
    }
}

impl CircleFeed for MockCircle {
    fn fetch_page<'a>(
        &'a self,
        remote_domain: u32,
        page_after: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Page>> + Send + 'a>> {
        self.requests
            .lock()
            .unwrap()
            .push((remote_domain, page_after.map(str::to_owned)));
        let answer = self.answers.lock().unwrap().pop_front();
        Box::pin(async move {
            match answer {
                Some(FeedAnswer::Page(page)) => Ok(page),
                Some(FeedAnswer::Error(error)) => Err(anyhow!(error)),
                None => Err(anyhow!("the mock circle has no scripted answer left")),
            }
        })
    }
}

/// A feed page carrying these attestations and this next cursor.
pub fn page(attestations: &[Attestation], next: Option<&str>) -> FeedAnswer {
    FeedAnswer::Page(Page {
        attestations: attestations.to_vec(),
        next: next.map(str::to_owned),
    })
}

/// A scripted Circle failure that names the status used by the test.
pub fn error_response(status: u16) -> FeedAnswer {
    FeedAnswer::Error(format!("circle answered {status} for the attestation page"))
}

/// Encodes these attestations as a Circle list response body.
pub fn page_body(attestations: &[Attestation]) -> Vec<u8> {
    let items: Vec<_> = attestations
        .iter()
        .map(|attestation| {
            serde_json::json!({
                "payload": attestation.payload,
                "messageHash": attestation.message_hash,
                "attestation": attestation.attestation,
            })
        })
        .collect();

    serde_json::json!({ "attestations": items })
        .to_string()
        .into_bytes()
}

/// Builds a `Link` header carrying the next cursor.
pub fn next_link(cursor: &str) -> String {
    format!(
        "<https://circle.test/v1/remote-domains/1/attestations?pageSize=100&pageAfter={cursor}>; rel=\"next\""
    )
}

/// A syntactically valid wire attestation whose fields are arbitrary hex.
pub fn wire_attestation(seed: u8) -> Attestation {
    Attestation {
        payload: format!("0x{}", hex_bytes(&[seed; 8])),
        message_hash: format!("0x{}", hex_bytes(&[seed; 32])),
        attestation: format!("0x{}", hex_bytes(&[seed; 65])),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Golden-vector fixtures.
//
// Payloads come from the canonical artifact and are re-addressed through the encoding crate's
// header builder.

use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
use miden_protocol::crypto::utils::Serializable;

use xreserve_deposit_relayer_lite::config::Config;
use xusdc_encoding::vectors::load;
use xusdc_encoding::xreserve::encoding::{DepositIntent, DepositIntentHeader, DepositNonce};

/// The Miden destination domain these tests address payloads to — a placeholder value, since the
/// real identifier is a Circle-owned decision that is still open.
pub const TEST_REMOTE_DOMAIN: u32 = 10001;

/// A valid 33-byte compressed SEC1 attester key (the pinned partner-fixture key). These tests
/// never verify a signature, so it only has to be a real curve point.
pub const ATTESTER_PUBKEY_HEX: &str =
    "03a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3f";

/// The xUSDC faucet the notes are routed at — public, because the routing attachment can bind
/// nothing else.
pub fn faucet_id() -> AccountId {
    AccountId::dummy(
        [0x22; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// A second public faucet, for proving a note addressed elsewhere will not build.
pub fn other_faucet_id() -> AccountId {
    AccountId::dummy(
        [0x33; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// The relayer's own account — the notes' producer.
pub fn relayer_id() -> AccountId {
    AccountId::dummy(
        [0x11; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// A valid config over the standard test identities.
pub fn test_config() -> Config {
    Config {
        circle_url: "https://circle.test".parse().unwrap(),
        page_size: 100,
        request_timeout: std::time::Duration::from_secs(30),
        remote_domain: TEST_REMOTE_DOMAIN,
        faucet_account_id: faucet_id(),
        relayer_account_id: relayer_id(),
        attester_public_key: ATTESTER_PUBKEY_HEX.to_string(),
        state_file: "unused".into(),
    }
}

/// A canonical DepositIntent re-addressed to `faucet` and carrying `nonce`, built through the
/// encoding crate's own header builder.
pub fn intent_with(nonce: [u8; 32], faucet: AccountId) -> DepositIntent {
    let vector = load()
        .families
        .mi
        .iter()
        .find(|vector| vector.id == "mi-pos-hookdata")
        .expect("the canonical accept vector is in the artifact");

    let base = DepositIntent::try_from(vector.payload().as_slice())
        .expect("the canonical vector is a structurally valid deposit intent");
    let header = base.header();

    let rebuilt = DepositIntentHeader::builder()
        .amount(header.amount())
        .remote_domain(TEST_REMOTE_DOMAIN)
        .remote_token(faucet)
        .remote_recipient(header.remote_recipient())
        .local_token(header.local_token())
        .local_depositor(header.local_depositor())
        .max_fee(header.max_fee())
        .nonce(DepositNonce::new(nonce))
        .build();

    DepositIntent::new(rebuilt, base.hook_data().clone())
}

/// A buildable wire attestation for a deposit with this nonce seed, addressed to the standard
/// faucet. The signature bytes are shape-only: nothing off-chain verifies them.
pub fn attestation(seed: u8) -> Attestation {
    attestation_for(&intent_with([seed; 32], faucet_id()))
}

/// The wire form of an arbitrary intent.
pub fn attestation_for(intent: &DepositIntent) -> Attestation {
    Attestation {
        payload: format!("0x{}", hex_bytes(&intent.to_bytes())),
        message_hash: format!("0x{}", hex_bytes(&[0u8; 32])),
        attestation: format!("0x{}", hex_bytes(&[0xAB; 65])),
    }
}

/// An attestation whose payload is not a DepositIntent at all.
pub fn undecodable_attestation() -> Attestation {
    Attestation {
        payload: format!("0x{}", hex_bytes(&[0xFF; 16])),
        message_hash: format!("0x{}", hex_bytes(&[0u8; 32])),
        attestation: format!("0x{}", hex_bytes(&[0xAB; 65])),
    }
}

// Scripted Miden adapter and assembled fixture.
//
// The adapter returns configured submission outcomes and records successful note counts so the
// relay loop's cursor behaviour can be tested.

use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::Note;
use miden_protocol::{Felt, Word};

use xreserve_deposit_relayer_lite::miden::MidenClient;
use xreserve_deposit_relayer_lite::mint::Identities;
use xreserve_deposit_relayer_lite::store::CursorStore;
use xreserve_deposit_relayer_lite::Relayer;

/// What one scripted submit should answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Accept,
    Fail,
}

/// Answers a script in order (then `Accept` forever), recording each call's note count.
#[derive(Debug, Default)]
pub struct ScriptedMiden {
    answers: Mutex<VecDeque<Answer>>,
    submissions: Mutex<Vec<usize>>,
}

impl ScriptedMiden {
    pub fn accepting() -> Self {
        Self::default()
    }

    pub fn script(answers: Vec<Answer>) -> Self {
        Self {
            answers: Mutex::new(answers.into()),
            submissions: Mutex::new(Vec::new()),
        }
    }

    /// The note count of every submitted transaction, in order.
    pub fn submissions(&self) -> Vec<usize> {
        self.submissions.lock().unwrap().clone()
    }
}

impl MidenClient for ScriptedMiden {
    fn submit_notes<'a>(
        &'a self,
        _sender: miden_protocol::account::AccountId,
        notes: Vec<Note>,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
        let answer = self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Answer::Accept);
        if answer == Answer::Accept {
            self.submissions.lock().unwrap().push(notes.len());
        }
        Box::pin(async move {
            match answer {
                Answer::Accept => Ok("0xdeadbeef".to_string()),
                Answer::Fail => Err(anyhow!("the node is unreachable")),
            }
        })
    }
}

/// Owns the dependencies from which a test can construct a [`Relayer`].
pub struct Fixture {
    pub config: Config,
    pub store: CursorStore,
    pub circle: Arc<MockCircle>,
    pub identities: Identities,
    pub rng: RandomCoin,
    _dir: tempfile::TempDir,
}

impl Fixture {
    pub fn new(mock: Arc<MockCircle>) -> Self {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut config = test_config();
        config.state_file = dir.path().join("cursor");

        let store = CursorStore::new(config.state_file.clone());
        let identities = Identities::from_config(&config).expect("the fixture config is valid");

        Self {
            config,
            store,
            circle: mock,
            identities,
            // Use a fixed seed to produce stable serial numbers.
            rng: RandomCoin::new(Word::from([Felt::from(7u32); 4])),
            _dir: dir,
        }
    }

    pub fn relayer<'a>(&'a mut self, miden: &'a dyn MidenClient) -> Relayer<'a, RandomCoin> {
        Relayer {
            config: &self.config,
            circle: self.circle.as_ref(),
            store: &self.store,
            miden,
            identities: &self.identities,
            rng: &mut self.rng,
        }
    }
}
