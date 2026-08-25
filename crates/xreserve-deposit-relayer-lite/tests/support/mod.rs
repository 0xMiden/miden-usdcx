//! Shared test fixtures: the canonical payloads, the recording mock Circle, and the scripted
//! submit adapter.
//!
//! **Payloads come from the golden artifact**, never from hand-rolled bytes: a payload is loaded
//! from `xusdc-encoding`'s canonical vector set and re-addressed through that crate's OWN header
//! builder. Distinct nonces are minted the same way, so no test restates a byte offset or a field
//! layout (single-owner rule).
//!
//! **The submit adapter is scripted, and fakes no Miden behaviour.** It answers this crate's
//! `MintSubmit` interface from a list; it does not simulate a node, and nothing here is evidence
//! about Miden. Circle may be mocked; Miden may not.

#![allow(dead_code)] // a shared fixture: each test binary uses the subset it needs

use std::collections::VecDeque;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::crypto::utils::Serializable;
use miden_protocol::note::Note;
use miden_protocol::{Felt, Word};
use sha3::{Digest, Keccak256};
use tempfile::TempDir;

use xreserve_deposit_relayer_lite::circle::{
    Attestation, CircleClient, HttpRequest, HttpResponse, Transport,
};
use xreserve_deposit_relayer_lite::config::Config;
use xreserve_deposit_relayer_lite::cycle::Relayer;
use xreserve_deposit_relayer_lite::mint::Identities;
use xreserve_deposit_relayer_lite::store::Store;
use xreserve_deposit_relayer_lite::submit::{MintSubmit, SubmitError, Submitted};

use xusdc_encoding::vectors::load;
use xusdc_encoding::xreserve::encoding::{DepositIntent, DepositIntentHeader, DepositNonce};

/// The Miden destination domain these tests address payloads to. **Placeholder — the real id is
/// Circle-owned and OPEN.**
pub const TEST_REMOTE_DOMAIN: u32 = 10001;

/// The canonical accept vector every payload here is derived from.
pub const BASE_VECTOR_ID: &str = "mi-pos-hookdata";

/// A valid 33-byte compressed SEC1 attester key. Taken from the sibling crate's pinned
/// partner-attester fixture — this suite never verifies a signature, so it needs the key only to be
/// a real curve point.
pub const ATTESTER_PUBKEY_HEX: &str =
    "03a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3f";

// IDENTITIES
// ================================================================================================

/// The xUSDC faucet the notes are routed at — PUBLIC, because the mint note's routing attachment
/// can bind nothing else.
pub fn faucet_id() -> AccountId {
    AccountId::dummy(
        [0x22; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// A DIFFERENT public faucet — for the case that proves a note addressed elsewhere will not build.
pub fn other_faucet_id() -> AccountId {
    AccountId::dummy(
        [0x33; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// The relayer's own account — the note's producer.
pub fn relayer_id() -> AccountId {
    AccountId::dummy(
        [0x11; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

// PAYLOADS (from the golden artifact)
// ================================================================================================

/// A canonical DepositIntent addressed to `faucet`, carrying `nonce`.
///
/// The base vector supplies every other field; only the addressing and the nonce are replaced, and
/// both go through `xusdc-encoding`'s own header builder rather than any byte surgery here.
pub fn intent_with(nonce: [u8; 32], faucet: AccountId) -> DepositIntent {
    let vector = load()
        .families
        .mi
        .iter()
        .find(|vector| vector.id == BASE_VECTOR_ID)
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

/// A distinct nonce per `seed`, so a page can carry several different deposits.
pub fn nonce(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// The wire attestation for a deposit with this nonce, addressed to the standard faucet.
pub fn attestation(seed: u8) -> Attestation {
    attestation_for(&intent_with(nonce(seed), faucet_id()))
}

/// The wire attestation for an arbitrary intent, with a correctly bound `messageHash`.
pub fn attestation_for(intent: &DepositIntent) -> Attestation {
    let payload = intent.to_bytes();
    let digest: [u8; 32] = Keccak256::digest(&payload).into();

    Attestation {
        payload: format!("0x{}", hex::encode(&payload)),
        message_hash: format!("0x{}", hex::encode(digest)),
        // 65 arbitrary bytes: this crate never verifies a signature (that is on-chain and
        // faucet-owned), so the value only has to be the right SHAPE.
        attestation: format!("0x{}", hex::encode([0xAB; 65])),
    }
}

/// An attestation whose payload is not a DepositIntent at all.
pub fn undecodable_attestation() -> Attestation {
    let payload = vec![0xFFu8; 16];
    let digest: [u8; 32] = Keccak256::digest(&payload).into();

    Attestation {
        payload: format!("0x{}", hex::encode(&payload)),
        message_hash: format!("0x{}", hex::encode(digest)),
        attestation: format!("0x{}", hex::encode([0xAB; 65])),
    }
}

/// An attestation whose `messageHash` does not bind its payload.
pub fn unbound_attestation(seed: u8) -> Attestation {
    let mut broken = attestation(seed);
    broken.message_hash = format!("0x{}", hex::encode([0x00; 32]));
    broken
}

// THE MOCK CIRCLE
// ================================================================================================

/// A recording fake Circle: it answers from a script and keeps every request it was handed.
///
/// It implements the crate's `Transport` seam directly, so it needs no HTTP server and binds no
/// socket, while still asserting on exactly the URL and headers the client built.
#[derive(Debug, Default)]
pub struct MockCircle {
    responses: Mutex<VecDeque<HttpResponse>>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl MockCircle {
    /// A mock that answers these responses, in order.
    pub fn new(responses: Vec<HttpResponse>) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
        })
    }

    /// A mock serving exactly one page, with no next cursor.
    pub fn one_page(attestations: &[Attestation]) -> Arc<Self> {
        Self::new(vec![page(attestations, None)])
    }

    /// Every request the client made, in order.
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// How many requests the client made.
    pub fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Transport for MockCircle {
    fn get<'a>(
        &'a self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse>> + Send + 'a>> {
        self.requests.lock().unwrap().push(request);
        let next = self.responses.lock().unwrap().pop_front();

        Box::pin(async move {
            next.ok_or_else(|| anyhow!("the mock circle has no scripted response left"))
        })
    }
}

/// A 200 carrying these attestations, and a `Link` header if there is a next page.
pub fn page(attestations: &[Attestation], next: Option<&str>) -> HttpResponse {
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

    HttpResponse {
        status: 200,
        body: serde_json::json!({ "attestations": items })
            .to_string()
            .into_bytes(),
        link: next.map(|cursor| {
            format!(
                "<https://circle.test/v1/remote-domains/{TEST_REMOTE_DOMAIN}/attestations?\
                 pageSize=100&pageAfter={cursor}>; rel=\"next\""
            )
        }),
    }
}

/// A non-200 answer.
pub fn error_response(status: u16) -> HttpResponse {
    HttpResponse {
        status,
        body: br#"{"message":"upstream failure"}"#.to_vec(),
        link: None,
    }
}

// THE SCRIPTED SUBMIT ADAPTER
// ================================================================================================

/// What the scripted adapter should answer for one submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Accept,
    AlreadyMinted,
    Fatal,
    Transient,
}

/// A `MintSubmit` that answers from a script, then falls back to a default.
#[derive(Debug)]
pub struct ScriptedSubmit {
    answers: Mutex<VecDeque<Answer>>,
    fallback: Answer,
    calls: Mutex<usize>,
}

impl ScriptedSubmit {
    /// Always answers the same way.
    pub fn always(answer: Answer) -> Self {
        Self {
            answers: Mutex::new(VecDeque::new()),
            fallback: answer,
            calls: Mutex::new(0),
        }
    }

    /// Answers the script in order, then `Accept` forever.
    pub fn script(answers: Vec<Answer>) -> Self {
        Self {
            answers: Mutex::new(answers.into()),
            fallback: Answer::Accept,
            calls: Mutex::new(0),
        }
    }

    /// How many submits were attempted.
    pub fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl MintSubmit for ScriptedSubmit {
    fn submit<'a>(
        &'a self,
        _sender: AccountId,
        _note: &'a Note,
    ) -> Pin<Box<dyn Future<Output = Result<Submitted, SubmitError>> + Send + 'a>> {
        *self.calls.lock().unwrap() += 1;
        let answer = self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(self.fallback);

        Box::pin(async move {
            match answer {
                Answer::Accept => Ok(Submitted::Accepted("0xdeadbeef".to_string())),
                Answer::AlreadyMinted => Ok(Submitted::AlreadyMinted),
                Answer::Fatal => Err(SubmitError::Fatal(anyhow!("the node refused this note"))),
                Answer::Transient => Err(SubmitError::Transient(anyhow!("the node is behind"))),
            }
        })
    }
}

// THE ASSEMBLED FIXTURE
// ================================================================================================

/// A valid config pointing at `store_path`.
pub fn test_config(store_path: PathBuf) -> Config {
    Config {
        circle_base_url: "https://circle.test".to_string(),
        remote_domain: TEST_REMOTE_DOMAIN,
        faucet_account_id: faucet_id().to_hex(),
        relayer_account_id: relayer_id().to_hex(),
        attester_pubkey_hex: ATTESTER_PUBKEY_HEX.to_string(),
        store_path,
        api_auth_token: None,
        api_auth_header: "Authorization".to_string(),
        poll_page_size: 100,
        poll_interval_ms: 1,
        request_timeout_ms: 30_000,
        max_response_bytes: 8 * 1024 * 1024,
    }
}

/// Everything a cycle needs, owned, so a test can borrow a [`Relayer`] out of it.
pub struct Fixture {
    pub config: Config,
    pub store: Store,
    pub circle: CircleClient,
    pub identities: Identities,
    pub rng: RandomCoin,
    pub mock: Arc<MockCircle>,
    _dir: TempDir,
}

impl Fixture {
    /// Assembles against `mock`, on a fresh store in a temporary directory.
    pub fn new(mock: Arc<MockCircle>) -> Self {
        Self::with_config(mock, |_| {})
    }

    /// As [`Self::new`], with a chance to adjust the config first.
    pub fn with_config(mock: Arc<MockCircle>, adjust: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut config = test_config(dir.path().join("state.db"));
        adjust(&mut config);

        let store = Store::open(&config.store_path).expect("a fresh store opens");
        let identities = Identities::from_config(&config).expect("the fixture config is valid");
        let circle = CircleClient::new(&config, mock.clone());

        Self {
            config,
            store,
            circle,
            identities,
            // a FIXED seed: a test wants reproducible serial numbers, which is exactly why the RNG
            // is a parameter rather than a global
            rng: RandomCoin::new(Word::from([Felt::from(7u32); 4])),
            mock,
            _dir: dir,
        }
    }

    /// Borrows a relayer that submits through `submit`.
    pub fn relayer<'a>(&'a mut self, submit: &'a dyn MintSubmit) -> Relayer<'a, RandomCoin> {
        Relayer {
            config: &self.config,
            circle: &self.circle,
            store: &self.store,
            submit,
            identities: &self.identities,
            rng: &mut self.rng,
        }
    }
}
