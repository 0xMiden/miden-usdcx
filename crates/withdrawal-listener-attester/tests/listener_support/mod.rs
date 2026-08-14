//! Shared fixtures for the **orchestration** suites — the discovery-to-status flow driven end to
//! end against the in-process Circle mock and the unit evidence adapter.
//!
//! # NON-GATING, and honest about why
//!
//! Nothing here touches a Miden node. `miden-client` has no v0.16 release, so the discovery gate's
//! exact-tag `SyncNotes`/`GetNotesById` leg and the burn-evidence reads are **PARKED**: this module
//! hands the orchestration a [`DiscoveredNote`] and a unit `BurnEvidenceReads` adapter through the
//! very ports the node-backed slice will fill, and fakes no node behind them. The GATING real-node
//! leg is the parked one; this suite is labelled NON-GATING accordingly.
//!
//! # Everything goes through the REAL units
//!
//! No token, payload, digest or signature is fabricated. The burn payload is encoded with the
//! shared encoding crate's burn-note codec and decoded back through the real discovery gate; the
//! digest is the frozen `prepare_withdrawal_200` fixture's own `messageHashToSign`; the signatures
//! are produced by the production signer over that digest; the allowlist holds the addresses those
//! keys actually recover to. A fixture that shortcut any of them would prove something about a flow
//! that cannot exist.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

#[path = "../evidence_support/mod.rs"]
pub mod evidence_support;
#[path = "../mock_circle/mod.rs"]
pub mod mock_circle;

/// The fixture loader, re-exported through `evidence_support` rather than declared a second time: a
/// `#[path]` module loaded twice is two distinct types with one file's contents, and the fixtures
/// here are shared with the evidence records on purpose.
pub use evidence_support::support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use miden_protocol::asset::AssetAmount;
use miden_protocol::note::NoteId;
use withdrawal_listener_attester::attester::{
    address_of, sign, Address, AttesterAllowlist, SecretKey, Signature65,
};
use withdrawal_listener_attester::circle::auth::AuthPosture;
use withdrawal_listener_attester::circle::client::PollPolicy;
use withdrawal_listener_attester::circle::rate::RateGovernor;
use withdrawal_listener_attester::circle::retry::RetryPolicy;
use withdrawal_listener_attester::circle::CircleClient;
use withdrawal_listener_attester::config::ListenerConfig;
use withdrawal_listener_attester::error::SignError;
use withdrawal_listener_attester::idempotency::{BurnKey, SubmissionStatus, SubmitLedger};
use withdrawal_listener_attester::listener::{
    run_once, DiscoveredNote, ListenerEvent, ListenerEvents, LocalKeyQuorumSigner, Outcome,
    QuorumSigner, RunContext, RunError,
};
use withdrawal_listener_attester::types::BurnPayload;
use withdrawal_listener_attester::validate::{
    DiscoveredDetails, DiscoveryRecord, ValidatedWithdrawal,
};
use xusdc_encoding::xreserve::encoding::ForeignChainAddress;

use evidence_support::UnitPort;
use mock_circle::{Endpoint, MockCircle, Reply, Script};

// THE BURN UNDER TEST
// ================================================================================================

/// The configured full-32-bit burn tag. A non-zero, non-round value, so a run that matched on a
/// prefix or on a defaulted `0` would not accidentally pass.
pub const BURN_TAG: u32 = 0xB0_1E_5A_FE;

/// Miden's remote domain in the config. `>= 1` (else `RemoteDomainBelowMinimum`) and different from
/// the burn's `destDomain` (else `DomainsMustDiffer`), so the happy path builds a valid request.
pub const MIDEN_DOMAIN: u32 = 10_001;

/// A `destinationDomain` that is NOT the burn payload's — the domain-mismatch injection.
pub const WRONG_DOMAIN: u32 = 7;

/// A `destinationRecipient` that is NOT the burn payload's — the recipient-mismatch injection.
/// Well-formed 32-byte hex, so what the gate refuses is the VALUE rather than the shape.
pub const WRONG_RECIPIENT: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000001";

/// The poll attempt ceiling `client_for` configures — so a `PollExhausted` assertion names the
/// bound the test actually set rather than a number copied out of the library.
pub const POLL_ATTEMPTS: u32 = 20;

/// The `messageHashToSign` the frozen `prepare_withdrawal_200` fixture carries — the digest the
/// attesters actually sign in these runs. Read from the fixture rather than declared, so a fixture
/// edit cannot leave the suite signing a digest Circle never returned.
pub fn fixture_digest() -> [u8; 32] {
    let hash = support::fixture_json("prepare_withdrawal_200")["batches"][0]["messageHashToSign"]
        .as_str()
        .expect("the fixture carries a messageHashToSign")
        .to_string();
    decode_hex32(&hash)
}

/// The burn payload that MATCHES the fixture's returned spec, so the gate accepts the fixture
/// response. Every field is read out of the fixture; nothing is typed twice.
pub fn payload() -> BurnPayload {
    let fixture = support::fixture_json("prepare_withdrawal_200");
    let spec = &fixture["batches"][0]["burnIntents"][0]["spec"];
    BurnPayload {
        amount: AssetAmount::new(spec["value"].as_str().unwrap().parse().unwrap()).unwrap(),
        dest_domain: spec["destinationDomain"].as_u64().unwrap() as u32,
        dest_recipient: ForeignChainAddress::new(decode_hex32(
            spec["destinationRecipient"].as_str().unwrap(),
        )),
        salt: [0x5a; 32],
    }
}

/// The evidence `burnTxId` the unit evidence port resolves for this burn — the value the batch is
/// keyed on and the mock echoes. Derived from the evidence fixtures, never hand-typed, so the wire
/// and the assembler cannot disagree.
pub fn burn_tx_id() -> String {
    evidence_support::burn_tx_id().to_hex()
}

pub fn note_id() -> NoteId {
    evidence_support::burn_note_id()
}

/// The discovery report for the burn under test: the configured tag, the burn payload encoded
/// with the shared encoding crate's own codec, and the LNV4 holder account as `metadata.sender`.
pub fn discovered() -> DiscoveredNote {
    discovered_with(BURN_TAG, Some(payload()))
}

/// A discovery report with an arbitrary `tag`, and `None` for a PRIVATE/erased note (`details =
/// None`) — the two discovery rejects that must stop the flow before Circle is touched.
pub fn discovered_with(tag: u32, payload: Option<BurnPayload>) -> DiscoveredNote {
    let details = payload.map(|p| {
        let id = evidence_support::other_account_id();
        let (prefix, suffix) = (id.prefix().as_felt(), id.suffix());
        DiscoveredDetails::from_raw_sender(p.encode(), prefix, suffix)
    });
    DiscoveredNote::new(note_id(), DiscoveryRecord::new(tag, details))
}

// KEYS, ADDRESSES, THE CONFIG
// ================================================================================================

/// A deterministic secret key from a single repeated byte (well below the curve order for any
/// byte).
pub fn key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).expect("a valid secp256k1 scalar")
}

/// The two registered attesters the happy path signs with.
pub const ATTESTER_A: u8 = 0x11;
pub const ATTESTER_B: u8 = 0x22;
/// A third key that is NOT registered — the allowlist negative.
pub const OUTSIDER: u8 = 0x33;

pub fn address(byte: u8) -> Address {
    address_of(&key(byte))
}

/// Signs `digest` with `key(byte)`, returning the pair `assemble_quorum` takes.
pub fn signed_pair(byte: u8, digest: &[u8; 32]) -> (Address, Signature65) {
    (
        address(byte),
        sign(digest, &key(byte)).expect("a 32-byte digest signs"),
    )
}

/// The production signer over the two registered attester keys.
pub fn production_signer() -> LocalKeyQuorumSigner {
    LocalKeyQuorumSigner::new(vec![key(ATTESTER_A), key(ATTESTER_B)])
}

/// The listener config for these runs: the burn tag, Miden's domain, and the attester allowlist.
/// The faucet id is the package default — this repo's LNV4-validated xUSDC faucet — which is the
/// same id the evidence fixtures' transaction stream runs against, so `assemble_evidence`'s faucet
/// filter is exercised against a matching id rather than being vacuously satisfied.
pub fn config_allowing(attesters: &[u8]) -> ListenerConfig {
    ListenerConfig::builder()
        .burn_tag(BURN_TAG)
        .miden_domain(MIDEN_DOMAIN)
        .attester_allowlist(AttesterAllowlist::new(
            attesters.iter().copied().map(address),
        ))
        .build()
        .expect("a valid config")
}

/// The happy-path config: both signing attesters registered.
pub fn config() -> ListenerConfig {
    config_allowing(&[ATTESTER_A, ATTESTER_B])
}

// THE COUNTING SIGNER — the non-vacuity oracle
// ================================================================================================

/// A [`QuorumSigner`] that COUNTS its invocations and delegates to whatever `pairs` says.
///
/// It is THE oracle of the mismatch cases: an `Err` from `run_once` proves the run stopped, but not
/// that it stopped BEFORE signing. Only "the signer was invoked zero times" proves that, and only
/// an interface that counts can say so.
pub struct CountingSigner {
    calls: Mutex<usize>,
    behaviour: Behaviour,
}

/// What the counting signer hands back once it has been (wrongly, in most of these cases) called.
pub enum Behaviour {
    /// Delegate to the real production signer over the two registered attesters.
    Production,
    /// Return exactly these `(claimed, signature)` pairs for every batch — the shapes
    /// `assemble_quorum` must refuse.
    Fixed(Vec<(Address, Signature65)>),
    /// Return one set per batch, but a different NUMBER of sets than there are batches.
    Sets(usize),
}

impl CountingSigner {
    pub fn new(behaviour: Behaviour) -> Self {
        Self {
            calls: Mutex::new(0),
            behaviour,
        }
    }

    pub fn production() -> Self {
        Self::new(Behaviour::Production)
    }

    /// How many times the orchestration reached the signer. **Zero is the assertion that matters**
    /// on every do-not-sign path.
    pub fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl QuorumSigner for CountingSigner {
    fn sign_batches(
        &self,
        validated: &ValidatedWithdrawal,
    ) -> Result<Vec<Vec<(Address, Signature65)>>, SignError> {
        *self.calls.lock().unwrap() += 1;
        match &self.behaviour {
            Behaviour::Production => production_signer().sign_batches(validated),
            Behaviour::Fixed(pairs) => Ok(vec![pairs.clone(); validated.batch_count()]),
            Behaviour::Sets(n) => Ok(vec![Vec::new(); *n]),
        }
    }
}

// THE EVENT SINK
// ================================================================================================

/// Captures every emitted event, so a test can assert what was reported — and, for the secrets
/// case, what was not.
#[derive(Default)]
pub struct CapturingEvents {
    events: Mutex<Vec<ListenerEvent>>,
}

impl CapturingEvents {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<ListenerEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Every captured event rendered through `Debug` — the shape an operator's log actually writes,
    /// and therefore the string a secret would leak through.
    pub fn rendered(&self) -> String {
        self.events()
            .iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The `step`/`outcome` slugs, in order — the B-step trace.
    pub fn steps(&self) -> Vec<(String, String)> {
        self.events()
            .iter()
            .map(|e| (e.step.to_string(), e.outcome.to_string()))
            .collect()
    }
}

impl ListenerEvents for CapturingEvents {
    fn emit(&self, event: &ListenerEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

// THE MOCK, THE CLIENT, THE LEDGER
// ================================================================================================

/// The frozen `prepare_withdrawal_200` body — what the gate validates against.
pub fn prepare_200() -> Value {
    support::fixture_json("prepare_withdrawal_200")
}

/// The prepare body with `batches` repeated `n` times — `0` is the fan-in refusal, `2` the fan-out
/// one. Both must be refused BEFORE the signer.
pub fn prepare_200_with_batches(n: usize) -> Value {
    let template = prepare_200()["batches"][0].clone();
    json!({ "batches": vec![template; n] })
}

/// The prepare body whose SOLE prepared batch carries the matching `burnIntents[0]` repeated `n`
/// times — the **single-batch fan-in**.
///
/// This is the shape that makes the batch count a liar. Every repeat matches the burn payload, so
/// the gate compares each one and passes each one; the batch's `messageHashToSign` covers the whole
/// intent SET, so one signature authorizes all of them; and there is still exactly ONE batch, so a
/// gate that counts batches sees nothing wrong. One burn would fund `n` releases.
///
/// `n = 0` is the other direction — a batch with no intent at all, whose digest would be bound to
/// no amount, no domain and no recipient.
pub fn prepare_200_with_intents(n: usize) -> Value {
    let mut body = prepare_200();
    let intent = body["batches"][0]["burnIntents"][0].clone();
    body["batches"][0]["burnIntents"] = json!(vec![intent; n]);
    body
}

/// The prepare body with one field of the returned `spec` replaced — each mismatch class the gate
/// must abort on.
pub fn prepare_200_with_spec_field(field: &str, value: Value) -> Value {
    let mut body = prepare_200();
    body["batches"][0]["burnIntents"][0]["spec"][field] = value;
    body
}

/// The prepare body with its `messageHashToSign` replaced (`""` is the present-but-empty case).
pub fn prepare_200_with_hash(hash: &str) -> Value {
    let mut body = prepare_200();
    body["batches"][0]["messageHashToSign"] = json!(hash);
    body
}

/// The `withdraw_201` one-element ARRAY, re-pointed at the burn under test.
pub fn created_201() -> Value {
    let mut body = support::fixture_json("withdraw_201");
    body[0]["burnTxId"] = json!(burn_tx_id());
    body
}

/// The `withdraw_409` conflict body for the burn under test — with its `withdrawalId`, or without.
pub fn conflict_409(with_withdrawal_id: bool) -> Value {
    let mut body = support::fixture_json("withdraw_409");
    body["burnTxId"] = json!(burn_tx_id());
    if !with_withdrawal_id {
        body.as_object_mut().unwrap().remove("withdrawalId");
    }
    body
}

/// The `withdrawal_status_200` body at `status`, for the burn under test.
pub fn status_200(status: &str) -> Value {
    let mut body = support::fixture_json("withdrawal_status_200");
    body["status"] = json!(status);
    body["burnTxId"] = json!(burn_tx_id());
    body
}

/// The happy-path script: prepare `200`, withdraw `201`, status `finalized`.
pub fn happy_script() -> Script {
    Script::new()
        .prepare(vec![Reply::json(200, prepare_200())])
        .withdraw(vec![Reply::json(201, created_201())])
        .status(vec![Reply::json(200, status_200("finalized"))])
}

pub fn mock(script: Script) -> MockCircle {
    MockCircle::start(script)
}

/// A client against the mock whose backoff and poll interval do not really sleep and whose rate
/// ceilings are too high to bind — so an assertion here is about the ONE policy it names.
pub fn client_for(mock: &MockCircle) -> CircleClient {
    CircleClient::new(mock.base_url(), AuthPosture::None)
        .expect("client builds against the mock base url")
        .with_transport(mock.transport())
        .with_retry_policy(RetryPolicy::new(3, 0))
        .with_rate_governor(Arc::new(RateGovernor::new(10_000, 10_000)))
        .with_poll_policy(PollPolicy::new(Duration::ZERO, POLL_ATTEMPTS))
}

/// A ledger on a REAL file — "at most once, across a restart" is only provable against a file a
/// second handle can reopen.
pub fn ledger_in(dir: &tempfile::TempDir) -> SubmitLedger {
    SubmitLedger::open(dir.path().join("submitted_burns.sqlite3")).expect("the ledger opens")
}

// THE CALL-LOG ORACLE
// ================================================================================================

/// How many `POST /v1/prepare-withdrawal` calls went out. Zero is what a discovery reject must
/// produce.
pub fn prepare_posts(mock: &MockCircle) -> usize {
    mock.requests_to(Endpoint::Prepare).len()
}

/// How many `POST /v1/withdraw` calls went out. **THE oracle**: an outcome assertion alone would
/// pass for a run that submitted and then returned a tidy value.
pub fn withdraw_posts(mock: &MockCircle) -> usize {
    mock.requests_to(Endpoint::Withdraw).len()
}

/// How many `GET /v1/withdrawal/{id}` polls went out.
pub fn status_gets(mock: &MockCircle) -> usize {
    mock.requests_to(Endpoint::Status).len()
}

/// The body of the n-th `POST /v1/withdraw` the driver actually built — the wire, not the intent.
pub fn withdraw_body(mock: &MockCircle, n: usize) -> Value {
    mock.requests_to(Endpoint::Withdraw)[n].body_json()
}

/// The burn's recorded ledger status, or `None` if the ledger has never seen it.
pub fn ledger_status(ledger: &SubmitLedger, burn_tx_id: &str) -> Option<SubmissionStatus> {
    ledger
        .record(&BurnKey::new(burn_tx_id))
        .expect("the ledger reads")
        .map(|r| r.status())
}

// DRIVING A RUN
// ================================================================================================

/// Runs the flow against `mock` with `cfg` and the evidence `port`, returning the outcome and the
/// counting signer — the two halves of nearly every assertion in the suites.
///
/// A case that needs to keep the ledger alive past the run (the idempotency family) builds its
/// context inline instead; this covers the ones whose whole question is "what came out, and was the
/// signer reached".
pub async fn run_against(
    mock: &MockCircle,
    cfg: ListenerConfig,
    port: UnitPort,
) -> (Result<Outcome, RunError>, CountingSigner) {
    let circle = client_for(mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let outcome = {
        let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);
        run_once(&ctx, &discovered()).await
    };
    (outcome, signer)
}

/// A `0x`-hex `burnSignatures[]` element, back into the typed signature — so a test can recover the
/// signer the WIRE carries rather than the one the assembler returned.
pub fn decode_signature(hex_str: &str) -> Signature65 {
    let bytes =
        hex::decode(hex_str.strip_prefix("0x").expect("a 0x-prefixed signature")).expect("hex");
    Signature65::from_bytes(&bytes).expect("a 65-byte signature")
}

pub fn decode_hex32(s: &str) -> [u8; 32] {
    let body = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(body)
        .expect("hex")
        .as_slice()
        .try_into()
        .expect("32 bytes")
}
