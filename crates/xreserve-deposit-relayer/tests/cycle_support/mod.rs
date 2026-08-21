//! `tests/cycle_support/mod.rs` — the scaffolding the orchestrator suites share.
//!
//! # The Miden submit ADAPTER — and what it deliberately is not
//!
//! [`ScriptedSubmit`] is a test adapter for the [`MintSubmit`] PORT: it is the seam's test-side
//! implementation, and it is **NON-GATING** (mock-boundary disclosure). It fakes no Miden behaviour
//! — it does not execute a transaction, does not build one, and does not pretend a note committed.
//! It answers the port's four documented answers on a script, so the ORCHESTRATION around the port
//! can be driven and counted: that a rejected attestation never reaches submit at all, that a
//! replayed one is submitted once, that a transient answer retries and a fatal one does not.
//!
//! The GATING leg — a real `XUsdcMintNote` committing in block N against a real local node — is a
//! later slice's, and it is blocked on a `miden-client` release for v0.16. That slice implements
//! this same port; nothing here stands in for it, and no test in this crate claims it does.
//!
//! Everything else in the pipeline is REAL: a real `CircleClient` over the schema-exact mock Circle
//! router, the real envelope binding, the DepositIntent codec and `XUsdcMintNote::create` from the
//! shared encoding crate, and a real SQLite idempotency store on a real file.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use miden_protocol::account::AccountId;
use miden_protocol::note::NoteId;
use serde_json::{json, Value};

use xreserve_deposit_relayer::circle::{CircleClient, RetryPolicy};
use xreserve_deposit_relayer::config::RelayerConfig;
use xreserve_deposit_relayer::cycle::{
    run_relayer_cycle, CycleReport, MintIdentities, MintSubmission, MintSubmit, MintSubmitted,
    RelayerCtx,
};
use xreserve_deposit_relayer::error::{Cause, RelayerError};
use xreserve_deposit_relayer::idempotency::{IdempotencyStore, TxId};
use xreserve_deposit_relayer::observability::{MetricsSnapshot, RelayerEvent};
use xusdc_encoding::xreserve::encoding::DepositIntent;

use crate::fixtures::{
    canonical_payload, AttestationVector, PartnerAttester, TEST_VECTOR_PAYLOAD_ID,
};
use crate::mint_support::{attester_pubkey, faucet_id, note_rng, relayer_sender_id};
use crate::mock_circle::{
    attestation_page, batch_href, link_header, Endpoint, MockCircle, RecordedRequest,
    RecordingSink, Reply, Script, MOCK_BASE_URL,
};

/// The Miden remote domain the cycle suites poll. **Placeholder — the Miden domain id is OPEN
/// (`REQUIRES CIRCLE CONFIRMATION`)**: Circle has assigned Miden none. Matches the mock's fixture
/// domain so the polled path and the advertised `/v1/info` domain are the same one.
pub const CYCLE_DOMAIN: u32 = crate::mock_circle::FIXTURE_MIDEN_DOMAIN;

/// A scripted answer from the submit port.
#[derive(Debug, Clone)]
pub enum SubmitReply {
    /// The node accepted the transaction.
    Accepted(TxId),
    /// The on-chain `usedNonces` assert fired (the on-chain replay guard) — a competing relayer
    /// minted this nonce first.
    AlreadyMinted,
    /// A TRANSIENT submit failure (node sync lag) — retryable.
    Transient,
    /// A FATAL submit failure — permanent.
    Fatal,
}

/// One submission as the port actually received it — so a test can assert not only THAT submit was
/// reached, but with which note and which sender.
#[derive(Debug, Clone)]
pub struct RecordedSubmission {
    pub sender: AccountId,
    pub note_id: NoteId,
}

/// The scripted, recording [`MintSubmit`] adapter (NON-GATING — see the module docs).
///
/// Replies are consumed in order; the LAST reply repeats forever, so `vec![Transient,
/// Accepted(..)]` is "transient once, then accepted". An empty script is a FATAL answer, so a test
/// that forgot to script the port fails loudly rather than silently passing.
#[derive(Debug)]
pub struct ScriptedSubmit {
    script: Vec<SubmitReply>,
    calls: Mutex<Vec<RecordedSubmission>>,
}

impl ScriptedSubmit {
    pub fn new(script: Vec<SubmitReply>) -> Arc<Self> {
        Arc::new(Self {
            script,
            calls: Mutex::new(Vec::new()),
        })
    }

    /// The port that always accepts, handing back a distinct id per call.
    pub fn always_accepting() -> Arc<Self> {
        Self::new(vec![SubmitReply::Accepted(tx_id(0xA1))])
    }

    /// Every submission the orchestration made, in order.
    pub fn calls(&self) -> Vec<RecordedSubmission> {
        self.calls.lock().unwrap().clone()
    }

    /// How many times the orchestration reached the port — the "no second mint" oracle.
    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl MintSubmit for ScriptedSubmit {
    fn submit_mint_note<'a>(
        &'a self,
        submission: MintSubmission<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<MintSubmitted, RelayerError>> + Send + 'a>> {
        let index = {
            let mut calls = self.calls.lock().unwrap();
            calls.push(RecordedSubmission {
                sender: submission.sender(),
                note_id: submission.note().id(),
            });
            calls.len() - 1
        };

        let reply = self
            .script
            .get(index.min(self.script.len().saturating_sub(1)))
            .cloned()
            .unwrap_or(SubmitReply::Fatal);

        Box::pin(async move {
            match reply {
                SubmitReply::Accepted(id) => Ok(MintSubmitted::Accepted(id)),
                SubmitReply::AlreadyMinted => Ok(MintSubmitted::AlreadyMinted),
                SubmitReply::Transient => Err(RelayerError::TransientSubmit(Cause::new(
                    ScriptedFailure("scripted transient submit failure (node sync lag)"),
                ))),
                SubmitReply::Fatal => Err(RelayerError::FatalSubmit(Cause::new(ScriptedFailure(
                    "scripted fatal submit failure",
                )))),
            }
        })
    }
}

/// A [`MintSubmit`] whose submit NEVER completes on its own — it awaits a very long sleep. Paired
/// with a paused tokio clock, it lets a test prove the submit DEADLINE bounds a hung node: the
/// deadline fires (virtual time), the attempt is treated as transient, and the retry budget is
/// spent — none of which happens if the submit future is awaited with no timeout.
#[derive(Debug)]
pub struct HangingSubmit {
    calls: Mutex<usize>,
}

impl HangingSubmit {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(0),
        })
    }

    pub fn call_count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl MintSubmit for HangingSubmit {
    fn submit_mint_note<'a>(
        &'a self,
        _submission: MintSubmission<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<MintSubmitted, RelayerError>> + Send + 'a>> {
        *self.calls.lock().unwrap() += 1;
        Box::pin(async move {
            // an hour — far past any submit deadline; the deadline (not this) is what must end the wait
            tokio::time::sleep(std::time::Duration::from_secs(3_600)).await;
            Ok(MintSubmitted::AlreadyMinted)
        })
    }
}

/// A [`MintSubmit`] whose submit is HELD IN FLIGHT until a test releases it. It is the pauseable
/// live submit the two-driver boundary needs: driver A runs a REAL `run_relayer_cycle`, claims its
/// nonce, and parks inside this submit (its claim genuinely `Pending`) while a second driver
/// attempts reclamation — then the test releases it and A's cycle completes its mint.
///
/// `wait_until_in_flight().await` returns once A's cycle has claimed and entered the submit;
/// `release()` lets the held submit resolve to `Accepted(tx_id)`.
#[derive(Debug)]
pub struct HeldSubmit {
    tx_id: TxId,
    in_flight: tokio::sync::Notify,
    release: tokio::sync::Notify,
    calls: Mutex<usize>,
}

impl HeldSubmit {
    pub fn new(tx_id: TxId) -> Arc<Self> {
        Arc::new(Self {
            tx_id,
            in_flight: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            calls: Mutex::new(0),
        })
    }

    /// Resolves once driver A's cycle has claimed its nonce and entered the (held) submit — the
    /// synchronization point a coordinator waits on before reclaiming.
    pub async fn wait_until_in_flight(&self) {
        self.in_flight.notified().await;
    }

    /// Lets the held submit resolve to `Accepted`.
    pub fn release(&self) {
        self.release.notify_one();
    }

    pub fn call_count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl MintSubmit for HeldSubmit {
    fn submit_mint_note<'a>(
        &'a self,
        _submission: MintSubmission<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<MintSubmitted, RelayerError>> + Send + 'a>> {
        *self.calls.lock().unwrap() += 1;
        Box::pin(async move {
            // announce we are in flight (A has claimed), then block until the test releases us
            self.in_flight.notify_one();
            self.release.notified().await;
            Ok(MintSubmitted::Accepted(self.tx_id))
        })
    }
}

/// The scripted adapter's own error type — a real `std::error::Error`, so the `Cause` chain a test
/// reads is the same shape a real adapter's would be.
#[derive(Debug)]
pub struct ScriptedFailure(pub &'static str);

impl std::fmt::Display for ScriptedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ScriptedFailure {}

/// A deterministic transaction id.
pub fn tx_id(tag: u8) -> TxId {
    TxId::new([tag; 32])
}

/// The mock's xUSDC identifier as the 32 raw bytes the config carries (the fixture holds
/// the `0x`-hex wire form the `/v1/info` body advertises). **The identifier and its encoding are
/// OPEN (`REQUIRES CIRCLE CONFIRMATION`)** — a placeholder, never a settled encoding.
pub fn fixture_xusdc_identifier_bytes() -> Vec<u8> {
    hex::decode(
        crate::mock_circle::FIXTURE_XUSDC_IDENTIFIER
            .strip_prefix("0x")
            .expect("the fixture identifier is 0x-prefixed"),
    )
    .expect("the fixture identifier is hex")
}

/// The cycle suites' config: the mock's origin, the fixture domain, page size 10, ZERO backoff (the
/// retry SEMANTICS are the subject, not the wall-clock delay), and the optional domain/token
/// fast-fail OFF — the package default, because its expected values (the Miden domain id and the
/// xUSDC identifier) are both OPEN (`REQUIRES CIRCLE CONFIRMATION`).
pub fn cycle_config() -> RelayerConfig {
    serde_json::from_value(serde_json::json!({
        "circle_base_url": MOCK_BASE_URL,
        "remote_domain": CYCLE_DOMAIN,
        "xusdc_identifier": fixture_xusdc_identifier_bytes(),
        "faucet_account_id": faucet_id().to_hex(),
        "rate_qps_per_ip": 5,
        "rate_qps_global": 35,
        "max_retry_attempts": 3,
        "backoff_base_ms": 0,
        "poll_page_size": 10,
        // zero, so a test driving `run_relayer_loop` does not incur a real inter-cycle sleep — the
        // retry/loop SEMANTICS are the subject here, not the wall-clock pacing
        "poll_interval_ms": 0,
    }))
    .expect("the cycle config deserializes")
}

/// [`cycle_config`] with `mutate` applied to its JSON before deserialization — for a test that
/// needs to turn a knob (a small `retry_batch_size`, a `stale_claim_secs`, the fast-fail flag)
/// without re-spelling the whole config.
pub fn cycle_config_with(mutate: impl FnOnce(&mut serde_json::Value)) -> RelayerConfig {
    let mut value = serde_json::json!({
        "circle_base_url": MOCK_BASE_URL,
        "remote_domain": CYCLE_DOMAIN,
        "xusdc_identifier": fixture_xusdc_identifier_bytes(),
        "faucet_account_id": faucet_id().to_hex(),
        "rate_qps_per_ip": 5,
        "rate_qps_global": 35,
        "max_retry_attempts": 3,
        "backoff_base_ms": 0,
        "poll_page_size": 10,
        "poll_interval_ms": 0,
    });
    mutate(&mut value);
    serde_json::from_value(value).expect("the cycle config deserializes")
}

/// The identities the mint note is built from: the relayer's own account, the faucet, and the
/// operator-configured attester key (the partner fixture's).
pub fn cycle_identities() -> MintIdentities {
    MintIdentities::new(relayer_sender_id(), faucet_id(), attester_pubkey())
}

/// A `CircleClient` over `mock`, with the suite's retry policy and the recording sink installed.
pub fn cycle_client(
    mock: &MockCircle,
    config: &RelayerConfig,
    sink: Arc<RecordingSink>,
) -> CircleClient {
    cycle_client_with(mock, config, sink)
}

/// [`cycle_client`] over ANY `EventSink` — so a test can install the real `WriteEventSink` (over a
/// buffer) exactly where the binary installs it, and read back what an operator would see.
pub fn cycle_client_with(
    mock: &MockCircle,
    config: &RelayerConfig,
    sink: Arc<dyn xreserve_deposit_relayer::observability::EventSink>,
) -> CircleClient {
    CircleClient::from_config(config)
        .expect("the cycle config builds a client")
        .with_transport(mock.transport())
        .with_retry_policy(RetryPolicy::from_config(config).expect("the retry policy is valid"))
        .with_event_sink(sink)
}

/// A REAL idempotency store on a REAL file inside `dir` — never an in-memory database: the dedup
/// this seam exists for is only provable against a store a restart could reopen.
pub fn cycle_store(dir: &tempfile::TempDir) -> IdempotencyStore {
    IdempotencyStore::open(dir.path().join("cycle-store.sqlite3")).expect("the store opens")
}

/// A REAL store on a REAL file, on a controllable clock — so a test can age a `Pending` record past
/// the stale-claim threshold, or watch the retry queue rotate as re-attempts re-stamp timestamps.
pub fn cycle_store_with_clock(dir: &tempfile::TempDir, clock: Arc<TestClock>) -> IdempotencyStore {
    IdempotencyStore::open_with_clock(dir.path().join("cycle-store.sqlite3"), clock)
        .expect("the store opens")
}

/// A manually-advanced [`Clock`](xreserve_deposit_relayer::idempotency::Clock): the seam a test
/// drives to make "older than the threshold" and "re-stamped just now" deterministic.
#[derive(Debug)]
pub struct TestClock(Mutex<u64>);

impl TestClock {
    pub fn at(seconds: u64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(seconds)))
    }

    pub fn set(&self, seconds: u64) {
        *self.0.lock().unwrap() = seconds;
    }

    pub fn advance(&self, seconds: u64) {
        *self.0.lock().unwrap() += seconds;
    }
}

impl xreserve_deposit_relayer::idempotency::Clock for TestClock {
    fn unix_seconds(&self) -> u64 {
        *self.0.lock().unwrap()
    }
}

// THE MALFORMED-PAGE-ELEMENT DRIVER
// ================================================================================================
//
// The driver, the attester fixtures and the page builders behind
// `tests/cycle_malformed_page_element.rs`. Each test keeps its own assertions; only the scaffolding
// that more than one of them needs lives here.

/// The `pageAfter` token [`linked_page`] hands back — what the cursor must hold after a cycle that
/// consumed such a page.
pub const PAGE_AFTER_CURSOR: &str = "cursor-past-the-poison";

/// Two `messageHash` values that are not 32 hex bytes, and are not each other — so a refusal that
/// fabricated a stand-in name for an undecodable hash would visibly collapse them onto one.
pub const UNDECODABLE_HASH: &str = "0xzzzz";
pub const OTHER_UNDECODABLE_HASH: &str = "0xwhat-even-is-this";

/// The one mutation more than one test needs: an attestation that is 66 bytes, not 65.
pub fn signature_of_the_wrong_length(element: &mut Value) {
    element["attestation"] = json!(format!("0x{}", "ab".repeat(66)));
}

/// What a run left behind: each cycle's outcome in order, everything emitted, the persisted cursor,
/// the size of the retry work list, the cumulative metrics, the batch requests that went out, and
/// how many times the mint port was reached.
pub struct RanCycles {
    pub cycles: Vec<Result<CycleReport, RelayerError>>,
    pub events: Vec<RelayerEvent>,
    pub cursor: Option<String>,
    pub retryable: usize,
    pub metrics: MetricsSnapshot,
    pub requests: Vec<RecordedRequest>,
    pub submits: usize,
}

impl RanCycles {
    /// Cycle `n`'s report, which must have succeeded.
    pub fn report(&self, n: usize) -> &CycleReport {
        self.cycles[n]
            .as_ref()
            .expect("a malformed element must not fail the cycle")
    }
}

/// Runs `count` cycles over the scripted batch replies — a real client, a real store on a real file,
/// and the scripted mint port, all shared across the cycles, so cycle 2 resumes from cycle 1's
/// cursor and store.
pub async fn run_cycles(batch: Vec<Reply>, count: usize) -> RanCycles {
    let mock = MockCircle::start(Script::new().batch(batch));
    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::always_accepting();
    let identities = cycle_identities();
    let mut rng = note_rng(11);
    let mut ctx = RelayerCtx::new(
        &config,
        &client,
        &store,
        submit.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );

    let mut cycles = Vec::new();
    for _ in 0..count {
        cycles.push(run_relayer_cycle(&mut ctx).await);
    }

    RanCycles {
        cycles,
        metrics: ctx.metrics().snapshot(),
        events: sink.events(),
        cursor: store
            .read_cursor(CYCLE_DOMAIN)
            .expect("the cursor reads")
            .map(|cursor| cursor.page_after().to_string()),
        retryable: store.retryable(16).expect("the work list reads").len(),
        requests: mock.requests_to(Endpoint::Batch),
        submits: submit.call_count(),
    }
}

/// Runs ONE cycle over a single linked page.
pub async fn run_one_page(page: Value) -> RanCycles {
    run_cycles(vec![linked_page(page)], 1).await
}

/// `n` REAL, envelope-valid attestations with distinct nonces — Circle signed every one, so a
/// refusal can only come from the field a test mutated. The nonce's offset comes from the decoder's
/// own view of the payload, never from a literal restated here.
pub fn valid_attesters(n: u8) -> Vec<AttestationVector> {
    let payload = canonical_payload(TEST_VECTOR_PAYLOAD_ID);
    let nonce = *DepositIntent::try_from(payload.as_slice())
        .expect("the canonical payload decodes")
        .header()
        .nonce()
        .as_bytes();
    let at = payload
        .windows(nonce.len())
        .position(|window| window == nonce)
        .expect("the nonce appears in its own payload");

    let attester = PartnerAttester::new();
    (0..n)
        .map(|tweak| {
            let mut tweaked = payload.clone();
            tweaked[at] ^= tweak;
            attester.attest(&tweaked)
        })
        .collect()
}

/// The page body for `vectors`, with element `index` mutated into a malformed one. A malformed
/// fixture differs from the valid page in exactly the one way its mutation names.
pub fn page_with(
    vectors: &[AttestationVector],
    index: usize,
    mutate: impl FnOnce(&mut Value),
) -> Value {
    let borrowed: Vec<&AttestationVector> = vectors.iter().collect();
    let mut page = attestation_page(&borrowed);
    mutate(&mut page["attestations"][index]);
    page
}

/// The page for `vectors` with element `index` carrying [`signature_of_the_wrong_length`] — the
/// mixed valid/malformed/valid page most of the suite drives.
pub fn poisoned_page(vectors: &[AttestationVector], index: usize) -> Value {
    page_with(vectors, index, signature_of_the_wrong_length)
}

/// ONE page carrying a valid element (index 0) beside EVERY malformed shape the envelope check can
/// produce: an attestation of the wrong length, a `messageHash` that does not bind its payload, a
/// `messageHash` of 31 bytes, a payload that is not hex, and the two `messageHash` values that
/// cannot be decoded at all. Takes SEVEN vectors, one per element.
pub fn every_malformed_shape_page(vectors: &[AttestationVector]) -> Value {
    let mut page = page_with(vectors, 1, signature_of_the_wrong_length);
    page["attestations"][2]["messageHash"] = json!(format!("0x{}", "11".repeat(32)));
    page["attestations"][3]["messageHash"] = json!(format!("0x{}", "22".repeat(31)));
    page["attestations"][4]["payload"] = json!("0xnot-hex-at-all");
    page["attestations"][5]["messageHash"] = json!(UNDECODABLE_HASH);
    page["attestations"][6]["messageHash"] = json!(OTHER_UNDECODABLE_HASH);
    page
}

/// The baseline a malformed element is compared against: ONE page holding an attestation Circle
/// really signed, over a payload that is not a DepositIntent. Its envelope binds, so the fetch layer
/// passes it and the per-attestation pipeline refuses it — one rejected entry, on the ordinary path.
pub fn page_with_an_ordinary_rejection() -> Value {
    attestation_page(&[&PartnerAttester::new().attest(&[0xAB; 16])])
}

/// A poisoned first page, then the documented FINAL page — no `Link` header on page two, which is
/// what ends the scan. The two-cycle script a cursor stall shows up in. Takes THREE vectors: two on
/// the poisoned page, one on the final page.
pub fn poisoned_then_final_pages(vectors: &[AttestationVector]) -> Vec<Reply> {
    vec![
        linked_page(poisoned_page(&vectors[..2], 0)),
        Reply::ok(attestation_page(&[&vectors[2]])),
    ]
}

/// A 200 carrying `body` and a `Link: rel=next` cursor — a page with a resume point behind it.
pub fn linked_page(body: Value) -> Reply {
    Reply::ok_linked(
        body,
        link_header(&[(
            "next",
            &batch_href(CYCLE_DOMAIN, 10, Some(("pageAfter", PAGE_AFTER_CURSOR))),
        )]),
    )
}

/// The `(messageHash, outcome)` of every terminal attestation event, in emission order.
pub fn attestation_events(events: &[RelayerEvent]) -> Vec<(String, &'static str)> {
    events
        .iter()
        .filter_map(|event| match event {
            RelayerEvent::Attestation {
                message_hash,
                outcome,
                ..
            } => Some((message_hash.clone(), *outcome)),
            _ => None,
        })
        .collect()
}

/// How many operator alerts the COMPLETE event stream carries.
pub fn alerts(events: &[RelayerEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, RelayerEvent::Alert { .. }))
        .count()
}
