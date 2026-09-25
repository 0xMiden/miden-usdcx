//! Shared fixtures for the `POST /v1/withdraw` suites (the drivers + the fund-safety gate) and
//! conflict-recovery, idempotency, retry.
//!
//! It exists because those suites were splitting one 1,200-line file's worth of setup between them
//! (a Rust file is capped at roughly 500-700 lines), and a fixture copied per target is a fixture
//! that drifts per target. The families now live in focused modules — `conflict_recovery` /
//! `submit_idempotency` / `retry_policy` / `submit_withdraw` — over ONE set of fixtures.
//!
//! # Everything here goes through the REAL gates
//!
//! No token is fabricated. [`authorized_for_burns`] mints its [`AuthorizedWithdrawal`] through the
//! real validation gate ([`validate_returned`]) and the real pre-submit allowlist gate
//! ([`authorize_submission`]), so a test cannot accidentally prove something about a submission
//! that could not exist in production.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

#[path = "../mock_circle/mod.rs"]
pub mod mock_circle;
#[path = "../support/mod.rs"]
pub mod support;

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use withdrawal_listener_attester::attester::{
    recover_address, sign, Address, AttesterAllowlist, SecretKey, Signature65,
};
use withdrawal_listener_attester::circle::auth::AuthPosture;
use withdrawal_listener_attester::circle::client::PollPolicy;
use withdrawal_listener_attester::circle::rate::RateGovernor;
use withdrawal_listener_attester::circle::retry::RetryPolicy;
use withdrawal_listener_attester::circle::schema::{
    BurnIntent, PrepareBurnIntentInput, PrepareWithdrawalRequest, PrepareWithdrawalResponse,
    WithdrawBatch,
};
use withdrawal_listener_attester::circle::wire::{DecimalAmount, Hex32, HexBytes};
use withdrawal_listener_attester::circle::CircleClient;
use withdrawal_listener_attester::config::ListenerConfig;
use withdrawal_listener_attester::idempotency::{BurnKey, SubmissionStatus, SubmitLedger};
use withdrawal_listener_attester::types::BurnPayload;
use withdrawal_listener_attester::validate::{
    validate_discovery, validate_returned, DiscoveredBurn, DiscoveredDetails, DiscoveryRecord,
    ValidatedWithdrawal,
};
use withdrawal_listener_attester::withdrawal_api::{
    authorize_submission, build_withdraw_request, AuthorizedWithdrawal,
};
use xusdc_encoding::xreserve::encoding::{CircleDomain, ForeignChainAddress, XReserveBurnItems};

use mock_circle::{Endpoint, MockCircle};

// FIXTURE CONSTANTS
// ================================================================================================

/// The `burnTxId` the `withdraw_201` / `withdraw_409` / `withdrawal_status_200` fixtures all carry
/// — so a scripted reply echoes the burn the request was actually built with.
pub const BURN_TX_ID: &str = "0x82a1c0dffe1d3c5b7a99b8d7f61534537291b0cfee0d2c4b6a89a8c7e6052443";
/// A second, DIFFERENT well-formed `burnTxId` — the echo-mismatch defect case, and the second batch
/// of every multi-burn request.
pub const OTHER_BURN_TX_ID: &str =
    "0x1111111111111111111111111111111111111111111111111111111111111111";
/// A third — so a multi-burn request can carry a burn that is neither of the above.
pub const THIRD_BURN_TX_ID: &str =
    "0x2222222222222222222222222222222222222222222222222222222222222222";
/// The `withdrawalId` the `withdraw_409` and `withdrawal_status_200` fixtures name.
pub const CONFLICT_WITHDRAWAL_ID: &str = "6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8";

/// The batch digest a single-batch fund-safety token is minted over.
pub const DIGEST: [u8; 32] = digest_for(0);

/// A distinct per-batch digest, so a multi-batch request's signatures are bound to their OWN batch
/// — as the gate produces them.
pub const fn digest_for(batch: usize) -> [u8; 32] {
    [0x5a + batch as u8; 32]
}

// THE REAL GATES
// ================================================================================================

pub fn burn_intents(n: usize) -> Vec<BurnIntent> {
    let prepared = support::fixture_json("prepare_withdrawal_200");
    let one: Vec<BurnIntent> =
        serde_json::from_value(prepared["batches"][0]["burnIntents"].clone())
            .expect("the fixture burnIntents deserialize");
    let template = one[0].clone();
    std::iter::repeat_with(|| template.clone())
        .take(n)
        .collect()
}

/// A deterministic secret key from a single repeated byte (well below the curve order for any
/// byte).
pub fn key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).expect("a valid secp256k1 scalar")
}

/// Signs `digest` with `key(byte)` and returns the recovered signer address and the 65-byte
/// signature.
pub fn signer(byte: u8, digest: &[u8; 32]) -> (Address, Signature65) {
    let sk = key(byte);
    let sig = sign(digest, &sk).expect("sign");
    let addr = recover_address(digest, &sig).expect("recoverable");
    (addr, sig)
}

pub fn hexbytes(sig: &Signature65) -> HexBytes {
    HexBytes::new(sig.to_hex()).expect("a 65-byte signature renders to valid 0x-hex")
}

pub fn decode_hex32(s: &str) -> [u8; 32] {
    let body = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(body).unwrap().as_slice().try_into().unwrap()
}

/// A `WithdrawBatch` carrying `signatures` verbatim (order preserved) over one canonical intent,
/// keyed on the fixture's `burnTxId`.
pub fn batch_with(signatures: Vec<HexBytes>) -> WithdrawBatch {
    batch_for(BURN_TX_ID, signatures)
}

pub fn batch_for(burn_tx_id: &str, signatures: Vec<HexBytes>) -> WithdrawBatch {
    WithdrawBatch::new(burn_intents(1), signatures, burn_tx_id.to_string(), false)
        .expect("a 1-intent, 2-signature batch")
}

/// A burn payload that MATCHES the 200 fixture's returned spec, so `validate_returned` accepts
/// the fixture response.
pub fn payload_matching_fixture() -> BurnPayload {
    let fixture = support::fixture_json("prepare_withdrawal_200");
    let intent = &fixture["batches"][0]["burnIntents"][0];
    let spec = &intent["spec"];
    XReserveBurnItems {
        dest_domain: CircleDomain::new(spec["destinationDomain"].as_u64().unwrap() as u32),
        dest_recipient: ForeignChainAddress::new(decode_hex32(
            spec["destinationRecipient"].as_str().unwrap(),
        )),
    }
}

pub fn depositor_matching_fixture() -> AccountId {
    let fixture = support::fixture_json("prepare_withdrawal_200");
    let remote_depositor = decode_hex32(
        fixture["batches"][0]["burnIntents"][0]["spec"]["hookData"]["remoteDepositor"]
            .as_str()
            .unwrap(),
    );
    let eth_address = remote_depositor[12..]
        .try_into()
        .expect("bytes32-embedded Ethereum address is 20 bytes");
    EthEmbeddedAccountId::new(eth_address)
        .expect("fixture remoteDepositor is an embedded account id")
        .into_account_id()
}

pub fn burn_matching_fixture() -> DiscoveredBurn {
    let fixture = support::fixture_json("prepare_withdrawal_200");
    let intent = &fixture["batches"][0]["burnIntents"][0];
    let value: u64 = intent["spec"]["value"].as_str().unwrap().parse().unwrap();
    let fee: u64 = intent["maxFee"].as_str().unwrap().parse().unwrap();
    let depositor = depositor_matching_fixture();
    let (prefix, suffix) = (depositor.prefix().as_felt(), depositor.suffix());
    let record = DiscoveryRecord::new(
        ListenerConfig::default().burn_tag(),
        Some(DiscoveredDetails::from_raw_sender(
            payload_matching_fixture().encode(),
            AssetAmount::new(value.checked_add(fee).unwrap()).unwrap(),
            prefix,
            suffix,
        )),
    );
    validate_discovery(&record, &ListenerConfig::default()).expect("fixture burn passes discovery")
}

pub fn config_matching_fixture() -> ListenerConfig {
    let fixture = support::fixture_json("prepare_withdrawal_200");
    let intent = &fixture["batches"][0]["burnIntents"][0];
    ListenerConfig::builder()
        .miden_domain(CircleDomain::new(
            intent["spec"]["hookData"]["remoteDomain"].as_u64().unwrap() as u32,
        ))
        .max_withdrawal_fee(
            AssetAmount::new(intent["maxFee"].as_str().unwrap().parse().unwrap()).unwrap(),
        )
        .build()
        .expect("fixture config is valid")
}

/// A `ValidatedWithdrawal` carrying exactly `digests`, minted through the REAL validation gate
/// against a fixture-derived prepare response — so the digests come from the gate, never from
/// ad-hoc test input.
pub fn validated(digests: &[[u8; 32]]) -> ValidatedWithdrawal {
    let template = support::fixture_json("prepare_withdrawal_200")["batches"][0].clone();
    let batches: Vec<Value> = digests
        .iter()
        .map(|d| {
            let mut b = template.clone();
            b["messageHashToSign"] = Value::String(format!("0x{}", hex::encode(d)));
            b
        })
        .collect();
    let resp: PrepareWithdrawalResponse =
        serde_json::from_value(json!({ "batches": batches })).expect("a valid prepare response");
    validate_returned(&resp, &burn_matching_fixture(), &config_matching_fixture())
        .expect("the fixture response passes B5")
}

/// A `ListenerConfig` whose attester allowlist is exactly `addrs`.
pub fn config_with_allowlist(addrs: impl IntoIterator<Item = Address>) -> ListenerConfig {
    let fixture = support::fixture_json("prepare_withdrawal_200");
    let intent = &fixture["batches"][0]["burnIntents"][0];
    ListenerConfig::builder()
        .miden_domain(CircleDomain::new(
            intent["spec"]["hookData"]["remoteDomain"].as_u64().unwrap() as u32,
        ))
        .max_withdrawal_fee(
            AssetAmount::new(intent["maxFee"].as_str().unwrap().parse().unwrap()).unwrap(),
        )
        .attester_allowlist(AttesterAllowlist::new(addrs))
        .build()
        .expect("a valid config")
}

/// A fund-safety-gated submission carrying ONE batch per entry of `burns`, each keyed on its own
/// `burnTxId` and signed by two registered attesters over its OWN validated digest.
///
/// Multi-burn is the interesting case and the reason this takes a slice: a `POST /v1/withdraw`
/// carries 1-5 batches, and a conflict or a status names ONE of them — so "which burn does this
/// answer bind to?" is only a real question when there is more than one.
pub fn authorized_for_burns(burns: &[&str]) -> AuthorizedWithdrawal {
    let mut batches = Vec::new();
    let mut digests = Vec::new();
    let mut registered = Vec::new();

    for (batch, burn) in burns.iter().enumerate() {
        let digest = digest_for(batch);
        let (a0, s0) = signer(0x11, &digest);
        let (a1, s1) = signer(0x22, &digest);
        registered.push(a0);
        registered.push(a1);
        batches.push(batch_for(burn, vec![hexbytes(&s0), hexbytes(&s1)]));
        digests.push(digest);
    }

    let request = build_withdraw_request(batches).expect("1..=5 batches");
    authorize_submission(
        request,
        &validated(&digests),
        &config_with_allowlist(registered),
    )
    .expect("every signer registered")
}

/// The single-batch gated submission for `burn_tx_id`.
pub fn authorized_for(burn_tx_id: &str) -> AuthorizedWithdrawal {
    authorized_for_burns(&[burn_tx_id])
}

/// The happy-path token: one batch, both signers registered, on the fixture's burn.
pub fn authorized_two_of_two() -> AuthorizedWithdrawal {
    authorized_for(BURN_TX_ID)
}

/// A two-batch token — two DISTINCT burns, each with its own digest and its own registered signers.
pub fn authorized_two_batches() -> AuthorizedWithdrawal {
    authorized_for_burns(&[BURN_TX_ID, OTHER_BURN_TX_ID])
}

/// A submission whose TWO batches carry the SAME `burnTxId` — the intra-request duplicate.
pub fn authorized_with_the_same_burn_twice() -> AuthorizedWithdrawal {
    authorized_for_burns(&[BURN_TX_ID, BURN_TX_ID])
}

/// The `PrepareWithdrawalRequest` wrapper the driver sends — any schema-valid single-batch request
/// exercises the wire.
pub fn a_prepare_request() -> PrepareWithdrawalRequest {
    let input = PrepareBurnIntentInput::builder()
        .value_including_fees(DecimalAmount::new("10000000").unwrap())
        .remote_domain(CircleDomain::new(10_001))
        .remote_depositor(Hex32::new(format!("0x{}", "11".repeat(32))).unwrap())
        .final_destination_domain(CircleDomain::new(0))
        .final_destination_recipient(Hex32::new(format!("0x{}", "22".repeat(32))).unwrap())
        .use_circle_forwarding(false)
        .build()
        .expect("a valid prepare input");
    PrepareWithdrawalRequest::new(vec![input])
}

// THE CLIENT AND THE LEDGER
// ================================================================================================

/// A client against the mock whose retry backoff and poll interval do not really sleep, and whose
/// rate ceilings are set far too high to bind — so a timing assertion elsewhere is about the ONE
/// policy it names.
pub fn client_for(mock: &MockCircle) -> CircleClient {
    CircleClient::new(mock.base_url(), AuthPosture::None)
        .expect("client builds against the mock base url")
        .with_transport(mock.transport())
        .with_retry_policy(RetryPolicy::new(3, 0))
        .with_rate_governor(Arc::new(RateGovernor::new(10_000, 10_000)))
        .with_poll_policy(PollPolicy::new(Duration::ZERO, 20))
}

/// A ledger on a REAL file in `dir` — "durable across a restart" is only provable against a file a
/// second, independent handle can reopen, so no test here reaches for an in-memory database (which
/// is precisely what `SubmitLedger::open` refuses).
pub fn ledger_in(dir: &tempfile::TempDir) -> SubmitLedger {
    SubmitLedger::open(dir.path().join("submitted_burns.sqlite3")).expect("the ledger opens")
}

// SCRIPTED BODIES
// ================================================================================================

pub fn conflict_body_full() -> Value {
    support::fixture_json("withdraw_409")
}

pub fn conflict_body_burn_only() -> Value {
    json!({ "burnTxId": BURN_TX_ID })
}

pub fn conflict_body_for(burn_tx_id: &str) -> Value {
    let mut body = support::fixture_json("withdraw_409");
    body["burnTxId"] = json!(burn_tx_id);
    body
}

pub fn conflict_body_echoing_another_burn() -> Value {
    conflict_body_for(OTHER_BURN_TX_ID)
}

/// The `withdraw_201` fixture (the one-element ARRAY) re-pointed at `burn_tx_id` — an honest `201`
/// for a burn other than the fixture's own.
pub fn created_body_for(burn_tx_id: &str) -> Value {
    let mut body = support::fixture_json("withdraw_201");
    body[0]["burnTxId"] = json!(burn_tx_id);
    body
}

/// A `201` ARRAY with one honest element per burn — what Circle returns for a multi-batch
/// submission.
pub fn created_body_for_all(burns: &[&str]) -> Value {
    Value::Array(
        burns
            .iter()
            .map(|burn| created_body_for(burn)[0].clone())
            .collect(),
    )
}

/// The `withdrawal_status_200` fixture with its `status` replaced — a scripted status body that
/// differs from the canonical one in exactly one field.
pub fn status_body(status: &str) -> Value {
    let mut body = support::fixture_json("withdrawal_status_200");
    body["status"] = Value::String(status.to_string());
    body
}

/// The `withdrawal_status_200` fixture at `status`, for `burn_tx_id`.
pub fn status_body_for(burn_tx_id: &str, status: &str) -> Value {
    let mut body = status_body(status);
    body["burnTxId"] = json!(burn_tx_id);
    body
}

// THE CALL-LOG ORACLE
// ================================================================================================

/// How many `POST /v1/withdraw` attempts actually went out. THE oracle of this suite: an outcome
/// assertion alone would pass for a driver that re-POSTed and then returned a tidy value.
pub fn withdraw_posts(mock: &MockCircle) -> usize {
    mock.requests_to(Endpoint::Withdraw).len()
}

/// How many `GET /v1/withdrawal/{id}` recoveries went out.
pub fn status_gets(mock: &MockCircle) -> usize {
    mock.requests_to(Endpoint::Status).len()
}

/// The burn's recorded status, or `None` if the ledger has never seen it.
pub fn status_of(ledger: &SubmitLedger, burn_tx_id: &str) -> Option<SubmissionStatus> {
    ledger
        .record(&BurnKey::new(burn_tx_id))
        .expect("the ledger reads")
        .map(|r| r.status())
}

/// The `withdrawalId` recorded against a burn — what an operator polls to reconcile it.
pub fn withdrawal_id_of(ledger: &SubmitLedger, burn_tx_id: &str) -> Option<String> {
    ledger
        .record(&BurnKey::new(burn_tx_id))
        .expect("the ledger reads")
        .and_then(|r| r.withdrawal_id().map(str::to_string))
}
