//! The discovery checklist, the `validate_returned` field-by-field gate, and the **DO-NOT-SIGN**
//! abort.
//!
//! **Validation gates signing.** This service releases real USDC, and this
//! is the last check before an attester signature is produced. The gate is proven two ways here:
//!
//! * **Field-by-field.** Circle's returned `burnIntents[].spec` (`value`,
//!   `destinationDomain`, `destinationRecipient`) is compared against the burn-note payload for
//!   EVERY batch — a mismatch in ANY batch (not just `batches[0]`) rejects; a missing
//!   `messageHashToSign` rejects.
//! * **Control-flow (the non-vacuity oracle).** The mismatch is driven through the REAL
//!   gate: on `Err`, NO signature is produced and NO withdraw call is reachable. The proof is
//!   structural — the flow-level signer takes a [`ValidatedWithdrawal`], which ONLY a full-match
//!   [`validate_returned`] can mint, so "signed anyway" is untypeable, not merely unreached.
//!
//! These are PURE tests (no node, no Circle): the mock `PrepareWithdrawalResponse` is parsed from
//! the schema-frozen fixtures, the burn payload is constructed locally, and the abort is exercised
//! through `validate_returned` + `sign_validated`. The `messageHashToSign` digest derivation and
//! the Circle-assigned `sourceDepositor` stay OPEN — parameterized, never resolved.

use assert_matches::assert_matches;
use rstest::rstest;
use serde_json::Value;

use miden_protocol::asset::AssetAmount;
use miden_protocol::Felt;
use withdrawal_listener_attester::attester::{SecretKey, Signature65};
use withdrawal_listener_attester::circle::schema::PrepareWithdrawalResponse;
use withdrawal_listener_attester::config::ListenerConfig;
use withdrawal_listener_attester::error::{DecodeError, DiscoveryReject, ValidationMismatch};
use withdrawal_listener_attester::types::BurnPayload;
use withdrawal_listener_attester::validate::{
    sign_validated, validate_discovery, validate_returned, DiscoveredDetails, DiscoveryRecord,
};

#[path = "support/mod.rs"]
mod support;

#[path = "attester_vectors/mod.rs"]
mod attester_vectors;
use attester_vectors::attesters;

// ================================================================================================
// FIXTURE HELPERS
// ================================================================================================

/// The 32 hex bytes behind a `0x…` string (panics on a malformed fixture — the fixtures are
/// frozen).
fn hex32(s: &str) -> [u8; 32] {
    let body = s.strip_prefix("0x").expect("0x-prefixed hex");
    let bytes = hex::decode(body).expect("valid hex");
    bytes.try_into().expect("exactly 32 bytes")
}

/// The burn payload that MATCHES `prepare_withdrawal_200.json`: `value = 10000000`,
/// `destinationDomain = 0`, `destinationRecipient = 0x…742d35cc…`. `salt` is not a compared field,
/// so any value serves.
fn matching_payload() -> BurnPayload {
    BurnPayload {
        amount: AssetAmount::new(10_000_000).unwrap(),
        dest_domain: 0,
        dest_recipient: hex32("0x000000000000000000000000742d35cc6634c0532925a3b844bc454e4438f44e"),
        salt: [0x11; 32],
    }
}

/// Parses a fixture into the response type. Panics if it does not deserialize — used only for
/// fixtures that MUST parse (the 200 / mismatch bodies).
fn response(stem: &str) -> PrepareWithdrawalResponse {
    serde_json::from_str(&support::fixture_text(stem))
        .unwrap_or_else(|e| panic!("{stem}.json must deserialize: {e}"))
}

/// The 200 fixture's JSON, as a mutable `Value` — for crafting multi-batch / field-edited variants.
fn base_200_json() -> Value {
    support::fixture_json("prepare_withdrawal_200")
}

fn response_from_value(v: &Value) -> Result<PrepareWithdrawalResponse, serde_json::Error> {
    serde_json::from_value(v.clone())
}

fn cfg() -> ListenerConfig {
    ListenerConfig::default()
}

/// A signing key for the positive control — signing MUST be reachable on a full match.
fn a_key() -> SecretKey {
    attesters()[0].secret().clone()
}

// ================================================================================================
// validate_returned: the field-by-field gate
// ================================================================================================

/// Positive: on a full match, the top-level `batches[]` wrapper is parsed (NOT a bare batch), the
/// gate returns `Ok`, and the minted [`ValidatedWithdrawal`] carries exactly one cleared digest.
#[test]
fn validate_returned_ok_on_full_match() {
    let resp = response("prepare_withdrawal_200");
    assert_eq!(
        resp.batches().len(),
        1,
        "the top-level batches[] wrapper is parsed"
    );

    let validated =
        validate_returned(&resp, &matching_payload(), &cfg()).expect("a full match validates");

    assert_eq!(
        validated.digests().len(),
        1,
        "one cleared digest per validated batch"
    );
    assert_eq!(
        validated.digests()[0],
        hex32("0x90afceed0c2b4a6988a7c6e504234261809fbeddfc1b3a597897b6d5f4133251"),
        "the cleared digest is the batch's messageHashToSign"
    );
}

/// A returned `value` (amount) that does not match the burn payload rejects with the exact variant.
#[test]
fn validate_returned_rejects_amount_mismatch() {
    let resp = response("prepare_withdrawal_200");
    let mut payload = matching_payload();
    payload.amount = AssetAmount::new(9_999_999).unwrap();

    assert_matches!(
        validate_returned(&resp, &payload, &cfg()),
        Err(ValidationMismatch::Amount { batch: 0, .. })
    );
}

/// A returned `destinationDomain` that does not match rejects with the exact variant.
#[test]
fn validate_returned_rejects_destination_domain_mismatch() {
    let resp = response("prepare_withdrawal_200");
    let mut payload = matching_payload();
    payload.dest_domain = 7;

    assert_matches!(
        validate_returned(&resp, &payload, &cfg()),
        Err(ValidationMismatch::DestinationDomain { batch: 0, .. })
    );
}

/// A returned `destinationRecipient` that does not match rejects with the exact variant.
#[test]
fn validate_returned_rejects_destination_recipient_mismatch() {
    let resp = response("prepare_withdrawal_200");
    let mut payload = matching_payload();
    payload.dest_recipient = [0x00; 32];

    assert_matches!(
        validate_returned(&resp, &payload, &cfg()),
        Err(ValidationMismatch::DestinationRecipient { batch: 0, .. })
    );
}

/// The `prepare_withdrawal_validation_mismatch` fixture (value / domain / recipient all diverge)
/// rejects against the matching payload — the canonical negative the abort test also drives.
#[test]
fn validate_returned_rejects_the_mismatch_fixture() {
    let resp = response("prepare_withdrawal_validation_mismatch");
    // The fixture diverges on value (99000000 ≠ 10000000) first, so the amount check fires.
    assert_matches!(
        validate_returned(&resp, &matching_payload(), &cfg()),
        Err(ValidationMismatch::Amount { batch: 0, .. })
    );
}

/// A response with no batches is refused — there is nothing to validate or sign, and an empty
/// prepare response matches no withdrawal.
#[test]
fn validate_returned_rejects_no_batches() {
    let mut v = base_200_json();
    v["batches"] = Value::Array(vec![]);
    let resp = response_from_value(&v).expect("an empty batches[] still deserializes");
    assert_matches!(
        validate_returned(&resp, &matching_payload(), &cfg()),
        Err(ValidationMismatch::NoBatches)
    );
}

/// A batch whose `burnIntents` array is EMPTY is refused — with no intent to compare, its digest is
/// bound to no amount/domain/recipient, so allowing it would mint a signing token vacuously. This
/// is the fund-safety hole the audit surfaced: the `check_spec` loop must not be skippable into
/// `Ok`.
#[test]
fn validate_returned_rejects_an_empty_burn_intents_batch() {
    let mut v = base_200_json();
    v["batches"][0]["burnIntents"] = Value::Array(vec![]);
    let resp = response_from_value(&v).expect("an empty burnIntents[] still deserializes");
    assert_matches!(
        validate_returned(&resp, &matching_payload(), &cfg()),
        Err(ValidationMismatch::EmptyBurnIntents { batch: 0 })
    );
}

/// The empty-`burnIntents` hole is closed for a LATER batch too: batch[0] is a full match, batch[1]
/// is empty — the gate must still reject (not stop at the first, valid batch).
#[test]
fn validate_returned_rejects_a_later_empty_burn_intents_batch() {
    let mut v = base_200_json();
    let good_batch = v["batches"][0].clone();
    let mut empty_batch = good_batch.clone();
    empty_batch["burnIntents"] = Value::Array(vec![]);
    v["batches"] = Value::Array(vec![good_batch, empty_batch]);

    let resp = response_from_value(&v).expect("both batches deserialize");
    assert_matches!(
        validate_returned(&resp, &matching_payload(), &cfg()),
        Err(ValidationMismatch::EmptyBurnIntents { batch: 1 })
    );
}

/// Control-flow proof for the empty-`burnIntents` hole: driven through the REAL signing flow, an
/// empty batch aborts and produces ZERO signatures — the token is never minted, so `sign` is never
/// reached.
#[test]
fn empty_burn_intents_aborts_the_signing_flow() {
    let mut v = base_200_json();
    v["batches"][0]["burnIntents"] = Value::Array(vec![]);
    let resp = response_from_value(&v).expect("an empty burnIntents[] still deserializes");
    assert_matches!(
        attempt_sign_flow(&resp, &matching_payload(), &cfg(), &a_key()),
        Err(ValidationMismatch::EmptyBurnIntents { batch: 0 })
    );
}

/// A present-but-malformed `messageHashToSign` — invalid hex, or the wrong byte length (31/33) — is
/// refused as `MalformedMessageHash`, BEFORE signing: a non-signable digest never reaches the
/// signer (`messageHashToSign` is an unconstrained external `String`, so these boundaries are real
/// risk).
#[test]
fn validate_returned_rejects_malformed_message_hash() {
    let valid = "0x90afceed0c2b4a6988a7c6e504234261809fbeddfc1b3a597897b6d5f4133251";
    assert_eq!(valid.len(), 66, "0x + 64 hex = 32 bytes");
    let not_hex = format!("0x{}", "g".repeat(64));
    let too_short = valid[..valid.len() - 2].to_string(); // 62 hex → 31 bytes
    let too_long = format!("{valid}00"); // 66 hex → 33 bytes

    for bad in [not_hex, too_short, too_long] {
        let mut v = base_200_json();
        v["batches"][0]["messageHashToSign"] = Value::from(bad.clone());
        let resp = response_from_value(&v).expect("a string hash still deserializes");
        assert_matches!(
            validate_returned(&resp, &matching_payload(), &cfg()),
            Err(ValidationMismatch::MalformedMessageHash { batch: 0, .. }),
            "a malformed hash `{bad}` must reject as MalformedMessageHash, not sign"
        );
    }
}

/// A mismatch injected in a LATER batch also rejects — forecloses "only `batches[0]` validated".
/// batch[0] matches; batch[1] carries a mismatched `value`.
#[test]
fn validate_returned_rejects_a_later_batch_mismatch() {
    let mut v = base_200_json();
    let good_batch = v["batches"][0].clone();
    let mut bad_batch = good_batch.clone();
    bad_batch["burnIntents"][0]["spec"]["value"] = Value::from("42");
    v["batches"] = Value::Array(vec![good_batch, bad_batch]);

    let resp = response_from_value(&v).expect("two well-formed batches deserialize");
    assert_eq!(resp.batches().len(), 2);

    assert_matches!(
        validate_returned(&resp, &matching_payload(), &cfg()),
        Err(ValidationMismatch::Amount { batch: 1, .. }),
        "the mismatch is in the SECOND batch — every batch must be checked"
    );
}

/// A truly-missing `messageHashToSign` cannot even form a `PrepareWithdrawalResponse` (the field is
/// required in the frozen schema) — so it is rejected at the parse boundary and can never reach
/// signing.
#[test]
fn missing_message_hash_fails_to_parse() {
    let parsed: Result<PrepareWithdrawalResponse, _> =
        serde_json::from_str(&support::fixture_text("prepare_withdrawal_missing_hash"));
    assert!(
        parsed.is_err(),
        "a response missing messageHashToSign must not deserialize (never signed)"
    );
}

/// A present-but-empty `messageHashToSign` parses (it is a `String`) but the gate rejects it: an
/// empty digest is not signable, so it is refused BEFORE signing rather than handed to the signer.
#[test]
fn validate_returned_rejects_empty_message_hash() {
    let mut v = base_200_json();
    v["batches"][0]["messageHashToSign"] = Value::from("");

    let resp = response_from_value(&v).expect("an empty-string hash still deserializes");
    assert_matches!(
        validate_returned(&resp, &matching_payload(), &cfg()),
        Err(ValidationMismatch::MissingMessageHash { batch: 0 })
    );
}

/// The optional local binary reconstruction is OFF the critical path (and deliberately not a
/// re-derivation): the gate validates against the JSON `spec` fields alone, so a garbage `encoded`
/// blob does NOT stop a full match — the partner never decodes it as the required path.
#[test]
fn validate_returned_does_not_depend_on_the_encoded_blob() {
    let mut v = base_200_json();
    v["batches"][0]["encoded"] = Value::from("0xdeadbeef");

    let resp = response_from_value(&v).expect("a short encoded blob still deserializes");
    assert!(
        validate_returned(&resp, &matching_payload(), &cfg()).is_ok(),
        "validation must succeed from the JSON spec fields alone (encoded is opaque, ASG-5)"
    );
}

/// The gate is deterministic: the same response + payload yields the same verdict every time — `Ok`
/// stays `Ok`, `Err` stays `Err` (the abort never "remembers" and passes on retry).
#[test]
fn validate_returned_is_deterministic() {
    let ok = response("prepare_withdrawal_200");
    assert!(validate_returned(&ok, &matching_payload(), &cfg()).is_ok());
    assert!(validate_returned(&ok, &matching_payload(), &cfg()).is_ok());

    let bad = response("prepare_withdrawal_validation_mismatch");
    assert_matches!(
        validate_returned(&bad, &matching_payload(), &cfg()),
        Err(ValidationMismatch::Amount { batch: 0, .. })
    );
    assert_matches!(
        validate_returned(&bad, &matching_payload(), &cfg()),
        Err(ValidationMismatch::Amount { batch: 0, .. })
    );
}

// ================================================================================================
// the DO-NOT-SIGN abort — validation gates signing — control-flow proof
// ================================================================================================

/// The withdrawal flow's ONLY signing entry: validate, then sign every cleared digest. `sign` is
/// reached ONLY inside the `Ok` branch — on a mismatch the `?` short-circuits before any signature
/// is produced. This is the executable enforcement that validation gates signing.
fn attempt_sign_flow(
    resp: &PrepareWithdrawalResponse,
    payload: &BurnPayload,
    cfg: &ListenerConfig,
    key: &SecretKey,
) -> Result<Vec<Signature65>, ValidationMismatch> {
    let validated = validate_returned(resp, payload, cfg)?;
    // Reachable ONLY with the proof-of-validation token above.
    Ok(sign_validated(&validated, key).expect("a cleared 32-byte digest signs"))
}

/// Positive control: on a full match the gate passes and signing IS reached — the baseline that
/// makes the abort meaningful. One signature is produced per validated batch.
#[test]
fn full_match_reaches_signing() {
    let resp = response("prepare_withdrawal_200");
    let sigs = attempt_sign_flow(&resp, &matching_payload(), &cfg(), &a_key())
        .expect("a full match must reach signing");
    assert_eq!(
        sigs.len(),
        1,
        "one signature over the one validated batch digest"
    );
}

/// The MANDATORY negative (non-vacuity oracle): the mismatch fixture is driven through the REAL
/// gate; the flow returns `Err` and produces ZERO signatures — `sign` is never reached.
#[test]
fn mismatch_aborts_and_produces_no_signature() {
    let resp = response("prepare_withdrawal_validation_mismatch");
    let result = attempt_sign_flow(&resp, &matching_payload(), &cfg(), &a_key());
    assert_matches!(
        result,
        Err(ValidationMismatch::Amount { batch: 0, .. }),
        "a mismatch must abort — no signature, no withdraw"
    );
}

/// Each mismatch class is a SEPARATE abort case — amount, destinationDomain, destinationRecipient,
/// and an empty messageHashToSign each abort with no signature produced.
#[rstest]
#[case::amount("value", Value::from("1"), is_amount)]
#[case::domain("destinationDomain", Value::from(7), is_domain)]
#[case::recipient(
    "destinationRecipient",
    Value::from("0x00000000000000000000000000000000000000000000000000000000deadbeef"),
    is_recipient
)]
fn each_spec_mismatch_class_aborts(
    #[case] field: &str,
    #[case] bad: Value,
    #[case] is_expected: fn(&ValidationMismatch) -> bool,
) {
    let mut v = base_200_json();
    v["batches"][0]["burnIntents"][0]["spec"][field] = bad;

    let resp = response_from_value(&v).expect("a single-field edit still deserializes");
    let err = attempt_sign_flow(&resp, &matching_payload(), &cfg(), &a_key())
        .expect_err("each mismatch class must abort with no signature");
    assert!(
        is_expected(&err),
        "the abort must pin the field-specific variant, got {err:?}"
    );
}

fn is_amount(e: &ValidationMismatch) -> bool {
    matches!(e, ValidationMismatch::Amount { batch: 0, .. })
}
fn is_domain(e: &ValidationMismatch) -> bool {
    matches!(e, ValidationMismatch::DestinationDomain { batch: 0, .. })
}
fn is_recipient(e: &ValidationMismatch) -> bool {
    matches!(e, ValidationMismatch::DestinationRecipient { batch: 0, .. })
}

/// The empty-hash class also aborts through the flow (no signature produced).
#[test]
fn empty_message_hash_class_aborts() {
    let mut v = base_200_json();
    v["batches"][0]["messageHashToSign"] = Value::from("");

    let resp = response_from_value(&v).expect("an empty hash still deserializes");
    assert_matches!(
        attempt_sign_flow(&resp, &matching_payload(), &cfg(), &a_key()),
        Err(ValidationMismatch::MissingMessageHash { .. })
    );
}

/// Idempotent abort: re-running the aborted flow with the SAME mismatching response aborts again —
/// the listener never "remembers" a prior verdict and signs on retry.
#[test]
fn abort_is_idempotent_on_retry() {
    let resp = response("prepare_withdrawal_validation_mismatch");
    let payload = matching_payload();
    let key = a_key();

    for _ in 0..3 {
        assert_matches!(
            attempt_sign_flow(&resp, &payload, &cfg(), &key),
            Err(ValidationMismatch::Amount { batch: 0, .. }),
            "every retry of the same mismatch aborts — no remembered pass"
        );
    }
}

// ================================================================================================
// DISCOVERY — validate_discovery (order load-bearing)
// ================================================================================================

/// Builds a public discovery record whose items decode to `payload` and whose sender is a genuine
/// account id (the config's faucet id, reused as a valid, canonical id).
fn public_record(tag: u32, payload: &BurnPayload) -> DiscoveryRecord {
    let items: Vec<Felt> = payload.encode();
    let faucet_id = ListenerConfig::default().faucet_id();
    let (prefix, suffix) = (faucet_id.prefix().as_felt(), faucet_id.suffix());
    DiscoveryRecord::new(
        tag,
        Some(DiscoveredDetails::from_raw_sender(items, prefix, suffix)),
    )
}

/// Positive: a public note whose tag matches exactly and whose payload + sender decode yields the
/// decoded burn and its depositor.
#[test]
fn discovery_ok_on_matching_public_note() {
    let payload = matching_payload();
    let record = public_record(cfg().burn_tag(), &payload);

    let discovered = validate_discovery(&record, &cfg()).expect("a matching public note validates");
    assert_eq!(discovered.payload(), &payload);
}

/// A PRIVATE note (`details = None`) is rejected as unobservable — the exact
/// `PrivateNoteUnobservable` variant.
#[test]
fn discovery_rejects_a_private_note() {
    let record = DiscoveryRecord::new(cfg().burn_tag(), None);
    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::PrivateNoteUnobservable)
    );
}

/// A wrong tag is rejected — tag matching is exact full-32-bit equality.
#[test]
fn discovery_rejects_a_wrong_tag() {
    let cfg = ListenerConfig::builder()
        .burn_tag(0xAABB_CCDD)
        .build()
        .unwrap();
    let record = public_record(0x1234_5678, &matching_payload());
    assert_matches!(
        validate_discovery(&record, &cfg),
        Err(DiscoveryReject::TagMismatch { .. })
    );
}

/// A tag sharing the configured tag's 16-bit PREFIX but differing in the low bits still rejects:
/// `SyncNotes` matches the FULL 32 bits, never a prefix (an exact match, never a prefix).
#[test]
fn discovery_rejects_a_prefix_only_tag_match() {
    let cfg = ListenerConfig::builder()
        .burn_tag(0xAABB_CCDD)
        .build()
        .unwrap();
    // Same high 16 bits (0xAABB), different low 16 — a prefix scan would wrongly accept this.
    let record = public_record(0xAABB_0000, &matching_payload());
    assert_matches!(
        validate_discovery(&record, &cfg),
        Err(DiscoveryReject::TagMismatch { .. }),
        "a 16-bit prefix match must NOT be accepted (full-32-bit equality)"
    );
}

/// Malformed `NoteStorage.items` (wrong felt count) is rejected — the shared encoding crate's
/// codec's verdict, carried through unflattened.
#[test]
fn discovery_rejects_malformed_items() {
    let faucet_id = ListenerConfig::default().faucet_id();
    let (prefix, suffix) = (faucet_id.prefix().as_felt(), faucet_id.suffix());
    // 17 felts, not the required 18.
    let items = vec![Felt::from(0u32); 17];
    let record = DiscoveryRecord::new(
        cfg().burn_tag(),
        Some(DiscoveredDetails::from_raw_sender(items, prefix, suffix)),
    );
    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::Decode(
            DecodeError::BurnItemsMalformed { .. }
        ))
    );
}

/// A zero sender is refused, never promoted to a zero `remoteDepositor`
/// (the sender is the exposed depositor; a zero there would attribute the burn to nobody).
#[test]
fn discovery_rejects_a_zero_sender() {
    let items = matching_payload().encode();
    let record = DiscoveryRecord::new(
        cfg().burn_tag(),
        Some(DiscoveredDetails::from_raw_sender(
            items,
            Felt::from(0u32),
            Felt::from(0u32),
        )),
    );
    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::Decode(DecodeError::SenderZero))
    );
}
