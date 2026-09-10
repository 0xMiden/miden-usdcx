//! Serde round-trip of every fixture against Circle's documented wire shapes — and the divergent
//! shapes that MUST fail.
//!
//! The round-trip is `fixture JSON → typed struct → JSON`, compared as `serde_json::Value`. That
//! comparison is what makes the test non-vacuous in both directions at once: a **missing** field in
//! the struct drops a key on the way back out, and an **invented** field adds one. Either way the
//! re-serialized value stops equalling the fixture, and the test fails. A
//! `from_str::<T>(…).is_ok()` check would have caught neither.
//!
//! Every rejection pins the exact serde error — `Category::Data` (a shape/type violation, not a
//! syntax error) plus the field serde names in its message. `is_err()` alone would pass on a typo
//! in the fixture path.
//!
//! The forbidden implementations this file forecloses (each has a named test):
//!
//! * a **flattened bare batch** — the top-level `{batches: [...]}` wrapper dropped from the prepare
//!   request/response or the withdraw request;
//! * the **withdraw response modelled as an object** — it is an ARRAY, one status per submitted batch;
//! * a **`sourceDepositor` field on `PrepareBurnIntentInput`** — Circle fills that server-side; the
//!   partner never sends it.

use assert_matches::assert_matches;
use serde_json::{json, Value};
use withdrawal_listener_attester::circle::schema::{
    BurnIntent, ForwardingOptions, PrepareBurnIntentInput, PrepareWithdrawalRequest,
    PrepareWithdrawalResponse, WithdrawBatch, WithdrawRequest, WithdrawSubmissionResponse,
    WithdrawalStatus, WithdrawalStatusKind,
};
use withdrawal_listener_attester::circle::wire::{DecimalAmount, ForwardingFee, Hex32, HexBytes};

#[path = "support/mod.rs"]
mod support;

use support::{fixture_json, fixture_text, walk_keys};

/// `fixture → T → JSON` must reproduce the fixture EXACTLY. Returns the decoded value so a caller
/// can go on to assert on its contents.
fn round_trip<T>(stem: &str) -> T
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let raw = fixture_json(stem);
    let decoded: T = serde_json::from_str(&fixture_text(stem))
        .unwrap_or_else(|e| panic!("{stem}.json failed to decode into the wire type: {e}"));
    let reserialized = serde_json::to_value(&decoded)
        .unwrap_or_else(|e| panic!("{stem} failed to re-serialize: {e}"));

    assert_eq!(
        raw, reserialized,
        "{stem}.json did not survive the round-trip: the struct dropped or invented a field"
    );

    decoded
}

/// A decode that must fail, with the exact serde error class pinned — and the text serde produced,
/// for the caller to assert the offending field by name.
fn reject<T: serde::de::DeserializeOwned>(source: &str, what: &str) -> String {
    let error = serde_json::from_str::<T>(source)
        .err()
        .unwrap_or_else(|| panic!("{what}: the divergent shape DECODED — the suite cannot fail"));

    assert_eq!(
        error.classify(),
        serde_json::error::Category::Data,
        "{what}: expected a data/shape rejection, got {:?} ({error})",
        error.classify()
    );

    error.to_string()
}

// HAPPY PATH — the three schema-exact 200/201 fixtures
// ================================================================================================

#[test]
fn prepare_withdrawal_200_round_trips_through_the_batches_wrapper() {
    let response: PrepareWithdrawalResponse = round_trip("prepare_withdrawal_200");

    assert_eq!(response.batches().len(), 1);
    let batch = &response.batches()[0];
    assert_eq!(batch.burn_intents().len(), 1);
    assert!(batch.encoded().starts_with("0x"));
    assert!(batch.message_hash_to_sign().starts_with("0x"));

    // the intent's spec is the JSON TransferSpec — 14 required fields, hookData a structured OBJECT
    // (never a hex bytes string: the binary WithdrawHookData is a different representation entirely)
    let spec = batch.burn_intents()[0].spec();
    assert_eq!(spec.version(), 1);
    assert_eq!(spec.value(), "9999000");
    assert_eq!(spec.destination_domain(), 0);
    assert_eq!(spec.hook_data().forwarding_calldata(), "0x");
}

#[test]
fn withdraw_201_round_trips_as_an_array_of_statuses() {
    let response: WithdrawSubmissionResponse = round_trip("withdraw_201");

    // ONE status per submitted batch — the response is a bare ARRAY, and the type is a Vec alias
    assert_eq!(response.len(), 1);
    assert_eq!(response[0].status(), WithdrawalStatusKind::Created);
    assert!(response[0].failure_reason().is_none());
    assert_eq!(response[0].transfer_spec_hashes().len(), 1);
}

#[test]
fn withdrawal_status_200_round_trips_as_the_same_object_withdraw_returns() {
    let status: WithdrawalStatus = round_trip("withdrawal_status_200");

    assert_eq!(status.status(), WithdrawalStatusKind::Finalized);
    assert!(status.status().is_terminal());
    assert!(status.transaction_hash().is_some());
    assert!(status.attestation().is_some());
}

// ERROR / MALFORMED FIXTURES
// ================================================================================================

#[test]
fn withdraw_failed_status_round_trips_with_its_failure_reason_and_no_transaction_hash() {
    let response: WithdrawSubmissionResponse = round_trip("withdraw_failed_status");

    let status = &response[0];
    assert_eq!(status.status(), WithdrawalStatusKind::Failed);
    assert!(status.status().is_terminal());
    assert!(
        !status.status().is_retryable(),
        "`failed` is terminal and NOT retryable — only `expired` is"
    );
    // failureReason is the conditional field, present exactly when the status is `failed`
    assert_eq!(status.failure_reason(), Some("verification_failed"));
    // and a failed withdrawal forwarded nothing, so there is no transaction hash to carry
    assert!(status.transaction_hash().is_none());
}

#[test]
fn a_validation_mismatch_is_a_well_formed_200_that_only_semantics_can_catch() {
    // The point of this fixture: it is SCHEMA-VALID. It decodes cleanly, which is exactly why the
    // field-by-field compare against the burn-note payload must exist — serde
    // cannot see that the value/domain/recipient are the wrong ones.
    let response: PrepareWithdrawalResponse = round_trip("prepare_withdrawal_validation_mismatch");

    let spec = response.batches()[0].burn_intents()[0].spec();
    assert_eq!(spec.value(), "99000000", "not the burned amount");
    assert_eq!(
        spec.destination_domain(),
        7,
        "not the burn note's destDomain"
    );
}

#[test]
fn a_200_missing_message_hash_to_sign_is_rejected_by_name() {
    let message = reject::<PrepareWithdrawalResponse>(
        &fixture_text("prepare_withdrawal_missing_hash"),
        "prepare_withdrawal_missing_hash",
    );

    assert!(
        message.contains("messageHashToSign"),
        "the rejection must name the missing field; got: {message}"
    );
}

#[test]
fn a_malformed_body_never_decodes_as_a_withdrawal_status() {
    // The fixture violates the schema three ways at once (snake_case key, off-enum status, 63-hex
    // hash). Serde reports the first one it MEETS, in document order — the off-enum `status`, since
    // the unknown `withdrawal_id` key is ignored on a response type (responses do not
    // `deny_unknown_fields`: Circle may add a field, and refusing to decode a withdrawal because it
    // grew one would strand real money).
    let message = reject::<WithdrawalStatus>(
        &fixture_text("malformed_body"),
        "malformed_body as a status",
    );

    assert!(
        message.contains("unknown variant") && message.contains("finalised"),
        "the rejection must name the off-enum status; got: {message}"
    );
}

#[test]
fn a_snake_case_key_does_not_satisfy_a_camel_case_required_field() {
    // The other half of `malformed_body`, isolated: with the off-enum status repaired, the snake_case
    // `withdrawal_id` still fails to supply the required camelCase `withdrawalId` — it is ignored as
    // an unknown key, and the required field is then missing. A wire type that tolerated snake_case
    // would silently accept a body Circle never sends.
    let mut body = fixture_json("malformed_body");
    body["status"] = json!("finalized");
    body["transferSpecHashes"] = json!([format!("0x{}", "ab".repeat(32))]);

    let message = reject::<WithdrawalStatus>(&body.to_string(), "a snake_case withdrawal_id");
    assert!(
        message.contains("withdrawalId"),
        "the rejection must name the field the body failed to supply; got: {message}"
    );
}

#[test]
fn an_off_enum_status_is_rejected_and_the_six_documented_ones_are_not() {
    // `finalised` (the en-GB spelling) is NOT in the enum. Accepting it would let a status the
    // service cannot reason about flow into the terminal-state logic.
    let message = reject::<WithdrawalStatusKind>(r#""finalised""#, "an off-enum status");
    assert!(
        message.contains("unknown variant"),
        "expected an unknown-variant rejection; got: {message}"
    );

    for (wire, expected) in [
        ("created", WithdrawalStatusKind::Created),
        ("verified", WithdrawalStatusKind::Verified),
        ("confirmed", WithdrawalStatusKind::Confirmed),
        ("finalized", WithdrawalStatusKind::Finalized),
        ("expired", WithdrawalStatusKind::Expired),
        ("failed", WithdrawalStatusKind::Failed),
    ] {
        let decoded: WithdrawalStatusKind =
            serde_json::from_str(&format!("\"{wire}\"")).expect("a documented status must decode");
        assert_eq!(decoded, expected, "status `{wire}`");
        // and it must go back out under the SAME wire spelling
        assert_eq!(serde_json::to_value(decoded).unwrap(), json!(wire));
    }
}

#[test]
fn the_terminal_and_retryable_status_partitions_match_the_documented_contract() {
    // Only `finalized`/`failed` are TERMINAL — polling stops there
    // (TEST-AND-VERIFICATION-HARNESS.md:191-195). `expired` is NOT terminal: it is a RETRYABLE
    // (resubmit) outcome, never a completed withdrawal, so treating it as terminal would strand a
    // recoverable withdrawal as though it were done.
    for kind in [
        WithdrawalStatusKind::Finalized,
        WithdrawalStatusKind::Failed,
    ] {
        assert!(kind.is_terminal(), "{kind:?} is a terminal completion");
    }
    for kind in [
        WithdrawalStatusKind::Created,
        WithdrawalStatusKind::Verified,
        WithdrawalStatusKind::Confirmed,
        WithdrawalStatusKind::Expired,
    ] {
        assert!(!kind.is_terminal(), "{kind:?} is NOT a terminal completion");
    }

    // `expired` is the only retryable status; it is retryable AND non-terminal.
    assert!(WithdrawalStatusKind::Expired.is_retryable());
    assert!(
        !WithdrawalStatusKind::Expired.is_terminal(),
        "expired is retryable, never terminal — the round-1 forbidden-impl"
    );
    assert!(!WithdrawalStatusKind::Failed.is_retryable());
}

// The threshold-violating fixture no longer ROUND-TRIPS: `burnSignatures: minItems 2` is a schema
// rule, so a batch carrying one signature is now refused at the wire (it is a body Circle would
// reject). Its decode-rejection, and the fact that its descending/duplicate ORDERING variants still
// decode verbatim so the quorum assembler can catch them, are pinned in `schema_constraints.rs`.

#[test]
fn an_error_body_never_decodes_as_the_endpoints_success_shape() {
    // The OpenAPI documents no error-body schema, so this crate declares no error type — what it DOES
    // guarantee is that an error body can never be mistaken for a success. Each of these would be a
    // silently-empty success if the success types were permissive.
    for stem in [
        "prepare_withdrawal_400",
        "prepare_withdrawal_missing_hash",
        "malformed_body",
    ] {
        reject::<PrepareWithdrawalResponse>(&fixture_text(stem), stem);
    }
    for stem in ["withdraw_400", "withdraw_409", "withdraw_500"] {
        reject::<WithdrawSubmissionResponse>(&fixture_text(stem), stem);
    }
    reject::<WithdrawalStatus>(
        &fixture_text("withdrawal_status_404"),
        "withdrawal_status_404",
    );
}

#[test]
fn the_409_conflict_body_carries_the_two_recovery_hints_as_raw_json() {
    // Circle's documentation: a 409 is a duplicate CONFLICT requiring recovery, never a success. The body is read as
    // raw JSON deliberately — declaring a typed Circle error struct would be declaring a schema
    // Circle has not published.
    let conflict = fixture_json("withdraw_409");

    assert!(conflict.get("withdrawalId").is_some_and(Value::is_string));
    assert!(conflict.get("burnTxId").is_some_and(Value::is_string));
    // and it is emphatically NOT a WithdrawalStatus: there is no `status` to report success from
    assert!(conflict.get("status").is_none());
}

// THE NON-VACUITY ORACLE — divergent shapes that MUST fail
// ================================================================================================

#[test]
fn a_flattened_bare_batch_is_not_a_prepare_withdrawal_response() {
    // FORBIDDEN IMPL: dropping the top-level `batches[]` wrapper. Feed the response type the bare
    // inner batch — the exact shape a "simplified" implementation would model.
    let bare_batch = fixture_json("prepare_withdrawal_200")["batches"][0].clone();
    let message = reject::<PrepareWithdrawalResponse>(
        &bare_batch.to_string(),
        "a bare PreparedBatch as a PrepareWithdrawalResponse",
    );

    assert!(
        message.contains("batches"),
        "the rejection must name the missing wrapper; got: {message}"
    );
}

#[test]
fn a_flattened_bare_batch_is_not_a_prepare_withdrawal_request() {
    // The same forbidden shape on the REQUEST side: a bare PrepareBurnIntentInput, unwrapped.
    let bare = serde_json::to_string(&sample_burn_intent_input()).unwrap();
    let message = reject::<PrepareWithdrawalRequest>(
        &bare,
        "a bare PrepareBurnIntentInput as a PrepareWithdrawalRequest",
    );

    assert!(message.contains("batches"), "got: {message}");
}

#[test]
fn a_flattened_bare_batch_is_not_a_withdraw_request() {
    // batch 1 is schema-valid (two signatures), so the ONLY thing wrong here is the missing wrapper
    let bare = fixture_json("withdraw_threshold_violating_sigs")["batches"][1].clone();
    let message = reject::<WithdrawRequest>(
        &bare.to_string(),
        "a bare WithdrawBatch as a WithdrawRequest",
    );

    assert!(message.contains("batches"), "got: {message}");
}

#[test]
fn the_withdraw_response_modelled_as_an_object_is_not_the_withdraw_response() {
    // FORBIDDEN IMPL: modelling `POST /v1/withdraw` as an object. The response is an ARRAY — one
    // status per submitted batch — so an object where the array belongs must be refused.
    let as_object = fixture_json("withdraw_201")[0].clone();
    let message = reject::<WithdrawSubmissionResponse>(
        &as_object.to_string(),
        "a single status object as the withdraw response",
    );

    assert!(
        message.contains("invalid type: map") || message.contains("expected a sequence"),
        "expected a map-where-sequence-belongs rejection; got: {message}"
    );

    // …and, symmetrically, the ARRAY must not decode as a single status either
    reject::<WithdrawalStatus>(
        &fixture_text("withdraw_201"),
        "the withdraw ARRAY as a single status",
    );
}

// sourceDepositor — ABSENT FROM THE REQUEST, PRESENT IN CIRCLE'S RESPONSE
// ================================================================================================

/// The request input the listener builds from a burn note: `remoteDepositor` = the Miden burner.
fn sample_burn_intent_input() -> PrepareBurnIntentInput {
    PrepareBurnIntentInput::builder()
        .value_excluding_fees(DecimalAmount::new("10.00").unwrap())
        .remote_domain(10001)
        .remote_depositor(
            Hex32::new("0x".to_string() + &"00".repeat(16) + "9a1b2c3d4e5f60718899aabbccdd0011")
                .unwrap(),
        )
        .final_destination_domain(0)
        .final_destination_recipient(
            Hex32::new(
                "0x".to_string() + &"00".repeat(12) + "742d35cc6634c0532925a3b844bc454e4438f44e",
            )
            .unwrap(),
        )
        .use_circle_forwarding(false)
        .build()
        .expect("the sample input satisfies every documented constraint")
}

#[test]
fn the_prepare_request_serializes_with_no_source_depositor_key_at_any_depth() {
    // FORBIDDEN IMPL: a `sourceDepositor` on PrepareBurnIntentInput. Circle assigns it server-side;
    // the partner sends `remoteDepositor` and NEVER `sourceDepositor`.
    // Swapping the two would hand Circle the wrong debtor.
    let request = PrepareWithdrawalRequest::new(vec![sample_burn_intent_input()]);
    let json = serde_json::to_value(&request).unwrap();

    let mut found = Vec::new();
    walk_keys(&json, &mut |key, _| {
        if key == "sourceDepositor" {
            found.push(key.to_string());
        }
    });
    assert!(
        found.is_empty(),
        "the partner-built request must carry no sourceDepositor at any depth; found {found:?}"
    );

    // it DOES carry remoteDepositor, under the top-level batches[] wrapper
    assert!(json.get("batches").is_some_and(Value::is_array));
    assert!(json["batches"][0].get("remoteDepositor").is_some());
}

#[test]
fn a_request_carrying_a_source_depositor_is_refused_rather_than_silently_ignored() {
    // Serde's default would DROP an unknown key. Then a caller who set `sourceDepositor` believing it
    // meaningful would ship a request that silently lacked it. The request types deny unknown fields,
    // so the mistake surfaces at the boundary.
    let mut input = serde_json::to_value(sample_burn_intent_input()).unwrap();
    input["sourceDepositor"] = json!("0x".to_string() + &"11".repeat(32));

    let message = reject::<PrepareBurnIntentInput>(
        &input.to_string(),
        "a PrepareBurnIntentInput carrying sourceDepositor",
    );
    assert!(
        message.contains("sourceDepositor") && message.contains("unknown field"),
        "expected an unknown-field rejection naming sourceDepositor; got: {message}"
    );
}

#[test]
fn circles_returned_transfer_spec_does_carry_the_source_depositor_it_assigned() {
    // The other half of the distinction: `sourceDepositor` is a real TransferSpec field — Circle
    // fills it and returns it. Modelling the RESPONSE without it would drop it on the round-trip.
    let response: PrepareWithdrawalResponse = round_trip("prepare_withdrawal_200");
    let spec = response.batches()[0].burn_intents()[0].spec();

    assert!(spec.source_depositor().starts_with("0x"));
    assert_ne!(
        spec.source_depositor(),
        spec.destination_recipient(),
        "distinct fields, distinct roles"
    );
}

// THE XOR AMOUNT PAIR + THE OPTIONAL FIELDS
// ================================================================================================

#[test]
fn the_optional_request_fields_are_omitted_from_the_wire_not_sent_as_null() {
    // `valueExcludingFees` XOR `valueIncludingFees`, and salt/finalDestinationCaller/forwardingOptions
    // are optional. A `null` is NOT an omission: the OpenAPI marks these absent-or-present, and a
    // schema validator rejects `"salt": null` against `^0x[a-fA-F0-9]{64}$`.
    let input = sample_burn_intent_input();
    let json = serde_json::to_value(&input).unwrap();

    assert_eq!(json.get("valueExcludingFees"), Some(&json!("10.00")));
    for omitted in [
        "valueIncludingFees",
        "salt",
        "finalDestinationCaller",
        "forwardingOptions",
    ] {
        assert!(
            json.get(omitted).is_none(),
            "`{omitted}` was not set, so it must not appear on the wire — not even as null"
        );
    }

    // token defaults to the one enum member the schema allows
    assert_eq!(json.get("token"), Some(&json!("USDC")));
}

#[test]
fn a_fully_populated_request_round_trips_every_optional_field() {
    let input = PrepareBurnIntentInput::builder()
        .value_including_fees(DecimalAmount::new("10.50").unwrap())
        .remote_domain(10001)
        .remote_depositor(Hex32::new("0x".to_string() + &"aa".repeat(32)).unwrap())
        .final_destination_domain(0)
        .final_destination_recipient(Hex32::new("0x".to_string() + &"bb".repeat(32)).unwrap())
        .final_destination_caller(Hex32::new("0x".to_string() + &"cc".repeat(32)).unwrap())
        .salt(Hex32::new("0x".to_string() + &"dd".repeat(32)).unwrap())
        .use_circle_forwarding(true)
        .forwarding_options(ForwardingOptions::new(
            Some(ForwardingFee::new("0.500000").unwrap()),
            Some(HexBytes::new("0xdeadbeef").unwrap()),
            Some(true),
        ))
        .build()
        .expect("every field satisfies its documented pattern");

    let json = serde_json::to_value(&input).unwrap();
    let decoded: PrepareBurnIntentInput = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), json);

    assert_eq!(decoded.value_including_fees(), Some("10.50"));
    assert!(decoded.value_excluding_fees().is_none());
    assert_matches!(decoded.forwarding_options(), Some(opts) if opts.uses_fast_finality() == Some(true));
}

// THE WITHDRAW BATCH — cardinality is carried, not silently clamped
// ================================================================================================

#[test]
fn a_withdraw_batch_carries_its_intents_and_signatures_verbatim() {
    let intent: BurnIntent = serde_json::from_value(
        fixture_json("prepare_withdrawal_200")["batches"][0]["burnIntents"][0].clone(),
    )
    .expect("the fixture's burn intent must decode");

    let batch = WithdrawBatch::new(
        vec![intent],
        vec![
            HexBytes::new("0x".to_string() + &"01".repeat(65)).unwrap(),
            HexBytes::new("0x".to_string() + &"02".repeat(65)).unwrap(),
        ],
        "0x".to_string() + &"03".repeat(32),
        false,
    )
    .expect("two signatures meets the documented minItems-2 threshold");
    let request = WithdrawRequest::new(vec![batch]).expect("one batch is within 1..=5");

    let json = serde_json::to_value(&request).unwrap();
    // the top-level wrapper, again — not a bare batch
    assert!(json.get("batches").is_some_and(Value::is_array));
    assert_eq!(
        json["batches"][0]["burnSignatures"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // and it survives the trip back
    let decoded: WithdrawRequest = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), json);
}
