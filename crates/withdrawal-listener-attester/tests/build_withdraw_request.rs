//! Builds the `POST /v1/withdraw` [`WithdrawRequest`] wrapper.
//!
//! The builder wraps `WithdrawBatch[]` in the top-level `{ batches: [..] }` (never a bare array or
//! a bare batch) and enforces the schema's `minItems 1` / `maxItems 5` on the batch list. The inner
//! `burnIntents` `1..=10` bound is the `WithdrawBatch` constructor's, exercised here so the
//! "batches/ intents bounds ignored" forbidden impl is foreclosed at both levels. Every
//! out-of-range case pins the exact [`SchemaError`] variant.

use assert_matches::assert_matches;
use serde_json::Value;

use withdrawal_listener_attester::circle::schema::{BurnIntent, WithdrawBatch, WithdrawRequest};
use withdrawal_listener_attester::circle::wire::{HexBytes, SchemaError};
use withdrawal_listener_attester::withdrawal_api::build_withdraw_request;

#[path = "support/mod.rs"]
mod support;

// ================================================================================================
// FIXTURES
// ================================================================================================

/// The `burnIntents` array Circle returned in the 200 fixture — the canonical intents a submission
/// carries verbatim.
fn burn_intents_value() -> Value {
    let prepared = support::fixture_json("prepare_withdrawal_200");
    prepared["batches"][0]["burnIntents"].clone()
}

/// A `Vec<BurnIntent>` of the given length, cloned from the fixture's single canonical intent.
fn burn_intents(n: usize) -> Vec<BurnIntent> {
    let one: Vec<BurnIntent> =
        serde_json::from_value(burn_intents_value()).expect("the fixture burnIntents deserialize");
    let template = one[0].clone();
    std::iter::repeat_with(|| template.clone())
        .take(n)
        .collect()
}

/// Two well-formed 65-byte signatures — enough to clear the schema's `minItems 2`.
fn two_signatures() -> Vec<HexBytes> {
    vec![
        HexBytes::new(format!("0x{}", "11".repeat(65))).unwrap(),
        HexBytes::new(format!("0x{}", "22".repeat(65))).unwrap(),
    ]
}

/// A schema-valid batch (1 intent, 2 signatures) — the unit `build_withdraw_request` wraps.
fn a_batch() -> WithdrawBatch {
    WithdrawBatch::new(
        burn_intents(1),
        two_signatures(),
        "0xburn_tx_evidence".to_string(),
        false,
    )
    .expect("a 1-intent, 2-signature batch is valid")
}

// ================================================================================================
// HAPPY PATH — the top-level batches[] wrapper, 1..=5
// ================================================================================================

#[test]
fn builds_a_single_batch_request() {
    let request = build_withdraw_request(vec![a_batch()]).expect("one batch is in range");
    assert_eq!(request.batches().len(), 1);
}

#[test]
fn builds_the_maximum_five_batches() {
    let batches: Vec<WithdrawBatch> = (0..5).map(|_| a_batch()).collect();
    let request = build_withdraw_request(batches).expect("five batches is the maximum");
    assert_eq!(request.batches().len(), 5);
}

/// The serialized body is the top-level `{ "batches": [...] }` OBJECT — never a bare array.
/// Flattening the wrapper is the classic simplification that produces a body Circle rejects.
#[test]
fn serialized_request_is_the_batches_wrapper_not_a_bare_array() {
    let request = build_withdraw_request(vec![a_batch()]).unwrap();
    let value: Value = serde_json::to_value(&request).expect("serializes");

    assert!(value.is_object(), "the body is an object, not a bare array");
    assert!(
        value.get("batches").is_some_and(Value::is_array),
        "with a top-level `batches` array: {value}"
    );
    // and it round-trips back to an equal request.
    let back: WithdrawRequest = serde_json::from_value(value).expect("round-trips");
    assert_eq!(back, request);
}

// ================================================================================================
// BATCH-COUNT BOUNDS — exact SchemaError
// ================================================================================================

#[test]
fn rejects_zero_batches() {
    let result = build_withdraw_request(Vec::new());
    assert_matches!(result, Err(SchemaError::BatchCountOutOfRange(0)));
}

#[test]
fn rejects_six_batches() {
    let batches: Vec<WithdrawBatch> = (0..6).map(|_| a_batch()).collect();
    let result = build_withdraw_request(batches);
    assert_matches!(result, Err(SchemaError::BatchCountOutOfRange(6)));
}

// ================================================================================================
// INNER burnIntents BOUNDS — the WithdrawBatch constructor's 1..=10 (foreclosed at both levels)
// ================================================================================================

#[test]
fn batch_rejects_zero_burn_intents() {
    let result = WithdrawBatch::new(
        burn_intents(0),
        two_signatures(),
        "0xburn_tx_evidence".to_string(),
        false,
    );
    assert_matches!(result, Err(SchemaError::BurnIntentCountOutOfRange(0)));
}

#[test]
fn batch_rejects_eleven_burn_intents() {
    let result = WithdrawBatch::new(
        burn_intents(11),
        two_signatures(),
        "0xburn_tx_evidence".to_string(),
        false,
    );
    assert_matches!(result, Err(SchemaError::BurnIntentCountOutOfRange(11)));
}

/// A batch at the inner maximum (10 intents) is accepted, and it wraps.
#[test]
fn batch_accepts_ten_burn_intents() {
    let batch = WithdrawBatch::new(
        burn_intents(10),
        two_signatures(),
        "0xburn_tx_evidence".to_string(),
        false,
    )
    .expect("ten intents is the inner maximum");
    let request = build_withdraw_request(vec![batch]).expect("wraps");
    assert_eq!(request.batches()[0].burn_intents().len(), 10);
}

/// Guard the fixture the whole file leans on: its `burnIntents` array is non-empty, so
/// `burn_intents` has a template to clone.
#[test]
fn fixture_burn_intents_are_nonempty() {
    let v = burn_intents_value();
    assert!(
        v.as_array().is_some_and(|a| !a.is_empty()),
        "the 200 fixture must carry at least one burn intent to clone"
    );
}
