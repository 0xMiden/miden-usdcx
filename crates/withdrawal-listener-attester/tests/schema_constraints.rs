//! The OpenAPI's own constraints, enforced at the wire boundary — one isolated negative per rule.
//!
//! Typing every constrained field as a bare `String`/`u32` would make the structs check JSON
//! *shape* and nothing else: a `token` of `"DAI"`, a `remoteDomain` of `0`, both fee fields at
//! once, a 31-byte `transferSpecHash` — all would decode happily. This file is the executable
//! statement that they do not.
//!
//! **Where the line sits.** A constraint the OpenAPI *documents* — a regex, an enum, a `minimum`, a
//! `minItems`, the value XOR — is a **schema** property, and a body violating it is one Circle will
//! reject (outbound) or one the listener must refuse to act on (inbound, Circle's documentation
//! "malformed Circle response → reject, not signed"). Those are enforced here, at decode. A
//! constraint the OpenAPI does NOT document is not invented: `encoded`, `messageHashToSign` and the
//! *request-side* `burnTxId` are typed `string` with no pattern, so they stay `String`.
//!
//! What is emphatically NOT here is *semantic* validation — "does this burn intent match the burn
//! note's amount/domain/recipient". That is the pre-signing gate's job, and
//! `prepare_withdrawal_validation_mismatch.json` is schema-valid precisely so that the mismatch
//! must be caught there rather than here.
//!
//! Every rejection pins the exact [`SchemaError`] variant, never `is_err()`.

use assert_matches::assert_matches;
use rstest::rstest;
use serde_json::{json, Value};
use withdrawal_listener_attester::circle::schema::{
    PrepareBurnIntentInput, PrepareWithdrawalResponse, WithdrawBatch, WithdrawRequest,
    WithdrawalStatus,
};
use withdrawal_listener_attester::circle::wire::{
    Calldata, DecimalAmount, DecimalUint, ForwardingFee, Hex20, Hex32, HexBytes, HexTxId,
    SchemaError, Token, Uuid,
};

#[path = "support/mod.rs"]
mod support;

use support::{fixture_json, fixture_text};

fn hex(bytes: usize) -> String {
    format!("0x{}", "ab".repeat(bytes))
}

/// A decode that must fail, with the serde error class pinned. Returns the message so the caller
/// can assert WHICH rule bit.
fn reject<T: serde::de::DeserializeOwned>(source: &Value, what: &str) -> String {
    let error = serde_json::from_value::<T>(source.clone())
        .err()
        .unwrap_or_else(|| panic!("{what}: an OpenAPI-invalid body DECODED"));

    assert_eq!(
        error.classify(),
        serde_json::error::Category::Data,
        "{what}: expected a data/shape rejection, got {:?} ({error})",
        error.classify()
    );

    error.to_string()
}

// THE SCALAR PATTERNS — each newtype refuses exactly what its regex refuses,
// and every reject pins the EXACT SchemaError variant
// ================================================================================================
//
// The variant matters, not just the failure. A constructor that rejected the right inputs for the
// WRONG reason would still be a bug — and a suite that only asked `is_err()` would not notice: swap
// `BadDecimalAmount` for `BadUuid` in the decimal constructor and every such test stays green. So
// each reject below names the variant it expects, and carries the offending value with it.

#[rstest]
#[case::exact_64_lowercase(&hex(32))]
#[case::exact_64_uppercase("0xAB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12")]
fn hex32_accepts_the_32_byte_form(#[case] input: &str) {
    assert_eq!(
        Hex32::new(input).expect("a 32-byte hex string").as_str(),
        input
    );
}

#[rstest]
#[case::missing_0x_prefix("ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12")]
#[case::one_digit_short("0xab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab1")]
#[case::one_digit_long("0xab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12a")]
#[case::non_hex_digit("0xzz12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12")]
#[case::empty("")]
#[case::bare_prefix("0x")]
fn hex32_rejects_everything_else_as_bad_hex32(#[case] input: &str) {
    // `^0x[a-fA-F0-9]{64}$` — every identifier/hash field on the Circle wire.
    assert_matches!(Hex32::new(input), Err(SchemaError::BadHex32(v)) if v == input);
}

#[rstest]
#[case::exact_40(&hex(20))]
#[case::zero_address_40_digits("0x0000000000000000000000000000000000000000")]
fn hex20_accepts_the_json_forwarding_address(#[case] input: &str) {
    assert!(Hex20::new(input).is_ok(), "{input} must be accepted");
}

#[rstest]
// the OpenAPI's PROSE says "if you are not forwarding funds, set to 0x0" — but its REGEX is
// `^0x[a-fA-F0-9]{40}$`, which "0x0" does not match. Where the two disagree the regex is the schema,
// so the zero address is forty zero digits.
#[case::prose_form_0x0("0x0")]
// …and the 32-byte form is the BINARY WithdrawHookData.forwardingContract, a different
// representation entirely, which Circle's own schema documentation warns must not be conflated
// with this one. Accepting it here would be that conflation.
#[case::binary_32_byte_form(&hex(32))]
#[case::empty("")]
fn hex20_rejects_the_binary_form_and_the_prose_form_as_bad_hex20(#[case] input: &str) {
    assert_matches!(Hex20::new(input), Err(SchemaError::BadHex20(v)) if v == input);
}

#[rstest]
#[case::not_forwarding("0x")]
#[case::bare_selector("0x12345678")]
#[case::selector_plus_data("0x12345678aabbccdd")]
fn calldata_accepts_empty_or_a_selector_plus_optional_data(#[case] input: &str) {
    assert_eq!(
        Calldata::new(input).expect("valid calldata").as_str(),
        input
    );
}

#[rstest]
#[case::short_of_a_selector("0x1234")]
#[case::non_hex("0x1234567z")]
#[case::no_prefix("12345678")]
fn calldata_rejects_everything_else_as_bad_calldata(#[case] input: &str) {
    // `^0x([a-fA-F0-9]{8}[a-fA-F0-9]*)?$`
    assert_matches!(Calldata::new(input), Err(SchemaError::BadCalldata(v)) if v == input);
}

#[rstest]
#[case::zero("0")]
#[case::smallest_unit("10000000")]
fn decimal_uint_accepts_the_smallest_unit_form(#[case] input: &str) {
    assert_eq!(DecimalUint::new(input).expect("valid").as_str(), input);
}

#[rstest]
#[case::the_decimal_form("10.00")]
#[case::negative("-1")]
#[case::scientific("1e6")]
#[case::empty("")]
fn decimal_uint_rejects_everything_else_as_bad_decimal_uint(#[case] input: &str) {
    // `^\d+$` — `value`, `maxFee`, `maxBlockHeight`. A uint256 amount cannot be a JSON number, and it
    // is NOT the request's "10.00" decimal form: confusing the two is a 10^6 error in a money field.
    assert_matches!(DecimalUint::new(input), Err(SchemaError::BadDecimalUint(v)) if v == input);
}

#[rstest]
#[case::whole("10")]
#[case::two_places("10.00")]
#[case::many_places("10.123456789")]
fn decimal_amount_accepts_the_request_side_decimal_form(#[case] input: &str) {
    assert_eq!(DecimalAmount::new(input).expect("valid").as_str(), input);
}

#[rstest]
#[case::trailing_dot("10.")]
#[case::leading_dot(".5")]
#[case::not_a_number("abc")]
#[case::empty("")]
fn decimal_amount_rejects_everything_else_as_bad_decimal_amount(#[case] input: &str) {
    // `^\d+(\.\d+)?$` — valueExcludingFees / valueIncludingFees. The EXACT variant is pinned: a
    // constructor that rejected these as, say, `BadUuid` would be reporting nonsense to the operator.
    assert_matches!(
        DecimalAmount::new(input),
        Err(SchemaError::BadDecimalAmount(v)) if v == input
    );
}

#[rstest]
#[case::whole("10")]
#[case::six_places("0.500000")]
fn a_forwarding_fee_accepts_at_most_six_decimals(#[case] input: &str) {
    assert_eq!(ForwardingFee::new(input).expect("valid").as_str(), input);
}

#[rstest]
#[case::seven_places("0.5000001")]
#[case::no_places_after_dot("0.")]
#[case::not_a_number("abc")]
fn a_forwarding_fee_rejects_everything_else_as_bad_forwarding_fee(#[case] input: &str) {
    // `^\d+(\.\d{1,6})?$` — USDC has six decimals, so a seventh cannot be represented.
    assert_matches!(
        ForwardingFee::new(input),
        Err(SchemaError::BadForwardingFee(v)) if v == input
    );
}

#[test]
fn a_withdrawal_id_accepts_a_uuid() {
    let canonical = "6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8";
    assert_eq!(Uuid::new(canonical).expect("a uuid").as_str(), canonical);
}

#[rstest]
#[case::wrong_group_lengths("6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f")]
#[case::missing_hyphens("6f1a2b3c4d5e6f708192a3b4c5d6e7f8")]
#[case::not_hex("zzzzzzzz-4d5e-6f70-8192-a3b4c5d6e7f8")]
#[case::empty("")]
fn a_withdrawal_id_rejects_everything_else_as_bad_uuid(#[case] input: &str) {
    assert_matches!(Uuid::new(input), Err(SchemaError::BadUuid(v)) if v == input);
}

#[rstest]
#[case::empty_body("0x")]
#[case::a_signature(&hex(65))]
fn hex_bytes_accepts_an_unbounded_hex_string(#[case] input: &str) {
    // `^0x[a-fA-F0-9]*$` — burnSignatures[], attestation, attestationPayload. The EMPTY body is legal.
    assert_eq!(HexBytes::new(input).expect("valid").as_str(), input);
}

#[rstest]
#[case::no_prefix("aabb")]
#[case::non_hex("0xnothex")]
#[case::empty("")]
fn hex_bytes_rejects_everything_else_as_bad_hex(#[case] input: &str) {
    assert_matches!(HexBytes::new(input), Err(SchemaError::BadHex(v)) if v == input);
}

#[test]
fn a_response_burn_tx_id_must_carry_at_least_one_digit() {
    // `^0x[a-fA-F0-9]+$` — note the `+`. The bare `0x` is legal for a signature body and NOT for a
    // burn tx id: an empty burn tx id would be evidence of nothing.
    assert_eq!(HexTxId::new(hex(32)).expect("valid").as_str(), hex(32));
    assert_matches!(HexTxId::new("0x"), Err(SchemaError::EmptyHex(v)) if v == "0x");
    assert_matches!(HexTxId::new("nothex"), Err(SchemaError::EmptyHex(v)) if v == "nothex");
}

#[test]
fn the_token_enum_has_exactly_one_member() {
    assert_eq!(Token::new("USDC").unwrap(), Token::Usdc);
    assert_matches!(Token::new("DAI"), Err(SchemaError::UnknownToken(t)) if t == "DAI");
    // …and it is case-SENSITIVE: the schema's enum member is the uppercase ticker
    assert_matches!(Token::new("usdc"), Err(SchemaError::UnknownToken(t)) if t == "usdc");
}

// THE PREPARE REQUEST — the cross-field rules the OpenAPI states in prose
// ================================================================================================

/// A schema-valid prepare input, as raw JSON — the baseline each negative perturbs by ONE field, so
/// each test isolates exactly one rule.
fn valid_prepare_input() -> Value {
    json!({
        "token": "USDC",
        "valueExcludingFees": "10.00",
        "remoteDomain": 10001,
        "remoteDepositor": hex(32),
        "finalDestinationDomain": 0,
        "finalDestinationRecipient": hex(32),
        "useCircleForwarding": false,
    })
}

#[test]
fn the_baseline_prepare_input_decodes_so_every_negative_below_isolates_one_rule() {
    serde_json::from_value::<PrepareBurnIntentInput>(valid_prepare_input())
        .expect("the baseline must be schema-valid, or the negatives prove nothing");
}

#[test]
fn a_non_usdc_token_is_refused() {
    let mut input = valid_prepare_input();
    input["token"] = json!("DAI");

    let message = reject::<PrepareBurnIntentInput>(&input, "token DAI");
    assert!(message.contains("DAI"), "got: {message}");
}

#[test]
fn both_fee_fields_at_once_violate_the_documented_xor() {
    // "valueExcludingFees XOR valueIncludingFees (pass one, not both)". Sending both leaves the amount
    // ambiguous — in a field that decides how much USDC is released.
    let mut input = valid_prepare_input();
    input["valueIncludingFees"] = json!("10.50");

    let message = reject::<PrepareBurnIntentInput>(&input, "both value fields");
    assert!(
        message.contains("valueExcludingFees") && message.contains("valueIncludingFees"),
        "the rejection must name both sides of the XOR; got: {message}"
    );
}

#[test]
fn neither_fee_field_violates_the_documented_xor() {
    let mut input = valid_prepare_input();
    input.as_object_mut().unwrap().remove("valueExcludingFees");

    let message = reject::<PrepareBurnIntentInput>(&input, "neither value field");
    assert!(
        message.contains("valueExcludingFees") && message.contains("valueIncludingFees"),
        "the rejection must name both sides of the XOR; got: {message}"
    );
}

#[test]
fn a_remote_domain_below_the_documented_minimum_is_refused() {
    // `remoteDomain: minimum 1`. Zero is the source-chain domain, not a remote one.
    let mut input = valid_prepare_input();
    input["remoteDomain"] = json!(0);

    let message = reject::<PrepareBurnIntentInput>(&input, "remoteDomain 0");
    assert!(message.contains("remoteDomain"), "got: {message}");
}

#[test]
fn a_remote_domain_equal_to_the_final_destination_is_refused() {
    // "Must differ from finalDestinationDomain" — a withdrawal to the domain it came from is not a
    // withdrawal.
    let mut input = valid_prepare_input();
    input["finalDestinationDomain"] = json!(10001);

    let message =
        reject::<PrepareBurnIntentInput>(&input, "remoteDomain == finalDestinationDomain");
    assert!(
        message.contains("differ") || message.contains("10001"),
        "got: {message}"
    );
}

#[rstest]
#[case::remote_depositor("remoteDepositor")]
#[case::final_destination_recipient("finalDestinationRecipient")]
#[case::final_destination_caller("finalDestinationCaller")]
#[case::salt("salt")]
fn a_malformed_32_byte_field_on_the_prepare_input_is_refused(#[case] field: &str) {
    let mut input = valid_prepare_input();
    input[field] = json!("0xdeadbeef"); // hex, but four bytes, not thirty-two

    let message = reject::<PrepareBurnIntentInput>(&input, field);
    assert!(message.contains("0xdeadbeef"), "got: {message}");
}

#[test]
fn a_forwarding_fee_with_seven_decimals_is_refused_inside_the_nested_options() {
    // the nested object's constraints are enforced too — not just the top-level ones
    let mut input = valid_prepare_input();
    input["useCircleForwarding"] = json!(true);
    input["forwardingOptions"] = json!({ "maxFee": "0.5000001" });

    let message =
        reject::<PrepareBurnIntentInput>(&input, "forwardingOptions.maxFee with 7 decimals");
    assert!(
        message.contains("6 decimals") && message.contains("0.5000001"),
        "the rejection must name the rule and the value; got: {message}"
    );
}

// THE WITHDRAW REQUEST — the cardinality bounds
// ================================================================================================

fn valid_withdraw_batch() -> Value {
    let intent = fixture_json("prepare_withdrawal_200")["batches"][0]["burnIntents"][0].clone();
    json!({
        "burnIntents": [intent],
        "burnSignatures": [hex(65), hex(65)],
        "burnTxId": hex(32),
        "useCircleForwarding": false,
    })
}

#[test]
fn the_baseline_withdraw_request_decodes() {
    serde_json::from_value::<WithdrawRequest>(json!({ "batches": [valid_withdraw_batch()] }))
        .expect("the baseline must be schema-valid");
}

#[rstest]
#[case::empty(0, false)]
#[case::one(1, true)]
#[case::five(5, true)]
#[case::six(6, false)]
fn a_withdraw_request_carries_one_to_five_batches(#[case] count: usize, #[case] ok: bool) {
    // `minItems: 1, maxItems: 5` ("up to five per request"). An EMPTY batches array decoded happily
    // before — a request that asks Circle to do nothing, submitted as though it asked for something.
    let batches: Vec<Value> = (0..count).map(|_| valid_withdraw_batch()).collect();
    let body = json!({ "batches": batches });

    if ok {
        assert_eq!(
            serde_json::from_value::<WithdrawRequest>(body)
                .expect("within bounds")
                .batches()
                .len(),
            count
        );
    } else {
        let message = reject::<WithdrawRequest>(&body, &format!("{count} batches"));
        assert!(
            message.contains("1 to 5 batches") && message.contains(&count.to_string()),
            "the rejection must name the bound and the actual count; got: {message}"
        );
    }
}

#[rstest]
#[case::none(0, false)]
#[case::one(1, true)]
#[case::ten(10, true)]
#[case::eleven(11, false)]
fn a_withdraw_batch_carries_one_to_ten_burn_intents(#[case] count: usize, #[case] ok: bool) {
    let intent = fixture_json("prepare_withdrawal_200")["batches"][0]["burnIntents"][0].clone();
    let mut batch = valid_withdraw_batch();
    batch["burnIntents"] = json!((0..count).map(|_| intent.clone()).collect::<Vec<_>>());

    assert_eq!(
        serde_json::from_value::<WithdrawBatch>(batch.clone()).is_ok(),
        ok,
        "{count} burnIntents"
    );
    if !ok {
        let message = reject::<WithdrawBatch>(&batch, &format!("{count} burnIntents"));
        assert!(
            message.contains("1 to 10 burn intents") && message.contains(&count.to_string()),
            "the rejection must name the bound and the actual count; got: {message}"
        );
    }
}

#[test]
fn a_batch_below_the_two_signature_threshold_is_refused_at_the_wire() {
    // `burnSignatures: minItems 2` — the partner's 2-of-n attester quorum. This is a SCHEMA rule, so
    // it is refused here; the ORDERING rules (ascending signer address, no duplicates) are not
    // expressible in the schema and remain the quorum assembler's job.
    let mut batch = valid_withdraw_batch();
    batch["burnSignatures"] = json!([hex(65)]);

    let message = reject::<WithdrawBatch>(&batch, "one signature");
    assert!(
        message.contains("burnSignatures") && message.contains("at least 2"),
        "the rejection must name the field and the threshold; got: {message}"
    );
}

#[test]
fn the_threshold_violating_fixture_is_refused_as_a_whole_and_its_ordering_variants_survive_decode()
{
    // the threshold-violating fixture carries three violations. The FIRST batch (one signature)
    // breaks a schema rule, so the request as a whole is refused at the wire — which is the correct
    // outcome: it is a body Circle would reject.
    let body = fixture_json("withdraw_threshold_violating_sigs");
    reject::<WithdrawRequest>(&body, "the threshold-violating fixture");

    // The other two violations are ORDERING rules the schema cannot express, so those batches DO
    // decode — and the wire type must carry them verbatim, unsorted and un-deduplicated, so the
    // quorum assembler can still see the defect it exists to catch.
    let descending: WithdrawBatch = serde_json::from_value(body["batches"][1].clone())
        .expect("two signatures in descending order is schema-valid");
    assert_eq!(descending.burn_signatures().len(), 2);
    assert!(
        descending.burn_signatures()[0].as_str() > descending.burn_signatures()[1].as_str(),
        "the descending order must be preserved, not silently sorted"
    );

    let duplicated: WithdrawBatch = serde_json::from_value(body["batches"][2].clone())
        .expect("a duplicated signer is schema-valid");
    assert_eq!(
        duplicated.burn_signatures()[0],
        duplicated.burn_signatures()[1],
        "the duplicate must be preserved, not silently deduplicated"
    );
}

// THE RESPONSE SIDE — a malformed Circle response is refused, not acted on
// ================================================================================================

/// The happy-path status, as raw JSON — the baseline the response negatives perturb.
fn valid_status() -> Value {
    fixture_json("withdrawal_status_200")
}

#[test]
fn a_transfer_spec_hash_of_the_wrong_length_is_refused_in_isolation() {
    // The auditor's exact case, isolated: the fixture `malformed_body.json` hides this behind an
    // off-enum status that serde meets first. Here EVERY other field is valid, so nothing else can
    // account for the rejection.
    let mut status = valid_status();
    let short = format!("0x{}", "ab".repeat(31)); // 31 bytes, not 32
    status["transferSpecHashes"] = json!([short]);

    let message = reject::<WithdrawalStatus>(&status, "a 31-byte transferSpecHash");
    assert!(
        message.contains(&"ab".repeat(31)) && message.contains("not a 32-byte 0x-hex string"),
        "the rejection must name the bad hash AND the rule it broke; got: {message}"
    );
}

#[rstest]
#[case::transaction_hash("transactionHash", "not a 32-byte 0x-hex string")]
#[case::burn_tx_id("burnTxId", "0x-hex")]
#[case::withdrawal_id("withdrawalId", "not a uuid")]
fn a_malformed_required_response_field_is_refused_in_isolation(
    #[case] field: &str,
    #[case] expected_rule: &str,
) {
    // Circle's documentation: "Malformed Circle response → reject, not signed." Each field is
    // broken
    // ALONE, and the
    // rejection must cite the rule THAT field broke — not merely "some data was bad".
    let mut status = valid_status();
    status[field] = json!("not-a-valid-value");

    let message = reject::<WithdrawalStatus>(&status, field);
    assert!(
        message.contains(expected_rule) && message.contains("not-a-valid-value"),
        "{field}: the rejection must cite its own rule and value; got: {message}"
    );
}

#[test]
fn a_transfer_spec_value_in_the_decimal_form_is_refused() {
    // `TransferSpec.value` is `^\d+$` (smallest unit). "10.00" is the REQUEST's decimal form — a
    // 10^6 confusion in the field that says how much money moves.
    let mut body = fixture_json("prepare_withdrawal_200");
    body["batches"][0]["burnIntents"][0]["spec"]["value"] = json!("10.00");

    let message = reject::<PrepareWithdrawalResponse>(&body, "a decimal TransferSpec.value");
    assert!(
        message.contains("smallest token unit") && message.contains("10.00"),
        "the rejection must cite the smallest-unit rule; got: {message}"
    );
}

#[test]
fn a_32_byte_forwarding_contract_address_is_refused_in_the_json_hook_data() {
    // The conflation Circle's documentation warns against, caught here: the JSON
    // `forwardingContractAddress` is TWENTY bytes, while the 32-byte form belongs to the BINARY
    // WithdrawHookData. A type that accepted both would let the two representations blur exactly
    // where Circle says not to.
    let mut body = fixture_json("prepare_withdrawal_200");
    body["batches"][0]["burnIntents"][0]["spec"]["hookData"]["forwardingContractAddress"] =
        json!(hex(32));

    let message = reject::<PrepareWithdrawalResponse>(&body, "a 32-byte forwardingContractAddress");
    assert!(
        message.contains("20-byte"),
        "the rejection must cite the 20-byte rule the 32-byte binary form violates; got: {message}"
    );
}

#[test]
fn the_undocumented_string_fields_are_not_given_an_invented_pattern() {
    // `encoded` and `messageHashToSign` are typed `string` in the OpenAPI with NO pattern, and the
    // REQUEST-side `burnTxId` likewise. Inventing a regex for them would be the same defect as
    // inventing a field — so a value that is not hex at all must still decode.
    let mut body = fixture_json("prepare_withdrawal_200");
    body["batches"][0]["encoded"] = json!("not-hex-and-that-is-allowed");
    body["batches"][0]["messageHashToSign"] = json!("also-not-hex");

    let decoded: PrepareWithdrawalResponse =
        serde_json::from_value(body).expect("no pattern is documented for these two fields");
    assert_eq!(
        decoded.batches()[0].encoded(),
        "not-hex-and-that-is-allowed"
    );

    // …while the RESPONSE-side burnTxId DOES document `^0x[a-fA-F0-9]+$`, and is enforced. The
    // asymmetry is the OpenAPI's, not ours.
    let mut batch = valid_withdraw_batch();
    batch["burnTxId"] = json!("a-miden-tx-id-in-some-other-form");
    assert!(
        serde_json::from_value::<WithdrawBatch>(batch).is_ok(),
        "the request-side burnTxId has no documented pattern"
    );
}

// THE FIXTURES STILL DECODE — the constraints did not break the corpus
// ================================================================================================

#[test]
fn every_schema_valid_fixture_still_decodes_under_the_new_constraints() {
    // The tightening must not have made the happy path unreachable.
    serde_json::from_str::<PrepareWithdrawalResponse>(&fixture_text("prepare_withdrawal_200"))
        .expect("prepare_withdrawal_200");
    serde_json::from_str::<PrepareWithdrawalResponse>(&fixture_text(
        "prepare_withdrawal_validation_mismatch",
    ))
    .expect("the validation-mismatch fixture is SCHEMA-valid — B5 is what must catch it");
    serde_json::from_str::<Vec<WithdrawalStatus>>(&fixture_text("withdraw_201"))
        .expect("withdraw_201");
    serde_json::from_str::<Vec<WithdrawalStatus>>(&fixture_text("withdraw_failed_status"))
        .expect("withdraw_failed_status");
    serde_json::from_str::<WithdrawalStatus>(&fixture_text("withdrawal_status_200"))
        .expect("withdrawal_status_200");
}
