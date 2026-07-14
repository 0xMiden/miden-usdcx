//! Absent ≠ present-and-null, and required means required.
//!
//! Two holes the round-2 types still had, both of them the same species of leniency — serde being
//! helpful where the schema is not:
//!
//! * **`token` carried `#[serde(default)]`.** The OpenAPI marks it **required**. A body that simply
//!   omitted it therefore had `"USDC"` *manufactured* for it. Today that guesses right (the enum has
//!   one member); the day Circle adds a second, it guesses silently and wrongly, on the field that
//!   says which asset is being released.
//!
//! * **`Option<T>` accepted an explicit `null`.** In the OpenAPI these properties are *optional*
//!   (may be absent) but **not nullable** (may not be present-and-null) — the two are different
//!   states, and serde's `Option<T>` collapses them. `{"salt": null}` was decoding as "no salt", so a
//!   caller who set salt to null believing it meaningful got a Circle-generated random salt instead,
//!   with no error anywhere. The wire types now refuse the null and accept only the omission.
//!
//! The asymmetry is worth stating plainly: **omitting** an optional field is legal and means "not
//! set"; **sending null** for it is not a thing the schema describes, so it is refused rather than
//! interpreted.

use rstest::rstest;
use serde_json::{json, Value};
use withdrawal_listener_attester::circle::schema::{
    ForwardingOptions, PrepareBurnIntentInput, WithdrawalStatus,
};

#[path = "support/mod.rs"]
mod support;

use support::fixture_json;

fn hex32() -> String {
    format!("0x{}", "ab".repeat(32))
}

/// A decode that must fail as a DATA (shape/value) error, returning the message to assert on.
fn reject<T: serde::de::DeserializeOwned>(source: &Value, what: &str) -> String {
    let error = serde_json::from_value::<T>(source.clone())
        .err()
        .unwrap_or_else(|| panic!("{what}: an OpenAPI-invalid body DECODED"));

    assert_eq!(
        error.classify(),
        serde_json::error::Category::Data,
        "{what}: expected a data rejection, got {:?} ({error})",
        error.classify()
    );

    error.to_string()
}

/// A schema-valid prepare input — the baseline every case below perturbs by exactly one field.
fn valid_prepare_input() -> Value {
    json!({
        "token": "USDC",
        "valueExcludingFees": "10.00",
        "remoteDomain": 10001,
        "remoteDepositor": hex32(),
        "finalDestinationDomain": 0,
        "finalDestinationRecipient": hex32(),
        "useCircleForwarding": false,
    })
}

// REQUIRED MEANS REQUIRED — nothing is manufactured for a body that omitted it
// ================================================================================================

#[test]
fn the_baseline_prepare_input_decodes_so_every_negative_below_isolates_one_field() {
    serde_json::from_value::<PrepareBurnIntentInput>(valid_prepare_input())
        .expect("the baseline must be schema-valid, or the negatives prove nothing");
}

#[rstest]
#[case::token("token")]
#[case::remote_domain("remoteDomain")]
#[case::remote_depositor("remoteDepositor")]
#[case::final_destination_domain("finalDestinationDomain")]
#[case::final_destination_recipient("finalDestinationRecipient")]
#[case::use_circle_forwarding("useCircleForwarding")]
fn omitting_a_required_prepare_field_is_refused_and_never_defaulted(#[case] field: &str) {
    // The OpenAPI's `required` list for PrepareBurnIntentInput, in full. `token` is the one that
    // regressed: a `#[serde(default)]` on it meant an omitted token silently BECAME `USDC`.
    let mut input = valid_prepare_input();
    input.as_object_mut().unwrap().remove(field);

    let message =
        reject::<PrepareBurnIntentInput>(&input, &format!("prepare input without {field}"));
    assert!(
        message.contains(field),
        "the rejection must name the missing required field; got: {message}"
    );
}

#[test]
fn an_omitted_token_is_not_quietly_turned_into_usdc() {
    // Called out on its own because it is the one that is easy to wave through: `USDC` is currently
    // the only member of the enum, so manufacturing it happens to be right. It is still a guess — and
    // it is a guess about WHICH ASSET is being released.
    let mut input = valid_prepare_input();
    input.as_object_mut().unwrap().remove("token");

    assert!(
        serde_json::from_value::<PrepareBurnIntentInput>(input).is_err(),
        "`token` is required; a body that omits it must be refused, not completed for it"
    );

    // …and supplying it explicitly is, of course, fine
    assert!(serde_json::from_value::<PrepareBurnIntentInput>(valid_prepare_input()).is_ok());
}

// ABSENT ≠ PRESENT-AND-NULL — on the request side
// ================================================================================================

/// The signature serde produces when a non-nullable property arrives as `null` — it tries to
/// deserialize the field's own type and meets a null instead. This is the string that distinguishes
/// "the NULLABILITY rule rejected this" from "something else rejected this first".
const NULL_REJECTION: &str = "invalid type: null";

/// The XOR validator's message — the rule that must NOT be what fires in the tests below.
const XOR_REJECTION: &str = "exactly one of";

#[rstest]
// The two amount fields need the OTHER one supplied, and that is the whole point of this case pair —
// see the comment in the body.
#[case::value_excluding_fees("valueExcludingFees", Some("valueIncludingFees"))]
#[case::value_including_fees("valueIncludingFees", Some("valueExcludingFees"))]
#[case::final_destination_caller("finalDestinationCaller", None)]
#[case::salt("salt", None)]
#[case::forwarding_options("forwardingOptions", None)]
fn an_explicit_null_optional_is_refused_rather_than_read_as_absent(
    #[case] field: &str,
    #[case] amount_partner: Option<&str>,
) {
    // These properties are optional (may be OMITTED) and non-nullable (may not be present-and-null).
    // Serde's `Option<T>` would collapse the two; the schema does not.
    //
    // THE TRAP THIS CASE HAD TO BE REBASED AROUND. The body must be valid in EVERY respect except the
    // null, or the test proves nothing. Nulling `valueExcludingFees` on a body where it is the only
    // amount field looks like a fine test and is not: if the field regressed to a plain `Option`, the
    // null would read as `None`, BOTH amount fields would then be absent, and the XOR validator would
    // reject the body anyway — green test, live regression. So each amount case supplies its partner,
    // leaving the null as the single thing wrong; under that regression the body would decode
    // CLEANLY, and the test fails as it must.
    let mut input = valid_prepare_input();
    if let Some(partner) = amount_partner {
        let object = input.as_object_mut().unwrap();
        object.remove("valueExcludingFees");
        object.remove("valueIncludingFees");
        input[partner] = json!("10.50");
    }
    input[field] = Value::Null;

    let message = reject::<PrepareBurnIntentInput>(&input, &format!("{field}: null"));

    // …and pin WHICH rule fired. Accepting any data error is what let the flawed case through.
    assert!(
        message.contains(NULL_REJECTION),
        "{field}: the rejection must come from the field's own non-nullable rule; got: {message}"
    );
    assert!(
        !message.contains(XOR_REJECTION),
        "{field}: the XOR validator fired instead of the nullability rule — this body is not \
         isolating what it claims to; got: {message}"
    );
}

#[test]
fn the_amount_null_cases_would_decode_cleanly_if_nullability_regressed() {
    // The explicit proof that the case above is now load-bearing rather than XOR-shadowed: strip the
    // null and the SAME body is fully valid. So the ONLY thing standing between it and a clean decode
    // is the non-nullable rule on the amount field — exactly the property under test.
    for (field, partner) in [
        ("valueExcludingFees", "valueIncludingFees"),
        ("valueIncludingFees", "valueExcludingFees"),
    ] {
        let mut input = valid_prepare_input();
        let object = input.as_object_mut().unwrap();
        object.remove("valueExcludingFees");
        object.remove("valueIncludingFees");
        input[partner] = json!("10.50");

        serde_json::from_value::<PrepareBurnIntentInput>(input.clone()).unwrap_or_else(|e| {
            panic!(
                "the base body for the `{field}: null` case must itself be valid, else that case \
                    passes on the XOR rule rather than the nullability rule: {e}"
            )
        });
    }
}

#[test]
fn omitting_those_same_optionals_is_perfectly_legal() {
    // The other half of the rule — otherwise "refuse null" would just be "refuse everything".
    let input = valid_prepare_input(); // carries none of salt/caller/forwardingOptions
    let decoded: PrepareBurnIntentInput = serde_json::from_value(input)
        .expect("an omitted optional is absence, and absence is legal");

    assert!(decoded.salt().is_none());
    assert!(decoded.final_destination_caller().is_none());
    assert!(decoded.forwarding_options().is_none());
}

#[rstest]
#[case::max_fee("maxFee")]
#[case::hook_data("hookData")]
#[case::uses_fast_finality("usesFastFinality")]
fn an_explicit_null_inside_forwarding_options_is_refused_too(#[case] field: &str) {
    // The nested object obeys the same rule — leniency must not survive one level down. The body is
    // otherwise EMPTY, and an empty forwardingOptions is valid (all three fields are optional), so the
    // null is unambiguously the only thing wrong: if this field regressed, the object would decode.
    let mut options = json!({});
    options[field] = Value::Null;

    let message =
        reject::<ForwardingOptions>(&options, &format!("forwardingOptions.{field}: null"));
    assert!(
        message.contains(NULL_REJECTION),
        "forwardingOptions.{field}: the rejection must come from the non-nullable rule; got: {message}"
    );

    // …and the empty object it was built from is indeed fine — which is what makes the null the sole
    // defect above rather than one of two
    assert!(serde_json::from_value::<ForwardingOptions>(json!({})).is_ok());
}

// ABSENT ≠ PRESENT-AND-NULL — on the response side
// ================================================================================================

#[rstest]
#[case::attestation_payload("attestationPayload")]
#[case::attestation("attestation")]
#[case::transaction_hash("transactionHash")]
#[case::failure_reason("failureReason")]
fn an_explicit_null_conditional_response_field_is_refused(#[case] field: &str) {
    // §10.11: a malformed Circle response is REJECTED, not acted on. A `null` where a conditional
    // field belongs is malformed — the schema says "absent, or a value of this type", never "null".
    //
    // The base fixture is a fully valid status, so the null is the sole defect: were this field to
    // regress to a plain `Option`, the body would decode cleanly and this test would fail.
    let mut status = fixture_json("withdrawal_status_200");
    status[field] = Value::Null;

    let message = reject::<WithdrawalStatus>(&status, &format!("response {field}: null"));
    assert!(
        message.contains(NULL_REJECTION),
        "response {field}: the rejection must come from the non-nullable rule; got: {message}"
    );
}

#[test]
fn the_conditional_response_fields_may_still_be_omitted() {
    // `withdraw_failed_status` is the live proof: a failed withdrawal carries no `transactionHash` at
    // all, and that must keep decoding.
    let failed = fixture_json("withdraw_failed_status");
    let decoded: WithdrawalStatus = serde_json::from_value(failed[0].clone())
        .expect("an omitted conditional field is absence, and absence is legal");

    assert!(decoded.transaction_hash().is_none());
    assert_eq!(decoded.failure_reason(), Some("verification_failed"));
}

#[rstest]
#[case::withdrawal_id("withdrawalId")]
#[case::burn_tx_id("burnTxId")]
#[case::status("status")]
#[case::use_circle_forwarding("useCircleForwarding")]
#[case::transfer_spec_hashes("transferSpecHashes")]
fn omitting_a_required_response_field_is_refused(#[case] field: &str) {
    let mut status = fixture_json("withdrawal_status_200");
    status.as_object_mut().unwrap().remove(field);

    let message = reject::<WithdrawalStatus>(&status, &format!("response without {field}"));
    assert!(
        message.contains(field),
        "the rejection must name the missing required field; got: {message}"
    );
}

#[rstest]
#[case::withdrawal_id("withdrawalId")]
#[case::burn_tx_id("burnTxId")]
#[case::status("status")]
#[case::transfer_spec_hashes("transferSpecHashes")]
fn a_null_required_response_field_is_refused(#[case] field: &str) {
    // A required field that arrives as `null` is not "present" in any useful sense.
    let mut status = fixture_json("withdrawal_status_200");
    status[field] = Value::Null;

    let message = reject::<WithdrawalStatus>(&status, &format!("response {field}: null"));
    assert!(
        message.contains(NULL_REJECTION),
        "response {field}: null must be refused as a type error, not read as absence; got: {message}"
    );
}
