//! §11.2 — the fixtures are frozen against the **OpenAPI**, not against this crate's structs.
//!
//! Every check below re-derives a constraint straight from the schema tables in
//! `CIRCLE-API-SURFACE.md` / `CIRCLE-DATA-SCHEMAS.md` — the field's regex, its enum, its
//! cardinality, its required-ness — and applies it to the fixture's RAW JSON. Nothing here touches a
//! wire type, deliberately: if these assertions ran through `PrepareWithdrawalResponse` they would
//! only ever prove the fixtures agree with the structs, which is exactly the circularity that lets a
//! fixture get "fixed" to make a wrong struct pass.
//!
//! This service releases real USDC. A fixture that drifts from the schema is a defect that would ship
//! a request Circle rejects — or, far worse, one it accepts and settles differently than intended.

use serde_json::Value;

#[path = "support/mod.rs"]
mod support;

use support::{
    fixture_json, fixtures_dir, is_calldata, is_decimal_uint, is_hex20, is_hex32, is_hex_any,
    is_hex_nonempty, is_uuid, str_at, walk_keys, ERROR_FIXTURES, HAPPY_PATH_FIXTURES, STATUS_ENUM,
};

#[test]
fn exactly_the_thirteen_required_fixtures_are_present() {
    let mut on_disk: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .filter_map(|e| {
            let path = e.unwrap().path();
            (path.extension()? == "json")
                .then(|| path.file_stem().unwrap().to_string_lossy().into_owned())
        })
        .collect();
    on_disk.sort();

    let mut required: Vec<String> = HAPPY_PATH_FIXTURES
        .iter()
        .chain(ERROR_FIXTURES.iter())
        .map(|s| s.to_string())
        .collect();
    required.sort();

    assert_eq!(
        on_disk, required,
        "§11.2 requires exactly these 13 fixtures: 3 happy-path + 10 error/malformed"
    );
}

// THE JSON TransferSpec — 14 required fields, each with its documented pattern
// ================================================================================================

/// The 32-byte-hex fields of the API `TransferSpec` (`CIRCLE-API-SURFACE.md`: "…`sourceContract`,
/// `destinationContract`, `sourceToken`, `destinationToken`, `sourceDepositor`,
/// `destinationRecipient`, `sourceSigner`, `destinationCaller` | string | `^0x[a-fA-F0-9]{64}$`").
const SPEC_HEX32_FIELDS: [&str; 8] = [
    "sourceContract",
    "destinationContract",
    "sourceToken",
    "destinationToken",
    "sourceDepositor",
    "destinationRecipient",
    "sourceSigner",
    "destinationCaller",
];

fn check_transfer_spec(spec: &Value, whose: &str) {
    // required(14): version, sourceDomain, destinationDomain, the 8 bytes32 fields, value, salt, hookData
    assert!(spec["version"].is_u64(), "{whose}: version is an integer");
    assert!(spec["sourceDomain"].is_u64(), "{whose}: sourceDomain");
    assert!(
        spec["destinationDomain"].is_u64(),
        "{whose}: destinationDomain"
    );

    for field in SPEC_HEX32_FIELDS {
        let value = str_at(spec, field);
        assert!(is_hex32(value), "{whose}.{field}: not 32-byte hex: {value}");
    }

    // `value` is the smallest token unit, as a DECIMAL-DIGITS string — never a JSON number (a
    // uint256 does not survive an f64) and never the request's "10.00" decimal form
    let value = str_at(spec, "value");
    assert!(
        is_decimal_uint(value),
        "{whose}.value: `^\\d+$`, got {value}"
    );
    assert!(is_hex32(str_at(spec, "salt")), "{whose}.salt");

    // hookData is a STRUCTURED OBJECT in the JSON API — not the hex bytes string the binary
    // WithdrawHookData is (CIRCLE-DATA-SCHEMAS.md §3.4: "DO NOT CONFLATE")
    let hook = &spec["hookData"];
    assert!(hook.is_object(), "{whose}.hookData must be an object");
    assert!(
        hook["remoteDomain"].is_u64(),
        "{whose}.hookData.remoteDomain"
    );
    assert!(
        is_hex32(str_at(hook, "remoteDepositor")),
        "{whose}.hookData.remoteDepositor"
    );
    assert!(
        is_hex32(str_at(hook, "remoteToken")),
        "{whose}.hookData.remoteToken"
    );
    // …and the forwarding contract is TWENTY bytes here, where the binary form is thirty-two
    let forwarding = str_at(hook, "forwardingContractAddress");
    assert!(
        is_hex20(forwarding),
        "{whose}.hookData.forwardingContractAddress: `^0x[a-fA-F0-9]{{40}}$` (20 bytes, NOT the \
         binary form's 32), got {forwarding}"
    );
    assert!(
        is_calldata(str_at(hook, "forwardingCalldata")),
        "{whose}.hookData.forwardingCalldata"
    );
}

fn check_burn_intent(intent: &Value, whose: &str) {
    // both are DECIMAL-DIGIT STRINGS: a uint256 maxBlockHeight/maxFee cannot be a JSON number
    assert!(
        is_decimal_uint(str_at(intent, "maxBlockHeight")),
        "{whose}.maxBlockHeight"
    );
    assert!(is_decimal_uint(str_at(intent, "maxFee")), "{whose}.maxFee");
    check_transfer_spec(&intent["spec"], &format!("{whose}.spec"));
}

#[test]
fn prepare_withdrawal_200_matches_the_prepare_withdrawal_response_schema() {
    let body = fixture_json("prepare_withdrawal_200");

    // `{ batches: [ { burnIntents, encoded, messageHashToSign } ] }` — the wrapper is required
    let batches = body["batches"]
        .as_array()
        .expect("PrepareWithdrawalResponse requires a top-level `batches` array");
    assert!(!batches.is_empty());

    for (i, batch) in batches.iter().enumerate() {
        let intents = batch["burnIntents"]
            .as_array()
            .expect("burnIntents required");
        assert!(!intents.is_empty());
        for (j, intent) in intents.iter().enumerate() {
            check_burn_intent(intent, &format!("batches[{i}].burnIntents[{j}]"));
        }
        assert!(is_hex_any(str_at(batch, "encoded")), "batches[{i}].encoded");
        assert!(
            is_hex32(str_at(batch, "messageHashToSign")),
            "batches[{i}].messageHashToSign"
        );
    }
}

#[test]
fn the_two_prepare_error_fixtures_are_the_shapes_they_claim_to_be() {
    // a validation mismatch is a schema-VALID 200 — that is the whole hazard it models
    let mismatch = fixture_json("prepare_withdrawal_validation_mismatch");
    let spec = &mismatch["batches"][0]["burnIntents"][0]["spec"];
    check_transfer_spec(spec, "validation_mismatch.spec");

    // …and it must genuinely diverge from the happy-path payload, or it models nothing
    let good = fixture_json("prepare_withdrawal_200");
    let good_spec = &good["batches"][0]["burnIntents"][0]["spec"];
    assert_ne!(spec["value"], good_spec["value"]);
    assert_ne!(spec["destinationDomain"], good_spec["destinationDomain"]);
    assert_ne!(
        spec["destinationRecipient"],
        good_spec["destinationRecipient"]
    );

    // the missing-hash fixture is missing EXACTLY the one required field, and nothing else
    let missing = fixture_json("prepare_withdrawal_missing_hash");
    let batch = &missing["batches"][0];
    assert!(
        batch.get("messageHashToSign").is_none(),
        "the field under test must be absent"
    );
    assert!(
        batch.get("burnIntents").is_some(),
        "the rest of the batch stays well-formed"
    );
    assert!(batch.get("encoded").is_some());
}

// THE WITHDRAWAL STATUS OBJECT — required vs conditional fields, and the status enum
// ================================================================================================

fn check_withdrawal_status(status: &Value, whose: &str) {
    // required: withdrawalId, burnTxId, status, useCircleForwarding, transferSpecHashes
    assert!(
        is_uuid(str_at(status, "withdrawalId")),
        "{whose}.withdrawalId must be a uuid"
    );
    assert!(
        is_hex_nonempty(str_at(status, "burnTxId")),
        "{whose}.burnTxId: `^0x[a-fA-F0-9]+$`"
    );

    let kind = str_at(status, "status");
    assert!(
        STATUS_ENUM.contains(&kind),
        "{whose}.status: `{kind}` is not one of the six documented values {STATUS_ENUM:?}"
    );
    assert!(
        status["useCircleForwarding"].is_boolean(),
        "{whose}.useCircleForwarding is required"
    );

    let hashes = status["transferSpecHashes"]
        .as_array()
        .unwrap_or_else(|| panic!("{whose}.transferSpecHashes is required"));
    for (i, hash) in hashes.iter().enumerate() {
        assert!(
            is_hex32(hash.as_str().unwrap()),
            "{whose}.transferSpecHashes[{i}] must be 32-byte hex"
        );
    }

    // conditional: attestationPayload, attestation, transactionHash, failureReason
    for hex_field in ["attestationPayload", "attestation"] {
        if let Some(v) = status.get(hex_field) {
            assert!(is_hex_any(v.as_str().unwrap()), "{whose}.{hex_field}");
        }
    }
    if let Some(v) = status.get("transactionHash") {
        assert!(
            is_hex32(v.as_str().unwrap()),
            "{whose}.transactionHash is 32-byte hex"
        );
    }
    // "failureReason: Returned when `status` is 'failed'."
    if status.get("failureReason").is_some() {
        assert_eq!(
            kind, "failed",
            "{whose}: failureReason appears only on a failed withdrawal"
        );
    }
}

#[test]
fn withdraw_201_is_an_array_of_schema_exact_statuses() {
    let body = fixture_json("withdraw_201");
    let statuses = body
        .as_array()
        .expect("POST /v1/withdraw returns an ARRAY (WithdrawSubmissionResponse), never an object");

    assert!(!statuses.is_empty());
    for (i, status) in statuses.iter().enumerate() {
        check_withdrawal_status(status, &format!("withdraw_201[{i}]"));
    }
}

#[test]
fn withdrawal_status_200_is_the_same_object_shape_not_an_array() {
    let body = fixture_json("withdrawal_status_200");
    assert!(
        body.is_object(),
        "GET /v1/withdrawal/{{id}} returns the object, not the array"
    );
    check_withdrawal_status(&body, "withdrawal_status_200");
}

#[test]
fn withdraw_failed_status_is_the_terminal_failed_shape() {
    let body = fixture_json("withdraw_failed_status");
    let status = &body.as_array().expect("still the array shape")[0];
    check_withdrawal_status(status, "withdraw_failed_status[0]");

    assert_eq!(str_at(status, "status"), "failed");
    assert!(
        status.get("failureReason").is_some(),
        "a failed withdrawal carries its reason"
    );
}

// THE WITHDRAW REQUEST — cardinality bounds, and the signature rules it deliberately violates
// ================================================================================================

#[test]
fn the_threshold_violating_fixture_is_a_well_formed_request_that_breaks_the_signature_rules() {
    let body = fixture_json("withdraw_threshold_violating_sigs");
    let batches = body["batches"]
        .as_array()
        .expect("WithdrawRequest requires the top-level `batches` wrapper");

    // WithdrawRequest: minItems 1, maxItems 5 ("up to five per request")
    assert!(
        (1..=5).contains(&batches.len()),
        "the fixture must stay a STRUCTURALLY valid request — the violation is in the signatures"
    );

    for (i, batch) in batches.iter().enumerate() {
        // WithdrawBatch.burnIntents: minItems 1, maxItems 10
        let intents = batch["burnIntents"].as_array().unwrap();
        assert!(
            (1..=10).contains(&intents.len()),
            "batches[{i}].burnIntents"
        );
        for (j, intent) in intents.iter().enumerate() {
            check_burn_intent(intent, &format!("batches[{i}].burnIntents[{j}]"));
        }

        assert!(
            is_hex_nonempty(str_at(batch, "burnTxId")),
            "batches[{i}].burnTxId is required"
        );
        assert!(batch["useCircleForwarding"].is_boolean());

        for (j, sig) in batch["burnSignatures"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            assert!(
                is_hex_any(sig.as_str().unwrap()),
                "batches[{i}].burnSignatures[{j}]: `^0x[a-fA-F0-9]*$`"
            );
        }
    }

    // …and now the three violations it exists to carry (`minItems: 2`, ascending order, no dupes)
    let sigs = |i: usize| batches[i]["burnSignatures"].as_array().unwrap().clone();
    assert_eq!(
        sigs(0).len(),
        1,
        "batch 0 is BELOW the minItems-2 threshold"
    );
    let descending = sigs(1);
    assert!(
        descending[0].as_str() > descending[1].as_str(),
        "batch 1 is in DESCENDING order (Circle verifies ascending)"
    );
    let duplicated = sigs(2);
    assert_eq!(duplicated[0], duplicated[1], "batch 2 repeats one signer");
}

// THE REQUEST SIDE NEVER CARRIES sourceDepositor
// ================================================================================================

#[test]
fn no_request_side_fixture_carries_a_source_depositor_outside_a_circle_returned_spec() {
    // `sourceDepositor` is legal INSIDE a Circle-returned TransferSpec (Circle fills it) and illegal
    // in a partner-built PrepareBurnIntentInput. The withdraw request's burnIntents are Circle's own
    // returned intents, echoed back verbatim — so the sweep is scoped to the one place the partner
    // authors fields: the prepare request's batch inputs. This crate ships no prepare-request fixture
    // (the request is built, not received), so the assertion that bites is the struct-level one in
    // `wire_roundtrip.rs`; this guards the fixture corpus against a future one being added wrongly.
    for stem in ["withdraw_threshold_violating_sigs"] {
        let body = fixture_json(stem);
        let mut offenders = Vec::new();

        walk_keys(&body, &mut |key, _| {
            // legal only under a `spec` (the Circle-returned TransferSpec)
            if key == "remoteDepositor" || key == "sourceDepositor" {
                offenders.push(key.to_string());
            }
        });

        // every occurrence in this fixture is inside a returned spec/hookData, never at batch level
        for batch in body["batches"].as_array().unwrap() {
            assert!(
                batch.get("sourceDepositor").is_none(),
                "{stem}: a batch the partner authors must never carry sourceDepositor"
            );
        }
        assert!(
            !offenders.is_empty(),
            "{stem}: the Circle-returned spec DOES carry these — a corpus with none would mean the \
             fixture lost its TransferSpec"
        );
    }
}

// THE ERROR BODIES
// ================================================================================================

#[test]
fn the_undocumented_error_bodies_stay_content_free() {
    // The OpenAPI defines no error-body schema. These fixtures therefore invent none: an empty object
    // is the honest fixture, and the HTTP status (in the filename) is the contract. If a future
    // Circle answer defines the body, this test is where the change lands — visibly.
    for stem in [
        "prepare_withdrawal_400",
        "withdraw_400",
        "withdraw_500",
        "withdrawal_status_404",
    ] {
        let body = fixture_json(stem);
        assert_eq!(
            body,
            serde_json::json!({}),
            "{stem}: no Circle error schema is documented, so no error field may be invented"
        );
    }

    // the 409 is the one exception, and it carries ONLY Circle's own field names — the two recovery
    // hints COMPONENT-SPEC §10.10 reads
    let conflict = fixture_json("withdraw_409");
    let keys: Vec<&String> = conflict.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        ["burnTxId", "withdrawalId"],
        "no invented error field"
    );
    assert!(is_uuid(str_at(&conflict, "withdrawalId")));
    assert!(is_hex_nonempty(str_at(&conflict, "burnTxId")));
}

#[test]
fn the_malformed_body_violates_the_schema_in_the_three_ways_it_claims_to() {
    let body = fixture_json("malformed_body");

    // 1. a snake_case key where the wire is camelCase
    assert!(body.get("withdrawal_id").is_some());
    assert!(body.get("withdrawalId").is_none());
    // 2. a status outside the six-member enum
    let status = str_at(&body, "status");
    assert!(
        !STATUS_ENUM.contains(&status),
        "`{status}` must be off-enum"
    );
    // 3. a transferSpecHashes entry of the wrong length
    let hash = body["transferSpecHashes"][0].as_str().unwrap();
    assert!(
        !is_hex32(hash),
        "the hash must be a BAD length, got a valid one: {hash}"
    );
}
