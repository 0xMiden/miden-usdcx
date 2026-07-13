//! `tests/circle_fetch_contract.rs` — the attestation FETCH shapes and what they refuse:
//! `T-RLY-01` (by `depositMessageHash` — the wrapper shape, and the response's binding to the hash
//! that was ASKED for), `T-RLY-02` (by source-chain `txHash` — the list shape + the client-side
//! pattern reject), `T-RLY-05` (a `messageHash` that does not bind its payload), and `T-RLY-06` (one
//! sub-case per malformed field).
//!
//! No live Circle leg (§11): every Circle endpoint is `REQUIRES CIRCLE CONFIRMATION` and is
//! exercised against the in-process schema-exact mock ([`mock_circle`]) — the relayer builds a real
//! `reqwest::Request` and the mock's axum router answers it, binding no socket. The attestation wire
//! data is the partner test vector from [`fixtures`] — a real secp256k1 signature over the real
//! raw-keccak digest of a canonical DC-1 DepositIntent payload — so the keccak binding these tests
//! assert is a genuine binding, not a self-consistent invention.

mod fixtures;
mod mock_circle;

use assert_matches::assert_matches;
use rstest::rstest;
use serde_json::{json, Value};

use fixtures::{test_vector, PartnerAttester, TEST_VECTOR_PAYLOAD_ID_EMPTY_HOOKDATA};
use mock_circle::{
    attestation_object, by_hash_wrapper, by_tx_hash_list, client_for, requested_hash, wrapper_with,
    Endpoint, MockCircle, Reply, Script, FIXTURE_MIDEN_DOMAIN, HASH_PARAM, TX_HASH,
};

use xreserve_deposit_relayer::circle::{
    fetch_attestation_by_message_hash, fetch_attestations_by_tx_hash, AuthPosture,
};
use xreserve_deposit_relayer::error::{HexField, RelayerError};

// T-RLY-01 — fetch_attestation_by_message_hash (the WRAPPER shape)
// ================================================================================================

#[tokio::test]
async fn t_rly_01_by_hash_flattens_the_wrapper_and_binds_the_raw_keccak_digest() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(by_hash_wrapper(&vector))]));
    let (client, sink) = client_for(&mock, AuthPosture::None);
    // the by-hash endpoint is a LOOKUP BY this hash — so this is the hash the relayer must ask for
    let requested = requested_hash(&vector);

    let fetched = fetch_attestation_by_message_hash(&client, &requested)
        .await
        .expect("a 200 wrapper response yields the validated attestation");

    // (1) the wrapper was flattened to its inner attestation object — the three wire fields survive
    //     verbatim.
    assert_eq!(fetched.object().payload(), vector.payload_hex());
    assert_eq!(fetched.object().message_hash(), vector.message_hash_hex());
    assert_eq!(fetched.object().attestation(), vector.attestation_hex());

    // (2) keccak256(decode_hex(payload)) == decode_hex(messageHash) — the RAW-keccak binding, on
    //     decoded bytes (not a string compare of the hex).
    assert_eq!(fetched.payload(), vector.payload());
    assert_eq!(fetched.message_hash(), vector.message_hash());
    assert_eq!(
        fixtures::keccak256(fetched.payload()),
        fetched.message_hash()
    );

    // (3) the attestation decodes to exactly 65 bytes (r‖s‖v).
    assert_eq!(fetched.attestation().len(), 65);
    assert_eq!(fetched.attestation(), vector.attestation());

    // the request went to the documented PATH-param endpoint, once, with no query string.
    let requests = mock.requests_to(Endpoint::ByHash);
    assert_eq!(requests.len(), 1, "one 200 → exactly one request");
    assert_eq!(requests[0].path, format!("/v1/attestations/{requested}"));
    assert!(
        requests[0].query.is_empty(),
        "the by-hash endpoint takes its hash in the PATH, not a query param"
    );
    assert!(sink.rejections().is_empty() && sink.alerts().is_empty());
}

/// The by-hash endpoint is the ONLY wrapped one. If the client accepted a bare (top-level)
/// attestation object here it would be decoding a shape Circle does not send — and the wrapper
/// flatten would be untested. So the unwrapped body must be REJECTED.
#[tokio::test]
async fn t_rly_01_by_hash_rejects_an_unwrapped_top_level_attestation_object() {
    let vector = test_vector();
    let mock =
        MockCircle::start(Script::new().by_hash(vec![Reply::ok(attestation_object(&vector))]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestation_by_message_hash(&client, HASH_PARAM)
        .await
        .expect_err("the by-hash endpoint returns a WRAPPER; a bare object is not that shape");

    assert_matches!(err, RelayerError::Decode(_));
    assert_eq!(
        sink.rejections().len(),
        1,
        "the rejection is logged, never dropped"
    );
    assert_eq!(
        sink.alerts().len(),
        1,
        "a schema decode error alerts (§8.4)"
    );
}

/// The documented path param is `^0x[a-fA-F0-9]{64}$`. A non-conforming hash is refused BEFORE any
/// request is issued — the relayer does not spend a request (or a rate-limit token) on an input the
/// API cannot accept.
#[tokio::test]
async fn t_rly_01_by_hash_rejects_a_malformed_hash_client_side_without_issuing_a_request() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(by_hash_wrapper(&vector))]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestation_by_message_hash(&client, "0xdeadbeef")
        .await
        .expect_err("a short hash violates ^0x[a-fA-F0-9]{64}$");

    assert_matches!(err, RelayerError::BadMessageHashFormat { .. });
    assert_eq!(
        mock.request_count(),
        0,
        "no request may be issued for a malformed hash"
    );
}

// T-RLY-02 — fetch_attestations_by_tx_hash (LIST + remoteDomain, client-side txHash reject)
// ================================================================================================

#[tokio::test]
async fn t_rly_02_by_tx_hash_returns_the_list_shape_with_remote_domain() {
    let vector_a = test_vector();
    let vector_b = PartnerAttester::new().attest(&fixtures::canonical_payload(
        TEST_VECTOR_PAYLOAD_ID_EMPTY_HOOKDATA,
    ));
    let body = by_tx_hash_list(&[(&vector_a, FIXTURE_MIDEN_DOMAIN), (&vector_b, 1)]);
    let mock = MockCircle::start(Script::new().by_tx_hash(vec![Reply::ok(body)]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    let fetched = fetch_attestations_by_tx_hash(&client, TX_HASH)
        .await
        .expect("a 200 list response decodes");

    assert_eq!(
        fetched.len(),
        2,
        "both elements decode (no wrapper on this endpoint)"
    );
    // each element carries remoteDomain >= 1 and a messageHash that binds its payload
    for element in &fetched {
        assert!(element.remote_domain() >= 1, "remoteDomain has minimum 1");
        assert_eq!(
            fixtures::keccak256(element.attestation().payload()),
            element.attestation().message_hash()
        );
        assert_eq!(element.attestation().attestation().len(), 65);
    }
    assert_eq!(fetched[0].remote_domain(), FIXTURE_MIDEN_DOMAIN);
    assert_eq!(fetched[0].attestation().payload(), vector_a.payload());
    assert_eq!(fetched[1].remote_domain(), 1);
    assert_eq!(fetched[1].attestation().payload(), vector_b.payload());

    // the txHash travels as a QUERY param on /v1/attestations (not a path segment).
    let requests = mock.requests_to(Endpoint::ByTxHash);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/attestations");
    assert_eq!(requests[0].query("txHash"), Some(TX_HASH));
    assert_eq!(
        requests[0].query.len(),
        1,
        "no undocumented query params are sent"
    );
}

/// The `txHash` pattern is enforced CLIENT-SIDE: a non-conforming value must produce
/// `Err(BadTxHashFormat)` with **no request issued** (spec §7.1 pre-condition).
#[rstest]
#[case::missing_0x_prefix("2222222222222222222222222222222222222222222222222222222222222222")]
#[case::one_hex_digit_short("0x222222222222222222222222222222222222222222222222222222222222222")]
#[case::one_hex_digit_long("0x22222222222222222222222222222222222222222222222222222222222222222")]
#[case::non_hex_digit("0x222222222222222222222222222222222222222222222222222222222222222g")]
#[case::uppercase_0x_prefix("0X2222222222222222222222222222222222222222222222222222222222222222")]
#[case::empty("")]
#[case::bare_0x("0x")]
#[case::leading_whitespace(" 0x2222222222222222222222222222222222222222222222222222222222222222")]
#[tokio::test]
async fn t_rly_02_rejects_a_malformed_tx_hash_client_side_without_issuing_a_request(
    #[case] tx_hash: &str,
) {
    let vector = test_vector();
    let mock = MockCircle::start(
        Script::new().by_tx_hash(vec![Reply::ok(by_tx_hash_list(&[(&vector, 1)]))]),
    );
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestations_by_tx_hash(&client, tx_hash)
        .await
        .expect_err("a txHash that violates ^0x[a-fA-F0-9]{64}$ is rejected client-side");

    assert_matches!(err, RelayerError::BadTxHashFormat { .. });
    assert_eq!(
        mock.request_count(),
        0,
        "no request may be issued for a malformed txHash"
    );
}

/// The documented pattern accepts both hex cases (`[a-fA-F0-9]`) — the client must not narrow it.
#[tokio::test]
async fn t_rly_02_accepts_a_mixed_case_tx_hash() {
    let vector = test_vector();
    let mixed = "0xAbCdEf2222222222222222222222222222222222222222222222222222222222";
    let mock = MockCircle::start(
        Script::new().by_tx_hash(vec![Reply::ok(by_tx_hash_list(&[(&vector, 1)]))]),
    );
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    fetch_attestations_by_tx_hash(&client, mixed)
        .await
        .expect("mixed-case hex conforms to ^0x[a-fA-F0-9]{64}$");
    assert_eq!(
        mock.requests_to(Endpoint::ByTxHash)[0].query("txHash"),
        Some(mixed)
    );
}

/// `remoteDomain` has `minimum: 1` in the OpenAPI. A `0` is schema-violating and must be rejected,
/// not silently carried toward the Miden side.
#[tokio::test]
async fn t_rly_02_rejects_a_remote_domain_below_the_documented_minimum() {
    let vector = test_vector();
    let mock = MockCircle::start(
        Script::new().by_tx_hash(vec![Reply::ok(by_tx_hash_list(&[(&vector, 0)]))]),
    );
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestations_by_tx_hash(&client, TX_HASH)
        .await
        .expect_err("remoteDomain = 0 violates the documented minimum of 1");

    assert_matches!(err, RelayerError::BadRemoteDomain { actual: 0 });
    assert_eq!(sink.rejections().len(), 1);
}

// T-RLY-05 — messageHash mismatch aborts (the raw-keccak binding, over the wire)
// ================================================================================================

#[tokio::test]
async fn t_rly_05_message_hash_that_does_not_bind_the_payload_aborts_and_alerts() {
    let vector = test_vector();
    // a well-formed 32-byte hash that is simply NOT keccak256(payload)
    let body = wrapper_with(&vector, |object| {
        object["messageHash"] =
            json!("0x0000000000000000000000000000000000000000000000000000000000000001");
    });
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(body)]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestation_by_message_hash(&client, HASH_PARAM)
        .await
        .expect_err("the envelope does not bind the payload it carries");

    assert_matches!(err, RelayerError::MessageHashMismatch { expected, actual } => {
        assert_eq!(expected, vector.message_hash(), "expected = the true raw keccak of the payload");
        assert_eq!(actual[31], 1, "actual = the digest Circle presented");
    });
    assert_eq!(sink.rejections().len(), 1, "logged, never silently dropped");
    assert_eq!(sink.alerts().len(), 1, "a binding mismatch alerts (§8.4)");
}

// T-RLY-06 — malformed response rejected: ONE sub-case PER invalid field
// ================================================================================================

/// Runs the by-hash fetch against a wrapper body whose inner object was mutated, and returns the
/// error (asserting a rejection was logged and never silently dropped).
async fn fetch_malformed(body: Value) -> RelayerError {
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(body)]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestation_by_message_hash(&client, HASH_PARAM)
        .await
        .expect_err("a schema-violating response must be rejected, never forwarded");

    assert_eq!(
        sink.rejections().len(),
        1,
        "every malformed response is logged with a reason (§8.4: never silently dropped)"
    );
    assert!(
        sink.alerts().len() == 1,
        "a malformed Circle response alerts (§8.4)"
    );
    err
}

#[tokio::test]
async fn t_rly_06_reject_missing_payload() {
    let vector = test_vector();
    let body = wrapper_with(&vector, |object| {
        object.as_object_mut().unwrap().remove("payload");
    });
    assert_matches!(fetch_malformed(body).await, RelayerError::Decode(_));
}

#[tokio::test]
async fn t_rly_06_reject_wrong_payload_field() {
    let vector = test_vector();
    // the payload is present, but under a field name the schema does not define
    let body = wrapper_with(&vector, |object| {
        let payload = object["payload"].clone();
        object.as_object_mut().unwrap().remove("payload");
        object["payloadHex"] = payload;
    });
    assert_matches!(fetch_malformed(body).await, RelayerError::Decode(_));
}

#[tokio::test]
async fn t_rly_06_reject_non_hex_payload() {
    let vector = test_vector();
    let body = wrapper_with(&vector, |object| {
        object["payload"] = json!("0xzz2e0acd0000000100");
    });
    assert_matches!(
        fetch_malformed(body).await,
        RelayerError::MalformedHex {
            field: HexField::Payload,
            ..
        }
    );
}

#[tokio::test]
async fn t_rly_06_reject_missing_message_hash() {
    let vector = test_vector();
    let body = wrapper_with(&vector, |object| {
        object.as_object_mut().unwrap().remove("messageHash");
    });
    assert_matches!(fetch_malformed(body).await, RelayerError::Decode(_));
}

#[tokio::test]
async fn t_rly_06_reject_wrong_length_message_hash() {
    let vector = test_vector();
    // 31 bytes — hex-valid, but not a keccak256 digest (^0x[a-fA-F0-9]{64}$ demands 32)
    let body = wrapper_with(&vector, |object| {
        object["messageHash"] =
            json!("0x00000000000000000000000000000000000000000000000000000000000011");
    });
    assert_matches!(
        fetch_malformed(body).await,
        RelayerError::BadMessageHashLength { actual: 31 }
    );
}

#[tokio::test]
async fn t_rly_06_reject_non_hex_message_hash() {
    let vector = test_vector();
    let body = wrapper_with(&vector, |object| {
        object["messageHash"] =
            json!("0xZZ00000000000000000000000000000000000000000000000000000000000011");
    });
    assert_matches!(
        fetch_malformed(body).await,
        RelayerError::MalformedHex {
            field: HexField::MessageHash,
            ..
        }
    );
}

#[tokio::test]
async fn t_rly_06_reject_attestation_not_65_bytes() {
    let vector = test_vector();
    // 64 bytes: r‖s with the `v` byte dropped. It must be REJECTED, never zero-extended to 65.
    let body = wrapper_with(&vector, |object| {
        let sixty_four = hex::encode(&vector.attestation()[..64]);
        object["attestation"] = json!(format!("0x{sixty_four}"));
    });
    assert_matches!(
        fetch_malformed(body).await,
        RelayerError::BadAttestationLength { actual: 64 }
    );
}

/// A body that is not JSON at all (a proxy's HTML error page served with a 200) is a decode
/// rejection — not a panic, and not a silent empty result.
#[tokio::test]
async fn t_rly_06_reject_non_json_body() {
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::Body {
        status: 200,
        body: "<html><body>502 Bad Gateway</body></html>".to_string(),
    }]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    assert_matches!(
        fetch_attestation_by_message_hash(&client, HASH_PARAM)
            .await
            .expect_err("a non-JSON 200 body is a decode rejection"),
        RelayerError::Decode(_)
    );
}

// T-RLY-01 (cont.) — the response must answer the question that was ASKED
// ================================================================================================

/// `GET /v1/attestations/{depositMessageHash}` is a LOOKUP BY that hash. A response whose
/// `messageHash` is not the one requested is answering a different question — however
/// internally-consistent it is — and the relayer must refuse it.
///
/// This is the check that a server bug, a caching proxy keyed on the wrong thing, or a substitution
/// by anything on the path would otherwise slip past: the payload↔hash binding still holds (it is a
/// real attestation, for a real deposit — just NOT the deposit the relayer asked about), so every
/// other check in the chain passes and a mint note would be built for the wrong DepositIntent.
#[tokio::test]
async fn t_rly_01_by_hash_rejects_a_response_carrying_a_hash_other_than_the_one_requested() {
    let vector = test_vector();
    // the mock serves a perfectly valid attestation — for a DIFFERENT deposit than the one asked for
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(by_hash_wrapper(&vector))]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let err = fetch_attestation_by_message_hash(&client, HASH_PARAM)
        .await
        .expect_err("the response does not answer the hash that was requested");

    assert_matches!(err, RelayerError::MessageHashNotRequested { requested, returned } => {
        assert_eq!(hex::encode(requested), HASH_PARAM.trim_start_matches("0x"));
        assert_eq!(returned, vector.message_hash(), "what the server actually sent back");
        assert_ne!(requested, returned);
    });
    assert_eq!(
        sink.rejections().len(),
        1,
        "logged, never silently accepted"
    );
    assert_eq!(sink.alerts().len(), 1, "a substituted attestation alerts");
}

/// The same fixture, requested under its OWN hash, passes — so the rejection above is about the
/// mismatch, not about the fixture being unusable (a check that rejects everything proves nothing).
#[tokio::test]
async fn t_rly_01_by_hash_accepts_the_response_that_answers_the_requested_hash() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().by_hash(vec![Reply::ok(by_hash_wrapper(&vector))]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let fetched = fetch_attestation_by_message_hash(&client, &requested_hash(&vector))
        .await
        .expect("the response answers exactly the hash that was requested");

    assert_eq!(fetched.message_hash(), vector.message_hash());
    assert!(sink.rejections().is_empty());
}
