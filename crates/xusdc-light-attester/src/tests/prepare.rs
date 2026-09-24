//! Prepare requests and unverified responses, without signing or submitting a withdrawal.

use std::time::Duration;

use reqwest::{header::CONTENT_TYPE, Method, StatusCode};
use serde_json::{json, Value};

use crate::circle::{read_prepared, CircleClient, CircleError, PrepareBatch, RawResponse};

use super::startup::{create_store_parent, TestArgs};
use super::validation::validated_burn;
use super::verify::serial;

fn client() -> CircleClient {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    CircleClient::new(&TestArgs::new(&tempdir, 1).load()).unwrap()
}

/// Every wire field comes from the right burn value, and the salt is the note serial.
#[test]
fn prepare_sends_the_right_values() {
    let cases = [
        (0, "0.000000", 9),
        (1, "0.000001", 7),
        (1_234_567, "1.234567", 9),
        (10_000_000, "10.000000", 9),
        (9_223_372_034_707_292_160, "9223372034707.292160", 9),
    ];
    // These expected values are written independently, not produced by the request helpers.
    let expected_salt = "0x0807060504030201181716151413121128272625242322213837363534333231";
    let other_salt = "0x0807060504030201181716151413121128272625242322213937363534333231";
    let client = client();
    let expected = |value: &str, domain: u32, salt: &str| {
        json!({
            "token": "USDC",
            "remoteDomain": 10007,
            "remoteDepositor": "0x00000000000000000000000000000000ba0000000000ca110000dd000000ef00",
            "finalDestinationDomain": domain,
            "finalDestinationRecipient": "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "valueIncludingFees": value,
            "salt": salt,
            "useCircleForwarding": true,
            "forwardingOptions": {"maxFee": "0.500000", "usesFastFinality": true},
        })
    };
    let mut burns: Vec<_> = cases
        .iter()
        .map(|&(amount, value, domain)| {
            let burn = validated_burn(amount, serial(0x3132_3334_3536_3738), domain);
            (burn, expected(value, domain, expected_salt))
        })
        .collect();
    let burn = validated_burn(10_000_000, serial(0x3132_3334_3536_3739), 9);
    burns.push((burn, expected("10.000000", 9, other_salt)));
    for (burn, expected) in &burns {
        assert_eq!(
            serde_json::to_value(PrepareBatch::from_burn(burn, 500_000)).unwrap(),
            *expected
        );
    }

    let (burn, expected) = &burns[0];
    let request = client.prepare_request(burn, 500_000).unwrap();
    assert_eq!(request.method(), Method::POST);
    assert_eq!(
        request.url().as_str(),
        "https://circle.example.invalid/v1/prepare-withdrawal"
    );
    assert_eq!(request.timeout(), Some(&Duration::from_millis(275)));
    assert_eq!(
        request.headers().len(),
        1,
        "no invented auth or idempotency headers"
    );
    assert_eq!(request.headers()[CONTENT_TYPE], "application/json");
    let body = request.body().and_then(|body| body.as_bytes()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(body).unwrap(),
        json!({"batches": [expected]})
    );
}

/// Only a 200 is decoded, and decoding does not approve a response. Any other status keeps
/// Circle's status and raw body.
#[test]
fn prepare_handles_circle_responses() {
    let prepared = read_prepared(RawResponse::new(
        StatusCode::OK,
        br#"{"batches":[]}"#.to_vec(),
    ))
    .unwrap();
    assert!(prepared.batches.is_empty());
    assert!(matches!(
        read_prepared(RawResponse::new(StatusCode::OK, b"not JSON".to_vec())),
        Err(CircleError::InvalidResponse(_))
    ));
    for (status, body) in [
        (StatusCode::CREATED, br#"{"batches":[]}"#.as_slice()),
        (StatusCode::TEMPORARY_REDIRECT, b"redirect".as_slice()),
        (
            StatusCode::BAD_REQUEST,
            br#"{"message":"rejected"}"#.as_slice(),
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            b"gateway failure".as_slice(),
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            b"undocumented response".as_slice(),
        ),
    ] {
        let error = read_prepared(RawResponse::new(status, body.to_vec())).unwrap_err();
        let CircleError::UnexpectedPrepareStatus {
            status: actual_status,
            body: actual_body,
        } = error
        else {
            panic!("status and raw body must survive: {error:?}");
        };
        assert_eq!((actual_status, actual_body.as_slice()), (status, body));
    }
}
