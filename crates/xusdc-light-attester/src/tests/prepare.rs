//! Prepare requests and unverified responses, without signing or submitting a withdrawal.

use std::collections::BTreeSet;
use std::time::Duration;

use reqwest::{header::CONTENT_TYPE, Method, StatusCode};
use serde_json::{json, Value};

use crate::burn::DiscoveredBurn;
use crate::circle::{read_prepared, CircleClient, CircleError, PrepareBatch, RawResponse};
use crate::config::Config;

use super::startup::{config_toml, create_store_parent};
use super::validation::discovered_burn;
use super::verify::serial;

/// A client for building requests. Its request worker runs on Tokio, so a test using it is async.
fn client() -> CircleClient {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let path = tempdir.path().join("attester.toml");
    std::fs::write(&path, config_toml(1)).unwrap();
    CircleClient::start(&Config::load(&path).unwrap())
        .unwrap()
        .0
}

/// Every wire field comes from the right burn value, and the salt is the burn's note ID, so burns
/// whose notes reuse one serial number still get different salts.
#[tokio::test]
async fn prepare_sends_the_right_values() {
    let cases = [
        (0, "0.000000", 9),
        (1, "0.000001", 7),
        (1_234_567, "1.234567", 9),
        (10_000_000, "10.000000", 9),
        (9_223_372_034_707_292_160, "9223372034707.292160", 9),
    ];
    let client = client();
    for forwarding in [false, true] {
        // Apart from the salt, which is each burn's note ID, these expected values are written
        // independently, not produced by the request helpers.
        let expected = |burn: &DiscoveredBurn, value: &str, domain: u32| {
            json!({
                "token": "USDC",
                "remoteDomain": 10007,
                "remoteDepositor": "0x00000000000000000000000000000000ba0000000000ca110000dd000000ef00",
                "finalDestinationDomain": domain,
                "finalDestinationRecipient": "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "valueIncludingFees": value,
                "salt": burn.note_id().to_hex(),
                "useCircleForwarding": forwarding,
            })
        };
        let mut burns: Vec<_> = cases
            .iter()
            .map(|&(amount, value, domain)| {
                let burn = discovered_burn(amount, serial(0x3132_3334_3536_3738), domain);
                let expected = expected(&burn, value, domain);
                (burn, expected)
            })
            .collect();
        let burn = discovered_burn(10_000_000, serial(0x3132_3334_3536_3739), 9);
        let other = expected(&burn, "10.000000", 9);
        burns.push((burn, other));
        for (burn, expected) in &burns {
            assert_eq!(
                serde_json::to_value(PrepareBatch::from_burn(burn, forwarding)).unwrap(),
                *expected
            );
        }
        let salts: BTreeSet<_> = burns
            .iter()
            .map(|(_, expected)| expected["salt"].to_string())
            .collect();
        assert_eq!(salts.len(), burns.len());

        let (burn, expected) = &burns[0];
        let request = client.prepare_request(burn, forwarding).unwrap();
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
}

#[test]
fn prepare_salt_is_unique_per_burn_and_stable_on_retry() {
    let first = discovered_burn(1_000_000, serial(7), 9);
    let second = discovered_burn(2_000_000, serial(7), 9);
    assert_ne!(first.note_id(), second.note_id());
    let salt =
        |burn| serde_json::to_value(PrepareBatch::from_burn(burn, false)).unwrap()["salt"].clone();
    assert_eq!(salt(&first), salt(&first), "retry must keep the salt");
    assert_ne!(
        salt(&first),
        salt(&second),
        "distinct burns need distinct salts"
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
