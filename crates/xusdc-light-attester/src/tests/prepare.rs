//! Prepare requests and unverified responses, without signing or submitting a withdrawal.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use miden_protocol::{Felt, Word};
use reqwest::{header::CONTENT_TYPE, Method, StatusCode};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::circle::{CircleClient, CircleError, ReqwestTransport, UnverifiedPrepareResponse};
use crate::config::Config;

use super::startup::{config_toml, create_store_parent};
use super::support::{CircleState, FakeCircle, ObservedRequest};
use super::validation::validated_burn;

fn serial(last: u64) -> Word {
    Word::new([
        Felt::new(0x0102_0304_0506_0708).unwrap(),
        Felt::new(0x1112_1314_1516_1718).unwrap(),
        Felt::new(0x2122_2324_2526_2728).unwrap(),
        Felt::new(last).unwrap(),
    ])
}

fn client(state: CircleState) -> (CircleClient, Arc<Mutex<Vec<ObservedRequest>>>) {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let path = tempdir.path().join("attester.toml");
    std::fs::write(&path, config_toml(1)).unwrap();
    let config = Config::load(&path).unwrap();
    let (transport, requests) = FakeCircle::new(state);
    (
        CircleClient::new(
            config.circle_api_base_url().clone(),
            config.circle_request_timeout(),
            Box::new(transport),
        ),
        requests,
    )
}

/// Every wire field comes from the right burn value; repeat calls keep the same serial salt.
#[tokio::test]
async fn prepare_sends_the_right_values() {
    let cases = [
        (0, "0.000000", 9),
        (1, "0.000001", 7),
        (1_234_567, "1.234567", 9),
        (10_000_000, "10.000000", 9),
        (9_223_372_034_707_292_160, "9223372034707.292160", 9),
    ];
    let mut burns: Vec<_> = cases
        .iter()
        .map(|(amount, _, domain)| validated_burn(*amount, serial(0x3132_3334_3536_3738), *domain))
        .collect();
    burns.push(validated_burn(10_000_000, serial(0x3132_3334_3536_3739), 9));

    // These expected bytes are written independently, not produced by the request helpers.
    let expected_salt = "0x0807060504030201181716151413121128272625242322213837363534333231";
    let other_salt = "0x0807060504030201181716151413121128272625242322213937363534333231";
    for forwarding in [false, true] {
        let (client, requests) = client(CircleState::ResponseBody(
            StatusCode::OK,
            br#"{"batches":[]}"#.to_vec(),
        ));
        for burn in &burns {
            client.prepare_withdrawal(burn, forwarding).await.unwrap();
        }
        client
            .prepare_withdrawal(&burns[0], forwarding)
            .await
            .unwrap();

        let mut expected: Vec<_> = cases.iter().map(|(_, amount, domain)| json!({
            "token": "USDC",
            "remoteDomain": 10007,
            "remoteDepositor": "0x00000000000000000000000000000000ba0000000000ca110000dd000000ef00",
            "finalDestinationDomain": domain,
            "finalDestinationRecipient": "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "valueIncludingFees": amount,
            "salt": expected_salt,
            "useCircleForwarding": forwarding,
        })).collect();
        let mut same_parameters = expected[3].clone();
        same_parameters["salt"] = json!(other_salt);
        expected.push(same_parameters);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), burns.len() + 1, "one POST per burn");
        for (request, expected) in requests
            .iter()
            .zip(expected.iter().chain(std::iter::once(&expected[0])))
        {
            assert_eq!(request.method, Method::POST);
            assert_eq!(
                request.url,
                "https://circle.example.invalid/v1/prepare-withdrawal"
            );
            assert_eq!(request.timeout, Some(Duration::from_millis(275)));
            assert_eq!(
                request.headers.len(),
                1,
                "no invented auth or idempotency headers"
            );
            assert_eq!(request.headers[CONTENT_TYPE], "application/json");
            assert_eq!(
                serde_json::from_slice::<Value>(&request.body).unwrap(),
                json!({"batches": [expected]})
            );
        }
    }
}

// Wire-shaped fixture only: neither these bytes nor the digest are a cryptographic test vector.
fn circle_response() -> Value {
    json!({"batches": [{
        "burnIntents": [{
            "maxBlockHeight": "184467440737095516170000",
            "maxFee": "003",
            "spec": {
                "version": 1,
                "sourceDomain": 6,
                "destinationDomain": 7,
                "sourceContract": "0x11",
                "destinationContract": "0x22",
                "sourceToken": "0x33",
                "destinationToken": "0x44",
                "sourceDepositor": "0x55",
                "destinationRecipient": "0x66",
                "sourceSigner": "0x77",
                "destinationCaller": "0x88",
                "value": "00097",
                "salt": "0x99",
                "hookData": {
                    "remoteDomain": 8,
                    "remoteDepositor": "0xaa",
                    "remoteToken": "0xbb",
                    "forwardingContractAddress": "0x0",
                    "forwardingCalldata": "0x12345678"
                }
            }
        }],
        "encoded": "0x1234",
        "messageHashToSign": "0x5678"
    }]})
}

/// Decoding does not approve a response; malformed replies and request failures remain errors.
#[tokio::test]
async fn prepare_handles_circle_responses() {
    let burn = validated_burn(100, serial(0x3132_3334_3536_3738), 9);
    let mut reply = circle_response();
    let mut other_intent = reply["batches"][0]["burnIntents"][0].clone();
    other_intent["maxFee"] = json!("004");
    reply["batches"][0]["burnIntents"]
        .as_array_mut()
        .unwrap()
        .push(other_intent);
    let mut other_batch = reply["batches"][0].clone();
    other_batch["encoded"] = json!("0xabcd");
    other_batch["messageHashToSign"] = json!("0xef01");
    reply["batches"].as_array_mut().unwrap().push(other_batch);
    reply["newServerField"] = json!(true);
    let (circle, requests) = client(CircleState::ResponseBody(
        StatusCode::OK,
        reply.to_string().into_bytes(),
    ));
    let response = circle.prepare_withdrawal(&burn, false).await.unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(response.batches.len(), 2);
    for (batch, encoded, hash) in [
        (&response.batches[0], "0x1234", "0x5678"),
        (&response.batches[1], "0xabcd", "0xef01"),
    ] {
        assert_eq!(
            (&*batch.encoded, &*batch.message_hash_to_sign),
            (encoded, hash)
        );
        assert_eq!(batch.burn_intents.len(), 2);
        for (intent, fee) in batch.burn_intents.iter().zip(["003", "004"]) {
            assert_eq!(
                (&*intent.max_block_height, &*intent.max_fee),
                ("184467440737095516170000", fee)
            );
            let spec = &intent.spec;
            assert_eq!(
                (spec.version, spec.source_domain, spec.destination_domain),
                (1, 6, 7)
            );
            assert_eq!(
                [
                    &*spec.source_contract,
                    &*spec.destination_contract,
                    &*spec.source_token,
                    &*spec.destination_token,
                    &*spec.source_depositor,
                    &*spec.destination_recipient,
                    &*spec.source_signer,
                    &*spec.destination_caller,
                    &*spec.value,
                    &*spec.salt
                ],
                ["0x11", "0x22", "0x33", "0x44", "0x55", "0x66", "0x77", "0x88", "00097", "0x99"]
            );
            let hook = &spec.hook_data;
            assert_eq!(hook.remote_domain, 8);
            assert_eq!(
                [
                    &*hook.remote_depositor,
                    &*hook.remote_token,
                    &*hook.forwarding_contract_address,
                    &*hook.forwarding_calldata
                ],
                ["0xaa", "0xbb", "0x0", "0x12345678"]
            );
        }
    }

    let mut missing = circle_response();
    missing["batches"][0]
        .as_object_mut()
        .unwrap()
        .remove("messageHashToSign");
    let mut wrong_shape = circle_response();
    wrong_shape["batches"][0]["burnIntents"] = json!({});
    for body in [
        b"not JSON".to_vec(),
        missing.to_string().into_bytes(),
        wrong_shape.to_string().into_bytes(),
    ] {
        let (circle, requests) = client(CircleState::ResponseBody(StatusCode::OK, body));
        assert!(matches!(
            circle.prepare_withdrawal(&burn, false).await,
            Err(CircleError::InvalidResponse(_))
        ));
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
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
        let (circle, requests) = client(CircleState::ResponseBody(status, body.to_vec()));
        let error = circle.prepare_withdrawal(&burn, false).await.unwrap_err();
        let CircleError::UnexpectedPrepareStatus {
            status: actual_status,
            body: actual_body,
        } = error
        else {
            panic!("status and raw body must survive: {error:?}");
        };
        assert_eq!((actual_status, actual_body.as_slice()), (status, body));
        assert_eq!(requests.lock().unwrap().len(), 1, "no automatic retry");
    }
    let (circle, requests) = client(CircleState::TransportError);
    assert!(matches!(
        circle.prepare_withdrawal(&burn, false).await,
        Err(CircleError::Unavailable)
    ));
    assert_eq!(requests.lock().unwrap().len(), 1);

    let body = circle_response().to_string();
    let response = real_http_response(StatusCode::OK, &body, false)
        .await
        .unwrap();
    assert_eq!(
        response.batches[0].encoded, "0x1234",
        "real transport must read the body"
    );
    assert!(
        matches!(
            real_http_response(StatusCode::OK, &body, true).await,
            Err(CircleError::Transport(_))
        ),
        "truncated body is a transport error"
    );
    assert!(
        matches!(
            real_http_response(StatusCode::OK, &"0".repeat((1 << 20) + 1), false).await,
            Err(CircleError::BodyTooLarge)
        ),
        "a body over the cap is refused before it is buffered"
    );
    let error = real_http_response(StatusCode::TEMPORARY_REDIRECT, "redirect body", false)
        .await
        .unwrap_err();
    assert!(
        matches!(error, CircleError::UnexpectedPrepareStatus { status: StatusCode::TEMPORARY_REDIRECT, body } if body == b"redirect body"),
        "do not follow redirects"
    );
}

/// One bounded local exchange, including deliberate truncation and redirect cases.
async fn real_http_response(
    status: StatusCode,
    body: &str,
    truncate: bool,
) -> Result<UnverifiedPrepareResponse, CircleError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let circle = CircleClient::new(
        url.parse().unwrap(),
        Duration::from_secs(2),
        Box::new(ReqwestTransport::new().unwrap()),
    );
    let burn = validated_burn(100, serial(0x3132_3334_3536_3738), 9);
    let serve = async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
            }
        }
        assert!(content_length < 4096);
        reader
            .read_exact(&mut vec![0; content_length])
            .await
            .unwrap();
        let response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nLocation: {url}/redirected\r\nConnection: close\r\n\r\n{body}", body.len() + usize::from(truncate));
        let mut stream = reader.into_inner();
        // The client may hang up early (an oversized body), so write errors are not failures.
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        let ((), result) = tokio::join!(serve, circle.prepare_withdrawal(&burn, false));
        result
    })
    .await
    .expect("local HTTP exchange must finish")
}
