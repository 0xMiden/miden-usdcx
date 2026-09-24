use reqwest::{Method, StatusCode};

use crate::chain::ChainError;
use crate::circle::{CircleApi, CircleClient, CircleError, REQUEST_GAP};

use super::{
    create_store_parent, load_config, ready_circle, start, CircleState, FakeCircle,
    ObservedRequest, TestChain, REQUEST_TIMEOUT,
};

#[tokio::test]
async fn unreachable_miden_node_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let result = start(
        load_config(&tempdir, 1),
        TestChain::anchor_only().unreachable(),
        ready_circle(),
    )
    .await;

    assert!(result.err().unwrap().downcast_ref::<ChainError>().is_some());
    assert!(!store_path.exists());
}

#[tokio::test]
async fn missing_faucet_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let (circle, requests) = FakeCircle::new(CircleState::Response(StatusCode::OK));
    let result = start(
        load_config(&tempdir, 1),
        TestChain::anchor_only().faucet_missing(),
        Box::new(circle),
    )
    .await;

    assert!(result.is_err());
    assert!(!store_path.exists());
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unreachable_circle_api_is_rejected() {
    for state in [
        CircleState::TransportError,
        CircleState::Response(StatusCode::NO_CONTENT),
    ] {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = create_store_parent(&tempdir);
        let (circle, requests) = FakeCircle::new(state);
        let result = start(
            load_config(&tempdir, 1),
            TestChain::anchor_only(),
            Box::new(circle),
        )
        .await;

        assert!(result
            .err()
            .unwrap()
            .downcast_ref::<CircleError>()
            .is_some());
        assert!(!store_path.exists());
        assert_eq!(*requests.lock().unwrap(), vec![ObservedRequest::Info]);
    }

    // The real client asks for Circle's info with the configured timeout and nothing else.
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let request = CircleClient::new(&load_config(&tempdir, 1))
        .unwrap()
        .info_request()
        .unwrap();
    assert_eq!(request.method(), Method::GET);
    assert_eq!(
        request.url().as_str(),
        "https://circle.example.invalid/v1/info"
    );
    assert_eq!(request.timeout(), Some(&REQUEST_TIMEOUT));
    assert!(request.headers().is_empty());
    assert!(request.body().is_none());
}

#[tokio::test]
async fn circle_requests_are_paced() {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let client = CircleClient::new(&load_config(&tempdir, 1)).unwrap();
    let started = std::time::Instant::now();
    for _ in 0..2 {
        // Plain HTTP is refused before any network I/O, so only the pacing takes time.
        let url = "http://circle.example.invalid/".parse().unwrap();
        let request = reqwest::Request::new(Method::GET, url);
        let error = client.send(request).await.unwrap_err();
        assert!(matches!(error, CircleError::Transport(source) if source.is_builder()));
    }
    assert!(started.elapsed() >= REQUEST_GAP);
}

/// Circle's reply is read in full up to 1 MiB and refused one byte past it. A 429 pauses the rest
/// of the cycle; other answers do not.
#[tokio::test]
async fn circle_replies_are_read_within_limits() {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let client = CircleClient::new(&load_config(&tempdir, 1)).unwrap();
    let reply = |status: StatusCode, length: usize| {
        reqwest::Response::from(
            http::Response::builder()
                .status(status)
                .body(vec![b'0'; length])
                .unwrap(),
        )
    };

    let read = client
        .read_reply(reply(StatusCode::OK, 1 << 20))
        .await
        .unwrap();
    assert_eq!((read.status, read.body.len()), (StatusCode::OK, 1 << 20));
    assert!(matches!(
        client
            .read_reply(reply(StatusCode::OK, (1 << 20) + 1))
            .await,
        Err(CircleError::BodyTooLarge)
    ));

    client
        .read_reply(reply(StatusCode::SERVICE_UNAVAILABLE, 0))
        .await
        .unwrap();
    assert!(!client.rate_limited());
    client
        .read_reply(reply(StatusCode::TOO_MANY_REQUESTS, 0))
        .await
        .unwrap();
    assert!(client.rate_limited());
}
