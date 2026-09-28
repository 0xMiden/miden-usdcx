use std::sync::Arc;

use reqwest::{Method, StatusCode};

use crate::chain::ChainError;
use crate::circle::{CircleClient, CircleError, REQUEST_GAP};

use super::{
    create_store_parent, load_config, ready_circle, start, ChainState, CircleState, FakeCircle,
    ObservedRequest, REQUEST_TIMEOUT,
};

#[tokio::test]
async fn unreachable_miden_node_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let result = start(
        load_config(&tempdir, 1),
        ChainState::Unreachable,
        ready_circle(),
    )
    .await;

    assert!(result.err().unwrap().downcast_ref::<ChainError>().is_some());
    assert!(store_path.is_file());
}

#[tokio::test]
async fn missing_faucet_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let (circle, requests) = FakeCircle::new(CircleState::Response(StatusCode::OK));
    let result = start(
        load_config(&tempdir, 1),
        ChainState::FaucetMissing,
        Box::new(circle),
    )
    .await;

    assert!(result.is_err());
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unreachable_circle_api_is_rejected() {
    for state in [
        CircleState::TransportError,
        CircleState::Response(StatusCode::NO_CONTENT),
    ] {
        let tempdir = tempfile::tempdir().unwrap();
        create_store_parent(&tempdir);
        let (circle, requests) = FakeCircle::new(state);
        let result = start(
            load_config(&tempdir, 1),
            ChainState::Ready,
            Box::new(circle),
        )
        .await;

        assert!(result
            .err()
            .unwrap()
            .downcast_ref::<CircleError>()
            .is_some());
        assert_eq!(*requests.lock().unwrap(), vec![ObservedRequest::Info]);
    }

    // The real client asks for Circle's info with the configured timeout and nothing else.
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let request = CircleClient::start(&load_config(&tempdir, 1))
        .unwrap()
        .0
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

/// Requests go out one gap apart even when their callers fall behind, a queued request whose
/// caller gave up is skipped, and the worker ends once the client is dropped.
#[tokio::test]
async fn circle_requests_are_paced() {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let (client, worker) = CircleClient::start(&load_config(&tempdir, 1)).unwrap();
    let client = Arc::new(client);
    // Plain HTTP is refused before any network I/O, so every attempt fails at once.
    let request = || {
        let url = "http://circle.example.invalid/".parse().unwrap();
        reqwest::Request::new(Method::GET, url)
    };
    let calls: Vec<_> = (0..3)
        .map(|_| {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                let error = client.send(request()).await.unwrap_err();
                assert!(matches!(error, CircleError::Transport(source) if source.is_builder()));
                std::time::Instant::now()
            })
        })
        .collect();
    tokio::task::yield_now().await;
    // Block the runtime past every slot the queued requests could have been given up front.
    std::thread::sleep(2 * REQUEST_GAP);
    let mut answered = Vec::new();
    for call in calls {
        answered.push(call.await.unwrap());
    }
    for pair in answered.windows(2) {
        assert!(pair[1] - pair[0] >= REQUEST_GAP);
    }

    let given_up = tokio::time::timeout(REQUEST_GAP / 2, client.send(request())).await;
    assert!(given_up.is_err());
    let asked = std::time::Instant::now();
    assert!(client.send(request()).await.is_err());
    assert!(
        asked.elapsed() < REQUEST_GAP,
        "the skipped request took no turn"
    );

    drop(client);
    worker.await.unwrap();
}
