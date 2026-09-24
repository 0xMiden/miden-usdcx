use reqwest::{Method, StatusCode};

use crate::chain::ChainError;
use crate::circle::{CircleClient, CircleError, HttpTransport, ReqwestTransport, REQUEST_GAP};

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
    let transport = Box::new(ReqwestTransport::new().unwrap());
    let request = CircleClient::new(&load_config(&tempdir, 1), transport)
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
    let transport = ReqwestTransport::new().unwrap();
    let started = std::time::Instant::now();
    for _ in 0..2 {
        // A non-HTTP URL fails before any network I/O, so only the pacing takes time.
        let url = "ftp://circle.example.invalid/".parse().unwrap();
        let request = reqwest::Request::new(Method::GET, url);
        assert!(transport.execute(request).await.is_err());
    }
    assert!(started.elapsed() >= REQUEST_GAP);
}
