use reqwest::{Method, StatusCode};

use crate::attester::StartError;

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

    assert!(matches!(result, Err(StartError::MidenNodeUnavailable(_))));
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

    assert!(matches!(result, Err(StartError::FaucetMissing)));
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

        assert!(matches!(result, Err(StartError::CircleUnavailable(_))));
        assert_eq!(
            *requests.lock().unwrap(),
            vec![ObservedRequest {
                method: Method::GET,
                url: "https://circle.example.invalid/v1/info".to_string(),
                timeout: Some(REQUEST_TIMEOUT),
            }]
        );
    }
}
