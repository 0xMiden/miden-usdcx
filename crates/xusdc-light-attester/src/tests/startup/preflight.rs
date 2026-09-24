use reqwest::{Method, StatusCode};

use crate::chain::ChainError;
use crate::circle::{read_reply, CircleClient, CircleError, REQUEST_GAP};

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

/// Requests go out one gap apart even after the worker falls behind, a queued request whose caller
/// gave up is skipped, and the worker ends once the client is dropped.
#[tokio::test(start_paused = true)]
async fn circle_requests_are_paced() {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let (circle, worker) = CircleClient::start(&load_config(&tempdir, 1)).unwrap();
    let client = &circle;
    // Plain HTTP is refused before any network I/O, so every attempt fails at once. A call returns
    // the time its answer arrived.
    let call = || async move {
        let url = "http://circle.example.invalid/".parse().unwrap();
        let error = client
            .send(reqwest::Request::new(Method::GET, url))
            .await
            .unwrap_err();
        assert!(matches!(error, CircleError::Transport(source) if source.is_builder()));
        tokio::time::Instant::now()
    };
    // The first request sets the earliest time the next one may go out.
    let mut answered = vec![call().await];

    // Polling each call once puts its request in the queue.
    let mut queued = [Box::pin(call()), Box::pin(call()), Box::pin(call())];
    std::future::poll_fn(|context| {
        for pending in &mut queued {
            assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
        }
        std::task::Poll::Ready(())
    })
    .await;
    // The worker falls behind: before it runs again, the clock passes every slot the queued
    // requests could have been given up front.
    tokio::time::advance(3 * REQUEST_GAP).await;
    for pending in queued {
        answered.push(pending.await);
    }
    for pair in answered.windows(2) {
        assert!(pair[1] - pair[0] >= REQUEST_GAP);
    }

    let given_up = tokio::time::timeout(REQUEST_GAP / 2, call()).await;
    assert!(given_up.is_err());
    let asked = tokio::time::Instant::now();
    assert!(
        call().await - asked < REQUEST_GAP,
        "the skipped request took no turn"
    );

    drop(circle);
    worker.await.unwrap();
}

/// Circle's reply is read in full up to 1 MiB and refused one byte past it.
#[tokio::test]
async fn circle_replies_are_read_within_limits() {
    let reply = |status: StatusCode, length: usize| {
        reqwest::Response::from(
            http::Response::builder()
                .status(status)
                .body(vec![b'0'; length])
                .unwrap(),
        )
    };

    let read = read_reply(reply(StatusCode::OK, 1 << 20)).await.unwrap();
    assert_eq!((read.status, read.body.len()), (StatusCode::OK, 1 << 20));
    assert!(matches!(
        read_reply(reply(StatusCode::OK, (1 << 20) + 1)).await,
        Err(CircleError::BodyTooLarge)
    ));
}
