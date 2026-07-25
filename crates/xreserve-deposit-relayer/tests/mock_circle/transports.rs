//! The [`HttpTransport`] implementations the contract tests install on the client.
//!
//! [`MockTransport`] is the mock Circle server: it takes the **real `reqwest::Request` the relayer
//! built** — its own base-URL join, its own query serialization, its own auth-header injection —
//! converts it verbatim to an `http::Request`, and drives the axum router with it via `tower`'s
//! `oneshot`. No socket is bound (the audit/CI sandbox denies `bind(127.0.0.1:0)` with EPERM), and
//! nothing is stubbed on the relayer's side of the seam: the rate governor, the backoff, the status
//! policy, the timeout, the response-size ceiling, the `Link`-cursor parse and the serde decode all
//! run for real.
//!
//! The other two transports model the two ways a peer can misbehave without ever answering:
//! [`AlwaysFailingTransport`] (the connection dies) and [`HangingTransport`] (the peer accepts the
//! request and then says nothing, forever — the availability attack that a missing timeout turns
//! into a permanently stalled relayer).

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use axum::Router;
use tower::ServiceExt;

use xreserve_deposit_relayer::circle::{HttpTransport, RawResponse};
use xreserve_deposit_relayer::error::{Cause, RelayerError};

/// The mock Circle server, as the client's transport.
#[derive(Clone)]
pub struct MockTransport {
    router: Router,
}

impl MockTransport {
    pub(crate) fn new(router: Router) -> Self {
        Self { router }
    }
}

impl fmt::Debug for MockTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MockTransport")
    }
}

impl HttpTransport for MockTransport {
    fn execute<'a>(
        &'a self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, RelayerError>> + Send + 'a>> {
        let router = self.router.clone();

        Box::pin(async move {
            let mut builder = Request::builder()
                .method(request.method().clone())
                .uri(request.url().as_str());
            for (name, value) in request.headers() {
                builder = builder.header(name.clone(), value.clone());
            }
            let http_request = builder
                .body(Body::empty())
                .expect("mock: the relayer's request converts to an http::Request");

            let response = router
                .oneshot(http_request)
                .await
                .expect("mock: the axum router is infallible");

            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("mock: the response body is in memory")
                .to_vec();

            Ok(RawResponse::new(status, headers, body))
        })
    }
}

/// A transport that fails the way a dead network does: no status, ever.
#[derive(Debug)]
pub struct AlwaysFailingTransport;

impl HttpTransport for AlwaysFailingTransport {
    fn execute<'a>(
        &'a self,
        _request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, RelayerError>> + Send + 'a>> {
        Box::pin(async {
            Err(RelayerError::Transport(Cause::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "connection refused",
            ))))
        })
    }
}

/// A transport that ACCEPTS the request and then never answers — the slowloris shape. Without a
/// request deadline the relayer waits on it forever: `max_attempts` is never reached, the
/// attestation is never submitted, and no alert is ever raised, because from the relayer's point of
/// view nothing has gone wrong yet. One unresponsive peer would stall the service indefinitely.
///
/// It counts its attempts, so a test can prove the deadline fired on EACH attempt rather than once.
#[derive(Debug, Default)]
pub struct HangingTransport {
    attempts: std::sync::atomic::AtomicU32,
}

impl HangingTransport {
    pub fn attempts(&self) -> u32 {
        self.attempts.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl HttpTransport for HangingTransport {
    fn execute<'a>(
        &'a self,
        _request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, RelayerError>> + Send + 'a>> {
        self.attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        Box::pin(async {
            // longer than any deadline a test configures: the point is that the RELAYER gives up,
            // not the peer
            tokio::time::sleep(Duration::from_secs(3600)).await;
            unreachable!("the request deadline must fire long before this resolves")
        })
    }
}
