//! The [`HttpTransport`] the withdrawal-driver contract tests install on the client.
//!
//! [`MockTransport`] takes the **real `reqwest::Request` the driver built** — its own base-URL
//! join, its own JSON body codec, its own auth-header injection — converts it verbatim to an
//! `http::Request` (BODY included, so a POST's serialized JSON reaches the handler), and drives the
//! axum router with it via `tower`'s `oneshot`. No socket is bound (the audit/CI sandbox denies
//! `bind(127.0.0.1:0)` with EPERM), and nothing is stubbed on the driver's side of the seam: the
//! status policy and the serde decoders all run for real.

#![allow(dead_code)]

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::Request;
use axum::Router;
use tower::ServiceExt;

use withdrawal_listener_attester::circle::{HttpTransport, RawResponse};
use withdrawal_listener_attester::error::{Cause, ListenerError};

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
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, ListenerError>> + Send + 'a>> {
        let router = self.router.clone();

        // Capture the body the driver built (a `.json()` body is in-memory, so `as_bytes` is `Some`),
        // so the mock receives — and can assert on — exactly the wire bytes the driver produced.
        let body = request
            .body()
            .and_then(|b| b.as_bytes())
            .map(|b| b.to_vec())
            .unwrap_or_default();

        Box::pin(async move {
            let mut builder = Request::builder()
                .method(request.method().clone())
                .uri(request.url().as_str());
            for (name, value) in request.headers() {
                builder = builder.header(name.clone(), value.clone());
            }
            let http_request = builder
                .body(Body::from(body))
                .expect("mock: the driver's request converts to an http::Request");

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

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A transport that fails the way a dead network does — no status, ever — and COUNTS how many times
/// it was asked.
///
/// The count is the oracle for the money-path rule that a status-less failure must be attempted
/// EXACTLY ONCE: a timeout can strike after Circle accepted the withdrawal and before the response
/// got back, so a driver that "just retries the connection error" is issuing a second, blind `POST
/// /v1/withdraw`. Nothing else in the suite can see that — the axum mock never receives the request
/// at all when the transport itself fails, so the mock's own call log stays empty and would report
/// a retry storm as zero calls.
#[derive(Debug, Default)]
pub struct CountingFailingTransport {
    attempts: AtomicUsize,
}

impl CountingFailingTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many times a driver asked this transport to execute a request.
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl HttpTransport for CountingFailingTransport {
    fn execute<'a>(
        &'a self,
        _request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, ListenerError>> + Send + 'a>> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(ListenerError::Transport(Cause::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out waiting for a response",
            ))))
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A transport that fails the way a dead network does: no status, ever — for proving a driver
/// surfaces a status-less failure as [`ListenerError::Transport`].
#[derive(Debug)]
pub struct AlwaysFailingTransport;

impl HttpTransport for AlwaysFailingTransport {
    fn execute<'a>(
        &'a self,
        _request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, ListenerError>> + Send + 'a>> {
        Box::pin(async {
            Err(ListenerError::Transport(Cause::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "connection refused",
            ))))
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
