//! The transport seam the Circle drivers will be built on.
//!
//! This slice makes **no Circle call**. What it fixes is the shape of the boundary: [`HttpTransport`]
//! is the injectable seam, and it exists because the *interesting* behavior — the URL and query the
//! listener builds, the auth header it injects, the status policy, the backoff, the decoders — lives
//! on both sides of the socket, and only the socket itself needs a network.
//!
//! That matters concretely here. The audit/CI sandbox denies `bind(127.0.0.1:0)` outright (EPERM), so
//! a loopback-server mock cannot be part of a gate that has to be green in every environment. With
//! the seam, the withdrawal drivers (W6) can be exercised end to end against a schema-exact mock
//! Circle server routed by `axum` and driven IN PROCESS through `tower`'s `ServiceExt::oneshot` — the
//! pattern the deposit relayer already proved — while still building a real `reqwest::Request`.
//!
//! The seam is defined now, with the crate scaffold, so the drivers are written against it from the
//! first line rather than being retrofitted onto a client that had already grown a hard-wired
//! `reqwest::Client` inside it.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use reqwest::header::HeaderMap;

use crate::error::ListenerError;

/// An HTTP response, exactly as it came back: status, headers, body. No interpretation — the status
/// policy and the decoders are the client's job, not the transport's.
#[derive(Debug, Clone)]
pub struct RawResponse {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl RawResponse {
    pub fn new(status: u16, headers: HeaderMap, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// The HTTP status — the contract the error fixtures are keyed on (400 / 409 / 500 / 404). It is
    /// deliberately NOT interpreted here: a 409 in particular is a duplicate *conflict* requiring
    /// recovery, never a success (§10.10), and that judgement belongs to the status policy.
    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// What executes a built request. The production implementation (reqwest over the network) and the
/// in-process mock Circle server both land with the driver slice (W6); this is the trait they will
/// both satisfy.
///
/// An error returned here is a request that produced NO HTTP status — a connection failure, a
/// timeout, a body that could not be read — and must be [`ListenerError::Transport`], which the retry
/// policy treats as transient. An oversized body is [`ListenerError::ResponseTooLarge`], which it
/// does not.
pub trait HttpTransport: fmt::Debug + Send + Sync {
    fn execute<'a>(
        &'a self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, ListenerError>> + Send + 'a>>;
}
