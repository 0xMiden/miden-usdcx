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
use reqwest::Url;

use crate::error::{Cause, ListenerError};

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

    /// Upcast to [`Any`](core::any::Any) so a caller can recover the concrete transport type — e.g.
    /// to read the [`ReqwestTransport`]'s configured ceiling off the INSTALLED transport (not a
    /// mirrored client field), which is what makes the ceiling-propagation test non-tautological.
    /// Implementors return `self`.
    fn as_any(&self) -> &dyn core::any::Any;
}

/// The production transport: `reqwest` over the network. The ONLY place this crate touches a socket —
/// and this slice never does, because every gate runs against the in-process mock. It exists so
/// [`CircleClient`](crate::circle::client::CircleClient) has a real default; the contract tests
/// install the mock in its place.
///
/// It **follows no redirect** (`redirect::Policy::none()`) and backstops that with an explicit
/// final-URL check: following a 3xx would re-issue the request — carrying the credential — at an
/// origin the peer chose, and since `Q-API-AUTH` is OPEN the credential may ride under any header
/// name, which reqwest's cross-origin strip list would not cover. Circle's documented API redirects
/// nowhere, so a 3xx is simply refused.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    http: reqwest::Client,
    /// The response-size ceiling this transport enforces WHILE READING — before an oversized external
    /// body can be buffered whole.
    max_response_bytes: usize,
}

impl ReqwestTransport {
    /// A transport over an existing `reqwest::Client`, bounding every response body to
    /// `max_response_bytes`.
    pub fn new(http: reqwest::Client, max_response_bytes: usize) -> Self {
        Self {
            http,
            max_response_bytes,
        }
    }

    /// The response-size ceiling this transport enforces while streaming.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

impl HttpTransport for ReqwestTransport {
    fn execute<'a>(
        &'a self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, ListenerError>> + Send + 'a>> {
        Box::pin(async move {
            let requested_url = request.url().clone();

            let response = self
                .http
                .execute(request)
                .await
                .map_err(|source| ListenerError::Transport(Cause::new(source)))?;

            // Fail closed on a followed redirect: `Response::url()` is the FINAL url after any
            // redirect chain, so a body served by an origin the client never chose is refused rather
            // than trusted. `Policy::none()` is what prevents the hop; this is the backstop.
            check_not_redirected(&requested_url, response.url())?;

            let status = response.status().as_u16();
            let headers = response.headers().clone();

            // The ceiling is enforced WHILE READING, not after: an oversized response is refused on its
            // advertised `Content-Length` before a byte is pulled, and — if that length lied or was
            // absent (chunked transfer encoding, which is what a hostile peer sends) — on the chunk that
            // crosses the line. The bytes past the ceiling are never allocated, so a malformed/oversized
            // Circle response cannot exhaust process memory before `ResponseTooLarge` is returned.
            let mut chunks = ReqwestChunks { response };
            let body = collect_bounded(&mut chunks, self.max_response_bytes).await?;

            Ok(RawResponse::new(status, headers, body))
        })
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Enforces the response-size ceiling — before the read (on the advertised length) and during it (per
/// chunk). Both halves matter: the `Content-Length` check refuses an oversized body without allocating
/// for it, and the per-chunk check catches the body that lied about its length or never declared one.
#[derive(Debug, Clone, Copy)]
pub struct BodyLimit {
    max: usize,
    seen: usize,
}

impl BodyLimit {
    pub fn new(max: usize) -> Self {
        Self { max, seen: 0 }
    }

    /// Refuses an advertised length over the ceiling BEFORE any byte is read. An absent
    /// `Content-Length` is not a rejection — it is why [`Self::push`] exists.
    ///
    /// # Errors
    /// [`ListenerError::ResponseTooLarge`] — the advertised body exceeds the ceiling.
    pub fn check_content_length(&self, content_length: Option<u64>) -> Result<(), ListenerError> {
        match content_length {
            Some(length) if length > self.max as u64 => Err(ListenerError::ResponseTooLarge {
                limit: self.max,
                actual: length as usize,
            }),
            _ => Ok(()),
        }
    }

    /// Accounts for a chunk that just arrived.
    ///
    /// # Errors
    /// [`ListenerError::ResponseTooLarge`] — the body has now exceeded the ceiling. The caller stops
    /// reading: the bytes past the ceiling are never buffered.
    pub fn push(&mut self, chunk_len: usize) -> Result<(), ListenerError> {
        self.seen = self.seen.saturating_add(chunk_len);
        if self.seen > self.max {
            return Err(ListenerError::ResponseTooLarge {
                limit: self.max,
                actual: self.seen,
            });
        }
        Ok(())
    }
}

/// A body arriving in pieces — the shape both a `reqwest::Response` and a test's scripted body take.
/// The seam is what makes the streaming ceiling TESTABLE without a socket (the sandbox denies `bind`).
pub trait ChunkSource: Send {
    /// What `Content-Length` claims, if anything. Possibly a lie; possibly absent.
    fn advertised_len(&self) -> Option<u64>;

    /// The next chunk, or `None` at the end of the body.
    fn next_chunk(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, ListenerError>> + Send + '_>>;
}

/// Collects a body under the size ceiling — **stopping the read** the moment it is crossed, so the
/// buffer never grows past the ceiling: the accounting happens BEFORE the chunk is appended, and the
/// chunk that crosses the line is dropped, not kept.
///
/// # Errors
/// * [`ListenerError::ResponseTooLarge`] — the body exceeds `max_bytes`. The rest is never read.
/// * [`ListenerError::Transport`] — the body could not be read to its end (a truncated body is never
///   returned as a success — half a JSON document decodes into nonsense).
pub async fn collect_bounded(
    source: &mut dyn ChunkSource,
    max_bytes: usize,
) -> Result<Vec<u8>, ListenerError> {
    let mut limit = BodyLimit::new(max_bytes);
    limit.check_content_length(source.advertised_len())?;

    let mut body = Vec::new();
    while let Some(chunk) = source.next_chunk().await? {
        // account FIRST: crossing the ceiling stops the read here, and the offending chunk is never
        // appended, so the buffer cannot exceed the ceiling even by one chunk's worth of allocation
        limit.push(chunk.len())?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The adapter from `reqwest::Response` to [`ChunkSource`]. Plumbing only — every decision about what
/// to accept lives in [`collect_bounded`].
struct ReqwestChunks {
    response: reqwest::Response,
}

impl ChunkSource for ReqwestChunks {
    fn advertised_len(&self) -> Option<u64> {
        self.response.content_length()
    }

    fn next_chunk(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, ListenerError>> + Send + '_>> {
        Box::pin(async move {
            let chunk = self
                .response
                .chunk()
                .await
                .map_err(|source| ListenerError::Transport(Cause::new(source)))?;
            Ok(chunk.map(|bytes| bytes.to_vec()))
        })
    }
}

/// Refuses a response that came back from a URL other than the one requested — i.e. a redirect that
/// was followed. A backstop that makes a weakened redirect policy fail CLOSED rather than silently
/// re-send the credential.
fn check_not_redirected(requested: &Url, responded: &Url) -> Result<(), ListenerError> {
    if requested != responded {
        return Err(ListenerError::Transport(Cause::new(RedirectFollowed {
            requested: requested.to_string(),
            followed: responded.to_string(),
        })));
    }
    Ok(())
}

/// The cause behind a refused response whose final URL differs from the requested one.
#[derive(Debug)]
struct RedirectFollowed {
    requested: String,
    followed: String,
}

impl fmt::Display for RedirectFollowed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "response came from `{}`, not the requested `{}` (a redirect was followed)",
            self.followed, self.requested
        )
    }
}

impl core::error::Error for RedirectFollowed {}
