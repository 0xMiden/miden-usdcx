//! What actually executes a built request — and the two bounds that keep a misbehaving peer from
//! taking the relayer down without ever telling it a lie.
//!
//! # The bounds
//!
//! **A request deadline.** A peer that accepts a request and then says nothing is not an error state
//! the relayer can observe: it is just… waiting. Without a deadline it waits forever — `max_attempts`
//! is never reached, the attestation is never submitted, and no alert is ever raised, because nothing
//! has *gone wrong* yet. [`TransportLimits::request_timeout`] turns that into an ordinary transient
//! failure: bounded, logged `Pending`, retried, and finally surfaced. It is enforced in the CLIENT
//! (around whatever transport is installed) and again inside [`ReqwestTransport`] by reqwest's own
//! connect/request deadlines.
//!
//! **A response-size ceiling.** A body has no natural end. Buffering one whole, unbounded, hands any
//! peer — or anything on the path — a memory-exhaustion lever. [`BodyLimit`] refuses an oversized
//! response on its advertised `Content-Length` *before reading a byte*, and re-checks every chunk as
//! the body streams in, because a `Content-Length` can lie or be absent entirely.
//!
//! # The seam
//!
//! [`HttpTransport`] exists because the *interesting* behavior — the URL and query the relayer
//! builds, the auth header it injects, the status policy, the backoff, the rate ceilings, the
//! decoders — lives on both sides of the socket, and only the socket itself needs a network. Making
//! it injectable lets the whole contract suite exercise the relayer's real `reqwest::Request` against
//! a real router, in process, in any environment (the audit/CI sandbox denies `bind(127.0.0.1:0)`
//! outright, so a loopback-server test cannot run there at all).

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::Url;

use crate::config::RelayerConfig;
use crate::error::{Cause, RelayerError};

/// The bounds every request runs under: how long it may take, and how much it may return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLimits {
    connect_timeout: Duration,
    request_timeout: Duration,
    max_response_bytes: usize,
}

impl TransportLimits {
    /// # Errors
    /// [`RelayerError::BadTransportLimits`] — a zero deadline (which can never be met) or a zero body
    /// ceiling (which would reject every response). Refused at construction rather than at runtime.
    pub fn new(
        connect_timeout: Duration,
        request_timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, RelayerError> {
        if connect_timeout.is_zero() || request_timeout.is_zero() || max_response_bytes == 0 {
            return Err(RelayerError::BadTransportLimits {
                connect_timeout_ms: connect_timeout.as_millis() as u64,
                request_timeout_ms: request_timeout.as_millis() as u64,
                max_response_bytes,
            });
        }

        Ok(Self {
            connect_timeout,
            request_timeout,
            max_response_bytes,
        })
    }

    /// # Errors
    /// [`RelayerError::BadTransportLimits`] — as [`Self::new`].
    pub fn from_config(config: &RelayerConfig) -> Result<Self, RelayerError> {
        Self::new(
            Duration::from_millis(config.connect_timeout_ms()),
            Duration::from_millis(config.request_timeout_ms()),
            config.max_response_bytes(),
        )
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// The deadline for ONE attempt (the retry policy is what bounds the attempts).
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self::from_config(&RelayerConfig::default())
            .expect("the package-default config carries valid transport limits")
    }
}

/// Enforces the response-size ceiling — before the read, and during it.
///
/// Both halves matter. The `Content-Length` check refuses an oversized body without allocating for
/// it; the per-chunk check catches the body that lied about its length, or never declared one
/// (chunked transfer encoding), which is precisely the shape an attacker would send.
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
    /// [`RelayerError::ResponseTooLarge`] — the advertised body exceeds the ceiling.
    pub fn check_content_length(&self, content_length: Option<u64>) -> Result<(), RelayerError> {
        match content_length {
            Some(length) if length > self.max as u64 => Err(RelayerError::ResponseTooLarge {
                limit: self.max,
                actual: length as usize,
            }),
            _ => Ok(()),
        }
    }

    /// Accounts for a chunk that just arrived.
    ///
    /// # Errors
    /// [`RelayerError::ResponseTooLarge`] — the body has now exceeded the ceiling. The caller stops
    /// reading: the bytes past the ceiling are never buffered.
    pub fn push(&mut self, chunk_len: usize) -> Result<(), RelayerError> {
        self.seen = self.seen.saturating_add(chunk_len);
        if self.seen > self.max {
            return Err(RelayerError::ResponseTooLarge {
                limit: self.max,
                actual: self.seen,
            });
        }

        Ok(())
    }

    pub fn seen(&self) -> usize {
        self.seen
    }
}

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

/// What executes a built request. [`ReqwestTransport`] is the production implementation and the
/// default; the contract tests install the mock Circle server as an alternative.
///
/// An error returned here is a request that produced NO HTTP status — a connection failure, a
/// timeout, a body that could not be read — and must be [`RelayerError::Transport`], which the retry
/// policy treats as transient. An oversized body is [`RelayerError::ResponseTooLarge`], which it
/// does not.
pub trait HttpTransport: fmt::Debug + Send + Sync {
    fn execute<'a>(
        &'a self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, RelayerError>> + Send + 'a>>;
}

/// The production transport: `reqwest` over the network. The ONLY place the relayer touches a socket.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    http: reqwest::Client,
    limits: TransportLimits,
}

impl ReqwestTransport {
    /// A transport over an existing `reqwest::Client`, with the default limits.
    pub fn new(http: reqwest::Client) -> Self {
        Self::with_limits(http, TransportLimits::default())
    }

    pub fn with_limits(http: reqwest::Client, limits: TransportLimits) -> Self {
        Self { http, limits }
    }

    pub fn limits(&self) -> TransportLimits {
        self.limits
    }
}

impl HttpTransport for ReqwestTransport {
    fn execute<'a>(
        &'a self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, RelayerError>> + Send + 'a>> {
        Box::pin(async move {
            let requested_url = request.url().clone();

            let response = self
                .http
                .execute(request)
                .await
                .map_err(|source| RelayerError::Transport(Cause::new(source)))?;

            // FAIL CLOSED on a followed redirect. `Policy::none()` is what PREVENTS one; this is what
            // happens if that policy is ever weakened — `Response::url()` is the FINAL url, after any
            // redirect chain, so a body served by an origin the relayer never chose is refused rather
            // than trusted.
            check_not_redirected(&requested_url, response.url())?;

            let status = response.status().as_u16();
            let headers = response.headers().clone();

            // The ceiling is enforced WHILE READING, not after: an oversized response is refused on
            // its advertised length before a byte is pulled, and — if that length lied, or was absent
            // (chunked transfer encoding, which is what a hostile peer sends) — on the chunk that
            // crosses the line. The bytes past the ceiling are never allocated. The policy lives in
            // `collect_bounded`; what follows is the adapter that hands it reqwest's chunks.
            let max = self.limits.max_response_bytes();
            let mut chunks = ReqwestChunks { response };
            let body = collect_bounded(&mut chunks, max).await?;

            Ok(RawResponse::new(status, headers, body))
        })
    }
}

/// A body arriving in pieces — the shape both `reqwest::Response` and a test's scripted body take.
///
/// This trait is the seam that makes the response-size ceiling TESTABLE. The ceiling is an
/// availability property of the *streaming* path ("stop before collecting it"), and that path lives
/// inside the production transport, which cannot be driven here: the sandbox denies `bind()`, so no
/// server exists to answer a real request, and reqwest exposes no way to hand it a connection
/// (`connect::Conn` is sealed). Rather than leave the enforcement untested — where it silently
/// regressed once already — the loop is expressed over this trait, and a test feeds it exactly what
/// an attacker would: an endless body with no `Content-Length`.
pub trait ChunkSource: Send {
    /// What `Content-Length` claims, if anything. Possibly a lie; possibly absent.
    fn advertised_len(&self) -> Option<u64>;

    /// The next chunk, or `None` at the end of the body.
    fn next_chunk(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, RelayerError>> + Send + '_>>;
}

/// Collects a body under the size ceiling — **stopping the read** the moment it is crossed.
///
/// Both halves matter. The `Content-Length` pre-check refuses an oversized body without allocating
/// for it at all; the per-chunk check catches the body that lied about its length or never declared
/// one. And the accounting happens BEFORE the chunk is appended, so the buffer never grows past the
/// ceiling: the chunk that crosses the line is dropped, not kept.
///
/// # Errors
/// * [`RelayerError::ResponseTooLarge`] — the body exceeds `max_bytes`. The rest of it is never read.
/// * [`RelayerError::Transport`] — the body could not be read to its end. A truncated body is never
///   returned as a success: half a JSON document decodes into nonsense, or worse, into a valid-looking
///   prefix.
pub async fn collect_bounded(
    source: &mut dyn ChunkSource,
    max_bytes: usize,
) -> Result<Vec<u8>, RelayerError> {
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

/// The adapter from `reqwest::Response` to [`ChunkSource`]. Plumbing only — every decision about
/// what to accept lives in [`collect_bounded`].
struct ReqwestChunks {
    response: reqwest::Response,
}

impl ChunkSource for ReqwestChunks {
    fn advertised_len(&self) -> Option<u64> {
        self.response.content_length()
    }

    fn next_chunk(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, RelayerError>> + Send + '_>> {
        Box::pin(async move {
            let chunk = self
                .response
                .chunk()
                .await
                .map_err(|source| RelayerError::Transport(Cause::new(source)))?;

            Ok(chunk.map(|bytes| bytes.to_vec()))
        })
    }
}

/// The relayer's redirect policy — a named seam, so the value the production client is built with can
/// be asserted (the client itself cannot be introspected, and no redirect can be exercised without a
/// network).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// Follow nothing. Following a redirect re-issues the request at an origin the PEER chose,
    /// carrying the credential with it — and reqwest strips only a fixed set of STANDARD header names
    /// on a cross-origin hop (`Authorization`, `Cookie`, `Proxy-Authorization`, `WWW-Authenticate`).
    /// `Q-API-AUTH` is OPEN, so the relayer's credential header may be called anything at all, and
    /// that list would not cover it. Circle's documented API redirects nowhere, so nothing legitimate
    /// is lost — and a 3xx simply becomes a permanent rejection.
    Never,
}

impl RedirectPolicy {
    /// The reqwest value the client is built with.
    pub fn to_reqwest(self) -> reqwest::redirect::Policy {
        match self {
            Self::Never => reqwest::redirect::Policy::none(),
        }
    }
}

/// Refuses a response that came back from a URL other than the one requested — i.e. a redirect that
/// was followed.
///
/// This is a BACKSTOP, and it is worth being precise about what it does and does not do:
/// [`RedirectPolicy::Never`] is what *prevents* a redirect from being followed (and therefore
/// prevents the credential from ever being re-sent). This check is what makes a regression of that
/// policy FAIL CLOSED instead of passing silently: the relayer refuses a body served by an origin it
/// never chose, rejects, and alerts.
///
/// # Errors
/// [`RelayerError::RedirectFollowed`] — the final URL is not the requested one.
pub fn check_not_redirected(requested: &Url, responded: &Url) -> Result<(), RelayerError> {
    if requested != responded {
        return Err(RelayerError::RedirectFollowed {
            requested: requested.to_string(),
            followed: responded.to_string(),
        });
    }

    Ok(())
}

/// Builds the production `reqwest::Client` under `limits` — the ONE HTTP client this crate creates.
///
/// Two settings are load-bearing, and neither is a default:
///
/// * **connect + request deadlines** — reqwest's defaults are `None` (wait forever).
/// * **[`RedirectPolicy::Never`]** — reqwest's default follows up to 10 redirects. See that type for
///   why following even one is a credential-exfiltration path here.
///
/// # Errors
/// [`RelayerError::Transport`] — the HTTP stack could not be built.
pub(crate) fn build_http_client(limits: &TransportLimits) -> Result<reqwest::Client, RelayerError> {
    reqwest::Client::builder()
        .connect_timeout(limits.connect_timeout())
        .timeout(limits.request_timeout())
        .redirect(RedirectPolicy::Never.to_reqwest())
        .build()
        .map_err(|source| RelayerError::Transport(Cause::new(source)))
}
