//! `CircleClient` — the Circle-facing HTTP transport the withdrawal drivers
//! ([`withdrawal_api`](crate::withdrawal_api)) build on: the base-URL join, the auth-header injection
//! point, the transport seam, and the response-size ceiling.
//!
//! The client fixes the request-building and the transport boundary, and leaves the per-endpoint
//! status policy to the drivers (a `200` for prepare, a `201`/`409` for withdraw, a `200`/`404` for
//! the poll). It also CARRIES the two policies every attempt runs under — the bounded
//! [`RetryPolicy`] and the documented [`RateGovernor`] ceilings — because they are properties of the
//! peer being talked to, not of one call: the [`retry`](crate::circle::retry) module's backoff loop
//! reads both off the client, so a driver cannot forget to rate-limit or retry unboundedly by
//! construction.
//!
//! Two rules about the credential are enforced HERE, at construction, because by the time a request is
//! on the wire it is too late:
//!
//! 1. **A configured key requires HTTPS** ([`ListenerError::InsecureAuthTransport`]) — over plaintext
//!    the key is readable by anything on the path.
//! 2. **No redirect is ever followed** ([`ReqwestTransport`] builds with `redirect::Policy::none()`),
//!    so there is no path on which the key is re-sent to an origin the peer chose (`Q-API-AUTH` is
//!    OPEN, so the key may ride under any header name).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::Url;
use serde::Serialize;

use crate::circle::auth::AuthPosture;
use crate::circle::rate::RateGovernor;
use crate::circle::retry::RetryPolicy;
use crate::circle::transport::{HttpTransport, RawResponse, ReqwestTransport};
use crate::config::ListenerConfig;
use crate::error::{Cause, ListenerError};

/// The default response-size ceiling: 1 MiB. A Circle withdrawal object (and even a five-batch array
/// of them) is kilobytes; a body past this is refused rather than buffered whole.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1 << 20;

/// The default per-attempt request deadline the production `reqwest` client is built with. A peer
/// that accepts a request and then says nothing must not stall the driver forever.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How a status poll paces itself: the wait between non-terminal polls, and the attempt ceiling that
/// bounds [`poll_status`](crate::withdrawal_api::poll_status) so it cannot loop forever on a
/// never-terminal status.
///
/// This is NOT the [`RetryPolicy`] (which governs transient HTTP
/// FAILURES) — it is only the cadence of a poll-to-terminal loop over a healthy endpoint, where every
/// answer is a successful `200` that simply is not terminal yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollPolicy {
    interval: Duration,
    max_attempts: u32,
}

impl PollPolicy {
    /// # Panics
    /// Never — `max_attempts` of `0` is clamped to `1` so at least one poll always runs.
    pub fn new(interval: Duration, max_attempts: u32) -> Self {
        Self {
            interval,
            max_attempts: max_attempts.max(1),
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
}

impl Default for PollPolicy {
    fn default() -> Self {
        // A 2s cadence, capped at 150 attempts (~5 minutes) — a healthy withdrawal reaches a terminal
        // status well within that; the cap only bounds a stuck one.
        Self::new(Duration::from_secs(2), 150)
    }
}

/// The Circle HTTP transport: base URL, auth-header injection point, the transport seam, the
/// response-size ceiling, and the status-poll cadence.
pub struct CircleClient {
    /// The base URL as the operator wrote it (round-trips through [`Self::base_url`] unchanged).
    base_url: String,
    /// The parsed form — every request path is joined onto this.
    base: Url,
    /// Builds requests. (Executing them is the transport's job.)
    http: reqwest::Client,
    auth: AuthPosture,
    /// Pre-validated at construction, so building a request cannot fail on the header.
    auth_header: Option<(HeaderName, HeaderValue)>,
    transport: Arc<dyn HttpTransport>,
    /// Whether `transport` is still the [`ReqwestTransport`] this client built for itself (and may
    /// therefore rebuild when the ceiling changes). A caller-supplied transport owns its own limits.
    transport_is_default: bool,
    /// The SINGLE source of the response-size ceiling. The default [`ReqwestTransport`] is (re)built
    /// with exactly this value, so the production streaming enforcement and the client-side post-check
    /// never diverge.
    max_response_bytes: usize,
    poll: PollPolicy,
    /// The bounded-retry/backoff policy the submit path runs its attempts under (§10.10).
    retry: RetryPolicy,
    /// The documented rate ceilings (§10.12). An `Arc` because the GLOBAL ceiling is only global if
    /// every client in the process shares ONE governor — a per-client governor would silently turn 35
    /// QPS global into 35 QPS *each*.
    governor: Arc<RateGovernor>,
}

impl fmt::Debug for CircleClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // no `auth_header` field: its HeaderValue holds the credential (`AuthPosture`'s Debug is the
        // redacting one, and it is the only auth field rendered)
        f.debug_struct("CircleClient")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("transport", &self.transport)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("poll", &self.poll)
            .field("retry", &self.retry)
            .field("governor", &self.governor)
            .finish()
    }
}

impl CircleClient {
    /// Builds a client against `base_url` with the given auth posture, the default response-size
    /// ceiling and poll policy, and the production [`ReqwestTransport`].
    ///
    /// # Errors
    /// * [`ListenerError::BadBaseUrl`] — `base_url` is not an `http`/`https` URL, or has no host.
    /// * [`ListenerError::InsecureAuthTransport`] — a credential is configured and `base_url` is not
    ///   HTTPS.
    /// * [`ListenerError::BadAuthHeader`] — the auth header is not a legal HTTP header.
    /// * [`ListenerError::Transport`] — the HTTP stack could not be built.
    pub fn new(base_url: impl AsRef<str>, auth: AuthPosture) -> Result<Self, ListenerError> {
        let base_url = base_url.as_ref().to_string();
        let base = Url::parse(&base_url).map_err(|source| ListenerError::BadBaseUrl {
            url: base_url.clone(),
            source: Cause::new(source),
        })?;
        if !matches!(base.scheme(), "http" | "https") {
            return Err(ListenerError::BadBaseUrl {
                url: base_url.clone(),
                source: Cause::new(UnsupportedScheme(base.scheme().to_string())),
            });
        }
        if base.host_str().is_none() {
            return Err(ListenerError::BadBaseUrl {
                url: base_url.clone(),
                source: Cause::new(MissingHost),
            });
        }

        // the credential may not cross a transport that cannot protect it
        if auth.carries_credential() && base.scheme() != "https" {
            return Err(ListenerError::InsecureAuthTransport { base_url });
        }

        let auth_header = auth.to_header()?;
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|source| ListenerError::Transport(Cause::new(source)))?;

        Ok(Self {
            base_url,
            base,
            transport: Arc::new(ReqwestTransport::new(
                http.clone(),
                DEFAULT_MAX_RESPONSE_BYTES,
            )),
            transport_is_default: true,
            http,
            auth,
            auth_header,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            poll: PollPolicy::default(),
            retry: RetryPolicy::default(),
            // the DOCUMENTED ceilings by default — a client that had to be told to rate-limit would
            // be a client that forgets to
            governor: Arc::new(RateGovernor::documented()),
        })
    }

    /// The client the operator's config describes: base URL, and the auth posture the config asks for
    /// (a key iff one is configured — never a hardcoded one).
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn from_config(config: &ListenerConfig) -> Result<Self, ListenerError> {
        Self::new(config.circle_base_url(), AuthPosture::from_config(config))
    }

    /// Replaces what EXECUTES the built requests. The default is [`ReqwestTransport`] (a real socket);
    /// the contract tests install the in-process mock Circle server, so the driver's real
    /// request-building, status policy and decoders run against a real router with no network involved.
    #[must_use]
    pub fn with_transport(mut self, transport: Arc<dyn HttpTransport>) -> Self {
        self.transport = transport;
        self.transport_is_default = false;
        self
    }

    /// Sets the response-size ceiling — the SINGLE source of truth.
    ///
    /// If the client is still using the [`ReqwestTransport`] it built for itself, that transport is
    /// REBUILT with the new ceiling, so the production streaming enforcement uses exactly this value —
    /// a lower ceiling is not left checked only after a default-sized buffer, and a higher one is not
    /// still rejected early at the default. A caller-supplied transport owns its own limits and is left
    /// untouched, but the client-side post-check still applies this ceiling to it.
    #[must_use]
    pub fn with_max_response_bytes(mut self, max: usize) -> Self {
        self.max_response_bytes = max;
        if self.transport_is_default {
            self.transport = Arc::new(ReqwestTransport::new(self.http.clone(), max));
        }
        self
    }

    /// Sets the status-poll cadence and attempt ceiling.
    #[must_use]
    pub fn with_poll_policy(mut self, poll: PollPolicy) -> Self {
        self.poll = poll;
        self
    }

    /// Sets the bounded-retry/backoff policy the submit path applies to TRANSIENT failures (§10.10).
    #[must_use]
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Installs the rate governor. Pass the SAME `Arc` to every client in the process: the 35 QPS
    /// ceiling is a per-process budget, and one governor per client would multiply it by the number of
    /// clients.
    #[must_use]
    pub fn with_rate_governor(mut self, governor: Arc<RateGovernor>) -> Self {
        self.governor = governor;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The base URL's host — the key the per-IP ceiling is enforced under. The constructor refuses a
    /// base URL with no host, so this is always present.
    pub fn host(&self) -> &str {
        self.base.host_str().expect("the base url is host-checked")
    }

    pub fn auth(&self) -> &AuthPosture {
        &self.auth
    }

    pub fn poll_policy(&self) -> &PollPolicy {
        &self.poll
    }

    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.retry
    }

    pub fn rate_governor(&self) -> &RateGovernor {
        &self.governor
    }

    /// The response-size ceiling — the SINGLE source shared with the default production transport (it
    /// is (re)built with exactly this value) and applied by the client-side post-check.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// The ceiling the **installed** transport is configured with, read off the transport ITSELF (not
    /// a mirrored client field) when it is a [`ReqwestTransport`]; `None` when the installed transport
    /// is some other type.
    ///
    /// Because it downcasts the actual `Arc<dyn HttpTransport>`, it returns the DEFAULT ceiling if
    /// [`Self::with_max_response_bytes`] fails to rebuild the default transport — so a test asserting
    /// the configured value catches a removed rebuild, and the propagation is observable without a
    /// socket.
    pub fn transport_max_response_bytes(&self) -> Option<usize> {
        self.transport
            .as_any()
            .downcast_ref::<ReqwestTransport>()
            .map(ReqwestTransport::max_response_bytes)
    }

    /// Builds a `GET` request for `path`, joined onto the base URL, with the auth header injected iff
    /// one is configured.
    pub(crate) fn build_get(&self, path: &str) -> Result<reqwest::Request, ListenerError> {
        let url = self.join(path)?;
        let mut builder = self.http.get(url);
        if let Some((name, value)) = &self.auth_header {
            builder = builder.header(name.clone(), value.clone());
        }
        builder
            .build()
            .map_err(|source| ListenerError::Transport(Cause::new(source)))
    }

    /// Builds a `POST` request for `path` with `body` serialized as JSON, the auth header injected iff
    /// one is configured. Uses `reqwest`'s own JSON body codec, so the mock receives exactly the bytes
    /// the production client would put on the wire.
    pub(crate) fn build_post(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<reqwest::Request, ListenerError> {
        let url = self.join(path)?;
        let mut builder = self.http.post(url).json(body);
        if let Some((name, value)) = &self.auth_header {
            builder = builder.header(name.clone(), value.clone());
        }
        builder
            .build()
            .map_err(|source| ListenerError::Transport(Cause::new(source)))
    }

    /// Executes a built request through the installed transport, **under the rate ceilings**, enforcing
    /// the response-size ceiling.
    ///
    /// # Every request is governed here, because here is the only place they all pass through
    ///
    /// The permit is taken HERE rather than in a driver or in the retry loop, and that is the whole
    /// point: this is the one choke point every Circle request funnels through — the `prepare` POST,
    /// the `withdraw` POST and each of its retries, and every `GET /v1/withdrawal/{id}` a `409`
    /// recovery polls. A governor wrapped around the retry loop instead would cover the POST attempts
    /// and silently miss the rest, which is not a smaller ceiling but no ceiling at all on the paths it
    /// misses — and a recovery poll loop is precisely where the request count explodes (a GET per poll,
    /// per conflict, with concurrent conflicts running independent loops).
    ///
    /// Because it sits at the boundary, "a new driver forgets to rate-limit" is not a mistake that can
    /// be made: a driver that does not come through here cannot reach the transport.
    ///
    /// It is also taken exactly ONCE per request. Acquiring at two layers would not be conservative —
    /// it would spend two permits per request and silently run the service at half the documented rate.
    ///
    /// # Errors
    /// * [`ListenerError::Transport`] — the request produced no HTTP status (connection/timeout/read).
    /// * [`ListenerError::ResponseTooLarge`] — the body exceeds the ceiling. Defense in depth: the
    ///   production transport already bounds its read, but the ceiling is the CLIENT's policy, so it
    ///   holds for every transport (the mock included).
    pub(crate) async fn execute(
        &self,
        request: reqwest::Request,
    ) -> Result<RawResponse, ListenerError> {
        // waits until this request fits inside both documented ceilings (§10.12)
        let _permit = self.governor.acquire(self.host()).await;

        let response = self.transport.execute(request).await?;
        if response.body().len() > self.max_response_bytes {
            return Err(ListenerError::ResponseTooLarge {
                limit: self.max_response_bytes,
                actual: response.body().len(),
            });
        }
        Ok(response)
    }

    fn join(&self, path: &str) -> Result<Url, ListenerError> {
        self.base
            .join(path)
            .map_err(|source| ListenerError::BadBaseUrl {
                url: format!("{}{path}", self.base_url),
                source: Cause::new(source),
            })
    }
}

/// A base URL that parsed but named a scheme the client cannot speak (`ftp://…`).
#[derive(Debug)]
struct UnsupportedScheme(String);

impl fmt::Display for UnsupportedScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported url scheme `{}` (expected http or https)",
            self.0
        )
    }
}

impl core::error::Error for UnsupportedScheme {}

/// A URL that parsed but carries no host (`file:///…`).
#[derive(Debug)]
struct MissingHost;

impl fmt::Display for MissingHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("url has no host")
    }
}

impl core::error::Error for MissingHost {}
