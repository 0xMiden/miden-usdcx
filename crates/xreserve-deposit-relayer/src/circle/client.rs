//! `CircleClient` — the Circle-facing HTTP transport and the policies that govern every request:
//! the rate ceilings ([`RateGovernor`]), the exponential backoff ([`with_backoff`]), the HTTP-status
//! policy ([`classify_status`]), the request deadline and the response-size ceiling
//! ([`TransportLimits`]), and the auth-header injection point ([`AuthPosture`]).
//!
//! Two rules about the credential are enforced HERE, at construction, because by the time a request
//! is on the wire it is too late:
//!
//! 1. **A configured key requires HTTPS.** Over plaintext the key is readable by anything on the
//!    path, and no amount of redaction in the logs changes that. A base URL without TLS + a
//!    configured credential is refused ([`RelayerError::InsecureAuthTransport`]) — at startup, not
//!    after the key has already been sent. A plaintext base URL with NO credential is fine: the
//!    documented API declares no auth at all, and the relayer does not invent a TLS requirement it
//!    does not have; it protects the key it was given.
//! 2. **No redirect is ever followed** (see [`build_http_client`]), so there is no code path on which
//!    the key is re-sent to an origin the peer chose.

use std::fmt;
use std::sync::Arc;

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::Url;

use crate::circle::auth::AuthPosture;
use crate::circle::rate::RateGovernor;
use crate::circle::retry::{with_backoff, RetryContext, RetryPolicy};
use crate::circle::status::{classify_status, StatusClass};
use crate::circle::transport::{
    build_http_client, HttpTransport, ReqwestTransport, TransportLimits,
};
use crate::config::RelayerConfig;
use crate::error::{Cause, RelayerError};
use crate::observability::{EventSink, NoopSink, RelayerEvent};

/// A successful (2xx) Circle response: the raw body, plus the `Link` header if there was one.
pub(crate) struct HttpOk {
    pub(crate) body: Vec<u8>,
    pub(crate) link: Option<String>,
}

/// The Circle HTTP transport: base URL, auth-header injection point, transport limits, rate
/// governor, retry policy, event sink.
pub struct CircleClient {
    /// The base URL as the operator wrote it (round-trips through `base_url()` unchanged).
    base_url: String,
    /// The parsed form — every request path is joined onto this, and it is the base a relative
    /// `Link` href resolves against.
    base: Url,
    /// The rate-governor key: the per-IP ceiling is per HOST.
    host: String,
    /// Builds requests. (Executing them is the transport's job.)
    http: reqwest::Client,
    auth: AuthPosture,
    /// Pre-validated at construction, so building a request cannot fail.
    auth_header: Option<(HeaderName, HeaderValue)>,
    transport: Arc<dyn HttpTransport>,
    /// Whether `transport` is still the one this client built (and may therefore rebuild when the
    /// limits change) — a caller-supplied transport owns its own dialing.
    transport_is_default: bool,
    limits: TransportLimits,
    governor: Arc<RateGovernor>,
    retry_policy: RetryPolicy,
    sink: Arc<dyn EventSink>,
}

impl fmt::Debug for CircleClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // no `auth_header` field: its HeaderValue holds the credential (`AuthPosture`'s Debug is the
        // redacting one, and it is the only auth field rendered)
        f.debug_struct("CircleClient")
            .field("base_url", &self.base_url)
            .field("host", &self.host)
            .field("auth", &self.auth)
            .field("transport", &self.transport)
            .field("limits", &self.limits)
            .field("governor", &self.governor)
            .field("retry_policy", &self.retry_policy)
            .finish()
    }
}

impl CircleClient {
    /// Builds a client against `base_url` with the given auth posture, the DOCUMENTED rate ceilings
    /// (5 QPS/IP, 35 QPS global), the default transport limits and retry policy, and no event sink
    /// ([`NoopSink`]).
    ///
    /// # Errors
    /// * [`RelayerError::BadBaseUrl`] — `base_url` is not a URL, or has no host.
    /// * [`RelayerError::InsecureAuthTransport`] — a credential is configured and `base_url` is not
    ///   HTTPS.
    /// * [`RelayerError::BadAuthHeader`] — the auth header is not a legal HTTP header.
    /// * [`RelayerError::Transport`] — the HTTP stack could not be built.
    pub fn new(base_url: impl AsRef<str>, auth: AuthPosture) -> Result<Self, RelayerError> {
        let base_url = base_url.as_ref().to_string();
        let base = Url::parse(&base_url).map_err(|source| RelayerError::BadBaseUrl {
            url: base_url.clone(),
            source: Cause::new(source),
        })?;
        let host = base
            .host_str()
            .ok_or_else(|| RelayerError::BadBaseUrl {
                url: base_url.clone(),
                source: Cause::new(MissingHost),
            })?
            .to_string();

        // the credential may not cross a transport that cannot protect it
        if auth.carries_credential() && base.scheme() != "https" {
            return Err(RelayerError::InsecureAuthTransport { url: base_url });
        }

        let auth_header = auth.to_header()?;
        let limits = TransportLimits::default();
        let http = build_http_client(&limits)?;

        Ok(Self {
            base_url,
            base,
            host,
            transport: Arc::new(ReqwestTransport::with_limits(http.clone(), limits)),
            transport_is_default: true,
            http,
            auth,
            auth_header,
            limits,
            governor: Arc::new(RateGovernor::from_config(&RelayerConfig::default())?),
            retry_policy: RetryPolicy::from_config(&RelayerConfig::default())?,
            sink: Arc::new(NoopSink),
        })
    }

    /// The client the operator's config describes: base URL, auth posture (a key iff one is
    /// configured — never a hardcoded one), transport limits, rate ceilings, retry policy.
    ///
    /// # Errors
    /// As [`Self::new`], plus [`RelayerError::BadRateLimit`] / [`RelayerError::BadRetryPolicy`] /
    /// [`RelayerError::BadTransportLimits`] for an impossible configuration.
    pub fn from_config(config: &RelayerConfig) -> Result<Self, RelayerError> {
        Ok(
            Self::new(config.circle_base_url(), AuthPosture::from_config(config))?
                .with_transport_limits(TransportLimits::from_config(config)?)
                .with_governor(Arc::new(RateGovernor::from_config(config)?))
                .with_retry_policy(RetryPolicy::from_config(config)?),
        )
    }

    /// Replaces what EXECUTES the built requests. The default is [`ReqwestTransport`] (a real
    /// socket); the contract tests install the mock Circle server, so the relayer's real
    /// request-building, status policy, backoff and decoders run against a real router with no
    /// network involved.
    #[must_use]
    pub fn with_transport(mut self, transport: Arc<dyn HttpTransport>) -> Self {
        self.transport = transport;
        self.transport_is_default = false;
        self
    }

    /// Sets the request deadline and the response-size ceiling.
    ///
    /// If the client is still using the transport it built for itself, that transport is rebuilt so
    /// reqwest's own connect/request deadlines match the new limits. A caller-supplied transport is
    /// left alone — it owns its own dialing — but the client-side deadline still bounds it, so a
    /// custom transport cannot hang the relayer either.
    #[must_use]
    pub fn with_transport_limits(mut self, limits: TransportLimits) -> Self {
        if self.transport_is_default {
            if let Ok(http) = build_http_client(&limits) {
                self.http = http.clone();
                self.transport = Arc::new(ReqwestTransport::with_limits(http, limits));
            }
        }
        self.limits = limits;
        self
    }

    /// Shares a governor with other clients — which is how the 35 QPS GLOBAL ceiling becomes global
    /// rather than per-client.
    #[must_use]
    pub fn with_governor(mut self, governor: Arc<RateGovernor>) -> Self {
        self.governor = governor;
        self
    }

    #[must_use]
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Installs the observability sink. Until one is installed, events go to [`NoopSink`].
    #[must_use]
    pub fn with_event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.sink = sink;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn auth(&self) -> &AuthPosture {
        &self.auth
    }

    pub fn governor(&self) -> &RateGovernor {
        &self.governor
    }

    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.retry_policy
    }

    pub fn transport_limits(&self) -> TransportLimits {
        self.limits
    }

    pub fn event_sink(&self) -> &dyn EventSink {
        self.sink.as_ref()
    }

    /// The parsed base URL — the base a relative `Link` href resolves against.
    pub(crate) fn base(&self) -> &Url {
        &self.base
    }

    /// Records a PERMANENT rejection (a decode failure, a broken binding, malformed pagination
    /// metadata, a malformed request parameter) and hands the error back unchanged: it is logged with
    /// its reason and alerted, and never silently dropped (§8.4). The status-code rejections are
    /// recorded by [`with_backoff`], which is where a status is decided.
    pub(crate) fn reject(&self, endpoint: &str, error: RelayerError) -> RelayerError {
        self.sink.emit(RelayerEvent::Rejected {
            endpoint: endpoint.to_string(),
            reason: error.to_string(),
        });
        self.sink.emit(RelayerEvent::Alert {
            endpoint: endpoint.to_string(),
            reason: error.to_string(),
        });
        error
    }

    /// GETs `path` under the full policy stack: rate ceilings, request deadline, exponential backoff,
    /// HTTP-status policy, response-size ceiling. Returns the 2xx body (and its `Link` header); every
    /// non-2xx becomes a [`RelayerError::Http`], retried or rejected per its class.
    pub(crate) async fn get(
        &self,
        endpoint: &str,
        path: &str,
        query: &[(&'static str, String)],
    ) -> Result<HttpOk, RelayerError> {
        let context = RetryContext::new(
            &self.governor,
            &self.host,
            &self.retry_policy,
            self.sink.as_ref(),
            endpoint,
        );
        with_backoff(&context, || self.send(path, query)).await
    }

    /// One attempt, under the deadline: build the request (injecting the auth header if one is
    /// configured), execute it through the transport, apply the status policy, enforce the size
    /// ceiling. **A non-2xx body is never parsed** — the OpenAPI documents no error-body schema, so
    /// the status alone decides.
    async fn send(
        &self,
        path: &str,
        query: &[(&'static str, String)],
    ) -> Result<HttpOk, RelayerError> {
        let request = self.build_request(path, query)?;

        // THE deadline — around whatever transport is installed, so no transport (production or
        // otherwise) can leave the relayer waiting on a peer that will never answer.
        let response = tokio::time::timeout(
            self.limits.request_timeout(),
            self.transport.execute(request),
        )
        .await
        .map_err(|_elapsed| RelayerError::RequestTimeout {
            after_ms: self.limits.request_timeout().as_millis() as u64,
        })??;

        let status = response.status();
        if classify_status(status) != StatusClass::Success {
            return Err(RelayerError::Http { status });
        }

        // defense in depth: the production transport already refused an oversized body before
        // buffering it, but the ceiling is the CLIENT's policy, so it holds for every transport.
        if response.body().len() > self.limits.max_response_bytes() {
            return Err(RelayerError::ResponseTooLarge {
                limit: self.limits.max_response_bytes(),
                actual: response.body().len(),
            });
        }

        // A present `Link` header that is not text is MALFORMED pagination metadata — not "no
        // pagination". Dropping it (as a `to_str().ok()` would) yields the same `next == None` as a
        // legitimate final page, and would silently truncate the scan.
        let link = match response.headers().get(reqwest::header::LINK) {
            None => None,
            Some(value) => Some(
                value
                    .to_str()
                    .map_err(|_| RelayerError::BadPaginationMetadata {
                        detail: "the Link header is not valid UTF-8".to_string(),
                    })?
                    .to_string(),
            ),
        };

        Ok(HttpOk {
            body: response.into_body(),
            link,
        })
    }

    /// The request the relayer puts on the wire: base-URL join, query params under their exact
    /// OpenAPI names, and the auth header if (and only if) one is configured.
    fn build_request(
        &self,
        path: &str,
        query: &[(&'static str, String)],
    ) -> Result<reqwest::Request, RelayerError> {
        let url = self
            .base
            .join(path)
            .map_err(|source| RelayerError::BadBaseUrl {
                url: format!("{}{path}", self.base_url),
                source: Cause::new(source),
            })?;

        let mut builder = self.http.get(url);
        if let Some((name, value)) = &self.auth_header {
            builder = builder.header(name.clone(), value.clone());
        }
        if !query.is_empty() {
            builder = builder.query(query);
        }

        builder
            .build()
            .map_err(|source| RelayerError::Transport(Cause::new(source)))
    }
}

/// A URL that parsed but carries no host (`file:///…`) — it cannot be a Circle base URL, and the
/// rate governor would have nothing to key its per-IP window by.
#[derive(Debug)]
struct MissingHost;

impl fmt::Display for MissingHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "url has no host")
    }
}

impl std::error::Error for MissingHost {}
