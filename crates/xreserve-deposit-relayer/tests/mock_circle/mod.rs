//! `tests/mock_circle/` — the **schema-exact mock Circle server** the Circle-facing contract suites
//! run against (§11 mock disclosure: every live Circle leg is `REQUIRES CIRCLE CONFIRMATION`, so the
//! Circle endpoints `CMP-D1`/`CMP-D3`/`CMP-D4` are exercised against this mock and never contacted
//! live; the Miden leg — which must NOT be faked — is a later slice).
//!
//! # A real router, driven in process — binding no socket
//!
//! The mock is an axum `Router` (real routing, real status codes, real headers, real JSON bodies)
//! installed as the client's `HttpTransport` ([`transports::MockTransport`]). The relayer builds a
//! **real `reqwest::Request`** and the mock receives exactly that. So the rate governor, the
//! exponential backoff, the HTTP-status policy, the request deadline, the response-size ceiling, the
//! `Link`-header cursor parse, and the serde decode are all exercised end to end. The one thing NOT
//! exercised is reqwest's socket write — reqwest's contract, not the relayer's — and the audit/CI
//! sandbox denies `bind(127.0.0.1:0)` outright, so a loopback-server mock could not run there at all.
//!
//! # Fixture fidelity is the point
//!
//! The bodies ([`bodies`]) are built to the exact OpenAPI shapes; malformed ones are produced by
//! MUTATING a valid body, so a malformed fixture differs from the valid one in exactly the way its
//! case name says. Every request is RECORDED (path, query, headers, arrival time), so a test can
//! assert not only what the relayer did with a response but what it put on the wire — that a bad
//! `txHash` produced NO request at all, that `/v1/info` carried no `domain` param, that the second
//! page carried the `pageAfter` cursor from the first page's `Link` header, and that no credential
//! leaked into a header when none was configured.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

pub mod bodies;
pub mod support;
pub mod transports;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::get;
use axum::Router;
use serde_json::Value;

use xreserve_deposit_relayer::circle::HttpTransport;
use xreserve_deposit_relayer::observability::{EventSink, RelayerEvent};

pub use bodies::*;
pub use support::*;
pub use transports::MockTransport;

/// The origin the mock answers for. **HTTPS**, because a configured credential may only cross a
/// TLS transport (the client refuses to attach one to a plaintext base URL) — and because nothing is
/// ever dialed, the scheme costs the mock nothing.
pub const MOCK_BASE_URL: &str = "https://circle.mock";

/// The four endpoints the relayer consumes. Used to route a scripted reply and to label a recorded
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Endpoint {
    /// `GET /v1/info` (CMP-D1).
    Info,
    /// `GET /v1/attestations/{depositMessageHash}` (CMP-D3) — the WRAPPER shape.
    ByHash,
    /// `GET /v1/attestations?txHash=` (CMP-D3 variant) — a LIST shape.
    ByTxHash,
    /// `GET /v1/remote-domains/{remoteDomain}/attestations` (CMP-D4) — a LIST shape + `Link`.
    Batch,
    /// Anything else — recorded so a stray request cannot pass unnoticed.
    Unexpected,
}

/// One scripted reply.
#[derive(Debug, Clone)]
pub enum Reply {
    /// The schema-exact success shape, optionally with a `Link` header.
    Json {
        status: u16,
        body: Value,
        /// `Link` header template; `{base}` is replaced with the mock's base URL at serve time.
        link: Option<String>,
    },
    /// A JSON body with a RAW `Link` header — arbitrary bytes, so a test can serve pagination
    /// metadata that is not even valid UTF-8.
    JsonRawLink {
        status: u16,
        body: Value,
        link: Vec<u8>,
    },
    /// An arbitrary (possibly non-JSON) body, so an error response can be proven to be handled on
    /// its STATUS alone — the OpenAPI documents status codes only, no error-body schema.
    Body { status: u16, body: String },
    /// A bare status code, no body.
    Status(u16),
    /// A status code plus a `Location` header — a redirect. The relayer must NOT follow it (a
    /// follow would re-send the credential to whatever origin the redirect names).
    Redirect { status: u16, location: String },
}

impl Reply {
    /// A 200 with a JSON body and no `Link` header.
    pub fn ok(body: Value) -> Self {
        Self::Json {
            status: 200,
            body,
            link: None,
        }
    }

    /// A 200 with a JSON body and a `Link` header (the paginated batch shape).
    pub fn ok_linked(body: Value, link: impl Into<String>) -> Self {
        Self::Json {
            status: 200,
            body,
            link: Some(link.into()),
        }
    }

    /// A 200 with a JSON body and a raw-bytes `Link` header.
    pub fn ok_raw_link(body: Value, link: Vec<u8>) -> Self {
        Self::JsonRawLink {
            status: 200,
            body,
            link,
        }
    }
}

/// The per-endpoint reply queues. Replies are consumed in order; the LAST reply repeats forever, so
/// `vec![Reply::Status(404), Reply::ok(body)]` is "404 once, then 200 from then on", and a
/// single-element queue is "always this".
#[derive(Debug, Clone, Default)]
pub struct Script {
    pub info: Vec<Reply>,
    pub by_hash: Vec<Reply>,
    pub by_tx_hash: Vec<Reply>,
    pub batch: Vec<Reply>,
}

impl Script {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn info(mut self, replies: Vec<Reply>) -> Self {
        self.info = replies;
        self
    }

    pub fn by_hash(mut self, replies: Vec<Reply>) -> Self {
        self.by_hash = replies;
        self
    }

    pub fn by_tx_hash(mut self, replies: Vec<Reply>) -> Self {
        self.by_tx_hash = replies;
        self
    }

    pub fn batch(mut self, replies: Vec<Reply>) -> Self {
        self.batch = replies;
        self
    }
}

/// One request as the mock actually received it — i.e. exactly what the relayer built.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub endpoint: Endpoint,
    pub path: String,
    /// Decoded query parameters, by name — empty when the request carried no query string at all
    /// (which is what `/v1/info`'s documented public no-`domain`-param shape must look like).
    pub query: BTreeMap<String, String>,
    /// Lower-cased header names → values (so an auth-header assertion is case-insensitive).
    pub headers: BTreeMap<String, String>,
    pub at: Instant,
}

impl RecordedRequest {
    pub fn query(&self, key: &str) -> Option<&str> {
        self.query.get(key).map(String::as_str)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(String::as_str)
    }
}

#[derive(Debug)]
struct MockState {
    script: Script,
    requests: Mutex<Vec<RecordedRequest>>,
    /// How many times each endpoint has been hit (the reply-queue index).
    hits: Mutex<BTreeMap<Endpoint, usize>>,
}

impl MockState {
    fn record(
        &self,
        endpoint: Endpoint,
        path: String,
        query: BTreeMap<String, String>,
        headers: &HeaderMap,
    ) {
        let headers = headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_lowercase(),
                    value.to_str().unwrap_or("<non-utf8>").to_string(),
                )
            })
            .collect();
        self.requests.lock().unwrap().push(RecordedRequest {
            endpoint,
            path,
            query,
            headers,
            at: Instant::now(),
        });
    }

    /// The next scripted reply for `endpoint`: queue element `n` for the n-th hit, with the last
    /// element repeating. An empty queue is a 599 (a test that forgot to script an endpoint it uses
    /// fails loudly rather than silently passing).
    fn next_reply(&self, endpoint: Endpoint) -> Reply {
        let queue = match endpoint {
            Endpoint::Info => &self.script.info,
            Endpoint::ByHash => &self.script.by_hash,
            Endpoint::ByTxHash => &self.script.by_tx_hash,
            Endpoint::Batch => &self.script.batch,
            Endpoint::Unexpected => &[] as &[Reply],
        };
        if queue.is_empty() {
            return Reply::Body {
                status: 599,
                body: format!("mock: no reply scripted for {endpoint:?}"),
            };
        }
        let mut hits = self.hits.lock().unwrap();
        let hit = hits.entry(endpoint).or_insert(0);
        let index = (*hit).min(queue.len() - 1);
        *hit += 1;
        queue[index].clone()
    }

    fn respond(&self, endpoint: Endpoint) -> Response<Body> {
        match self.next_reply(endpoint) {
            Reply::Json { status, body, link } => {
                let mut builder = Response::builder()
                    .status(StatusCode::from_u16(status).expect("valid status"))
                    .header("content-type", "application/json");
                if let Some(link) = link {
                    builder = builder.header("link", link.replace("{base}", MOCK_BASE_URL));
                }
                builder
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("fixture serializes"),
                    ))
                    .expect("response builds")
            }
            Reply::JsonRawLink { status, body, link } => Response::builder()
                .status(StatusCode::from_u16(status).expect("valid status"))
                .header("content-type", "application/json")
                .header(
                    "link",
                    HeaderValue::from_bytes(&link).expect("a header value the mock can serve"),
                )
                .body(Body::from(
                    serde_json::to_vec(&body).expect("fixture serializes"),
                ))
                .expect("response builds"),
            Reply::Body { status, body } => Response::builder()
                .status(StatusCode::from_u16(status).expect("valid status"))
                .body(Body::from(body))
                .expect("response builds"),
            Reply::Status(status) => Response::builder()
                .status(StatusCode::from_u16(status).expect("valid status"))
                .body(Body::empty())
                .expect("response builds"),
            Reply::Redirect { status, location } => Response::builder()
                .status(StatusCode::from_u16(status).expect("valid status"))
                .header("location", location)
                .body(Body::empty())
                .expect("response builds"),
        }
    }
}

/// The mock Circle server: an axum router + the request log, exposed to the relayer as an
/// [`HttpTransport`].
#[derive(Debug)]
pub struct MockCircle {
    state: Arc<MockState>,
    router: Router,
}

impl MockCircle {
    /// Builds the mock. Binds nothing, spawns nothing — [`Self::transport`] hands it to the client.
    pub fn start(script: Script) -> Self {
        let state = Arc::new(MockState {
            script,
            requests: Mutex::new(Vec::new()),
            hits: Mutex::new(BTreeMap::new()),
        });

        // axum 0.8 path syntax: `{param}` (0.7's `:param` no longer parses).
        let router = Router::new()
            .route("/v1/info", get(info_handler))
            .route("/v1/attestations", get(by_tx_hash_handler))
            .route("/v1/attestations/{message_hash}", get(by_hash_handler))
            .route(
                "/v1/remote-domains/{remote_domain}/attestations",
                get(batch_handler),
            )
            .fallback(unexpected_handler)
            .with_state(Arc::clone(&state));

        Self { state, router }
    }

    /// The transport to install on the `CircleClient` (`.with_transport(mock.transport())`).
    pub fn transport(&self) -> Arc<dyn HttpTransport> {
        Arc::new(MockTransport::new(self.router.clone()))
    }

    /// The base URL to hand to `CircleClient`.
    pub fn base_url(&self) -> &'static str {
        MOCK_BASE_URL
    }

    /// Every request the mock received, in arrival order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.requests.lock().unwrap().clone()
    }

    /// Total requests received (across all endpoints) — the retry/no-retry oracle.
    pub fn request_count(&self) -> usize {
        self.state.requests.lock().unwrap().len()
    }

    /// Requests received on one endpoint.
    pub fn requests_to(&self, endpoint: Endpoint) -> Vec<RecordedRequest> {
        self.requests()
            .into_iter()
            .filter(|r| r.endpoint == endpoint)
            .collect()
    }
}

// HANDLERS
// ================================================================================================

async fn info_handler(
    State(state): State<Arc<MockState>>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response<Body> {
    state.record(Endpoint::Info, "/v1/info".to_string(), query, &headers);
    state.respond(Endpoint::Info)
}

async fn by_hash_handler(
    State(state): State<Arc<MockState>>,
    Path(message_hash): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response<Body> {
    state.record(
        Endpoint::ByHash,
        format!("/v1/attestations/{message_hash}"),
        query,
        &headers,
    );
    state.respond(Endpoint::ByHash)
}

async fn by_tx_hash_handler(
    State(state): State<Arc<MockState>>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response<Body> {
    state.record(
        Endpoint::ByTxHash,
        "/v1/attestations".to_string(),
        query,
        &headers,
    );
    state.respond(Endpoint::ByTxHash)
}

async fn batch_handler(
    State(state): State<Arc<MockState>>,
    Path(remote_domain): Path<u32>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response<Body> {
    state.record(
        Endpoint::Batch,
        format!("/v1/remote-domains/{remote_domain}/attestations"),
        query,
        &headers,
    );
    state.respond(Endpoint::Batch)
}

async fn unexpected_handler(
    State(state): State<Arc<MockState>>,
    headers: HeaderMap,
) -> Response<Body> {
    state.record(
        Endpoint::Unexpected,
        "<unrouted>".to_string(),
        BTreeMap::new(),
        &headers,
    );
    // 418: deliberately NOT 404/429/5xx, so a stray request can never be mistaken for a scripted
    // retryable status.
    Response::builder()
        .status(StatusCode::IM_A_TEAPOT)
        .body(Body::empty())
        .expect("response builds")
}

// EVENT SINK — the observability oracle
// ================================================================================================

/// An [`EventSink`] that records everything the relayer emits, so a test can assert the §8.4
/// obligations directly: that a 404 was logged `Pending` (and therefore NOT silently dropped), that
/// a 400 raised an `Alert`, that a 500 alerted only after the threshold.
#[derive(Debug, Default)]
pub struct RecordingSink {
    events: Mutex<Vec<RelayerEvent>>,
}

impl RecordingSink {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn events(&self) -> Vec<RelayerEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn pending(&self) -> Vec<RelayerEvent> {
        self.events()
            .into_iter()
            .filter(|e| matches!(e, RelayerEvent::Pending { .. }))
            .collect()
    }

    pub fn alerts(&self) -> Vec<RelayerEvent> {
        self.events()
            .into_iter()
            .filter(|e| matches!(e, RelayerEvent::Alert { .. }))
            .collect()
    }

    pub fn rejections(&self) -> Vec<RelayerEvent> {
        self.events()
            .into_iter()
            .filter(|e| matches!(e, RelayerEvent::Rejected { .. }))
            .collect()
    }
}

impl EventSink for RecordingSink {
    fn emit(&self, event: RelayerEvent) {
        self.events.lock().unwrap().push(event);
    }
}
