//! `tests/mock_circle/` — the **schema-exact mock Circle server** the withdrawal-driver contract
//! suites run against.
//!
//! Every live Circle leg is `REQUIRES CIRCLE CONFIRMATION`, so the three withdrawal
//! endpoints are exercised against this mock and never contacted live.
//!
//! # A real router, driven in process — binding no socket
//!
//! The mock is an axum `Router` (real routing, real status codes, real headers, real JSON bodies)
//! installed as the client's [`HttpTransport`] ([`MockTransport`]). The driver builds a **real
//! `reqwest::Request`** — its own base-URL join, its own JSON body codec, its own auth-header
//! injection — and the mock receives exactly that, including the request BODY, so a test can assert
//! on the wire shape the driver actually produced (the `{ batches: [..] }` wrapper, not a bare
//! array). No socket is bound: the audit/CI sandbox denies `bind(127.0.0.1:0)` (EPERM), so a
//! loopback-server mock could not run in a gate at all — the request is driven through `tower`'s
//! `ServiceExt::oneshot`.
//!
//! # Scripted replies, per endpoint
//!
//! Each endpoint has a reply QUEUE consumed in order, with the LAST reply repeating forever — so a
//! status poll can be scripted `created → verified → confirmed → finalized` across successive
//! `GET`s, and a single-element queue is "always this".

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

pub mod transports;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, Response, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use serde_json::Value;

use withdrawal_listener_attester::circle::HttpTransport;

pub use transports::MockTransport;

/// The origin the mock answers for. **HTTPS**, because a configured credential may only cross a TLS
/// transport (the client refuses to attach one to a plaintext base URL) — and because nothing is
/// ever dialed, the scheme costs the mock nothing.
pub const MOCK_BASE_URL: &str = "https://xreserve-api.mock";

/// The three withdrawal endpoints the driver consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Endpoint {
    /// `POST /v1/prepare-withdrawal`.
    Prepare,
    /// `POST /v1/withdraw`.
    Withdraw,
    /// `GET /v1/withdrawal/{withdrawalId}`.
    Status,
    /// Anything else — recorded so a stray request cannot pass unnoticed.
    Unexpected,
}

/// One scripted reply.
#[derive(Debug, Clone)]
pub enum Reply {
    /// A JSON body with a status code.
    Json { status: u16, body: Value },
    /// An arbitrary (possibly non-JSON) body — so an error response can be proven handled on its
    /// STATUS alone (the OpenAPI documents status codes only, no error-body schema).
    Body { status: u16, body: String },
    /// A bare status code, no body.
    Status(u16),
}

impl Reply {
    /// A JSON reply with the given status.
    pub fn json(status: u16, body: Value) -> Self {
        Self::Json { status, body }
    }
}

/// The per-endpoint reply queues. The LAST reply repeats forever.
#[derive(Debug, Clone, Default)]
pub struct Script {
    pub prepare: Vec<Reply>,
    pub withdraw: Vec<Reply>,
    pub status: Vec<Reply>,
}

impl Script {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare(mut self, replies: Vec<Reply>) -> Self {
        self.prepare = replies;
        self
    }

    pub fn withdraw(mut self, replies: Vec<Reply>) -> Self {
        self.withdraw = replies;
        self
    }

    pub fn status(mut self, replies: Vec<Reply>) -> Self {
        self.status = replies;
        self
    }
}

/// One request as the mock actually received it — i.e. exactly what the driver built.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub endpoint: Endpoint,
    pub method: String,
    pub path: String,
    /// Lower-cased header names → values (so an auth-header assertion is case-insensitive).
    pub headers: BTreeMap<String, String>,
    /// The raw request body bytes — for a POST, exactly the JSON the driver serialized.
    pub body: Vec<u8>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(String::as_str)
    }

    /// The body parsed as JSON (panics if it is not JSON — a POST body always is here).
    pub fn body_json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("recorded body is not JSON: {e}; body={:?}", self.body))
    }
}

#[derive(Debug)]
struct MockState {
    script: Script,
    requests: Mutex<Vec<RecordedRequest>>,
    hits: Mutex<BTreeMap<Endpoint, usize>>,
}

impl MockState {
    fn record(
        &self,
        endpoint: Endpoint,
        method: &Method,
        path: String,
        headers: &HeaderMap,
        body: Vec<u8>,
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
            method: method.as_str().to_string(),
            path,
            headers,
            body,
        });
    }

    /// The next scripted reply: queue element `n` for the n-th hit, the last element repeating. An
    /// empty queue is a 599 (a test that forgot to script an endpoint it uses fails loudly).
    fn next_reply(&self, endpoint: Endpoint) -> Reply {
        let queue = match endpoint {
            Endpoint::Prepare => &self.script.prepare,
            Endpoint::Withdraw => &self.script.withdraw,
            Endpoint::Status => &self.script.status,
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
            Reply::Json { status, body } => Response::builder()
                .status(StatusCode::from_u16(status).expect("valid status"))
                .header("content-type", "application/json")
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
        }
    }
}

/// The mock Circle server: an axum router + the request log, exposed to the driver as an
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

        let router = Router::new()
            .route("/v1/prepare-withdrawal", post(prepare_handler))
            .route("/v1/withdraw", post(withdraw_handler))
            .route("/v1/withdrawal/{withdrawal_id}", get(status_handler))
            .fallback(unexpected_handler)
            .with_state(Arc::clone(&state));

        Self { state, router }
    }

    /// The transport to install on the
    /// [`CircleClient`](withdrawal_listener_attester::circle::CircleClient).
    pub fn transport(&self) -> Arc<dyn HttpTransport> {
        Arc::new(MockTransport::new(self.router.clone()))
    }

    /// The base URL to hand to the client.
    pub fn base_url(&self) -> &'static str {
        MOCK_BASE_URL
    }

    /// Every request the mock received, in arrival order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.requests.lock().unwrap().clone()
    }

    /// Total requests received (across all endpoints).
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

async fn prepare_handler(
    State(state): State<Arc<MockState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    state.record(
        Endpoint::Prepare,
        &method,
        "/v1/prepare-withdrawal".to_string(),
        &headers,
        body.to_vec(),
    );
    state.respond(Endpoint::Prepare)
}

async fn withdraw_handler(
    State(state): State<Arc<MockState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    state.record(
        Endpoint::Withdraw,
        &method,
        "/v1/withdraw".to_string(),
        &headers,
        body.to_vec(),
    );
    state.respond(Endpoint::Withdraw)
}

async fn status_handler(
    State(state): State<Arc<MockState>>,
    Path(withdrawal_id): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    state.record(
        Endpoint::Status,
        &method,
        format!("/v1/withdrawal/{withdrawal_id}"),
        &headers,
        body.to_vec(),
    );
    state.respond(Endpoint::Status)
}

async fn unexpected_handler(
    State(state): State<Arc<MockState>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    state.record(
        Endpoint::Unexpected,
        &method,
        "<unrouted>".to_string(),
        &headers,
        body.to_vec(),
    );
    // 418: deliberately NOT 404/409/5xx, so a stray request can never be mistaken for a scripted
    // status the driver has a policy for.
    Response::builder()
        .status(StatusCode::IM_A_TEAPOT)
        .body(Body::empty())
        .expect("response builds")
}
