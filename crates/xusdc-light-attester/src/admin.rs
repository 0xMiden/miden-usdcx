//! List and release holds in the running attester.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{ensure, Context};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use miden_protocol::note::NoteId;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub(crate) mod client;
pub use client::AdminArgs;

use crate::store::{HoldEntry, ReleaseError, ReleaseSelection};

const COMMAND_WAIT: Duration = Duration::from_secs(60);
const HEADER_WAIT: Duration = Duration::from_secs(10);
const CONNECTION_WAIT: Duration = Duration::from_secs(70);
const CLEANUP_WAIT: Duration = Duration::from_secs(5);
const BODY_LIMIT: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 16;

#[derive(Debug, Clone)]
pub(crate) struct AdminConfig {
    pub(crate) listen: SocketAddr,
    pub(crate) token_file: PathBuf,
}

pub(crate) fn parse_listen(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "admin address must be a literal socket address")?;
    if !address.ip().is_loopback() {
        return Err("admin address must be loopback".into());
    }
    Ok(address)
}

// Read at most one byte beyond the accepted representation, including its optional newline.
fn load_token(path: &Path) -> anyhow::Result<[u8; 32]> {
    let mut bytes = Vec::new();
    File::open(path)
        .context("cannot open admin token file")?
        .take(66)
        .read_to_end(&mut bytes)
        .context("cannot read admin token file")?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    ensure!(
        bytes.len() == 64,
        "admin token must contain 64 hex characters and an optional newline"
    );
    let mut token = [0; 32];
    hex::decode_to_slice(bytes, &mut token)
        .context("admin token must contain 64 hex characters")?;
    Ok(token)
}

pub(crate) fn parse_note_id(value: &str) -> anyhow::Result<NoteId> {
    let id = NoteId::try_from_hex(value).context("invalid note ID")?;
    ensure!(
        id.to_string() == value,
        "note ID must use canonical lowercase hex"
    );
    Ok(id)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseRequest {
    pub(crate) note_id: String,
    pub(crate) expected_event_seq: i64,
    #[serde(default)]
    pub(crate) circle_not_accepted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HoldsPage {
    pub(crate) faucet_account_id: String,
    pub(crate) trusted_anchor_block: u32,
    pub(crate) trusted_anchor_commitment: String,
    pub(crate) holds: Vec<HoldEntry>,
    pub(crate) next_after: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Released {
    pub(crate) burns: usize,
    pub(crate) withdrawals: usize,
}

pub(crate) enum Operation {
    List(
        Option<NoteId>,
        oneshot::Sender<Result<HoldsPage, ReleaseError>>,
    ),
    Release(
        ReleaseSelection,
        oneshot::Sender<Result<Released, ReleaseError>>,
    ),
}

pub(crate) struct Command {
    pub(crate) operation: Operation,
    pub(crate) deadline: Instant,
}

impl Command {
    pub(crate) fn abandoned(&self) -> bool {
        self.deadline <= Instant::now()
            || match &self.operation {
                Operation::List(_, reply) => reply.is_closed(),
                Operation::Release(_, reply) => reply.is_closed(),
            }
    }
}

#[derive(Clone)]
struct ServerState {
    token: [u8; 32],
    commands: mpsc::Sender<Command>,
    shutdown: CancellationToken,
}

pub(crate) struct Server {
    listener: TcpListener,
    state: ServerState,
    #[cfg(test)]
    pub(crate) accepted: std::sync::Arc<tokio::sync::Notify>,
}

impl Server {
    #[cfg(test)]
    pub(crate) fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }
    pub(crate) async fn bind(
        config: &AdminConfig,
    ) -> anyhow::Result<(Self, mpsc::Receiver<Command>)> {
        let token = load_token(&config.token_file)?;
        let listener = TcpListener::bind(config.listen)
            .await
            .context("cannot bind admin listener")?;
        let (commands, receiver) = mpsc::channel(16);
        Ok((
            Self {
                listener,
                #[cfg(test)]
                accepted: std::sync::Arc::new(tokio::sync::Notify::new()),
                state: ServerState {
                    token,
                    commands,
                    shutdown: CancellationToken::new(),
                },
            },
            receiver,
        ))
    }

    pub(crate) async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        #[cfg(test)]
        let on_accept = self.accepted;
        let Self {
            listener, state, ..
        } = self;
        let stop = state.shutdown.clone();
        let router = Router::new()
            .route("/admin/attester/holds", get(list))
            .route("/admin/attester/holds/release", post(release))
            .layer(DefaultBodyLimit::max(BODY_LIMIT))
            .layer(middleware::from_fn_with_state(state.clone(), authenticate))
            .with_state(state);
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                    let (stream, _) = match accepted {
                        Ok(value) => value,
                        Err(error) if matches!(error.kind(),
                            ErrorKind::ConnectionRefused | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
                        ) => continue,
                        Err(error) => {
                            warn!(%error, "admin listener accept failed");
                            tokio::select! {
                                biased;
                                () = shutdown.cancelled() => break,
                                () = tokio::time::sleep(Duration::from_secs(1)) => {},
                            }
                            continue;
                        }
                    };
                    let service = TowerToHyperService::new(router.clone());
                    let stop_connection = stop.clone();
                    connections.spawn(async move {
                        let mut builder = hyper::server::conn::http1::Builder::new();
                        builder.keep_alive(false).max_buf_size(16 * 1024)
                            .timer(TokioTimer::new()).header_read_timeout(HEADER_WAIT);
                        let connection = builder.serve_connection(TokioIo::new(stream), service);
                        tokio::pin!(connection);
                        tokio::select! {
                            _ = tokio::time::sleep(CONNECTION_WAIT) => {},
                            _ = &mut connection => {},
                            () = stop_connection.cancelled() => {
                                connection.as_mut().graceful_shutdown();
                                let _ = connection.await;
                            }
                        }
                    });
                    #[cfg(test)]
                    on_accept.notify_one();
                }
            }
        }
        drop(listener);
        stop.cancel();
        let _ = tokio::time::timeout(CLEANUP_WAIT, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        connections.shutdown().await;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ErrorBody {
    code: String,
    message: String,
}

#[derive(Debug)]
enum AdminError {
    Unauthorized,
    InvalidInput(&'static str),
    BodyTooLarge,
    Stopping,
    QueueFull,
    Unavailable,
    ReplyTimeout,
    Release(ReleaseError),
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid admin credentials",
            ),
            Self::InvalidInput(message) => (StatusCode::BAD_REQUEST, "invalid_input", message),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "release body exceeds 16 KiB",
            ),
            Self::Stopping => (
                StatusCode::SERVICE_UNAVAILABLE,
                "stopping",
                "attester is stopping",
            ),
            Self::QueueFull => (
                StatusCode::SERVICE_UNAVAILABLE,
                "queue_full",
                "command was not admitted",
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "attester is unavailable",
            ),
            Self::ReplyTimeout => (
                StatusCode::SERVICE_UNAVAILABLE,
                "reply_timeout",
                "outcome may be unknown; list holds again before selecting another release",
            ),
            Self::Release(ReleaseError::Invalid) => (
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "invalid hold selection",
            ),
            Self::Release(ReleaseError::Conflict) => (
                StatusCode::CONFLICT,
                "hold_changed",
                "list holds again before selecting a release",
            ),
            Self::Release(ReleaseError::CircleCheck) => (
                StatusCode::BAD_REQUEST,
                "circle_check_required",
                "check Circle and assert non-acceptance for the held withdrawal",
            ),
            Self::Release(ReleaseError::Store(_)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_failed",
                "attester store failed",
            ),
        };
        (
            status,
            Json(ErrorBody {
                code: code.into(),
                message: message.into(),
            }),
        )
            .into_response()
    }
}

async fn authenticate(
    State(state): State<ServerState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let mut candidate = [0; 32];
    let authenticated = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| value.len() == 64)
        .is_some_and(|value| hex::decode_to_slice(value, &mut candidate).is_ok())
        && bool::from(candidate.ct_eq(&state.token));
    let mut response = if authenticated {
        next.run(request).await
    } else {
        AdminError::Unauthorized.into_response()
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("fixed header"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    after: Option<String>,
}

async fn list(
    State(state): State<ServerState>,
    query: Result<Query<ListQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<HoldsPage>, AdminError> {
    let Query(query) = query.map_err(|_| AdminError::InvalidInput("invalid query"))?;
    let after = query
        .after
        .map(|id| parse_note_id(&id))
        .transpose()
        .map_err(|_| AdminError::InvalidInput("invalid page cursor"))?;
    let (reply, receive) = oneshot::channel();
    dispatch(&state, Operation::List(after, reply), receive).await
}

async fn release(
    State(state): State<ServerState>,
    body: Result<Json<ReleaseRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Released>, AdminError> {
    let Json(request) = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            AdminError::BodyTooLarge
        } else {
            AdminError::InvalidInput("invalid release body")
        }
    })?;
    if request.expected_event_seq <= 0 {
        return Err(AdminError::InvalidInput("invalid hold selection"));
    }
    let selection = ReleaseSelection {
        note_id: parse_note_id(&request.note_id)
            .map_err(|_| AdminError::InvalidInput("invalid hold selection"))?,
        expected_event_seq: request.expected_event_seq,
        circle_not_accepted: request.circle_not_accepted,
    };
    let (reply, receive) = oneshot::channel();
    dispatch(&state, Operation::Release(selection, reply), receive).await
}

async fn dispatch<T: Serialize>(
    state: &ServerState,
    operation: Operation,
    receive: oneshot::Receiver<Result<T, ReleaseError>>,
) -> Result<Json<T>, AdminError> {
    if state.shutdown.is_cancelled() {
        return Err(AdminError::Stopping);
    }
    let deadline = Instant::now() + COMMAND_WAIT;
    state
        .commands
        .try_send(Command {
            operation,
            deadline,
        })
        .map_err(|failure| match failure {
            mpsc::error::TrySendError::Full(_) => AdminError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => AdminError::Unavailable,
        })?;
    tokio::time::timeout_at(deadline, receive)
        .await
        .map_err(|_| AdminError::ReplyTimeout)?
        .map_err(|_| AdminError::Unavailable)?
        .map(Json)
        .map_err(AdminError::Release)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_and_listener_inputs_are_bounded() {
        let file = tempfile::NamedTempFile::new().unwrap();
        for value in ["ab".repeat(32), format!("{}\n", "AB".repeat(32))] {
            std::fs::write(file.path(), value).unwrap();
            assert_eq!(load_token(file.path()).unwrap(), [0xab; 32]);
        }
        for value in [
            String::new(),
            "ab".repeat(31),
            "gh".repeat(32),
            format!("{}\r\n", "ab".repeat(32)),
            "ab".repeat(1000),
        ] {
            std::fs::write(file.path(), value).unwrap();
            assert!(load_token(file.path()).is_err());
        }
        for value in ["127.0.0.1:8090", "[::1]:8090"] {
            assert!(parse_listen(value).is_ok());
        }
        for value in [
            "0.0.0.0:8090",
            "localhost:8090",
            "[::]:8090",
            "192.0.2.1:8090",
        ] {
            assert!(parse_listen(value).is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_selections_are_not_queued_and_queue_failures_are_distinct() {
        let (commands, mut inbox) = mpsc::channel(1);
        let state = ServerState {
            token: [0; 32],
            commands,
            shutdown: CancellationToken::new(),
        };
        let canonical = format!("0x{}", "ab".repeat(32));
        for (note_id, expected_event_seq) in [
            (canonical.clone(), 0),
            (canonical, -1),
            (format!("0x{}", "AB".repeat(32)), 1),
            ("invalid".into(), 1),
        ] {
            let response = release(
                State(state.clone()),
                Ok(Json(ReleaseRequest {
                    note_id,
                    expected_event_seq,
                    circle_not_accepted: false,
                })),
            )
            .await
            .into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let error: ErrorBody = serde_json::from_slice(&body).unwrap();
            assert_eq!(error.code, "invalid_input");
            assert_eq!(error.message, "invalid hold selection");
            assert!(matches!(
                inbox.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
        let (reply, _receive) = oneshot::channel();
        state
            .commands
            .try_send(Command {
                operation: Operation::List(None, reply),
                deadline: Instant::now() + COMMAND_WAIT,
            })
            .unwrap_or_else(|_| panic!());
        let (reply, receive) = oneshot::channel::<Result<HoldsPage, ReleaseError>>();
        let response = dispatch(&state, Operation::List(None, reply), receive)
            .await
            .into_response();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<ErrorBody>(&body).unwrap().code,
            "queue_full"
        );
        inbox.recv().await.unwrap();
        let (reply, receive) = oneshot::channel::<Result<HoldsPage, ReleaseError>>();
        let response = dispatch(&state, Operation::List(None, reply), receive)
            .await
            .into_response();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<ErrorBody>(&body).unwrap().code,
            "reply_timeout"
        );
        assert!(inbox.recv().await.unwrap().abandoned());
        drop(inbox);
        let (reply, receive) = oneshot::channel::<Result<HoldsPage, ReleaseError>>();
        let response = dispatch(&state, Operation::List(None, reply), receive)
            .await
            .into_response();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<ErrorBody>(&body).unwrap().code,
            "unavailable"
        );
    }
}
