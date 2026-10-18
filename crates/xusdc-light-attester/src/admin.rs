//! List and release holds in the running attester.
//!
//! A loopback HTTP listener authenticates each request with a bearer token and queues it for the
//! attester's own task, which runs it against the store between steps of a cycle and sends back the
//! result. The listener never opens the store itself.

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

/// How long a request waits for the attester to run its command.
const COMMAND_WAIT: Duration = Duration::from_secs(60);
/// How long a connection may take to send its request headers.
const HEADER_WAIT: Duration = Duration::from_secs(10);
/// The longest a connection stays open, a little over [`COMMAND_WAIT`].
const CONNECTION_WAIT: Duration = Duration::from_secs(70);
/// How long shutdown waits for open connections to finish before dropping them.
const CLEANUP_WAIT: Duration = Duration::from_secs(5);
/// The largest request body accepted.
const BODY_LIMIT: usize = 16 * 1024;
/// The most connections served at once; further ones wait in the listen backlog.
const MAX_CONNECTIONS: usize = 16;

/// Where the admin listener binds and the file holding its bearer token.
#[derive(Debug, Clone)]
pub(crate) struct AdminConfig {
    pub(crate) listen: SocketAddr,
    pub(crate) token_file: PathBuf,
}

/// Parses the listener address, accepting only a loopback address.
pub(crate) fn parse_listen(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| "admin address must be a literal socket address")?;
    if !address.ip().is_loopback() {
        return Err("admin address must be loopback".into());
    }
    Ok(address)
}

/// Reads the 32-byte admin token, stored as 64 hex characters and an optional newline.
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

/// Parses a note ID in the canonical form the holds list prints.
///
/// One spelling per note means a note ID from the list can be compared and paged on as text.
pub(crate) fn parse_note_id(value: &str) -> anyhow::Result<NoteId> {
    let id = NoteId::try_from_hex(value).context("invalid note ID")?;
    ensure!(
        id.to_string() == value,
        "note ID must use canonical lowercase hex"
    );
    Ok(id)
}

/// The body of a release request: one hold, as the holds list showed it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseRequest {
    pub(crate) note_id: String,
    /// The hold's `event_seq` from the list. The release is refused if the hold has changed since.
    pub(crate) expected_event_seq: i64,
    /// The operator confirms Circle did not accept the withdrawal. Required to release a held
    /// withdrawal.
    #[serde(default)]
    pub(crate) circle_not_accepted: bool,
}

/// One page of holds, in note order.
///
/// The faucet and trusted anchor let the operator confirm which attester answered.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HoldsPage {
    pub(crate) faucet_account_id: String,
    pub(crate) trusted_anchor_block: u32,
    pub(crate) trusted_anchor_commitment: String,
    pub(crate) holds: Vec<HoldEntry>,
    /// The cursor for the next page, or `None` on the last page.
    pub(crate) next_after: Option<String>,
}

/// How many burns and withdrawals a release made eligible again.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Released {
    pub(crate) burns: usize,
    pub(crate) withdrawals: usize,
}

/// A store operation the attester runs for the listener, with the channel for its result.
pub(crate) enum Operation {
    /// Lists the holds after the given note ID, or from the start.
    List(
        Option<NoteId>,
        oneshot::Sender<Result<HoldsPage, ReleaseError>>,
    ),
    /// Releases the selected hold.
    Release(
        ReleaseSelection,
        oneshot::Sender<Result<Released, ReleaseError>>,
    ),
}

/// An operation queued for the attester, with the time its request stops waiting.
pub(crate) struct Command {
    pub(crate) operation: Operation,
    pub(crate) deadline: Instant,
}

impl Command {
    /// Whether the request has stopped waiting, by timing out or disconnecting, so the command
    /// should not run.
    pub(crate) fn abandoned(&self) -> bool {
        self.deadline <= Instant::now()
            || match &self.operation {
                Operation::List(_, reply) => reply.is_closed(),
                Operation::Release(_, reply) => reply.is_closed(),
            }
    }
}

/// What every request handler shares.
#[derive(Clone)]
struct ServerState {
    token: [u8; 32],
    /// The attester's inbox.
    commands: mpsc::Sender<Command>,
    /// Cancelled when the listener stops, so new requests are refused and open connections close.
    shutdown: CancellationToken,
}

/// The admin listener, bound but not yet serving.
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
    /// Loads the token and binds the listener, returning it with the inbox the attester reads.
    ///
    /// The inbox is bounded, so a request that finds it full is refused rather than queued.
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

    /// Serves requests until `shutdown` is cancelled, then gives open connections
    /// [`CLEANUP_WAIT`] to finish.
    ///
    /// Each connection carries one request and is capped at [`CONNECTION_WAIT`], so a slow or idle
    /// client cannot hold one of the [`MAX_CONNECTIONS`] slots.
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
                // Reaping finished connections frees their slots.
                Some(_) = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                    let (stream, _) = match accepted {
                        Ok(value) => value,
                        // The client went away before it was accepted.
                        Err(error) if matches!(error.kind(),
                            ErrorKind::ConnectionRefused | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
                        ) => continue,
                        // Other failures, such as running out of file descriptors, can persist,
                        // so pause before accepting again.
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
        // Stop accepting, ask open connections to finish, then drop whatever is left.
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

/// The JSON body of every error answer: a stable code for scripts and a message for the operator.
#[derive(Serialize, Deserialize, Debug)]
struct ErrorBody {
    code: String,
    message: String,
}

/// Why a request failed, each mapped to one HTTP status and error code.
#[derive(Debug)]
enum AdminError {
    /// The bearer token is missing or wrong.
    Unauthorized,
    InvalidInput(&'static str),
    BodyTooLarge,
    /// The listener is shutting down.
    Stopping,
    /// The attester's inbox is full.
    QueueFull,
    /// The attester stopped taking commands, or dropped this one unanswered.
    Unavailable,
    /// The attester did not answer in time. The command may still have run.
    ReplyTimeout,
    /// The store refused or failed the operation.
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

/// Lets a request through only with the admin bearer token, compared in constant time.
///
/// Every answer, refused or not, is marked `no-store` so no hold listing is cached.
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

/// The query of a holds listing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    /// The last note ID of the previous page.
    after: Option<String>,
}

/// `GET /admin/attester/holds`: one page of holds.
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

/// `POST /admin/attester/holds/release`: releases one hold selected from the list.
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

/// Queues an operation for the attester and waits up to [`COMMAND_WAIT`] for its result.
///
/// A full inbox is refused at once rather than waited on. A timeout leaves the outcome unknown:
/// the attester drops a command whose deadline has passed, but one it has already started still
/// commits.
async fn dispatch<T: Serialize>(
    state: &ServerState,
    operation: Operation,
    receive: oneshot::Receiver<Result<T, ReleaseError>>,
) -> Result<Json<T>, AdminError> {
    if state.shutdown.is_cancelled() {
        return Err(AdminError::Stopping);
    }
    // The attester checks the same deadline, so it skips a command this request no longer waits
    // for.
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
