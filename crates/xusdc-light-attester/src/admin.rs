//! List and release holds in the running attester.
//!
//! The attester listens on a Unix socket. File permissions decide who may connect, so there is no
//! token: the socket is created readable and writable only by the service's user. A client sends
//! one JSON request on one line and reads one JSON reply on one line, then the connection closes.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{ensure, Context};
use miden_protocol::note::NoteId;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub(crate) mod client;
pub use client::AdminArgs;

use crate::store::{HoldEntry, ReleaseError, ReleaseSelection};

const COMMAND_WAIT: Duration = Duration::from_secs(60);
const REQUEST_WAIT: Duration = Duration::from_secs(10);
const CONNECTION_WAIT: Duration = Duration::from_secs(70);
const CLEANUP_WAIT: Duration = Duration::from_secs(5);
const REQUEST_LIMIT: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 16;

#[derive(Debug, Clone)]
pub(crate) struct AdminConfig {
    pub(crate) socket: PathBuf,
}

pub(crate) fn parse_note_id(value: &str) -> anyhow::Result<NoteId> {
    let id = NoteId::try_from_hex(value).context("invalid note ID")?;
    ensure!(
        id.to_string() == value,
        "note ID must use canonical lowercase hex"
    );
    Ok(id)
}

/// One line a client sends.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Holds {
        #[serde(default)]
        after: Option<String>,
    },
    Release {
        note_id: String,
        expected_event_seq: i64,
        #[serde(default)]
        circle_not_accepted: bool,
    },
}

/// One line the attester answers with: `{"ok": …}` or `{"error": {"code": …, "message": …}}`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reply<T> {
    Ok(T),
    Error(ErrorBody),
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ErrorBody {
    pub(crate) code: String,
    pub(crate) message: String,
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
    commands: mpsc::Sender<Command>,
    shutdown: CancellationToken,
}

pub(crate) struct Server {
    listener: UnixListener,
    path: PathBuf,
    state: ServerState,
    #[cfg(test)]
    pub(crate) accepted: std::sync::Arc<tokio::sync::Notify>,
}

impl Server {
    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn bind(config: &AdminConfig) -> anyhow::Result<(Self, mpsc::Receiver<Command>)> {
        let path = config.socket.clone();
        remove_stale_socket(&path)?;
        let listener = UnixListener::bind(&path).context("cannot bind admin socket")?;
        // The socket is reachable from its directory for the moment between the bind and this
        // call, so the directory itself should be private to the service.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .context("cannot restrict admin socket permissions")?;
        let (commands, receiver) = mpsc::channel(16);
        Ok((
            Self {
                listener,
                path,
                #[cfg(test)]
                accepted: std::sync::Arc::new(tokio::sync::Notify::new()),
                state: ServerState {
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
            listener,
            path,
            state,
            ..
        } = self;
        let stop = state.shutdown.clone();
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                    let stream = match accepted {
                        Ok((stream, _)) => stream,
                        Err(error) => {
                            warn!(%error, "admin socket accept failed");
                            tokio::select! {
                                biased;
                                () = shutdown.cancelled() => break,
                                () = tokio::time::sleep(Duration::from_secs(1)) => {},
                            }
                            continue;
                        }
                    };
                    let state = state.clone();
                    connections.spawn(async move {
                        let _ = tokio::time::timeout(CONNECTION_WAIT, serve(state, stream)).await;
                    });
                    #[cfg(test)]
                    on_accept.notify_one();
                }
            }
        }
        drop(listener);
        let _ = fs::remove_file(&path);
        stop.cancel();
        let _ = tokio::time::timeout(CLEANUP_WAIT, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        connections.shutdown().await;
        Ok(())
    }
}

/// Removes a socket file left by an attester that is no longer running. Refuses to remove anything
/// that is not a socket, or a socket that still accepts connections.
fn remove_stale_socket(path: &Path) -> anyhow::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("cannot inspect admin socket path"),
    };
    ensure!(
        metadata.file_type().is_socket(),
        "admin socket path exists and is not a socket"
    );
    match std::os::unix::net::UnixStream::connect(path) {
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
            fs::remove_file(path).context("cannot remove stale admin socket")
        }
        Ok(_) => anyhow::bail!("another attester is serving the admin socket"),
        Err(error) => Err(error).context("cannot check the existing admin socket"),
    }
}

#[derive(Debug)]
enum AdminError {
    InvalidInput(&'static str),
    RequestTooLarge,
    Stopping,
    QueueFull,
    Unavailable,
    ReplyTimeout,
    Release(ReleaseError),
}

impl AdminError {
    fn body(&self) -> ErrorBody {
        let (code, message) = match self {
            Self::InvalidInput(message) => ("invalid_input", *message),
            Self::RequestTooLarge => ("request_too_large", "request exceeds 16 KiB"),
            Self::Stopping => ("stopping", "attester is stopping"),
            Self::QueueFull => ("queue_full", "command was not admitted"),
            Self::Unavailable => ("unavailable", "attester is unavailable"),
            Self::ReplyTimeout => (
                "reply_timeout",
                "outcome may be unknown; list holds again before selecting another release",
            ),
            Self::Release(ReleaseError::Invalid) => ("invalid_input", "invalid hold selection"),
            Self::Release(ReleaseError::Conflict) => (
                "hold_changed",
                "list holds again before selecting a release",
            ),
            Self::Release(ReleaseError::CircleCheck) => (
                "circle_check_required",
                "check Circle and assert non-acceptance for the held withdrawal",
            ),
            Self::Release(ReleaseError::Store(_)) => ("store_failed", "attester store failed"),
        };
        ErrorBody {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Answers one connection: read its request line, run it, write the reply line.
async fn serve(state: ServerState, stream: UnixStream) {
    let (read, mut write) = stream.into_split();
    let reply = match read_request(&state, read).await {
        Ok(request) => handle(&state, request).await,
        Err(error) => encode::<()>(Err(error)),
    };
    let _ = write.write_all(&reply).await;
    let _ = write.shutdown().await;
}

async fn read_request(
    state: &ServerState,
    read: tokio::net::unix::OwnedReadHalf,
) -> Result<Request, AdminError> {
    let mut line = Vec::new();
    let mut reader = BufReader::new(read.take(REQUEST_LIMIT as u64 + 1));
    tokio::select! {
        () = state.shutdown.cancelled() => return Err(AdminError::Stopping),
        read = tokio::time::timeout(REQUEST_WAIT, reader.read_until(b'\n', &mut line)) => {
            read.map_err(|_| AdminError::InvalidInput("request not received in time"))?
                .map_err(|_| AdminError::InvalidInput("invalid request"))?;
        }
    }
    if line.len() > REQUEST_LIMIT {
        return Err(AdminError::RequestTooLarge);
    }
    serde_json::from_slice(&line).map_err(|_| AdminError::InvalidInput("invalid request"))
}

async fn handle(state: &ServerState, request: Request) -> Vec<u8> {
    match request {
        Request::Holds { after } => {
            let after = match after.map(|id| parse_note_id(&id)).transpose() {
                Ok(after) => after,
                Err(_) => {
                    return encode::<()>(Err(AdminError::InvalidInput("invalid page cursor")))
                }
            };
            let (reply, receive) = oneshot::channel();
            encode(dispatch(state, Operation::List(after, reply), receive).await)
        }
        Request::Release {
            note_id,
            expected_event_seq,
            circle_not_accepted,
        } => {
            let note_id = match parse_note_id(&note_id) {
                Ok(note_id) if expected_event_seq > 0 => note_id,
                _ => return encode::<()>(Err(AdminError::InvalidInput("invalid hold selection"))),
            };
            let selection = ReleaseSelection {
                note_id,
                expected_event_seq,
                circle_not_accepted,
            };
            let (reply, receive) = oneshot::channel();
            encode(dispatch(state, Operation::Release(selection, reply), receive).await)
        }
    }
}

fn encode<T: Serialize>(result: Result<T, AdminError>) -> Vec<u8> {
    let reply = match result {
        Ok(value) => Reply::Ok(value),
        Err(error) => Reply::Error(error.body()),
    };
    let mut line = serde_json::to_vec(&reply).expect("admin replies serialize");
    line.push(b'\n');
    line
}

async fn dispatch<T>(
    state: &ServerState,
    operation: Operation,
    receive: oneshot::Receiver<Result<T, ReleaseError>>,
) -> Result<T, AdminError> {
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
        .map_err(AdminError::Release)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_code(line: &[u8]) -> String {
        match serde_json::from_slice::<Reply<serde_json::Value>>(line).unwrap() {
            Reply::Error(error) => error.code,
            Reply::Ok(value) => panic!("expected an error, got {value}"),
        }
    }

    #[test]
    fn requests_are_tagged_and_closed() {
        for line in [
            r#"{"op":"holds"}"#,
            r#"{"op":"holds","after":null}"#,
            r#"{"op":"release","note_id":"0x00","expected_event_seq":1}"#,
        ] {
            assert!(serde_json::from_str::<Request>(line).is_ok(), "{line}");
        }
        for line in [
            r#"{"op":"delete"}"#,
            r#"{"holds":[]}"#,
            r#"{"op":"holds","extra":true}"#,
            r#"{"op":"release","note_id":"0x00","expected_event_seq":1,"extra":true}"#,
        ] {
            assert!(serde_json::from_str::<Request>(line).is_err(), "{line}");
        }
    }

    #[tokio::test]
    async fn only_a_stale_socket_is_replaced_and_the_new_one_is_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.sock");
        let config = AdminConfig {
            socket: path.clone(),
        };
        fs::write(&path, b"not a socket").unwrap();
        assert!(Server::bind(&config).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not a socket");
        fs::remove_file(&path).unwrap();

        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let (live, _receiver) = Server::bind(&config).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(Server::bind(&config).is_err(), "a live socket is kept");
        assert!(path.exists());
        drop(live);
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_selections_are_not_queued_and_queue_failures_are_distinct() {
        let (commands, mut inbox) = mpsc::channel(1);
        let state = ServerState {
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
            let line = handle(
                &state,
                Request::Release {
                    note_id,
                    expected_event_seq,
                    circle_not_accepted: false,
                },
            )
            .await;
            assert_eq!(error_code(&line), "invalid_input");
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
        let list = || handle(&state, Request::Holds { after: None });
        assert_eq!(error_code(&list().await), "queue_full");
        inbox.recv().await.unwrap();
        assert_eq!(error_code(&list().await), "reply_timeout");
        assert!(inbox.recv().await.unwrap().abandoned());
        drop(inbox);
        assert_eq!(error_code(&list().await), "unavailable");
    }
}
