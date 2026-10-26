use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use clap::Parser;
use miden_client::rpc::{AddTransactionError, EndpointError, GrpcError, RpcEndpoint, RpcError};
use miden_client::ClientError;
use miden_protocol::crypto::utils::Serializable;
use miden_protocol::transaction::TransactionId;
use miden_usdcx::xreserve::encoding::{DepositIntent, DepositIntentHeader, DepositNonce};
use rstest::rstest;
use tempfile::TempDir;
use usdcx_telemetry::FailureClass::{Actionable, Transient};

use super::*;

#[derive(Debug)]
struct TestMiden {
    reached_page: CancellationToken,
}

impl MidenClient for TestMiden {
    async fn retain_unminted(
        &mut self,
        nonces: Vec<DepositNonce>,
    ) -> Result<Vec<DepositNonce>, Failure> {
        assert!(nonces.is_empty());
        self.reached_page.cancel();
        Ok(nonces)
    }

    async fn submit_notes(&mut self, _: Vec<Note>) -> Result<TransactionId, Failure> {
        Err(Failure::new(
            Actionable("unexpected_submission"),
            anyhow!("the shutdown fixture must not submit a transaction"),
        ))
    }
}

fn config(directory: &TempDir, url: &str) -> Config {
    let mut config = Config::try_parse_from([
        "relayer",
        "--circle-url",
        url,
        "--page-size",
        "1",
        "--request-timeout",
        "1s",
        "--poll-interval",
        "60s",
        "--remote-domain",
        "10007",
        "--miden-node-url",
        "http://127.0.0.1:1",
        "--miden-data-dir",
        "unused",
        "--faucet-account-id",
        "0xbb405fd9fe431bd1135a292de098cb",
        "--relayer-account-id",
        "0xbb405fd9fe431bd1135a292de098cb",
        "--attester-public-key",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "--state-file",
        "unused",
    ])
    .unwrap();
    config.state_file = directory.path().join("progress.json");
    config
}

fn page_server(body: String, next: bool) -> (String, thread::JoinHandle<()>) {
    let (url, server) = pages_server(vec![(body, next)]);
    (url, thread::spawn(move || drop(server.join().unwrap())))
}

/// Serves `pages` in order, one per request, and returns the request lines it was sent. A page
/// with `next` links to the `older` cursor.
fn pages_server(pages: Vec<(String, bool)>) -> (String, thread::JoinHandle<Vec<String>>) {
    cursor_pages_server(
        pages
            .into_iter()
            .map(|(body, next)| (body, next.then_some("older")))
            .collect(),
    )
}

fn cursor_pages_server(
    pages: Vec<(String, Option<&'static str>)>,
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for (body, next) in pages {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 4096];
            let read = stream.read(&mut request).unwrap();
            assert!(read > 0);
            let request = String::from_utf8_lossy(&request[..read]);
            requests.push(request.lines().next().unwrap_or_default().to_owned());
            let link = next
                .map(|cursor| {
                    format!(
                        "Link: <https://circle.invalid/feed?pageAfter={cursor}>; rel=\"next\"\r\n"
                    )
                })
                .unwrap_or_default();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{link}Connection: close\r\n\r\n{body}", body.len()).unwrap();
        }
        requests
    });
    (url, server)
}

#[tokio::test]
async fn proving_mode_caps_the_circle_request_without_dropping_deposits() {
    for (remote, requested, expected) in [
        (false, 100, 10),
        (true, 100, 40),
        (false, 3, 3),
        (true, 3, 3),
    ] {
        let directory = TempDir::new().unwrap();
        let oversized =
            serde_json::json!({"attestations": vec![serde_json::Value::Null; expected + 1]})
                .to_string();
        let (url, server) = pages_server(vec![
            (oversized, true),
            ("{\"attestations\":[]}".into(), false),
        ]);
        let mut config = config(&directory, &url);
        config.page_size = requested.try_into().unwrap();
        config.prover_url = remote.then(|| "https://prover.invalid".parse().unwrap());
        assert_eq!(config.prover_timeout, Duration::from_secs(30));
        let mut relayer = Relayer::new(
            config,
            TestMiden {
                reached_page: CancellationToken::new(),
            },
        )
        .unwrap();
        let before = relayer.store.state().unwrap();
        let failure = relayer.scan(&CancellationToken::new()).await.unwrap_err();
        assert_eq!(failure.class, Transient("invalid_response"));
        assert_eq!(relayer.store.state().unwrap(), before);
        assert_eq!(
            relayer.scan(&CancellationToken::new()).await.unwrap(),
            ScanOutcome::Complete
        );
        let requests = server.join().unwrap();
        assert_eq!(requests[0], requests[1]);
        assert!(
            requests[0].contains(&format!("pageSize={expected} ")),
            "{}",
            requests[0]
        );
    }
}

#[test]
fn programmatic_config_cannot_bypass_prover_validation() {
    let directory = TempDir::new().unwrap();
    let mut config = config(&directory, "http://127.0.0.1:1");
    config.prover_url = Some("file:///tmp/prover".parse().unwrap());
    assert!(config.validate_prover().is_err());
    config.prover_url = None;
    config.prover_timeout = Duration::ZERO;
    assert!(config.validate_prover().is_err());
}

#[rstest]
#[case::expired_head(true, 40, false)]
#[case::expired_resume(true, 40, true)]
#[case::smaller_stays_smaller(true, 3, false)]
#[case::other_failure(false, 40, true)]
#[tokio::test]
async fn a_failed_submission_keeps_progress_and_only_expiration_reduces_pages(
    #[case] expired: bool,
    #[case] page_size: u16,
    #[case] resumed: bool,
) {
    struct FailsOnce {
        error: Option<ClientError>,
        batches: Vec<Vec<miden_protocol::Word>>,
    }
    impl MidenClient for FailsOnce {
        async fn retain_unminted(
            &mut self,
            nonces: Vec<DepositNonce>,
        ) -> Result<Vec<DepositNonce>, Failure> {
            Ok(nonces)
        }

        async fn submit_notes(&mut self, notes: Vec<Note>) -> Result<TransactionId, Failure> {
            self.batches.push(
                notes
                    .iter()
                    .map(|note| note.storage().commitment())
                    .collect(),
            );
            if let Some(error) = self.error.take() {
                return Err(Failure::new(Transient("transaction_submit"), error)
                    .context("submitting the mint transaction"));
            }
            Ok(TransactionId::new(
                miden_protocol::EMPTY_WORD,
                miden_protocol::EMPTY_WORD,
                miden_protocol::EMPTY_WORD,
                miden_protocol::EMPTY_WORD,
            ))
        }
    }

    let directory = TempDir::new().unwrap();
    let mut config = config(&directory, "http://127.0.0.1:1");
    let vectors = miden_usdcx::vectors::load();
    let vector = vectors
        .families
        .mi
        .iter()
        .find(|vector| vector.id == "mi-pos-hookdata")
        .unwrap();
    let intent = DepositIntent::try_from(vector.payload().as_slice()).unwrap();
    let header = intent.header();
    // The encoding vector's target is private; a mint note must target a public account.
    let count = usize::from(page_size.min(11));
    let entries = (1..=count)
        .map(|index| {
            let header = DepositIntentHeader::builder()
                .amount(header.amount())
                .remote_domain(config.remote_domain)
                .remote_token(config.faucet_account_id)
                .remote_recipient(header.remote_recipient())
                .local_token(header.local_token())
                .local_depositor(header.local_depositor())
                .max_fee(header.max_fee())
                .nonce(DepositNonce::new([index as u8; 32]))
                .build();
            let payload = DepositIntent::new(header, intent.hook_data().clone()).to_bytes();
            serde_json::json!({
            "payload": format!("0x{}", hex::encode(payload)),
            "messageHash": format!("0x{}", hex::encode([index as u8; 32])),
            "attestation": format!("0x{}", "00".repeat(65)),
            })
        })
        .collect::<Vec<_>>();
    let body =
        |entries: &[serde_json::Value]| serde_json::json!({"attestations": entries}).to_string();
    let retry_size = if expired {
        page_size.min(10)
    } else {
        page_size
    };
    let mut pages = vec![(body(&entries), Some("stale-outgoing"))];
    let chunks = entries.chunks(usize::from(retry_size)).collect::<Vec<_>>();
    pages.extend(chunks.iter().enumerate().map(|(index, entries)| {
        (
            body(entries),
            (index + 1 < chunks.len()).then_some("retry-next"),
        )
    }));
    pages.push((body(&[]), None));
    let (url, server) = cursor_pages_server(pages);
    config.circle_url = url.parse().unwrap();
    config.prover_url = Some("https://prover.invalid".parse().unwrap());
    config.page_size = page_size.try_into().unwrap();
    if resumed {
        Store::new(config.state_file.clone())
            .set_state(&store::State {
                watermark: Some(MessageHash::new([88; 32])),
                scan: Some(ScanProgress {
                    head: MessageHash::new([99; 32]),
                    resume: CircleCursor::new("resume-here"),
                }),
            })
            .unwrap();
    }
    let error = ClientError::RpcError(RpcError::RequestError {
        endpoint: RpcEndpoint::SubmitProvenTx,
        error_kind: if expired {
            GrpcError::InvalidArgument
        } else {
            GrpcError::DeadlineExceeded
        },
        endpoint_error: expired
            .then_some(EndpointError::AddTransaction(AddTransactionError::Expired)),
        source: None,
    });
    let mut relayer = Relayer::new(
        config,
        FailsOnce {
            error: Some(error),
            batches: Vec::new(),
        },
    )
    .unwrap();
    let before = relayer.store.state().unwrap();
    let saved_bytes = std::fs::read(&relayer.config.state_file).unwrap();
    assert_eq!(
        relayer
            .scan(&CancellationToken::new())
            .await
            .unwrap_err()
            .class,
        Transient("transaction_submit")
    );
    assert_eq!(relayer.store.state().unwrap(), before);
    assert_eq!(
        std::fs::read(&relayer.config.state_file).unwrap(),
        saved_bytes
    );
    assert_eq!(
        relayer.scan(&CancellationToken::new()).await.unwrap(),
        ScanOutcome::Complete
    );
    let batches = &relayer.miden_client.batches;
    assert_eq!(batches[0].len(), count);
    assert_eq!(batches[1..].concat(), batches[0]);
    assert!(batches[1..]
        .iter()
        .all(|batch| batch.len() <= usize::from(retry_size)));
    assert_eq!(
        relayer.store.state().unwrap().watermark,
        Some(MessageHash::new([if resumed { 99 } else { 1 }; 32]))
    );
    assert_eq!(
        relayer.scan(&CancellationToken::new()).await.unwrap(),
        ScanOutcome::Complete
    );
    let requests = server.join().unwrap();
    assert!(requests[0].contains(&format!("pageSize={page_size}")));
    for request in &requests[1..] {
        assert!(
            request.contains(&format!("pageSize={retry_size}")),
            "{request}"
        );
        assert!(!request.contains("stale-outgoing"), "{request}");
    }
    assert_eq!(requests[0].contains("pageAfter=resume-here"), resumed);
    assert_eq!(requests[1].contains("pageAfter=resume-here"), resumed);
    if chunks.len() > 1 {
        assert!(requests[2].contains("pageAfter=retry-next"));
    }
}

/// Startup warns when the proving cap lowers the configured page size, naming both sizes, and
/// stays quiet when the configured size already fits.
#[rstest]
#[case::local_cap(100, false, Some("configured_page_size=100 page_size=10"))]
#[case::remote_cap(100, true, Some("configured_page_size=100 page_size=40"))]
#[case::fits(3, false, None)]
fn startup_warns_when_the_proving_cap_lowers_the_page_size(
    #[case] requested: u16,
    #[case] remote: bool,
    #[case] warning: Option<&str>,
) {
    #[derive(Clone, Default)]
    struct Logs(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Logs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let directory = TempDir::new().unwrap();
    let mut config = config(&directory, "http://127.0.0.1:1");
    config.page_size = requested.try_into().unwrap();
    config.prover_url = remote.then(|| "https://prover.invalid".parse().unwrap());
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        Relayer::new(
            config,
            TestMiden {
                reached_page: CancellationToken::new(),
            },
        )
        .unwrap();
    });

    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let warned = logs.lines().find(|line| line.contains(" WARN "));
    match warning {
        Some(fields) => assert!(warned.is_some_and(|line| line.contains(fields)), "{logs}"),
        None => assert!(warned.is_none(), "{logs}"),
    }
}

#[test]
fn startup_creates_progress_and_preserves_a_resumed_scan() {
    let directory = TempDir::new().unwrap();
    let config = config(&directory, "http://127.0.0.1:1");
    let store = Store::new(config.state_file.clone());
    let build = |config| {
        Relayer::new(
            config,
            TestMiden {
                reached_page: CancellationToken::new(),
            },
        )
    };
    drop(build(config.clone()).unwrap());
    assert_eq!(store.state().unwrap(), store::State::default());

    let saved = store::State {
        watermark: Some(MessageHash::new([1; 32])),
        scan: Some(ScanProgress {
            head: MessageHash::new([2; 32]),
            resume: CircleCursor::new("older"),
        }),
    };
    store.set_state(&saved).unwrap();
    let bytes = std::fs::read(&config.state_file).unwrap();
    drop(build(config.clone()).unwrap());
    assert_eq!(store.state().unwrap(), saved);
    assert_eq!(std::fs::read(&config.state_file).unwrap(), bytes);
}

#[test]
fn startup_refuses_corrupt_progress_without_replacing_it() {
    let directory = TempDir::new().unwrap();
    let config = config(&directory, "http://127.0.0.1:1");
    std::fs::write(&config.state_file, "{broken").unwrap();
    let result = Relayer::new(
        config.clone(),
        TestMiden {
            reached_page: CancellationToken::new(),
        },
    );
    let error = format!("{:#}", result.err().unwrap());
    assert!(error.contains("reading relayer startup progress"));
    assert_eq!(std::fs::read(&config.state_file).unwrap(), b"{broken");
    assert!(!config.state_file.with_extension("tmp").exists());
}

#[test]
fn startup_refuses_a_progress_directory_without_write_permission() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TempDir::new().unwrap();
    let config = config(&directory, "http://127.0.0.1:1");
    let store = Store::new(config.state_file.clone());
    store.set_state(&store::State::default()).unwrap();
    let bytes = std::fs::read(&config.state_file).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = Relayer::new(
        config.clone(),
        TestMiden {
            reached_page: CancellationToken::new(),
        },
    );
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = format!("{:#}", result.err().unwrap());
    assert!(error.contains("checking relayer progress persistence"));
    assert!(error.contains("Permission denied"));
    assert_eq!(std::fs::read(&config.state_file).unwrap(), bytes);
}

#[tokio::test]
async fn stopping_after_a_page_saves_the_resume_cursor() {
    let directory = TempDir::new().unwrap();
    let body = serde_json::json!({"attestations": [{
        "payload": "0x", "messageHash": format!("0x{}", "01".repeat(32)),
        "attestation": format!("0x{}", "00".repeat(65)),
    }]})
    .to_string();
    let (url, server) = page_server(body, true);
    let config = config(&directory, &url);
    let path = config.state_file.clone();
    let shutdown = CancellationToken::new();
    let mut relayer = Relayer::new(
        config,
        TestMiden {
            reached_page: shutdown.clone(),
        },
    )
    .unwrap();
    assert_eq!(relayer.scan(&shutdown).await.unwrap(), ScanOutcome::Stopped);
    drop(relayer);
    server.join().unwrap();
    let saved = Store::new(path).state().unwrap();
    assert!(saved.watermark.is_none());
    let scan = saved.scan.unwrap();
    assert_eq!(scan.head, MessageHash::new([1; 32]));
    assert_eq!(scan.resume.as_str(), "older");
}

/// An entry that does not decode does not hold up its page: the page is recorded as done, and the
/// entry's message hash, which could still be read, becomes the watermark like any other.
#[tokio::test]
async fn a_page_with_an_undecodable_entry_is_recorded_as_done() {
    let directory = TempDir::new().unwrap();
    let body = serde_json::json!({"attestations": [{
        "payload": "not hex", "messageHash": format!("0x{}", "01".repeat(32)),
        "attestation": "0x00",
    }]})
    .to_string();
    let (url, server) = page_server(body, false);
    let config = config(&directory, &url);
    let path = config.state_file.clone();
    let mut relayer = Relayer::new(
        config,
        TestMiden {
            reached_page: CancellationToken::new(),
        },
    )
    .unwrap();
    assert_eq!(
        relayer.scan(&CancellationToken::new()).await.unwrap(),
        ScanOutcome::Complete
    );
    drop(relayer);
    server.join().unwrap();
    let saved = Store::new(path).state().unwrap();
    assert_eq!(saved.watermark, Some(MessageHash::new([1; 32])));
    assert!(saved.scan.is_none());
}

/// A head page where no message hash can be read does not end the scan: the walk follows its next
/// link, and the first readable hash it meets becomes the watermark.
#[tokio::test]
async fn a_head_page_without_a_readable_hash_still_walks_to_the_next_page() {
    let directory = TempDir::new().unwrap();
    let unreadable = serde_json::json!({"attestations": [{
        "payload": "0x", "messageHash": "not hex",
        "attestation": format!("0x{}", "00".repeat(65)),
    }]})
    .to_string();
    let readable = serde_json::json!({"attestations": [{
        "payload": "not hex", "messageHash": format!("0x{}", "02".repeat(32)),
        "attestation": "0x00",
    }]})
    .to_string();
    let (url, server) = pages_server(vec![(unreadable, true), (readable, false)]);
    let config = config(&directory, &url);
    let path = config.state_file.clone();
    let mut relayer = Relayer::new(
        config,
        TestMiden {
            reached_page: CancellationToken::new(),
        },
    )
    .unwrap();
    assert_eq!(
        relayer.scan(&CancellationToken::new()).await.unwrap(),
        ScanOutcome::Complete
    );
    drop(relayer);
    // Checked before joining the server, which would otherwise wait for a page never asked for.
    let saved = Store::new(path).state().unwrap();
    assert_eq!(saved.watermark, Some(MessageHash::new([2; 32])));
    assert!(saved.scan.is_none());
    let requests = server.join().unwrap();
    assert!(!requests[0].contains("pageAfter"), "{}", requests[0]);
    assert!(requests[1].contains("pageAfter=older"), "{}", requests[1]);
}

#[tokio::test]
async fn shutdown_wakes_the_poll_wait() {
    let directory = TempDir::new().unwrap();
    let (url, server) = page_server("{\"attestations\":[]}".into(), false);
    let config = config(&directory, &url);
    let shutdown = CancellationToken::new();
    let reached_page = CancellationToken::new();
    let relayer = Relayer::new(
        config,
        TestMiden {
            reached_page: reached_page.clone(),
        },
    )
    .unwrap();
    let worker = tokio::spawn(relayer.run_until(shutdown.clone()));
    tokio::time::timeout(Duration::from_secs(2), reached_page.cancelled())
        .await
        .unwrap();
    server.join().unwrap();
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn an_unreachable_circle_fails_the_scan_as_transient() {
    let directory = TempDir::new().unwrap();
    let mut relayer = Relayer::new(
        config(&directory, "http://127.0.0.1:1"),
        TestMiden {
            reached_page: CancellationToken::new(),
        },
    )
    .unwrap();
    let failure = relayer.scan(&CancellationToken::new()).await.unwrap_err();
    assert_eq!(failure.class, Transient("circle_unavailable"));
}

#[tokio::test]
async fn a_page_that_cannot_be_recorded_fails_the_scan_as_actionable() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TempDir::new().unwrap();
    let body = serde_json::json!({"attestations": [{
        "payload": "0x", "messageHash": format!("0x{}", "01".repeat(32)),
        "attestation": format!("0x{}", "00".repeat(65)),
    }]})
    .to_string();
    let (url, server) = page_server(body, false);
    let mut relayer = Relayer::new(
        config(&directory, &url),
        TestMiden {
            reached_page: CancellationToken::new(),
        },
    )
    .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = relayer.scan(&CancellationToken::new()).await;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    server.join().unwrap();
    let failure = result.unwrap_err();
    assert_eq!(failure.class, Actionable("progress_file"));
}
