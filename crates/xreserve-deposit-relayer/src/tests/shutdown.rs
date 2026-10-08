use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use clap::Parser;
use miden_protocol::account::AccountId;
use miden_protocol::transaction::TransactionId;
use miden_usdcx::note::xreserve_mint::XUsdcMintNote;
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
        notes: Vec<XUsdcMintNote>,
    ) -> Result<Vec<XUsdcMintNote>, Failure> {
        assert!(notes.is_empty());
        self.reached_page.cancel();
        Ok(notes)
    }

    async fn submit_notes(&mut self, _: AccountId, _: Vec<Note>) -> Result<TransactionId, Failure> {
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
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        let link = if next {
            "Link: <https://circle.invalid/feed?pageAfter=older>; rel=\"next\"\r\n"
        } else {
            ""
        };
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{link}Connection: close\r\n\r\n{body}", body.len()).unwrap();
    });
    (url, server)
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
