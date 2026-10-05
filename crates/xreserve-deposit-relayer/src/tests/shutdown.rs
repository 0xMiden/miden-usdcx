use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use anyhow::bail;
use clap::Parser;
use miden_protocol::account::AccountId;
use miden_protocol::transaction::TransactionId;
use miden_usdcx::note::xreserve_mint::XUsdcMintNote;
use tempfile::TempDir;

use super::*;

#[derive(Debug)]
struct TestMiden {
    reached_page: Sender<()>,
}

impl MidenClient for TestMiden {
    fn retain_unminted(&mut self, notes: Vec<XUsdcMintNote>) -> Result<Vec<XUsdcMintNote>> {
        assert!(notes.is_empty());
        self.reached_page.send(())?;
        Ok(notes)
    }

    fn submit_notes(&mut self, _: AccountId, _: Vec<Note>) -> Result<TransactionId> {
        bail!("the shutdown fixture must not submit a transaction")
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
fn stopping_after_a_page_saves_the_resume_cursor() {
    let directory = TempDir::new().unwrap();
    let body = serde_json::json!({"attestations": [{
        "payload": "0x", "messageHash": format!("0x{}", "01".repeat(32)),
        "attestation": format!("0x{}", "00".repeat(65)),
    }]})
    .to_string();
    let (url, server) = page_server(body, true);
    let config = config(&directory, &url);
    let path = config.state_file.clone();
    let (stop, shutdown) = mpsc::channel();
    let mut relayer = Relayer::new(config, Box::new(TestMiden { reached_page: stop })).unwrap();
    assert_eq!(relayer.scan(&shutdown).unwrap(), ScanOutcome::Stopped);
    drop(relayer);
    server.join().unwrap();
    let saved = Store::new(path).state().unwrap();
    assert!(saved.watermark.is_none());
    let scan = saved.scan.unwrap();
    assert_eq!(scan.head, MessageHash::new([1; 32]));
    assert_eq!(scan.resume.as_str(), "older");
}

#[test]
fn shutdown_wakes_the_poll_wait() {
    let directory = TempDir::new().unwrap();
    let (url, server) = page_server("{\"attestations\":[]}".into(), false);
    let config = config(&directory, &url);
    let (stop, shutdown) = mpsc::channel();
    let (reached_page, page) = mpsc::channel();
    let (done, result) = mpsc::channel();
    let worker = thread::spawn(move || {
        let relayer = Relayer::new(config, Box::new(TestMiden { reached_page })).unwrap();
        done.send(relayer.run_until(shutdown)).unwrap();
    });
    page.recv_timeout(Duration::from_secs(2)).unwrap();
    server.join().unwrap();
    stop.send(()).unwrap();
    result
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
}
