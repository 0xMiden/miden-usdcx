use tempfile::TempDir;

use super::*;
use crate::shutdown_tests::{config, page_server, pages_server};

fn head(hash: u8) -> String {
    serde_json::json!({"attestations": [{"messageHash": format!("0x{}", hex::encode([hash; 32]))}]})
        .to_string()
}

#[tokio::test]
async fn initialization_reads_only_one_head_and_never_opens_miden_state() {
    let directory = TempDir::new().unwrap();
    let (url, server) = pages_server(vec![(head(91), true)]);
    let mut config = config(&directory, &url);
    config.page_size = 100.try_into().unwrap();
    config.miden_data_dir = directory.path().join("must-not-exist");
    config.prover_url = Some("https://must-not-contact.invalid".parse().unwrap());

    assert_eq!(
        initialize_state_at_current_head(&config).await.unwrap(),
        MessageHash::new([91; 32])
    );
    let requests = server.join().unwrap();
    assert_eq!(
        requests,
        ["GET /v1/remote-domains/10007/attestations?pageSize=1 HTTP/1.1"]
    );
    assert!(!config.miden_data_dir.exists());
    assert_eq!(
        Store::new(config.state_file.clone()).state().unwrap(),
        State {
            watermark: Some(MessageHash::new([91; 32])),
            scan: None,
        }
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn initialization_rejects_missing_unreadable_or_invalid_heads_without_state() {
    for body in [
        "{\"attestations\":[]}",
        "{\"attestations\":[{}]}",
        "not json",
    ] {
        let directory = TempDir::new().unwrap();
        let (url, server) = page_server(body.to_owned(), true);
        let config = config(&directory, &url);
        assert!(initialize_state_at_current_head(&config).await.is_err());
        server.join().unwrap();
        assert!(!config.state_file.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn initialization_refuses_existing_state_before_contacting_circle() {
    for bytes in [b"".as_slice(), b"not progress", b"{\"watermark\":null}"] {
        let directory = TempDir::new().unwrap();
        let config = config(&directory, "http://127.0.0.1:1");
        std::fs::write(&config.state_file, bytes).unwrap();
        let error = initialize_state_at_current_head(&config).await.unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(std::fs::read(&config.state_file).unwrap(), bytes);
    }
}
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::anyhow;
use miden_protocol::crypto::utils::Serializable;
use miden_protocol::transaction::TransactionId;
use miden_protocol::{Word, EMPTY_WORD};
use miden_usdcx::xreserve::encoding::{DepositIntent, DepositIntentHeader, DepositNonce};
use usdcx_telemetry::FailureClass::Transient;

#[derive(Default)]
struct Calls {
    retains: usize,
    submitted: Vec<Vec<Word>>,
}

#[derive(Default)]
struct RecordingMiden {
    calls: Arc<Mutex<Calls>>,
    minted: Vec<DepositNonce>,
    fail_once: bool,
}

impl MidenClient for RecordingMiden {
    async fn retain_unminted(
        &mut self,
        nonces: Vec<DepositNonce>,
    ) -> Result<Vec<DepositNonce>, Failure> {
        self.calls.lock().unwrap().retains += 1;
        Ok(nonces
            .into_iter()
            .filter(|nonce| !self.minted.contains(nonce))
            .collect())
    }

    async fn submit_notes(&mut self, notes: Vec<Note>) -> Result<TransactionId, Failure> {
        self.calls.lock().unwrap().submitted.push(
            notes
                .iter()
                .map(|note| note.storage().commitment())
                .collect(),
        );
        if std::mem::take(&mut self.fail_once) {
            return Err(Failure::new(
                Transient("transaction_submit"),
                anyhow!("fixture inclusion response lost"),
            ));
        }
        Ok(TransactionId::new(
            EMPTY_WORD, EMPTY_WORD, EMPTY_WORD, EMPTY_WORD,
        ))
    }
}

fn deposit(config: &Config, hash: u8, nonce: u8) -> serde_json::Value {
    let vectors = miden_usdcx::vectors::load();
    let vector = vectors
        .families
        .mi
        .iter()
        .find(|vector| vector.id == "mi-pos-hookdata")
        .unwrap();
    let intent = DepositIntent::try_from(vector.payload().as_slice()).unwrap();
    let old = intent.header();
    let header = DepositIntentHeader::builder()
        .amount(old.amount())
        .remote_domain(config.remote_domain)
        .remote_token(config.faucet_account_id)
        .remote_recipient(old.remote_recipient())
        .local_token(old.local_token())
        .local_depositor(old.local_depositor())
        .max_fee(old.max_fee())
        .nonce(DepositNonce::new([nonce; 32]))
        .build();
    serde_json::json!({
        "payload": format!("0x{}", hex::encode(DepositIntent::new(header, intent.hook_data().clone()).to_bytes())),
        "messageHash": format!("0x{}", hex::encode([hash; 32])),
        "attestation": format!("0x{}", "00".repeat(65)),
    })
}

fn page(entries: &[serde_json::Value]) -> String {
    serde_json::json!({"attestations": entries}).to_string()
}

fn expected_storage(config: &Config, entry: serde_json::Value) -> Word {
    let entry = Entry::Attestation(serde_json::from_value(entry).unwrap());
    let note = Minter::from_config(config)
        .build_notes(&[entry])
        .notes
        .pop()
        .unwrap();
    Note::from(note).storage().commitment()
}

#[tokio::test]
async fn guarded_scan_stops_at_exact_hash_and_restart_stays_above_history() {
    let directory = TempDir::new().unwrap();
    let mut config = config(&directory, "http://127.0.0.1:1");
    config.page_size = 3.try_into().unwrap();
    // Reserve nonces are deliberately unrelated to feed order and message-hash equality.
    let fresh = deposit(&config, 21, 240);
    let entries = [
        fresh.clone(),
        deposit(&config, 11, 7),
        deposit(&config, 31, 128),
    ];
    let expected = expected_storage(&config, fresh);
    let (url, server) = pages_server(vec![(page(&entries), true), (page(&entries), true)]);
    config.circle_url = url.parse().unwrap();
    Store::new(config.state_file.clone())
        .initialize(MessageHash::new([11; 32]))
        .unwrap();
    let miden = RecordingMiden::default();
    let calls = miden.calls.clone();
    let mut relayer = Relayer::new_with_head_watermark(config.clone(), miden, true).unwrap();
    assert_eq!(
        relayer.scan(&CancellationToken::new()).await.unwrap(),
        ScanOutcome::Complete
    );
    assert_eq!(calls.lock().unwrap().submitted, vec![vec![expected]]);
    assert_eq!(
        relayer.store.state().unwrap(),
        State {
            watermark: Some(MessageHash::new([21; 32])),
            scan: None
        }
    );
    drop(relayer);
    let miden = RecordingMiden::default();
    let restarted_calls = miden.calls.clone();
    let mut restarted = Relayer::new_with_head_watermark(config, miden, true).unwrap();
    assert_eq!(
        restarted.scan(&CancellationToken::new()).await.unwrap(),
        ScanOutcome::Complete
    );
    assert!(restarted_calls.lock().unwrap().submitted.is_empty());
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| !request.contains("pageAfter")));
}

#[test]
fn guarded_start_rejects_missing_null_and_resumed_progress_without_rewriting() {
    let directory = TempDir::new().unwrap();
    let config = config(&directory, "http://127.0.0.1:1");
    let error = Relayer::new_with_head_watermark(config.clone(), RecordingMiden::default(), true)
        .err()
        .unwrap();
    assert!(error.is::<HeadWatermarkError>());
    assert!(!config.state_file.exists());
    for state in [
        State::default(),
        State {
            watermark: Some(MessageHash::new([11; 32])),
            scan: Some(ScanProgress {
                head: MessageHash::new([21; 32]),
                resume: CircleCursor::new("older"),
            }),
        },
    ] {
        let before = serde_json::to_vec(&state).unwrap();
        std::fs::write(&config.state_file, &before).unwrap();
        let error =
            Relayer::new_with_head_watermark(config.clone(), RecordingMiden::default(), true)
                .err()
                .unwrap();
        assert!(error.is::<HeadWatermarkError>());
        assert_eq!(std::fs::read(&config.state_file).unwrap(), before);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}

#[tokio::test]
async fn missing_empty_or_overflowed_head_boundary_stops_the_process_without_mint_actions() {
    for count in 0..=2 {
        let directory = TempDir::new().unwrap();
        let mut config = config(&directory, "http://127.0.0.1:1");
        config.page_size = 2.try_into().unwrap();
        let entries = (0..count)
            .map(|index| deposit(&config, 21 + index, 240 - index))
            .collect::<Vec<_>>();
        let (url, server) = pages_server(vec![(page(&entries), true)]);
        config.circle_url = url.parse().unwrap();
        Store::new(config.state_file.clone())
            .initialize(MessageHash::new([11; 32]))
            .unwrap();
        let before = std::fs::read(&config.state_file).unwrap();
        let miden = RecordingMiden::default();
        let calls = miden.calls.clone();
        let relayer = Relayer::new_with_head_watermark(config.clone(), miden, true).unwrap();
        assert_eq!(std::fs::read(&config.state_file).unwrap(), before);
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            relayer.run_until(CancellationToken::new()),
        )
        .await
        .expect("boundary failure must be terminal")
        .unwrap_err();
        assert!(error.is::<HeadWatermarkError>());
        assert_eq!(calls.lock().unwrap().retains, 0);
        assert!(calls.lock().unwrap().submitted.is_empty());
        assert_eq!(std::fs::read(&config.state_file).unwrap(), before);
        assert_eq!(server.join().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn guarded_restart_after_unknown_inclusion_filters_already_minted_nonce() {
    let directory = TempDir::new().unwrap();
    let mut config = config(&directory, "http://127.0.0.1:1");
    config.page_size = 2.try_into().unwrap();
    let entries = [deposit(&config, 21, 240), deposit(&config, 11, 7)];
    let (url, server) = pages_server(vec![(page(&entries), false), (page(&entries), false)]);
    config.circle_url = url.parse().unwrap();
    Store::new(config.state_file.clone())
        .initialize(MessageHash::new([11; 32]))
        .unwrap();
    let before = std::fs::read(&config.state_file).unwrap();
    let mut relayer = Relayer::new_with_head_watermark(
        config.clone(),
        RecordingMiden {
            fail_once: true,
            ..Default::default()
        },
        true,
    )
    .unwrap();
    assert!(relayer.scan(&CancellationToken::new()).await.is_err());
    assert_eq!(std::fs::read(&config.state_file).unwrap(), before);
    drop(relayer);
    let miden = RecordingMiden {
        minted: vec![DepositNonce::new([240; 32])],
        ..Default::default()
    };
    let calls = miden.calls.clone();
    let mut restarted = Relayer::new_with_head_watermark(config, miden, true).unwrap();
    assert_eq!(
        restarted.scan(&CancellationToken::new()).await.unwrap(),
        ScanOutcome::Complete
    );
    assert!(calls.lock().unwrap().submitted.is_empty());
    assert!(restarted.store.state().unwrap().scan.is_none());
    assert_eq!(server.join().unwrap().len(), 2);
}

#[tokio::test]
async fn ordinary_mode_still_walks_older_pages() {
    let directory = TempDir::new().unwrap();
    let mut config = config(&directory, "http://127.0.0.1:1");
    let first = deposit(&config, 21, 240);
    let older = deposit(&config, 11, 7);
    let (url, server) = pages_server(vec![(page(&[first]), true), (page(&[older]), false)]);
    config.circle_url = url.parse().unwrap();
    let miden = RecordingMiden::default();
    let calls = miden.calls.clone();
    let mut relayer = Relayer::new(config, miden).unwrap();
    assert_eq!(
        relayer.scan(&CancellationToken::new()).await.unwrap(),
        ScanOutcome::Complete
    );
    assert_eq!(calls.lock().unwrap().submitted.len(), 2);
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("pageAfter=older"));
}

#[tokio::test]
async fn guarded_scan_rechecks_changed_progress_before_any_feed_request() {
    let directory = TempDir::new().unwrap();
    let config = config(&directory, "http://127.0.0.1:1");
    Store::new(config.state_file.clone())
        .initialize(MessageHash::new([11; 32]))
        .unwrap();
    let miden = RecordingMiden::default();
    let calls = miden.calls.clone();
    let mut relayer = Relayer::new_with_head_watermark(config.clone(), miden, true).unwrap();
    let changed = b"{\"watermark\":null}";
    std::fs::write(&config.state_file, changed).unwrap();
    let failure = relayer.scan(&CancellationToken::new()).await.unwrap_err();
    assert!(failure.error.is::<HeadWatermarkError>());
    assert_eq!(std::fs::read(&config.state_file).unwrap(), changed);
    assert_eq!(calls.lock().unwrap().retains, 0);
    assert!(calls.lock().unwrap().submitted.is_empty());
}
