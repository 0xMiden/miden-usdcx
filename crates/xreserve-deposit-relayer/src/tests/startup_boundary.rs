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
