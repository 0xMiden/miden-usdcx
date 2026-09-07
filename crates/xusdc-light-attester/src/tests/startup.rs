//! Startup configuration and preflight contract tests.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::Word;
use reqwest::{Method, StatusCode};
use tempfile::TempDir;

use crate::attester::{Attester, StartError};
use crate::circle::HttpTransport;
use crate::config::Config;
use crate::store::{ScanCursor, ScanState, Store, TrustedAnchor};

use super::support::{
    faucet_account_id, ready_circle, startup_anchor, CircleState, FakeCircle, ObservedRequest,
    TestChain, FAUCET_ACCOUNT_ID,
};

const OTHER_FAUCET_ACCOUNT_ID: &str = "0x9b405fd9fe431bd1135a292de098cb";
const SIGNING_KEY_ONE: &str =
    "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SIGNING_KEY_TWO: &str =
    "0x02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const CONFIG_FILE: &str = "attester.toml";
const STORE_FILE: &str = "state/checkpoints/withdrawal-cursor.sqlite3";
const REQUEST_TIMEOUT: Duration = Duration::from_millis(275);
const LOCK_CHILD_CONFIG: &str = "XUSDC_ATTESTER_LOCK_CHILD_CONFIG";

fn config_toml(deployment_block: u64) -> String {
    let anchor_commitment = startup_anchor().header().commitment().to_hex();
    format!(
        "circle_request_timeout_ms = {}\n\
         faucet_account_id_hex = \"{FAUCET_ACCOUNT_ID}\"\n\
         circle_api_base_url = \"https://circle.example.invalid\"\n\
         poll_interval_ms = 1000\n\
         faucet_deployment_block = {deployment_block}\n\
         trusted_anchor_block = 0\n\
         trusted_anchor_commitment_hex = \"{anchor_commitment}\"\n\
         minimum_finality_depth_blocks = 1\n\
         expected_signing_public_keys_hex = [\"{SIGNING_KEY_ONE}\", \"{SIGNING_KEY_TWO}\"]\n\
         store_path = \"{STORE_FILE}\"\n",
        REQUEST_TIMEOUT.as_millis()
    )
}

fn replace_setting(config: &str, key: &str, replacement: &str) -> String {
    config
        .lines()
        .map(|line| {
            if line.starts_with(&format!("{key} =")) {
                replacement
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn remove_setting(config: &str, key: &str) -> String {
    replace_setting(config, key, "")
}

fn write_config(tempdir: &TempDir, deployment_block: u32) -> PathBuf {
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, config_toml(u64::from(deployment_block))).unwrap();
    path
}

fn load_config(tempdir: &TempDir, deployment_block: u32) -> Config {
    Config::load(&write_config(tempdir, deployment_block)).unwrap()
}

fn create_store_parent(tempdir: &TempDir) -> PathBuf {
    let path = tempdir.path().join(STORE_FILE);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

fn assert_config_error(config: &str, expected_error: &str) {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, config).unwrap();
    let error = Config::load(&path).expect_err("invalid config must be rejected");
    assert_eq!(error.to_string(), expected_error);
}

fn other_faucet_account_id() -> AccountId {
    AccountId::from_hex(OTHER_FAUCET_ACCOUNT_ID).unwrap()
}

fn trusted_anchor() -> TrustedAnchor {
    TrustedAnchor {
        block_num: BlockNumber::GENESIS,
        commitment: startup_anchor().header().commitment(),
    }
}

async fn start(
    config: Config,
    chain: TestChain,
    circle: Box<dyn HttpTransport>,
) -> Result<Attester, StartError> {
    Attester::start(config, Box::new(chain), circle).await
}

#[test]
fn invalid_config_is_rejected() {
    let valid = config_toml(1);
    let cases = [
        (
            "circle_request_timeout_ms",
            "circle_request_timeout_ms = 0",
            "circle request timeout must be greater than zero",
        ),
        (
            "faucet_account_id_hex",
            "faucet_account_id_hex = \"invalid\"",
            "faucet account id is invalid",
        ),
        (
            "faucet_account_id_hex",
            "faucet_account_id_hex = \"0xBB405FD9FE431BD1135A292DE098CB\"",
            "faucet account id must use canonical 0x-prefixed lowercase hex",
        ),
        (
            "circle_api_base_url",
            "circle_api_base_url = \"not a URL\"",
            "Circle API base URL is invalid",
        ),
        (
            "circle_api_base_url",
            "circle_api_base_url = \"http://circle.example.invalid\"",
            "Circle API base URL must be an absolute HTTPS URL",
        ),
        (
            "poll_interval_ms",
            "poll_interval_ms = 0",
            "poll interval must be greater than zero",
        ),
        (
            "faucet_deployment_block",
            "faucet_deployment_block = 4294967296",
            "failed to parse config",
        ),
        (
            "trusted_anchor_block",
            "trusted_anchor_block = 4294967296",
            "failed to parse config",
        ),
        (
            "trusted_anchor_commitment_hex",
            "trusted_anchor_commitment_hex = \"0X0100000000000000020000000000000003000000000000000400000000000000\"",
            "trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex",
        ),
        (
            "trusted_anchor_commitment_hex",
            "trusted_anchor_commitment_hex = \"0x01\"",
            "trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex",
        ),
        (
            "trusted_anchor_commitment_hex",
            "trusted_anchor_commitment_hex = \"0x01000000000000000200000000000000030000000000000004000000000000AA\"",
            "trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex",
        ),
        (
            "trusted_anchor_commitment_hex",
            "trusted_anchor_commitment_hex = \"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"",
            "trusted anchor commitment is invalid",
        ),
        (
            "minimum_finality_depth_blocks",
            "minimum_finality_depth_blocks = 0",
            "minimum finality depth must be greater than zero",
        ),
        (
            "store_path",
            "store_path = \"\"",
            "store path must not be empty",
        ),
        (
            "store_path",
            "store_path = \"missing/store.sqlite3\"",
            "store path parent does not exist",
        ),
    ];

    for (key, replacement, expected_error) in cases {
        assert_config_error(&replace_setting(&valid, key, replacement), expected_error);
    }

    for missing_key in [
        "circle_request_timeout_ms",
        "faucet_account_id_hex",
        "circle_api_base_url",
        "poll_interval_ms",
        "faucet_deployment_block",
        "trusted_anchor_block",
        "trusted_anchor_commitment_hex",
        "minimum_finality_depth_blocks",
        "expected_signing_public_keys_hex",
        "store_path",
    ] {
        assert_config_error(
            &remove_setting(&valid, missing_key),
            "failed to parse config",
        );
    }

    for invalid_toml in [
        "circle_request_timeout_ms =".to_string(),
        replace_setting(
            &valid,
            "circle_request_timeout_ms",
            "circle_request_timeout_ms = \"1000\"",
        ),
        format!("{valid}unknown_setting = true\n"),
    ] {
        assert_config_error(&invalid_toml, "failed to parse config");
    }

    let tempdir = tempfile::tempdir().unwrap();
    let missing_path = tempdir.path().join("missing.toml");
    let error = Config::load(&missing_path).expect_err("missing config must be rejected");
    assert_eq!(error.to_string(), "failed to read config");

    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    std::fs::write(tempdir.path().join("not-a-directory"), b"file").unwrap();
    let invalid = replace_setting(
        &valid,
        "store_path",
        "store_path = \"not-a-directory/store.sqlite3\"",
    );
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, invalid).unwrap();
    let error = match Config::load(&path) {
        Err(error) => error,
        Ok(_) => panic!("a store parent file must be rejected"),
    };
    assert_eq!(error.to_string(), "store path parent must be a directory");

    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let absolute_store = tempdir.path().join("absolute.sqlite3");
    let config = replace_setting(
        &config_toml(0),
        "store_path",
        &format!("store_path = {:?}", absolute_store),
    );
    let config = replace_setting(
        &config,
        "expected_signing_public_keys_hex",
        "expected_signing_public_keys_hex = [\"unchecked\"]",
    );
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, config).unwrap();
    let config = Config::load(&path).expect("unchecked signing keys remain accepted in S1");
    assert_eq!(config.store_path(), absolute_store);
    assert_eq!(config.faucet_deployment_block(), BlockNumber::from(0u32));
    assert_eq!(config.trusted_anchor_block(), BlockNumber::from(0u32));
    assert_eq!(
        config.trusted_anchor_commitment(),
        startup_anchor().header().commitment()
    );
    assert_eq!(config.minimum_finality_depth_blocks(), 1);
    assert_eq!(config.expected_signing_public_keys_hex(), ["unchecked"]);
}

#[tokio::test]
async fn new_store_starts_at_deployment_block() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let attester = start(
        load_config(&tempdir, 1_234_567),
        TestChain::anchor_only(),
        ready_circle(),
    )
    .await
    .unwrap();

    assert!(store_path.is_file());
    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        BlockNumber::from(1_234_567u32)
    );
}

/// A bad anchor must not claim the store; fixing the config lets the same path start normally.
#[tokio::test]
async fn bad_anchor_does_not_create_store() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let config_path = write_config(&tempdir, 1);
    let bad_config = replace_setting(
        &config_toml(1),
        "trusted_anchor_commitment_hex",
        &format!(
            "trusted_anchor_commitment_hex = \"{}\"",
            Word::empty().to_hex()
        ),
    );
    std::fs::write(&config_path, bad_config).unwrap();

    let result = start(
        Config::load(&config_path).unwrap(),
        TestChain::anchor_only(),
        ready_circle(),
    )
    .await;
    assert!(matches!(result, Err(StartError::TrustedAnchorInvalid)));
    assert!(!store_path.exists());

    let attester = start(
        load_config(&tempdir, 1),
        TestChain::anchor_only(),
        ready_circle(),
    )
    .await
    .unwrap();
    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        BlockNumber::from(1u32)
    );
    assert!(store_path.is_file());
}

#[tokio::test]
async fn existing_store_resumes_from_saved_block() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let saved_block = BlockNumber::from(2u32);
    let mut store = Store::open_or_create(
        &store_path,
        faucet_account_id(),
        ScanCursor {
            next_block: BlockNumber::from(1u32),
        },
        trusted_anchor(),
    )
    .unwrap();
    store
        .save_scan_progress(
            &[],
            &[],
            &ScanState {
                cursor: ScanCursor {
                    next_block: saved_block,
                },
                authenticated_parent: Some(BlockHeader::mock(1u32, None, None, &[], Word::empty())),
            },
        )
        .unwrap();
    drop(store);

    let attester = start(
        load_config(&tempdir, 700),
        TestChain::anchor_only(),
        ready_circle(),
    )
    .await
    .unwrap();

    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        saved_block
    );
}

enum InvalidStoreCase {
    ZeroByte,
    Corrupt,
    WrongSchema,
    WrongVersion,
    MissingRow,
    ExtraRow,
    OutOfRange,
    WrongFaucet,
    CorruptParent,
    CorruptCandidate,
}

fn create_valid_store(path: &Path) {
    drop(
        Store::open_or_create(
            path,
            faucet_account_id(),
            ScanCursor {
                next_block: BlockNumber::from(1u32),
            },
            trusted_anchor(),
        )
        .unwrap(),
    );
}

fn write_invalid_store(path: &Path, case: InvalidStoreCase) {
    match case {
        InvalidStoreCase::ZeroByte => std::fs::write(path, b"").unwrap(),
        InvalidStoreCase::Corrupt => std::fs::write(path, b"not sqlite").unwrap(),
        InvalidStoreCase::WrongSchema => {
            let connection = rusqlite::Connection::open(path).unwrap();
            connection
                .execute("CREATE TABLE unrelated (value INTEGER NOT NULL)", [])
                .unwrap();
            connection.pragma_update(None, "user_version", 2).unwrap();
        }
        InvalidStoreCase::WrongVersion => {
            create_valid_store(path);
            rusqlite::Connection::open(path)
                .unwrap()
                .pragma_update(None, "user_version", 999)
                .unwrap();
        }
        InvalidStoreCase::MissingRow => {
            create_valid_store(path);
            let connection = rusqlite::Connection::open(path).unwrap();
            connection
                .execute("DELETE FROM attester_state", [])
                .unwrap();
        }
        InvalidStoreCase::ExtraRow => {
            create_valid_store(path);
            let connection = rusqlite::Connection::open(path).unwrap();
            connection
                .pragma_update(None, "ignore_check_constraints", true)
                .unwrap();
            connection
                .execute(
                    "INSERT INTO attester_state
                     SELECT 2, faucet_account_id, anchor_block, anchor_commitment,
                            next_block, authenticated_parent
                     FROM attester_state WHERE singleton = 1",
                    [],
                )
                .unwrap();
        }
        InvalidStoreCase::OutOfRange => {
            create_valid_store(path);
            let connection = rusqlite::Connection::open(path).unwrap();
            connection
                .pragma_update(None, "ignore_check_constraints", true)
                .unwrap();
            connection
                .execute(
                    "UPDATE attester_state SET next_block = 4294967296 WHERE singleton = 1",
                    [],
                )
                .unwrap();
        }
        InvalidStoreCase::WrongFaucet => {
            let store = Store::open_or_create(
                path,
                other_faucet_account_id(),
                ScanCursor {
                    next_block: BlockNumber::from(1u32),
                },
                trusted_anchor(),
            )
            .unwrap();
            drop(store);
        }
        InvalidStoreCase::CorruptParent => {
            create_valid_store(path);
            rusqlite::Connection::open(path)
                .unwrap()
                .execute(
                    "UPDATE attester_state
                     SET next_block = 2, authenticated_parent = X'00'
                     WHERE singleton = 1",
                    [],
                )
                .unwrap();
        }
        InvalidStoreCase::CorruptCandidate => {
            create_valid_store(path);
            rusqlite::Connection::open(path)
                .unwrap()
                .execute(
                    "INSERT INTO burn_candidates (note_id, nullifier, note, creation_block)
                     VALUES (X'00', X'01', X'02', 0)",
                    [],
                )
                .unwrap();
        }
    }
}

#[tokio::test]
async fn invalid_store_is_rejected() {
    for case in [
        InvalidStoreCase::ZeroByte,
        InvalidStoreCase::Corrupt,
        InvalidStoreCase::WrongSchema,
        InvalidStoreCase::WrongVersion,
        InvalidStoreCase::MissingRow,
        InvalidStoreCase::ExtraRow,
        InvalidStoreCase::OutOfRange,
        InvalidStoreCase::WrongFaucet,
        InvalidStoreCase::CorruptParent,
        InvalidStoreCase::CorruptCandidate,
    ] {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = create_store_parent(&tempdir);
        write_invalid_store(&store_path, case);

        let result = start(
            load_config(&tempdir, 1),
            TestChain::anchor_only(),
            ready_circle(),
        )
        .await;
        assert!(matches!(result, Err(StartError::InvalidStore)));
    }
}

#[tokio::test]
async fn store_cannot_be_opened_twice() {
    if let Some(config_path) = std::env::var_os(LOCK_CHILD_CONFIG) {
        let result = start(
            Config::load(Path::new(&config_path)).unwrap(),
            TestChain::anchor_only(),
            ready_circle(),
        )
        .await;
        assert!(matches!(result, Err(StartError::StoreLocked)));
        return;
    }

    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let config_path = write_config(&tempdir, 1);
    let store = Store::open_or_create(
        &store_path,
        faucet_account_id(),
        ScanCursor {
            next_block: BlockNumber::from(1u32),
        },
        trusted_anchor(),
    )
    .unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("tests::startup::store_cannot_be_opened_twice")
        .env(LOCK_CHILD_CONFIG, config_path)
        .status()
        .unwrap();
    drop(store);

    assert!(status.success());
}

#[tokio::test]
async fn unreachable_miden_node_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let result = start(
        load_config(&tempdir, 1),
        TestChain::anchor_only().unreachable(),
        ready_circle(),
    )
    .await;

    assert!(matches!(result, Err(StartError::MidenNodeUnavailable(_))));
    assert!(!store_path.exists());
}

#[tokio::test]
async fn missing_faucet_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let (circle, requests) = FakeCircle::new(CircleState::Response(StatusCode::OK));
    let result = start(
        load_config(&tempdir, 1),
        TestChain::anchor_only().faucet_missing(),
        Box::new(circle),
    )
    .await;

    assert!(matches!(result, Err(StartError::FaucetMissing)));
    assert!(!store_path.exists());
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unreachable_circle_api_is_rejected() {
    for state in [
        CircleState::TransportError,
        CircleState::Response(StatusCode::NO_CONTENT),
    ] {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = create_store_parent(&tempdir);
        let (circle, requests) = FakeCircle::new(state);
        let result = start(
            load_config(&tempdir, 1),
            TestChain::anchor_only(),
            Box::new(circle),
        )
        .await;

        assert!(matches!(result, Err(StartError::CircleUnavailable(_))));
        assert!(!store_path.exists());
        assert_eq!(
            *requests.lock().unwrap(),
            vec![ObservedRequest {
                method: Method::GET,
                url: "https://circle.example.invalid/v1/info".to_string(),
                timeout: Some(REQUEST_TIMEOUT),
            }]
        );
    }
}
