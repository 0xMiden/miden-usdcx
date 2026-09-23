use std::path::Path;
use std::process::Command;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;

use crate::config::Config;
use crate::store::{ScanCursor, Store};

use super::{
    create_store_parent, faucet_account_id, load_config, ready_circle, start, write_config,
    ChainState, FAUCET_ACCOUNT_ID,
};

const OTHER_FAUCET_ACCOUNT_ID: &str = "0x9b405fd9fe431bd1135a292de098cb";
const LOCK_CHILD_CONFIG: &str = "XUSDC_ATTESTER_LOCK_CHILD_CONFIG";

fn other_faucet_account_id() -> AccountId {
    AccountId::from_hex(OTHER_FAUCET_ACCOUNT_ID).unwrap()
}

#[tokio::test]
async fn new_store_starts_at_deployment_block() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let attester = start(
        load_config(&tempdir, 1_234_567),
        ChainState::Ready,
        ready_circle(),
    )
    .await
    .unwrap();

    assert!(store_path.is_file());
    assert_eq!(
        attester.store.scan_cursor().unwrap().next_block,
        BlockNumber::from(1_234_567u32)
    );
}

#[tokio::test]
async fn existing_store_resumes_from_saved_block() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let saved_block = BlockNumber::from(91u32);
    let store = Store::open_or_create(
        &store_path,
        faucet_account_id(),
        ScanCursor {
            next_block: saved_block,
        },
    )
    .unwrap();
    drop(store);

    let attester = start(
        load_config(&tempdir, 700),
        ChainState::Ready,
        ready_circle(),
    )
    .await
    .unwrap();

    assert_eq!(
        attester.store.scan_cursor().unwrap().next_block,
        saved_block
    );
}

enum InvalidStoreCase {
    ZeroByte,
    Corrupt,
    WrongSchema,
    MissingColumn,
    MissingRow,
    ExtraRow,
    OutOfRange,
    WrongFaucet,
}

const STATE_TABLE: &str = "CREATE TABLE attester_state (
    singleton INTEGER PRIMARY KEY,
    faucet_account_id TEXT NOT NULL,
    next_block INTEGER NOT NULL
) STRICT;";

fn state_database(path: &Path, faucet: &str, next_block: i64) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection.execute_batch(STATE_TABLE).unwrap();
    connection
        .execute(
            "INSERT INTO attester_state (singleton, faucet_account_id, next_block)
             VALUES (1, ?1, ?2)",
            rusqlite::params![faucet, next_block],
        )
        .unwrap();
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
        }
        InvalidStoreCase::MissingColumn => {
            let connection = rusqlite::Connection::open(path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE attester_state (
                        singleton INTEGER PRIMARY KEY,
                        faucet_account_id TEXT NOT NULL
                    ) STRICT;",
                )
                .unwrap();
        }
        InvalidStoreCase::MissingRow => {
            let connection = rusqlite::Connection::open(path).unwrap();
            connection.execute_batch(STATE_TABLE).unwrap();
        }
        InvalidStoreCase::ExtraRow => {
            state_database(path, FAUCET_ACCOUNT_ID, 1);
            rusqlite::Connection::open(path)
                .unwrap()
                .execute(
                    "INSERT INTO attester_state (singleton, faucet_account_id, next_block)
                     VALUES (2, ?1, 2)",
                    [FAUCET_ACCOUNT_ID],
                )
                .unwrap();
        }
        InvalidStoreCase::OutOfRange => {
            state_database(path, FAUCET_ACCOUNT_ID, 4_294_967_296);
        }
        InvalidStoreCase::WrongFaucet => {
            let store = Store::open_or_create(
                path,
                other_faucet_account_id(),
                ScanCursor {
                    next_block: BlockNumber::from(1u32),
                },
            )
            .unwrap();
            drop(store);
        }
    }
}

#[tokio::test]
async fn invalid_store_is_rejected() {
    for case in [
        InvalidStoreCase::ZeroByte,
        InvalidStoreCase::Corrupt,
        InvalidStoreCase::WrongSchema,
        InvalidStoreCase::MissingColumn,
        InvalidStoreCase::MissingRow,
        InvalidStoreCase::ExtraRow,
        InvalidStoreCase::OutOfRange,
        InvalidStoreCase::WrongFaucet,
    ] {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = create_store_parent(&tempdir);
        write_invalid_store(&store_path, case);

        let result = start(load_config(&tempdir, 1), ChainState::Ready, ready_circle()).await;
        assert_eq!(
            result.err().unwrap().to_string(),
            "failed to open attester store"
        );
    }
}

#[tokio::test]
async fn store_cannot_be_opened_twice() {
    if let Some(config_path) = std::env::var_os(LOCK_CHILD_CONFIG) {
        let result = start(
            Config::load(Path::new(&config_path)).unwrap(),
            ChainState::Ready,
            ready_circle(),
        )
        .await;
        let error = result.err().unwrap();
        assert!(format!("{error:#}").contains("attester store is locked by another process"));
        return;
    }

    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let config_path = write_config(&tempdir, 1);
    let cursor = ScanCursor {
        next_block: BlockNumber::from(1u32),
    };
    // Reopen the new store, as a restarted attester does: that path must take the lock too.
    drop(Store::open_or_create(&store_path, faucet_account_id(), cursor).unwrap());
    let store = Store::open_or_create(&store_path, faucet_account_id(), cursor).unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("tests::startup::store::store_cannot_be_opened_twice")
        .env(LOCK_CHILD_CONFIG, config_path)
        .status()
        .unwrap();
    drop(store);

    assert!(status.success());
}
