use std::path::Path;
use std::process::Command;

use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::Word;

use crate::config::Config;
use crate::store::{ScanCursor, ScanState, Store, StoreError, TrustedAnchor};

use super::{
    config_toml, create_store_parent, faucet_account_id, load_config, ready_circle, start,
    startup_anchor, write_config, TestChain,
};

const OTHER_FAUCET_ACCOUNT_ID: &str = "0x9b405fd9fe431bd1135a292de098cb";
const LOCK_CHILD_CONFIG: &str = "XUSDC_ATTESTER_LOCK_CHILD_CONFIG";

fn other_faucet_account_id() -> AccountId {
    AccountId::from_hex(OTHER_FAUCET_ACCOUNT_ID).unwrap()
}

fn trusted_anchor() -> TrustedAnchor {
    TrustedAnchor {
        block_num: BlockNumber::GENESIS,
        commitment: startup_anchor().header().commitment(),
    }
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
    assert!(result.is_err());
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
    MissingColumn,
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
        }
        InvalidStoreCase::WrongVersion => {
            create_valid_store(path);
            rusqlite::Connection::open(path)
                .unwrap()
                .pragma_update(None, "user_version", 999)
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
        InvalidStoreCase::MissingColumn,
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
        assert!(result.err().unwrap().downcast_ref::<StoreError>().is_some());
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
        assert!(result.err().unwrap().downcast_ref::<StoreError>().is_some());
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
        .arg("tests::startup::store::store_cannot_be_opened_twice")
        .env(LOCK_CHILD_CONFIG, config_path)
        .status()
        .unwrap();
    drop(store);

    assert!(status.success());
}
