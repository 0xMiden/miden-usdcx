use std::path::Path;
use std::process::Command;

use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockNumber, ProvenBlock};
use miden_protocol::note::NoteType;
use miden_protocol::Word;
use miden_standards::note::BurnNote;

use crate::burn::{BurnCandidate, DiscoveredBurn};
use crate::config::Config;
use crate::store::{ScanCursor, ScanState, Store, TrustedAnchor};

use super::{
    config_toml, create_store_parent, faucet_account_id, load_config, load_config_with_anchor,
    note, ready_circle, replace_setting, scan_limits, start, startup_anchor, transaction,
    write_config, BlockFactory, TestChain,
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
    drop(attester);

    let mut factory = BlockFactory::new(faucet_account_id());
    factory.push(Vec::new(), Vec::new());
    let anchor = factory.push(Vec::new(), Vec::new());
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let result = start(
        load_config_with_anchor(&tempdir, 0, &anchor),
        TestChain::new(factory.blocks(), scan_limits(1, 1)).0,
        ready_circle(),
    )
    .await;
    assert!(result.err().unwrap().downcast_ref::<StoreError>().is_some());
    assert!(
        !store_path.exists(),
        "rejected config must not pin a fresh store"
    );
    let attester = start(
        load_config_with_anchor(&tempdir, 1, &anchor),
        TestChain::new(factory.blocks(), scan_limits(1, 1)).0,
        ready_circle(),
    )
    .await
    .unwrap();
    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        BlockNumber::from(1u32)
    );
}

/// One public note is still pending and another was consumed in the next block.
fn create_populated_store(path: &Path) -> (Vec<ProvenBlock>, BurnCandidate, DiscoveredBurn) {
    let pending = note(BurnNote::script(), NoteType::Public, 1, 60);
    let consumed = note(BurnNote::script(), NoteType::Public, 1, 61);
    let tx = transaction(faucet_account_id(), &[consumed.nullifier]);
    let candidate = BurnCandidate::try_new(
        pending.public_note.unwrap(),
        1u32.into(),
        faucet_account_id(),
    )
    .unwrap();
    let consumed_candidate = BurnCandidate::try_new(
        consumed.public_note.unwrap(),
        1u32.into(),
        faucet_account_id(),
    )
    .unwrap();
    let burn = consumed_candidate
        .clone()
        .into_discovered(2u32.into(), tx.id());
    let mut factory = BlockFactory::new(faucet_account_id());
    factory.push(Vec::new(), Vec::new());
    let anchor = factory.push(vec![pending.output, consumed.output], Vec::new());
    let child = factory.push(Vec::new(), vec![tx]);
    let mut store = Store::open_or_create(
        path,
        faucet_account_id(),
        ScanCursor {
            next_block: 1u32.into(),
        },
        TrustedAnchor {
            block_num: 1u32.into(),
            commitment: anchor.header().commitment(),
        },
    )
    .unwrap();
    store
        .save_scan_progress(
            &[candidate.clone(), consumed_candidate],
            &[],
            &ScanState {
                cursor: ScanCursor {
                    next_block: 2u32.into(),
                },
                authenticated_parent: Some(anchor.header().clone()),
            },
        )
        .unwrap();
    store
        .save_scan_progress(
            &[],
            std::slice::from_ref(&burn),
            &ScanState {
                cursor: ScanCursor {
                    next_block: 3u32.into(),
                },
                authenticated_parent: Some(BlockHeader::mock(1u32, None, None, &[])),
            },
        )
        .unwrap();
    (factory.blocks(), candidate, burn)
}

#[tokio::test]
async fn existing_store_resumes_from_saved_block() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let (blocks, candidate, burn) = create_populated_store(&store_path);
    for fallback in [0, 700] {
        let attester = start(
            load_config_with_anchor(&tempdir, fallback, &blocks[1]),
            TestChain::new(blocks.clone(), scan_limits(2, 2)).0,
            ready_circle(),
        )
        .await
        .unwrap();
        assert_eq!(
            attester.store.scan_state().unwrap(),
            ScanState {
                cursor: ScanCursor {
                    next_block: 3u32.into()
                },
                authenticated_parent: Some(blocks[2].header().clone()),
            }
        );
        assert_eq!(attester.store.candidates(), Ok(vec![candidate.clone()]));
        assert_eq!(attester.store.discovered_burns(), Ok(vec![burn.clone()]));
    }

    // Even before the first scan, the saved cursor wins over an edited fallback.
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    create_valid_store(&store_path);
    let attester = start(
        load_config(&tempdir, 700),
        TestChain::anchor_only(),
        ready_circle(),
    )
    .await
    .unwrap();

    assert_eq!(
        attester.store.scan_state().unwrap(),
        ScanState {
            cursor: ScanCursor {
                next_block: 1u32.into()
            },
            authenticated_parent: None,
        }
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
    CorruptParent,
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
        InvalidStoreCase::CorruptParent,
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
            TestChain::anchor_only(),
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
    drop(
        Store::open_or_create(&store_path, faucet_account_id(), cursor, trusted_anchor()).unwrap(),
    );
    let store =
        Store::open_or_create(&store_path, faucet_account_id(), cursor, trusted_anchor()).unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("tests::startup::store::store_cannot_be_opened_twice")
        .env(LOCK_CHILD_CONFIG, config_path)
        .status()
        .unwrap();
    drop(store);

    assert!(status.success());
}
