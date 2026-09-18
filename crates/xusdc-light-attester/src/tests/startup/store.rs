use std::path::Path;
use std::process::Command;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteAttachment, NoteAttachments, NoteType};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, Word};
use miden_standards::note::BurnNote;
use miden_usdcx::note::xreserve_burn::FIXED_XUSDC_BURN_TAG;
use rusqlite::params;

use crate::store::{ScanCursor, ScanState, Store, TrustedAnchor, CANNOT_UPGRADE, STORE_VERSION};
use crate::tests::support::{scan_limits, store_version, BlockFactory};

use super::{
    create_store_parent, faucet_account_id, load_config, ready_circle, start, startup_anchor,
    TestArgs, TestChain,
};
use crate::tests::support::{note, test_note, transaction};

const OTHER_FAUCET_ACCOUNT_ID: &str = "0x9b405fd9fe431bd1135a292de098cb";
const LOCK_CHILD_STORE_PATH: &str = "XUSDC_ATTESTER_LOCK_CHILD_STORE_PATH";

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
    drop(attester);
    assert_eq!(store_version(&store_path), STORE_VERSION);
}

/// A bad anchor must not claim the store; fixing the config lets the same path start normally.
#[tokio::test]
async fn bad_anchor_does_not_create_store() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let mut args = TestArgs::new(&tempdir, 1);
    args.replace("--trusted-anchor-commitment", Word::empty().to_hex());

    let result = start(args.load(), TestChain::anchor_only(), ready_circle()).await;
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
    let mut factory = BlockFactory::new();
    let anchor = factory.push(Vec::new(), Vec::new());
    let checkpoint = factory.push(Vec::new(), Vec::new());
    let trusted_anchor = TrustedAnchor {
        block_num: BlockNumber::GENESIS,
        commitment: anchor.header().commitment(),
    };
    let saved_block = BlockNumber::from(2u32);
    let mut store = Store::open_or_create(
        &store_path,
        faucet_account_id(),
        ScanCursor {
            next_block: BlockNumber::from(1u32),
        },
        trusted_anchor,
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
                authenticated_parent: Some(checkpoint.header().clone()),
            },
        )
        .unwrap();
    drop(store);

    let mut args = TestArgs::new(&tempdir, 700);
    args.replace(
        "--trusted-anchor-commitment",
        anchor.header().commitment().to_hex(),
    );
    let chain = TestChain::new(factory.blocks(), scan_limits(1, 1)).0;
    let attester = start(args.load(), chain, ready_circle()).await.unwrap();

    assert_eq!(
        attester.store.scan_state().unwrap().cursor.next_block,
        saved_block
    );
}

#[derive(Clone, Copy)]
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
    MalformedWithdrawalPayload,
    Unversioned,
    NewerVersion,
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
            connection
                .pragma_update(None, "user_version", STORE_VERSION)
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
            connection
                .pragma_update(None, "user_version", STORE_VERSION)
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
                     SELECT 2, faucet_account_id, anchor_block, anchor_commitment, scan_start,
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
        InvalidStoreCase::MalformedWithdrawalPayload => {
            create_valid_store(path);
            let burn = note(
                BurnNote::script(),
                NoteType::Public,
                FIXED_XUSDC_BURN_TAG,
                99,
            );
            let (assets, metadata, recipient, attachments) =
                burn.public_note.unwrap().into_note().into_parts();
            let withdrawal = attachments.get(1).unwrap();
            let mut words = withdrawal.content().as_words().to_vec();
            words[0][1] = Felt::ONE;
            let malformed = test_note(Note::with_attachments(
                assets,
                metadata.into_partial_metadata(),
                recipient,
                NoteAttachments::new(vec![
                    attachments.get(0).unwrap().clone(),
                    NoteAttachment::with_words(withdrawal.attachment_scheme(), words).unwrap(),
                ])
                .unwrap(),
            ));
            let note = malformed.public_note.unwrap();
            let burn_tx_id = transaction(faucet_account_id(), &[note.as_note().nullifier()]).id();
            rusqlite::Connection::open(path)
                .unwrap()
                .execute(
                    "INSERT INTO burns (
                        note_id, nullifier, note, creation_block, consumption_block, burn_tx_id,
                        status
                     ) VALUES (?1, ?2, ?3, 0, 1, ?4, 'DISCOVERED')",
                    params![
                        note.id().to_bytes(),
                        note.as_note().nullifier().to_bytes(),
                        note.to_bytes(),
                        burn_tx_id.to_bytes(),
                    ],
                )
                .unwrap();
        }
        // What an attester wrote before stores had a version.
        InvalidStoreCase::Unversioned => {
            create_valid_store(path);
            rusqlite::Connection::open(path)
                .unwrap()
                .pragma_update(None, "user_version", 0)
                .unwrap();
        }
        InvalidStoreCase::NewerVersion => {
            create_valid_store(path);
            rusqlite::Connection::open(path)
                .unwrap()
                .pragma_update(None, "user_version", STORE_VERSION + 1)
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
        InvalidStoreCase::MalformedWithdrawalPayload,
        InvalidStoreCase::Unversioned,
        InvalidStoreCase::NewerVersion,
    ] {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = create_store_parent(&tempdir);
        write_invalid_store(&store_path, case);
        let before = std::fs::read(&store_path).unwrap();

        let error = start(
            load_config(&tempdir, 1),
            TestChain::anchor_only(),
            ready_circle(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "failed to open attester store");
        // Taking the store's lock writes SQLite's header into an empty file; any other refused
        // store is left exactly as it was.
        if !matches!(case, InvalidStoreCase::ZeroByte) {
            assert_eq!(std::fs::read(&store_path).unwrap(), before);
        }
        let cause = format!("{error:#}");
        // SQLite's own finding is kept as the cause.
        if matches!(case, InvalidStoreCase::OutOfRange) {
            assert!(
                cause.contains("CHECK constraint failed in attester_state"),
                "{cause}"
            );
        }
        if matches!(case, InvalidStoreCase::Unversioned) {
            assert!(cause.contains(CANNOT_UPGRADE), "{cause}");
        }
        if matches!(case, InvalidStoreCase::NewerVersion) {
            assert!(cause.contains("is newer than this attester"), "{cause}");
        }
        if matches!(case, InvalidStoreCase::MalformedWithdrawalPayload) {
            assert!(cause.contains("attester store is invalid"), "{cause}");
        }
    }
}

#[tokio::test]
async fn store_cannot_be_opened_twice() {
    if let Some(store_path) = std::env::var_os(LOCK_CHILD_STORE_PATH) {
        let tempdir = tempfile::tempdir().unwrap();
        create_store_parent(&tempdir);
        let mut args = TestArgs::new(&tempdir, 1);
        args.replace("--store-path", store_path);
        let result = start(args.load(), TestChain::anchor_only(), ready_circle()).await;
        let error = result.err().unwrap();
        assert!(format!("{error:#}").contains("attester store is locked by another process"));
        return;
    }

    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
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
        .env(LOCK_CHILD_STORE_PATH, store_path)
        .status()
        .unwrap();
    drop(store);

    assert!(status.success());
}
