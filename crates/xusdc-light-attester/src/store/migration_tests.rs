//! What the store's layout guarantees: a migration runs inside the transaction that creates the
//! store, the history table's foreign key is enforced, and a history row is never changed or
//! removed.

use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::Word;

use super::{initialize_store, proto, Message, Store, TrustedAnchor, MIGRATIONS, STORE_VERSION};

const FAUCET: &str = "0xbb405fd9fe431bd1135a292de098cb";

fn anchor() -> TrustedAnchor {
    TrustedAnchor {
        block_num: BlockNumber::GENESIS,
        commitment: Word::empty(),
    }
}

/// A store as version 1 laid it out, which scanned from a separate block and kept the next block
/// beside the header before it.
fn version_one_store(path: &std::path::Path, authenticated_parent: Option<&BlockHeader>) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection.execute_batch(MIGRATIONS[0]).unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    let next_block = authenticated_parent.map_or(3, |parent| parent.block_num().as_u32() + 1);
    connection
        .execute(
            "INSERT INTO attester_state (
                singleton, faucet_account_id, anchor_block, anchor_commitment, scan_start,
                next_block, authenticated_parent
             ) VALUES (1, ?1, 0, ?2, 3, ?3, ?4)",
            rusqlite::params![
                AccountId::from_hex(FAUCET).unwrap().to_bytes(),
                Word::empty().to_bytes(),
                next_block,
                authenticated_parent
                    .map(|parent| proto::blockchain::BlockHeader::from(parent).encode_to_vec()),
            ],
        )
        .unwrap();
}

/// Opening a version-1 store brings it to the current version and keeps the last authenticated
/// header as the checkpoint. A store that had not authenticated a block has none yet.
#[test]
fn a_version_one_store_keeps_its_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let header = BlockHeader::mock(5u32, None, None, &[]);
    for (name, saved) in [("scanned", Some(&header)), ("new", None)] {
        let path = directory.path().join(name);
        version_one_store(&path, saved);

        let store =
            Store::open_or_create(&path, AccountId::from_hex(FAUCET).unwrap(), anchor()).unwrap();

        assert_eq!(store.checkpoint().unwrap().as_ref(), saved, "{name}");
        let version: u32 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, STORE_VERSION, "{name}");
        // The scan start and the next block are gone with the layout that needed them.
        for column in ["scan_start", "next_block", "authenticated_parent"] {
            assert!(
                store
                    .connection
                    .prepare(&format!("SELECT {column} FROM attester_state"))
                    .is_err(),
                "{name}: {column}"
            );
        }
    }
}

/// A migration that fails part way leaves the store as it was: no partial layout and no version.
#[test]
fn failed_migration_changes_nothing() {
    let mut connection = rusqlite::Connection::open_in_memory().unwrap();
    // A leftover object named like the second table the migration creates stops it after the
    // first table was made.
    connection
        .execute_batch("CREATE VIEW burns AS SELECT 1")
        .unwrap();

    let result = initialize_store(
        &mut connection,
        AccountId::from_hex("0xbb405fd9fe431bd1135a292de098cb").unwrap(),
        TrustedAnchor {
            block_num: BlockNumber::GENESIS,
            commitment: Word::empty(),
        },
    );

    assert!(result.is_err());
    let objects: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_schema ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(objects, ["burns"]);
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 0);
}

/// The store's connection enforces the history table's foreign key, so a history row needs a burn
/// the store knows.
#[test]
fn history_rows_need_a_known_burn() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open_or_create(
        &directory.path().join("store.sqlite3"),
        AccountId::from_hex("0xbb405fd9fe431bd1135a292de098cb").unwrap(),
        TrustedAnchor {
            block_num: BlockNumber::GENESIS,
            commitment: Word::empty(),
        },
    )
    .unwrap();
    let enforced: bool = store
        .connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    assert!(enforced);
    let error = store
        .connection
        .execute(
            "INSERT INTO submission_events (note_id, recorded_at, kind)
             VALUES (X'00', 0, 'OUTCOME')",
            [],
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "FOREIGN KEY constraint failed");
}

/// A burn's history only grows: the store refuses to change or remove a row once it is written.
#[test]
fn history_rows_cannot_be_changed_or_removed() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open_or_create(
        &directory.path().join("store.sqlite3"),
        AccountId::from_hex("0xbb405fd9fe431bd1135a292de098cb").unwrap(),
        TrustedAnchor {
            block_num: BlockNumber::GENESIS,
            commitment: Word::empty(),
        },
    )
    .unwrap();
    store
        .connection
        .execute_batch(
            "INSERT INTO burns (note_id, nullifier, note, creation_block, status)
                 VALUES (X'01', X'02', X'03', 0, 'CANDIDATE');
             INSERT INTO submission_events (note_id, recorded_at, kind)
                 VALUES (X'01', 0, 'OUTCOME');",
        )
        .unwrap();
    for (change, refusal) in [
        (
            "UPDATE submission_events SET kind = 'AUTHORIZED'",
            "submission history cannot be changed",
        ),
        (
            "DELETE FROM submission_events",
            "submission history cannot be removed",
        ),
    ] {
        let error = store.connection.execute(change, []).unwrap_err();
        assert_eq!(error.to_string(), refusal);
    }
    let kinds: Vec<String> = store
        .connection
        .prepare("SELECT kind FROM submission_events")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(kinds, ["OUTCOME"]);
}
