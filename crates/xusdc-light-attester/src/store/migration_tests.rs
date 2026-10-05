//! What the store's layout guarantees: a migration runs inside the transaction that creates the
//! store, the history table's foreign key is enforced, and a history row is never changed or
//! removed.

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::Word;

use super::{initialize_store, ScanCursor, Store, TrustedAnchor};

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
        ScanCursor {
            next_block: BlockNumber::GENESIS,
        },
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
        ScanCursor {
            next_block: BlockNumber::GENESIS,
        },
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
        ScanCursor {
            next_block: BlockNumber::GENESIS,
        },
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
