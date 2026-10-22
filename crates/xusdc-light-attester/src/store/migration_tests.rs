//! What the store's layout guarantees: a migration runs inside the transaction that creates the
//! store, the history table's foreign key is enforced, and a history row is never changed or
//! removed.

use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::Word;

use super::{
    initialize_store, proto, upgrade, Message, Store, TrustedAnchor, MIGRATIONS, STORE_VERSION,
};

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

/// Upgrading from version 2 keeps every burn, saved submission and history row. Version 3 rebuilds
/// the burns table without the columns it drops, and the history table's foreign key holds against
/// the rebuilt table. Version 4 adds the withdrawal-limit retry time, with no burn waiting.
#[test]
fn migrations_preserve_burns_submissions_and_history() {
    let mut connection = rusqlite::Connection::open_in_memory().unwrap();
    let enforced: bool = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    assert!(enforced);
    for migration in &MIGRATIONS[..2] {
        connection.execute_batch(migration).unwrap();
    }
    connection
        .execute_batch(
            "INSERT INTO burns (note_id, nullifier, note, creation_block, status)
                 VALUES (X'01', X'11', X'21', 4, 'CANDIDATE');
             INSERT INTO burns (
                    note_id, nullifier, note, creation_block, consumption_block, burn_tx_id,
                    status, hold_reason
                 ) VALUES (X'02', X'12', X'22', 5, 7, X'32', 'DISCOVERED', 1);
             INSERT INTO submission_events (note_id, recorded_at, kind, burn_hold_reason)
                 VALUES (X'02', 0, 'BURN_HELD', 1);",
        )
        .unwrap();

    let transaction = connection.transaction().unwrap();
    transaction.execute_batch(MIGRATIONS[2]).unwrap();
    transaction
        .execute_batch(
            "INSERT INTO submissions (note_id, endpoint, body, transfer_spec_hash, status)
             VALUES (X'02', 'https://circle.invalid/v1/withdraw', X'01', X'02', 'SUBMITTING');
         INSERT INTO submission_events (note_id, recorded_at, kind, body)
             VALUES (X'02', 11, 'AUTHORIZED', X'01');
         PRAGMA user_version = 3;",
        )
        .unwrap();
    upgrade(&transaction, 3).unwrap();
    // The history rows are checked against the rebuilt table here.
    transaction.commit().unwrap();

    type Burn = (Vec<u8>, Vec<u8>, Vec<u8>, u32, Option<u32>, Option<i64>);
    let burns: Vec<Burn> = connection
        .prepare(
            "SELECT note_id, nullifier, note, creation_block, consumption_block, hold_reason
             FROM burns ORDER BY note_id",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        burns,
        [
            (vec![1], vec![0x11], vec![0x21], 4, None, None),
            (vec![2], vec![0x12], vec![0x22], 5, Some(7), Some(1)),
        ]
    );
    let history: Vec<(Vec<u8>, String)> = connection
        .prepare("SELECT note_id, kind FROM submission_events")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        history,
        [
            (vec![2], "BURN_HELD".to_owned()),
            (vec![2], "AUTHORIZED".to_owned())
        ]
    );
    let saved: (String, Vec<u8>, Vec<u8>, String) = connection.query_row(
        "SELECT endpoint, body, transfer_spec_hash, status FROM submissions WHERE note_id = X'02'",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    ).unwrap();
    assert_eq!(
        saved,
        (
            "https://circle.invalid/v1/withdraw".into(),
            vec![1],
            vec![2],
            "SUBMITTING".into()
        )
    );
    let authorized_body: Vec<u8> = connection
        .query_row(
            "SELECT body FROM submission_events WHERE kind = 'AUTHORIZED'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(authorized_body, [1]);
    let waiting: u32 = connection
        .query_row(
            "SELECT count(*) FROM burns WHERE withdrawal_limit_retry_at IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(waiting, 0);
    let index: String = connection.query_row(
        "SELECT name FROM sqlite_schema WHERE type = 'index' AND name = 'burns_waiting_for_limit'",
        [], |row| row.get(0)
    ).unwrap();
    assert_eq!(index, "burns_waiting_for_limit");

    let error = connection
        .execute(
            "INSERT INTO submission_events (note_id, recorded_at, kind)
             VALUES (X'00', 0, 'OUTCOME')",
            [],
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "FOREIGN KEY constraint failed");
    for column in ["status", "burn_tx_id"] {
        assert!(
            connection
                .prepare(&format!("SELECT {column} FROM burns"))
                .is_err(),
            "{column}"
        );
    }
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        tables,
        [
            "attester_state",
            "burns",
            "sqlite_sequence",
            "submission_events",
            "submissions"
        ]
    );
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, STORE_VERSION);
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
            "INSERT INTO burns (note_id, nullifier, note, creation_block)
                 VALUES (X'01', X'02', X'03', 0);
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
