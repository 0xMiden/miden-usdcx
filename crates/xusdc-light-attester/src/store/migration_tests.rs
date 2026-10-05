//! A migration runs inside the transaction that creates the store.

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::Word;

use super::{initialize_store, ScanCursor, TrustedAnchor};

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
