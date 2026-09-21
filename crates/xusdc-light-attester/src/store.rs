//! Durable scan cursor and the single-writer store boundary.

use std::path::Path;
use std::time::Duration;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use rusqlite::params;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct ScanCursor {
    /// The exact next block included in the next scan.
    pub(crate) next_block: BlockNumber,
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub(crate) enum StoreError {
    #[error("attester store is invalid")]
    Invalid,
    #[error("attester store is locked by another process")]
    Locked,
}

#[allow(dead_code)]
pub(crate) struct Store {
    connection: rusqlite::Connection,
}

#[allow(dead_code)]
impl Store {
    pub(crate) fn open_or_create(
        path: &Path,
        faucet_account_id: AccountId,
        initial_cursor: ScanCursor,
    ) -> Result<Self, StoreError> {
        let existing_length = match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => Some(metadata.len()),
            Ok(_) => return Err(StoreError::Invalid),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(StoreError::Invalid),
        };

        let mut connection = rusqlite::Connection::open(path).map_err(classify_error)?;
        connection
            .busy_timeout(Duration::ZERO)
            .map_err(classify_error)?;
        connection
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .map_err(classify_error)?;
        connection
            .execute_batch("BEGIN EXCLUSIVE; COMMIT;")
            .map_err(classify_error)?;

        match existing_length {
            None => initialize_store(&mut connection, faucet_account_id, initial_cursor)?,
            Some(0) => return Err(StoreError::Invalid),
            Some(_) => validate_store(&connection, faucet_account_id)?,
        }

        Ok(Self { connection })
    }

    pub(crate) fn scan_cursor(&self) -> Result<ScanCursor, StoreError> {
        let next_block = self
            .connection
            .query_row(
                "SELECT next_block FROM attester_state WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(classify_error)?;

        Ok(ScanCursor {
            next_block: BlockNumber::from(
                u32::try_from(next_block).map_err(|_| StoreError::Invalid)?,
            ),
        })
    }
}

fn initialize_store(
    connection: &mut rusqlite::Connection,
    faucet_account_id: AccountId,
    initial_cursor: ScanCursor,
) -> Result<(), StoreError> {
    let transaction = connection.transaction().map_err(classify_error)?;
    transaction
        .execute_batch(
            "CREATE TABLE attester_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                faucet_account_id TEXT NOT NULL,
                next_block INTEGER NOT NULL CHECK (next_block BETWEEN 0 AND 4294967295)
            ) STRICT;",
        )
        .map_err(classify_error)?;
    transaction
        .execute(
            "INSERT INTO attester_state (singleton, faucet_account_id, next_block)
             VALUES (1, ?1, ?2)",
            params![
                faucet_account_id.to_hex(),
                i64::from(initial_cursor.next_block.as_u32())
            ],
        )
        .map_err(classify_error)?;
    transaction.commit().map_err(classify_error)
}

fn validate_store(
    connection: &rusqlite::Connection,
    faucet_account_id: AccountId,
) -> Result<(), StoreError> {
    validate_store_format(connection)?;

    let (stored_faucet, next_block, row_count) = connection
        .query_row(
            "SELECT faucet_account_id, next_block, (SELECT COUNT(*) FROM attester_state)
             FROM attester_state
             WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(classify_error)?;

    if row_count != 1
        || stored_faucet != faucet_account_id.to_hex()
        || u32::try_from(next_block).is_err()
    {
        return Err(StoreError::Invalid);
    }

    Ok(())
}

fn validate_store_format(connection: &rusqlite::Connection) -> Result<(), StoreError> {
    let quick_check = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .map_err(classify_error)?;
    if quick_check != "ok" {
        return Err(StoreError::Invalid);
    }

    connection
        .prepare(
            "SELECT singleton, faucet_account_id, next_block
             FROM attester_state LIMIT 0",
        )
        .map_err(classify_error)?;

    Ok(())
}

fn classify_error(error: rusqlite::Error) -> StoreError {
    match error {
        rusqlite::Error::SqliteFailure(sqlite_error, _)
            if matches!(
                sqlite_error.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            StoreError::Locked
        }
        _ => StoreError::Invalid,
    }
}
