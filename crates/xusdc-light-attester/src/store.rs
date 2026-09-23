//! Durable scan cursor and the single-writer store boundary.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use rusqlite::params;

pub(crate) const INVALID: &str = "attester store is invalid";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct ScanCursor {
    /// The exact next block included in the next scan.
    pub(crate) next_block: BlockNumber,
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
    ) -> anyhow::Result<Self> {
        let exists = path.try_exists().context(INVALID)?;

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

        if exists {
            validate_store(&connection, faucet_account_id)?;
        } else {
            initialize_store(&mut connection, faucet_account_id, initial_cursor)?;
        }

        Ok(Self { connection })
    }

    pub(crate) fn scan_cursor(&self) -> anyhow::Result<ScanCursor> {
        let next_block = self
            .connection
            .query_row(
                "SELECT next_block FROM attester_state WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(classify_error)?;

        Ok(ScanCursor {
            next_block: BlockNumber::from(u32::try_from(next_block).context(INVALID)?),
        })
    }
}

fn initialize_store(
    connection: &mut rusqlite::Connection,
    faucet_account_id: AccountId,
    initial_cursor: ScanCursor,
) -> anyhow::Result<()> {
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
) -> anyhow::Result<()> {
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
        bail!(INVALID);
    }

    Ok(())
}

fn validate_store_format(connection: &rusqlite::Connection) -> anyhow::Result<()> {
    let quick_check = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .map_err(classify_error)?;
    if quick_check != "ok" {
        bail!(INVALID);
    }

    connection
        .prepare(
            "SELECT singleton, faucet_account_id, next_block
             FROM attester_state LIMIT 0",
        )
        .map_err(classify_error)?;

    Ok(())
}

fn classify_error(error: rusqlite::Error) -> anyhow::Error {
    let locked = matches!(
        &error,
        rusqlite::Error::SqliteFailure(sqlite_error, _)
            if matches!(
                sqlite_error.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    );
    anyhow::Error::new(error).context(if locked {
        "attester store is locked by another process"
    } else {
        "attester store query failed"
    })
}
