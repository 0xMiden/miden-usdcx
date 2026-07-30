//! The row↔record codec, and the conversions the store refuses to fudge.
//!
//! Nothing here trusts the database. A row may have been written by a build with a different
//! layout, by a partial upgrade, or by a hand-edited `UPDATE` — so every field is CHECKED on the
//! way out (width, status token, integer range) and a row that does not make sense becomes
//! [`RelayerError::CorruptStoreRecord`] rather than a default. There is no safe default here:
//! guessing "not submitted" re-mints a deposit that may already be on chain, and guessing the other
//! way strands one.

use rusqlite::{Connection, OptionalExtension, Row};

use super::record::{IdempotencyRecord, SubmissionStatus, TxId};
use crate::error::{Cause, RelayerError};

/// The record's columns, in the order [`row_to_record`] reads them.
pub(super) const RECORD_COLUMNS: &str =
    "nonce_key, attestation_message_hash, submitted_tx_id, block_num, status, timestamp";

/// The log entry for `nonce_key`, or `None` if the store has never seen it.
pub(super) fn read_record(
    conn: &Connection,
    nonce_key: &[u8; 32],
) -> Result<Option<IdempotencyRecord>, RelayerError> {
    // two nested results, meaning different things: the OUTER one is SQLite's (was there a row?), the
    // INNER one is ours (does the row make sense?). Flattening the inner one into `None` would report
    // an already-minted nonce as never seen — so it is transposed out, not swallowed.
    let row: Option<Result<IdempotencyRecord, RelayerError>> = conn
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM submitted_nonce WHERE nonce_key = ?1"),
            rusqlite::params![&nonce_key[..]],
            |row| Ok(row_to_record(row)),
        )
        .optional()
        .map_err(store_failed)?;

    row.transpose()
}

/// Writes `current` forward into `to`, with the transaction id / block number the transition
/// carries. The CALLER has already checked the machine's edge and is inside the write transaction.
///
/// `tx_id` and `block_num` are set when the transition carries them and otherwise LEFT ALONE: a
/// commit must not erase the transaction id it is committing, and a retry claim must not erase the
/// evidence of the attempt that failed.
pub(super) fn write_status(
    conn: &Connection,
    current: &IdempotencyRecord,
    to: SubmissionStatus,
    tx_id: Option<TxId>,
    block_num: Option<u32>,
    now: u64,
) -> Result<IdempotencyRecord, RelayerError> {
    let updated = IdempotencyRecord {
        submitted_tx_id: tx_id.or(current.submitted_tx_id),
        block_num: block_num.or(current.block_num),
        status: to,
        timestamp: now,
        ..current.clone()
    };

    conn.execute(
        "UPDATE submitted_nonce
         SET submitted_tx_id = ?1, block_num = ?2, status = ?3, timestamp = ?4
         WHERE nonce_key = ?5",
        rusqlite::params![
            updated.submitted_tx_id.map(|id| id.as_bytes().to_vec()),
            updated.block_num,
            updated.status.as_token(),
            to_sql_seconds(updated.timestamp)?,
            &updated.nonce_key[..],
        ],
    )
    .map_err(store_failed)?;

    Ok(updated)
}

/// Reads one row of [`RECORD_COLUMNS`].
pub(super) fn row_to_record(row: &Row<'_>) -> Result<IdempotencyRecord, RelayerError> {
    let nonce_key = digest(
        &row.get::<_, Vec<u8>>(0).map_err(store_failed)?,
        "nonce_key",
    )?;
    let attestation_message_hash = digest(
        &row.get::<_, Vec<u8>>(1).map_err(store_failed)?,
        "attestation_message_hash",
    )?;

    let submitted_tx_id = row
        .get::<_, Option<Vec<u8>>>(2)
        .map_err(store_failed)?
        .map(|bytes| digest(&bytes, "submitted_tx_id").map(TxId::new))
        .transpose()?;

    let block_num = row
        .get::<_, Option<i64>>(3)
        .map_err(store_failed)?
        .map(|block| {
            u32::try_from(block).map_err(|_| corrupt(format!("block number {block} is not a u32")))
        })
        .transpose()?;

    let status = SubmissionStatus::from_token(&row.get::<_, String>(4).map_err(store_failed)?)?;
    let timestamp = from_sql_seconds(row.get::<_, i64>(5).map_err(store_failed)?)?;

    Ok(IdempotencyRecord {
        nonce_key,
        attestation_message_hash,
        submitted_tx_id,
        block_num,
        status,
        timestamp,
    })
}

/// A 32-byte digest column, width-checked. (The schema `CHECK`s the width too — this is the
/// reader's own guard, because the row may have been written by something that is not this build.)
pub(super) fn digest(bytes: &[u8], column: &str) -> Result<[u8; 32], RelayerError> {
    bytes
        .try_into()
        .map_err(|_| corrupt(format!("{column} is {} bytes, not 32", bytes.len())))
}

/// SQLite integers are signed 64-bit; the store's seconds are unsigned. Both conversions are
/// checked — a timestamp that does not survive the round trip is a corrupt row, never a wrapped
/// number.
pub(super) fn to_sql_seconds(seconds: u64) -> Result<i64, RelayerError> {
    i64::try_from(seconds).map_err(|_| corrupt(format!("timestamp {seconds} does not fit an i64")))
}

pub(super) fn from_sql_seconds(seconds: i64) -> Result<u64, RelayerError> {
    u64::try_from(seconds).map_err(|_| corrupt(format!("timestamp {seconds} is negative")))
}

pub(super) fn corrupt(detail: String) -> RelayerError {
    RelayerError::CorruptStoreRecord { detail }
}

/// Every `rusqlite` failure becomes ONE relayer error, with the original preserved as its source
/// (the SQLite primary/extended code is what an operator needs; a flattened string is not).
pub(super) fn store_failed(err: rusqlite::Error) -> RelayerError {
    RelayerError::IdempotencyStore(Cause::new(err))
}
