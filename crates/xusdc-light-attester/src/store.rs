//! Durable discovery state and the single-writer store boundary.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use miden_objects::prost::Message;
use miden_objects::{proto, DecodeMessageExt};
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::{PublicOutputNote, TransactionId};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::Word;
use rusqlite::{params, Params, Transaction};

use crate::burn::{BurnCandidate, BurnRefusal, DiscoveredBurn};

const DISCOVERED: &str = "DISCOVERED";
const REFUSED: &str = "REFUSED";

pub(crate) const INVALID: &str = "attester store is invalid";
pub(crate) const CONFLICT: &str = "authenticated evidence conflicts with the attester store";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScanCursor {
    /// The exact next block included in the next scan.
    pub(crate) next_block: BlockNumber,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustedAnchor {
    pub(crate) block_num: BlockNumber,
    pub(crate) commitment: Word,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanState {
    /// The cursor and its authenticated parent are one checkpoint: neither may advance alone.
    pub(crate) cursor: ScanCursor,
    pub(crate) authenticated_parent: Option<BlockHeader>,
}

pub(crate) struct Store {
    connection: rusqlite::Connection,
    initial_cursor: ScanCursor,
    faucet_account_id: AccountId,
}

impl Store {
    pub(crate) fn open_or_create(
        path: &Path,
        faucet_account_id: AccountId,
        initial_cursor: ScanCursor,
        trusted_anchor: TrustedAnchor,
    ) -> anyhow::Result<Self> {
        let exists = path.try_exists().context(INVALID)?;

        let mut connection = rusqlite::Connection::open(path).map_err(classify_error)?;
        // Keep the exclusive connection lock for the store's lifetime so a second attester cannot
        // create a competing cursor or submission queue.
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
            validate_store(
                &connection,
                faucet_account_id,
                initial_cursor,
                trusted_anchor,
            )?;
        } else {
            initialize_store(
                &mut connection,
                faucet_account_id,
                initial_cursor,
                trusted_anchor,
            )?;
        }

        Ok(Self {
            connection,
            initial_cursor,
            faucet_account_id,
        })
    }

    pub(crate) fn scan_state(&self) -> anyhow::Result<ScanState> {
        load_scan_state(&self.connection, self.initial_cursor)
    }

    #[cfg(test)]
    pub(crate) fn candidates(&self) -> anyhow::Result<Vec<BurnCandidate>> {
        load_candidates(&self.connection, self.faucet_account_id, "", [])
    }

    pub(crate) fn note_known(&self, note_id: NoteId) -> anyhow::Result<bool> {
        exists(
            &self.connection,
            "SELECT EXISTS (SELECT 1 FROM burns WHERE note_id = ?1)",
            [note_id.to_bytes()],
        )
    }

    pub(crate) fn candidate_by_nullifier(
        &self,
        nullifier: Nullifier,
    ) -> anyhow::Result<Option<BurnCandidate>> {
        let mut candidates = load_candidates(
            &self.connection,
            self.faucet_account_id,
            "AND nullifier = ?1",
            [nullifier.to_bytes()],
        )?;
        Ok(candidates.pop())
    }

    /// Records a proven-invalid burn without changing its evidence or scan progress.
    #[allow(dead_code)]
    pub(crate) fn refuse_burn(
        &mut self,
        note_id: NoteId,
        reason: BurnRefusal,
    ) -> anyhow::Result<()> {
        let updated = self
            .connection
            .execute(
                "UPDATE burns SET status = ?1, refusal_reason = ?2
             WHERE note_id = ?3 AND status = ?4 AND refusal_reason IS NULL",
                params![REFUSED, reason.as_str(), note_id.to_bytes(), DISCOVERED],
            )
            .map_err(classify_error)?;
        (updated == 1)
            .then_some(())
            .ok_or_else(|| anyhow!(CONFLICT))
    }

    #[cfg(test)]
    pub(crate) fn discovered_burns(&self) -> anyhow::Result<Vec<DiscoveredBurn>> {
        load_burns(&self.connection, self.faucet_account_id, true)
    }

    /// Filters discovered burns by verified waiting depth; used by the later submit stage.
    #[allow(dead_code)]
    pub(crate) fn burns_ready_for_withdrawal(
        &self,
        proof_lag_block: BlockNumber,
        minimum_depth_blocks: u32,
    ) -> anyhow::Result<Vec<DiscoveredBurn>> {
        let Some(parent) = self.scan_state()?.authenticated_parent else {
            return Ok(Vec::new());
        };
        let Some(last_depth_safe_block) = parent.block_num().checked_sub(minimum_depth_blocks)
        else {
            return Ok(Vec::new());
        };
        // Waiting depth comes from the header we verified and saved, not the RPC's reported tip.
        let last_ready_block = std::cmp::min(proof_lag_block, last_depth_safe_block);
        Ok(load_burns(&self.connection, self.faucet_account_id, false)?
            .into_iter()
            .filter(|burn| burn.consumption_block() <= last_ready_block)
            .collect())
    }

    pub(crate) fn save_scan_progress(
        &mut self,
        candidates: &[BurnCandidate],
        burns: &[DiscoveredBurn],
        next_state: &ScanState,
    ) -> anyhow::Result<()> {
        validate_scan_state(next_state, self.initial_cursor)?;
        validate_discovery_records(candidates, burns, next_state.cursor, self.initial_cursor)?;

        // One block's evidence, cursor, and verified header commit as one unit. A crash therefore
        // either records that complete block or scans it again from the previous checkpoint.
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let current_state = load_scan_state(&transaction, self.initial_cursor)?;

        // Advance one block at a time so no caller can silently skip burn evidence.
        if next_state.cursor.next_block.checked_sub(1) != Some(current_state.cursor.next_block) {
            bail!(CONFLICT);
        }
        if let Some(current_parent) = &current_state.authenticated_parent {
            let next_parent = next_state.authenticated_parent.as_ref().context(INVALID)?;
            if next_parent.prev_block_commitment() != current_parent.commitment() {
                bail!(CONFLICT);
            }
        }

        for candidate in candidates {
            insert_candidate(&transaction, candidate)?;
        }
        for burn in burns {
            insert_burn(&transaction, burn)?;
        }

        let authenticated_parent = next_state
            .authenticated_parent
            .as_ref()
            .map(|header| proto::blockchain::BlockHeader::from(header).encode_to_vec());
        let updated = transaction
            .execute(
                "UPDATE attester_state
                 SET next_block = ?1, authenticated_parent = ?2
                 WHERE singleton = 1",
                params![
                    i64::from(next_state.cursor.next_block.as_u32()),
                    authenticated_parent
                ],
            )
            .map_err(classify_error)?;
        if updated != 1 {
            bail!(INVALID);
        }

        transaction.commit().map_err(classify_error)
    }
}

fn initialize_store(
    connection: &mut rusqlite::Connection,
    faucet_account_id: AccountId,
    initial_cursor: ScanCursor,
    trusted_anchor: TrustedAnchor,
) -> anyhow::Result<()> {
    let transaction = connection.transaction().map_err(classify_error)?;
    transaction
        .execute_batch(
            "CREATE TABLE attester_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                faucet_account_id BLOB NOT NULL,
                anchor_block INTEGER NOT NULL CHECK (anchor_block BETWEEN 0 AND 4294967295),
                anchor_commitment BLOB NOT NULL,
                next_block INTEGER NOT NULL CHECK (next_block BETWEEN 0 AND 4294967295),
                authenticated_parent BLOB
            ) STRICT;",
        )
        .map_err(classify_error)?;
    create_burns_table(&transaction)?;
    transaction
        .execute(
            "INSERT INTO attester_state (
                singleton,
                faucet_account_id,
                anchor_block,
                anchor_commitment,
                next_block,
                authenticated_parent
             ) VALUES (1, ?1, ?2, ?3, ?4, NULL)",
            params![
                faucet_account_id.to_bytes(),
                i64::from(trusted_anchor.block_num.as_u32()),
                trusted_anchor.commitment.to_bytes(),
                i64::from(initial_cursor.next_block.as_u32()),
            ],
        )
        .map_err(classify_error)?;
    transaction.commit().map_err(classify_error)
}

fn create_burns_table(connection: &rusqlite::Connection) -> anyhow::Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE burns (
            note_id BLOB PRIMARY KEY,
            nullifier BLOB NOT NULL UNIQUE,
            note BLOB NOT NULL,
            creation_block INTEGER NOT NULL CHECK (creation_block BETWEEN 0 AND 4294967295),
            consumption_block INTEGER
                CHECK (consumption_block > creation_block AND consumption_block <= 4294967295),
            burn_tx_id BLOB,
            status TEXT NOT NULL CHECK (status IN ('CANDIDATE', 'DISCOVERED', 'REFUSED')),
            refusal_reason TEXT CHECK (refusal_reason IN (
                'wrong_tag', 'invalid_withdrawal'
            )),
            CHECK ((status != 'REFUSED' AND refusal_reason IS NULL)
                OR (status = 'REFUSED' AND refusal_reason IS NOT NULL)),
            CHECK ((status = 'CANDIDATE') = (consumption_block IS NULL)),
            CHECK ((consumption_block IS NULL) = (burn_tx_id IS NULL))
        ) STRICT;",
        )
        .map_err(classify_error)
}

fn validate_store(
    connection: &rusqlite::Connection,
    faucet_account_id: AccountId,
    initial_cursor: ScanCursor,
    trusted_anchor: TrustedAnchor,
) -> anyhow::Result<()> {
    validate_store_format(connection)?;

    // Stored chain state becomes the next run's trust base, so reject any malformed or
    // internally inconsistent row before using it.
    let row_count = connection
        .query_row("SELECT COUNT(*) FROM attester_state", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(classify_error)?;
    if row_count != 1 {
        bail!(INVALID);
    }

    let (stored_faucet, anchor_block, anchor_commitment) = connection
        .query_row(
            "SELECT faucet_account_id, anchor_block, anchor_commitment
             FROM attester_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(classify_error)?;

    if decode_canonical::<AccountId>(&stored_faucet)? != faucet_account_id {
        bail!(INVALID);
    }

    let stored_anchor = TrustedAnchor {
        block_num: decode_block_number(anchor_block)?,
        commitment: decode_canonical(&anchor_commitment)?,
    };
    if stored_anchor != trusted_anchor {
        bail!("configured trusted anchor differs from the store");
    }
    let state = load_scan_state(connection, initial_cursor)?;
    if state
        .authenticated_parent
        .as_ref()
        .is_some_and(|parent| parent.block_num() < trusted_anchor.block_num)
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

    for probe in [
        "SELECT singleton, faucet_account_id, anchor_block, anchor_commitment,
            next_block, authenticated_parent FROM attester_state LIMIT 0",
        "SELECT note_id, nullifier, note, creation_block, consumption_block, burn_tx_id, status,
            refusal_reason FROM burns LIMIT 0",
    ] {
        connection.prepare(probe).map_err(classify_error)?;
    }

    Ok(())
}

fn load_scan_state(
    connection: &rusqlite::Connection,
    initial_cursor: ScanCursor,
) -> anyhow::Result<ScanState> {
    let (next_block, authenticated_parent) = connection
        .query_row(
            "SELECT next_block, authenticated_parent
             FROM attester_state WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .map_err(classify_error)?;

    let state = ScanState {
        cursor: ScanCursor {
            next_block: decode_block_number(next_block)?,
        },
        authenticated_parent: authenticated_parent
            .as_deref()
            .map(decode_header)
            .transpose()?,
    };
    validate_scan_state(&state, initial_cursor)?;
    Ok(state)
}

fn validate_scan_state(state: &ScanState, initial_cursor: ScanCursor) -> anyhow::Result<()> {
    match &state.authenticated_parent {
        Some(parent) if state.cursor.next_block.checked_sub(1) != Some(parent.block_num()) => {
            Err(anyhow!(INVALID))
        }
        None if state.cursor != initial_cursor => Err(anyhow!(INVALID)),
        _ => Ok(()),
    }
}

fn validate_discovery_records(
    candidates: &[BurnCandidate],
    burns: &[DiscoveredBurn],
    cursor: ScanCursor,
    initial_cursor: ScanCursor,
) -> anyhow::Result<()> {
    if candidates.iter().any(|candidate| {
        candidate.creation_block() < initial_cursor.next_block
            || candidate.creation_block() >= cursor.next_block
    }) || burns.iter().any(|burn| {
        burn.creation_block() < initial_cursor.next_block
            || burn.creation_block() >= burn.consumption_block()
            || burn.consumption_block() >= cursor.next_block
    }) {
        bail!(CONFLICT);
    }
    Ok(())
}

fn load_candidates<P: Params>(
    connection: &rusqlite::Connection,
    faucet_account_id: AccountId,
    filter: &str,
    params: P,
) -> anyhow::Result<Vec<BurnCandidate>> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT note_id, nullifier, note, creation_block
             FROM burns WHERE status = 'CANDIDATE' {filter} ORDER BY creation_block, note_id"
        ))
        .map_err(classify_error)?;
    let rows = statement
        .query_map(params, |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(classify_error)?;

    let mut candidates = Vec::new();
    for row in rows {
        let (note_id, nullifier, note, creation_block) = row.map_err(classify_error)?;
        let note = decode_note(&note, &note_id, &nullifier)?;
        candidates.push(
            BurnCandidate::new(
                note,
                decode_block_number(creation_block)?,
                faucet_account_id,
            )
            .context(INVALID)?,
        );
    }
    Ok(candidates)
}

fn load_burns(
    connection: &rusqlite::Connection,
    faucet_account_id: AccountId,
    include_refused: bool,
) -> anyhow::Result<Vec<DiscoveredBurn>> {
    let mut statement = connection
        .prepare(
            "SELECT note_id, nullifier, note, creation_block, consumption_block,
                    burn_tx_id FROM burns
             WHERE status != 'CANDIDATE' AND (?1 OR status != 'REFUSED')",
        )
        .map_err(classify_error)?;
    let rows = statement
        .query_map([include_refused], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })
        .map_err(classify_error)?;

    let mut burns = Vec::new();
    for row in rows {
        let (note_id, nullifier, note, creation_block, consumption_block, burn_tx_id) =
            row.map_err(classify_error)?;
        let note = decode_note(&note, &note_id, &nullifier)?;
        let creation_block = decode_block_number(creation_block)?;
        let consumption_block = decode_block_number(consumption_block)?;
        let burn_tx_id = decode_canonical::<TransactionId>(&burn_tx_id)?;
        burns.push(
            DiscoveredBurn::new(
                note,
                creation_block,
                consumption_block,
                burn_tx_id,
                faucet_account_id,
            )
            .context(INVALID)?,
        );
    }
    Ok(burns)
}

fn insert_candidate(
    transaction: &Transaction<'_>,
    candidate: &BurnCandidate,
) -> anyhow::Result<()> {
    let note_id = candidate.note_id().to_bytes();
    let nullifier = candidate.nullifier().to_bytes();
    let note = candidate.note().to_bytes();
    let creation_block = i64::from(candidate.creation_block().as_u32());

    // A note already recorded, as a candidate or as a burn, clashes with the table's keys.
    transaction
        .execute(
            "INSERT INTO burns (note_id, nullifier, note, creation_block, status)
             VALUES (?1, ?2, ?3, ?4, 'CANDIDATE')",
            params![note_id, nullifier, note, creation_block],
        )
        .map_err(classify_write_error)?;
    Ok(())
}

fn insert_burn(transaction: &Transaction<'_>, burn: &DiscoveredBurn) -> anyhow::Result<()> {
    let note_id = burn.note_id().to_bytes();
    let nullifier = burn.nullifier().to_bytes();
    let note = burn.note().to_bytes();
    let creation_block = i64::from(burn.creation_block().as_u32());
    let consumption_block = i64::from(burn.consumption_block().as_u32());
    let burn_tx_id = burn.burn_tx_id().to_bytes();

    // Promotion turns the exact saved candidate into this burn in place, one row per note.
    let promoted = transaction
        .execute(
            "UPDATE burns SET consumption_block = ?5, burn_tx_id = ?6, status = ?7
             WHERE note_id = ?1 AND nullifier = ?2 AND note = ?3 AND creation_block = ?4
                AND status = 'CANDIDATE'",
            params![
                note_id,
                nullifier,
                note,
                creation_block,
                consumption_block,
                burn_tx_id,
                DISCOVERED,
            ],
        )
        .map_err(classify_write_error)?;
    if promoted == 1 {
        return Ok(());
    }

    // Any other record of this note or its nullifier clashes with the table's keys.
    transaction
        .execute(
            "INSERT INTO burns (
                note_id,
                nullifier,
                note,
                creation_block,
                consumption_block,
                burn_tx_id,
                status
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                note_id,
                nullifier,
                note,
                creation_block,
                consumption_block,
                burn_tx_id,
                DISCOVERED,
            ],
        )
        .map_err(classify_write_error)?;
    Ok(())
}

fn decode_note(
    note_bytes: &[u8],
    note_id_bytes: &[u8],
    nullifier_bytes: &[u8],
) -> anyhow::Result<PublicOutputNote> {
    let note = decode_canonical::<PublicOutputNote>(note_bytes)?;
    let note_id = decode_canonical::<NoteId>(note_id_bytes)?;
    let nullifier = decode_canonical::<Nullifier>(nullifier_bytes)?;
    if note.id() != note_id || note.as_note().nullifier() != nullifier {
        bail!(INVALID);
    }
    Ok(note)
}

fn decode_header(bytes: &[u8]) -> anyhow::Result<BlockHeader> {
    proto::blockchain::BlockHeader::decode(bytes)
        .context(INVALID)?
        .decode_and_build_unchecked()
        .context(INVALID)
}

fn decode_block_number(value: i64) -> anyhow::Result<BlockNumber> {
    Ok(BlockNumber::from(u32::try_from(value).context(INVALID)?))
}

fn decode_canonical<T>(bytes: &[u8]) -> anyhow::Result<T>
where
    T: Deserializable + Serializable,
{
    let value = T::read_from_bytes(bytes).context(INVALID)?;
    if value.to_bytes() != bytes {
        bail!(INVALID);
    }
    Ok(value)
}

fn exists<P: Params>(
    connection: &rusqlite::Connection,
    sql: &str,
    params: P,
) -> anyhow::Result<bool> {
    connection
        .query_row(sql, params, |row| row.get(0))
        .map_err(classify_error)
}

fn classify_write_error(error: rusqlite::Error) -> anyhow::Error {
    if matches!(
        &error,
        rusqlite::Error::SqliteFailure(sqlite_error, _)
            if sqlite_error.code == rusqlite::ErrorCode::ConstraintViolation
    ) {
        anyhow::Error::new(error).context(CONFLICT)
    } else {
        classify_error(error)
    }
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
