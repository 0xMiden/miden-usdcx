//! Durable discovery state and the single-writer store boundary.

use std::path::Path;
use std::time::Duration;

use alloy_primitives::B256;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::{PublicOutputNote, TransactionId};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::Word;
use rusqlite::{params, Params, Transaction};

use crate::burn::{BurnCandidate, BurnRefusal, DiscoveredBurn};
use crate::submission::{HoldReason, SavedSubmission, SubmissionStatus};
use crate::verify::validate_saved_request;

const DISCOVERED: &str = "DISCOVERED";
const REFUSED: &str = "REFUSED";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("attester store is invalid")]
    Invalid,
    #[error("attester store is locked by another process")]
    Locked,
    #[error("configured trusted anchor differs from the store")]
    AnchorChanged,
    #[error("authenticated evidence conflicts with the attester store")]
    Conflict,
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
    ) -> Result<Self, StoreError> {
        let existing_length = match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => Some(metadata.len()),
            Ok(_) => return Err(StoreError::Invalid),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(StoreError::Invalid),
        };

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

        match existing_length {
            None => initialize_store(
                &mut connection,
                faucet_account_id,
                initial_cursor,
                trusted_anchor,
            )?,
            Some(0) => return Err(StoreError::Invalid),
            Some(_) => validate_store(
                &connection,
                faucet_account_id,
                initial_cursor,
                trusted_anchor,
            )?,
        }

        Ok(Self {
            connection,
            initial_cursor,
            faucet_account_id,
        })
    }

    pub(crate) fn scan_state(&self) -> Result<ScanState, StoreError> {
        load_scan_state(&self.connection, self.initial_cursor)
    }

    pub(crate) fn candidates(&self) -> Result<Vec<BurnCandidate>, StoreError> {
        load_candidates(&self.connection, self.faucet_account_id)
    }

    pub(crate) fn save_submission(&self, record: &SavedSubmission) -> Result<(), StoreError> {
        validate_submission(record)?;
        // Only an explicitly supplied fresh authorization can replace a confirmed failure.
        let written = self
            .connection
            .execute(
                "INSERT INTO submissions (
                note_id, endpoint, body, transfer_spec_hash, use_circle_forwarding, status
             ) SELECT ?1, ?2, ?3, ?4, ?5, 'SUBMITTING'
             WHERE EXISTS (SELECT 1 FROM burns
                 WHERE note_id = ?1 AND status = 'DISCOVERED')
             ON CONFLICT (note_id) DO UPDATE SET
                endpoint = excluded.endpoint, body = excluded.body,
                transfer_spec_hash = excluded.transfer_spec_hash,
                use_circle_forwarding = excluded.use_circle_forwarding,
                status = 'SUBMITTING', withdrawal_id = NULL, hold_reason = NULL,
                last_http_status = NULL, last_response = NULL, last_error = NULL
             WHERE submissions.status IN ('FAILED', 'EXPIRED')
                AND submissions.withdrawal_id IS NOT NULL",
                params![
                    record.note_id.to_bytes(),
                    record.endpoint,
                    record.body,
                    record.transfer_spec_hash.as_slice(),
                    record.use_circle_forwarding
                ],
            )
            .map_err(classify_write_error)?;
        (written == 1).then_some(()).ok_or(StoreError::Conflict)
    }

    #[cfg(test)]
    pub(crate) fn submission(
        &self,
        note_id: NoteId,
    ) -> Result<Option<SavedSubmission>, StoreError> {
        Ok(load_submissions(&self.connection, Some(note_id), None)?.pop())
    }

    pub(crate) fn submissions_to_recover(&self) -> Result<Vec<SavedSubmission>, StoreError> {
        load_submissions(&self.connection, None, Some(SubmissionStatus::Submitting))
    }

    pub(crate) fn submissions_to_poll(&self) -> Result<Vec<SavedSubmission>, StoreError> {
        load_submissions(&self.connection, None, Some(SubmissionStatus::Submitted))
    }

    pub(crate) fn save_submission_outcome(
        &self,
        outcome: &SavedSubmission,
    ) -> Result<(), StoreError> {
        validate_submission_outcome(outcome)?;
        // Submission and polling change only outcomes, never a request or a known ID.
        let updated = self
            .connection
            .execute(
                "UPDATE submissions SET status = ?1, withdrawal_id = ?2, hold_reason = ?3,
                last_http_status = ?4, last_response = ?5, last_error = ?6
             WHERE note_id = ?7 AND status IN ('SUBMITTING', 'SUBMITTED')
                AND (withdrawal_id IS NULL OR withdrawal_id = ?2)",
                params![
                    outcome.status.as_str(),
                    outcome.withdrawal_id,
                    outcome.hold_reason.map(HoldReason::as_str),
                    outcome.last_http_status,
                    outcome.last_response,
                    outcome.last_error,
                    outcome.note_id.to_bytes(),
                ],
            )
            .map_err(classify_error)?;
        (updated == 1).then_some(()).ok_or(StoreError::Conflict)
    }

    pub(crate) fn retry_held_submission(&self, note_id: NoteId) -> Result<(), StoreError> {
        // Keep the saved ID and bytes: recovery resumes GET if an ID is already known.
        let updated = self
            .connection
            .execute(
                "UPDATE submissions SET status = 'SUBMITTING', hold_reason = NULL
             WHERE note_id = ?1 AND status = 'HELD' AND hold_reason = 'http_rejected'",
                [note_id.to_bytes()],
            )
            .map_err(classify_error)?;
        (updated == 1).then_some(()).ok_or(StoreError::Conflict)
    }

    /// Records a proven-invalid burn without changing its evidence or scan progress.
    pub(crate) fn refuse_burn(
        &mut self,
        note_id: NoteId,
        reason: BurnRefusal,
    ) -> Result<(), StoreError> {
        let updated = self
            .connection
            .execute(
                "UPDATE burns SET status = ?1, refusal_reason = ?2
             WHERE note_id = ?3 AND status = ?4 AND refusal_reason IS NULL
                AND NOT EXISTS (SELECT 1 FROM submissions WHERE note_id = ?3)",
                params![REFUSED, reason.as_str(), note_id.to_bytes(), DISCOVERED],
            )
            .map_err(classify_error)?;
        (updated == 1).then_some(()).ok_or(StoreError::Conflict)
    }

    #[cfg(test)]
    pub(crate) fn discovered_burns(&self) -> Result<Vec<DiscoveredBurn>, StoreError> {
        load_burns(&self.connection, self.faucet_account_id, true)
    }

    /// Filters discovered burns by verified waiting depth; used by the later submit stage.
    pub(crate) fn burns_ready_for_withdrawal(
        &self,
        proof_lag_block: BlockNumber,
        minimum_depth_blocks: u32,
    ) -> Result<Vec<DiscoveredBurn>, StoreError> {
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
    ) -> Result<(), StoreError> {
        validate_scan_state(next_state, self.initial_cursor)?;
        validate_discovery_records(candidates, burns, next_state.cursor, self.initial_cursor)?;

        // One block's evidence, cursor, and verified header commit as one unit. A crash therefore
        // either records that complete block or scans it again from the previous checkpoint.
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let current_state = load_scan_state(&transaction, self.initial_cursor)?;

        // Advance one block at a time so no caller can silently skip burn evidence.
        if next_state.cursor.next_block.checked_sub(1) != Some(current_state.cursor.next_block) {
            return Err(StoreError::Conflict);
        }
        if let Some(current_parent) = &current_state.authenticated_parent {
            let next_parent = next_state
                .authenticated_parent
                .as_ref()
                .ok_or(StoreError::Invalid)?;
            if next_parent.prev_block_commitment() != current_parent.commitment() {
                return Err(StoreError::Conflict);
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
            .map(Serializable::to_bytes);
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
            return Err(StoreError::Invalid);
        }

        transaction.commit().map_err(classify_error)
    }
}

fn initialize_store(
    connection: &mut rusqlite::Connection,
    faucet_account_id: AccountId,
    initial_cursor: ScanCursor,
    trusted_anchor: TrustedAnchor,
) -> Result<(), StoreError> {
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
            ) STRICT;

            CREATE TABLE burn_candidates (
                note_id BLOB PRIMARY KEY,
                nullifier BLOB NOT NULL UNIQUE,
                note BLOB NOT NULL,
                creation_block INTEGER NOT NULL CHECK (creation_block BETWEEN 0 AND 4294967295)
            ) STRICT;",
        )
        .map_err(classify_error)?;
    create_burns_table(&transaction)?;
    transaction
        .execute_batch(
            "CREATE TABLE submissions (
            note_id BLOB PRIMARY KEY,
            endpoint TEXT NOT NULL,
            body BLOB NOT NULL,
            transfer_spec_hash BLOB NOT NULL,
            use_circle_forwarding INTEGER NOT NULL CHECK (use_circle_forwarding IN (0, 1)),
            status TEXT NOT NULL CHECK (status IN (
                'SUBMITTING', 'SUBMITTED', 'FINALIZED', 'EXPIRED', 'FAILED', 'HELD'
            )),
            withdrawal_id TEXT,
            hold_reason TEXT CHECK (hold_reason IN (
                'http_rejected', 'response_mismatch', 'unknown_status'
            )),
            last_http_status INTEGER,
            last_response BLOB,
            last_error TEXT
        ) STRICT;",
        )
        .map_err(classify_error)?;
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

fn create_burns_table(connection: &rusqlite::Connection) -> Result<(), StoreError> {
    connection
        .execute_batch(
            "CREATE TABLE burns (
            note_id BLOB PRIMARY KEY,
            nullifier BLOB NOT NULL UNIQUE,
            note BLOB NOT NULL,
            creation_block INTEGER NOT NULL CHECK (creation_block BETWEEN 0 AND 4294967295),
            consumption_block INTEGER NOT NULL
                CHECK (consumption_block > creation_block AND consumption_block <= 4294967295),
            burn_tx_id BLOB NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('DISCOVERED', 'REFUSED')),
            refusal_reason TEXT CHECK (refusal_reason IN (
                'wrong_tag', 'invalid_withdrawal'
            )),
            CHECK ((status = 'DISCOVERED' AND refusal_reason IS NULL)
                OR (status = 'REFUSED' AND refusal_reason IS NOT NULL))
        ) STRICT;",
        )
        .map_err(classify_error)
}

fn validate_store(
    connection: &rusqlite::Connection,
    faucet_account_id: AccountId,
    initial_cursor: ScanCursor,
    trusted_anchor: TrustedAnchor,
) -> Result<(), StoreError> {
    validate_store_format(connection)?;

    // Stored chain state becomes the next run's trust base, so reject any malformed or
    // internally inconsistent row before using it.
    let row_count = connection
        .query_row("SELECT COUNT(*) FROM attester_state", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(classify_error)?;
    if row_count != 1 {
        return Err(StoreError::Invalid);
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
        return Err(StoreError::Invalid);
    }

    let stored_anchor = TrustedAnchor {
        block_num: decode_block_number(anchor_block)?,
        commitment: decode_canonical(&anchor_commitment)?,
    };
    if stored_anchor != trusted_anchor {
        return Err(StoreError::AnchorChanged);
    }
    let state = load_scan_state(connection, initial_cursor)?;
    if state
        .authenticated_parent
        .as_ref()
        .is_some_and(|parent| parent.block_num() < trusted_anchor.block_num)
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
    for probe in [
        "SELECT singleton, faucet_account_id, anchor_block, anchor_commitment,
            next_block, authenticated_parent FROM attester_state LIMIT 0",
        "SELECT note_id, nullifier, note, creation_block FROM burn_candidates LIMIT 0",
        "SELECT note_id, nullifier, note, creation_block, consumption_block, burn_tx_id, status,
            refusal_reason FROM burns LIMIT 0",
        "SELECT note_id, endpoint, body, transfer_spec_hash, use_circle_forwarding, status,
            withdrawal_id, hold_reason, last_http_status, last_response, last_error
            FROM submissions LIMIT 0",
    ] {
        connection.prepare(probe).map_err(classify_error)?;
    }

    Ok(())
}

impl SubmissionStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Submitting => "SUBMITTING",
            Self::Submitted => "SUBMITTED",
            Self::Finalized => "FINALIZED",
            Self::Expired => "EXPIRED",
            Self::Failed => "FAILED",
            Self::Held => "HELD",
        }
    }
}

impl HoldReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::HttpRejected => "http_rejected",
            Self::ResponseMismatch => "response_mismatch",
            Self::UnknownStatus => "unknown_status",
        }
    }
}

fn load_submissions(
    connection: &rusqlite::Connection,
    note_id: Option<NoteId>,
    status: Option<SubmissionStatus>,
) -> Result<Vec<SavedSubmission>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT note_id, endpoint, body, transfer_spec_hash,
            use_circle_forwarding, status, withdrawal_id, hold_reason,
            last_http_status, last_response, last_error FROM submissions
         WHERE (?1 IS NULL OR note_id = ?1) AND (?2 IS NULL OR status = ?2)
         ORDER BY note_id",
        )
        .map_err(classify_error)?;
    let mut rows = statement
        .query(params![
            note_id.map(|id| id.to_bytes()),
            status.map(SubmissionStatus::as_str)
        ])
        .map_err(classify_error)?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(classify_error)? {
        let status = match row.get::<_, String>(5).map_err(classify_error)?.as_str() {
            "SUBMITTING" => SubmissionStatus::Submitting,
            "SUBMITTED" => SubmissionStatus::Submitted,
            "FINALIZED" => SubmissionStatus::Finalized,
            "EXPIRED" => SubmissionStatus::Expired,
            "FAILED" => SubmissionStatus::Failed,
            "HELD" => SubmissionStatus::Held,
            _ => return Err(StoreError::Invalid),
        };
        let hold_reason = match row
            .get::<_, Option<String>>(7)
            .map_err(classify_error)?
            .as_deref()
        {
            None => None,
            Some("http_rejected") => Some(HoldReason::HttpRejected),
            Some("response_mismatch") => Some(HoldReason::ResponseMismatch),
            Some("unknown_status") => Some(HoldReason::UnknownStatus),
            _ => return Err(StoreError::Invalid),
        };
        let record = SavedSubmission {
            note_id: decode_canonical(&row.get::<_, Vec<u8>>(0).map_err(classify_error)?)?,
            endpoint: row.get(1).map_err(classify_error)?,
            body: row.get(2).map_err(classify_error)?,
            transfer_spec_hash: B256::from(row.get::<_, [u8; 32]>(3).map_err(classify_error)?),
            use_circle_forwarding: match row.get::<_, i64>(4).map_err(classify_error)? {
                0 => false,
                1 => true,
                _ => return Err(StoreError::Invalid),
            },
            status,
            withdrawal_id: row.get(6).map_err(classify_error)?,
            hold_reason,
            last_http_status: row.get(8).map_err(classify_error)?,
            last_response: row.get(9).map_err(classify_error)?,
            last_error: row.get(10).map_err(classify_error)?,
        };
        validate_submission(&record)?;
        if !exists(
            connection,
            "SELECT EXISTS (SELECT 1 FROM burns
             WHERE note_id = ?1 AND status = 'DISCOVERED')",
            [record.note_id.to_bytes()],
        )? {
            return Err(StoreError::Invalid);
        }
        records.push(record);
    }
    Ok(records)
}

fn validate_submission(record: &SavedSubmission) -> Result<(), StoreError> {
    let endpoint = reqwest::Url::parse(&record.endpoint).map_err(|_| StoreError::Invalid)?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || endpoint.path() != "/v1/withdraw"
        || !validate_saved_request(record)
    {
        return Err(StoreError::Invalid);
    }
    validate_submission_outcome(record)
}

fn validate_submission_outcome(outcome: &SavedSubmission) -> Result<(), StoreError> {
    if (outcome.status == SubmissionStatus::Held) != outcome.hold_reason.is_some()
        || outcome
            .withdrawal_id
            .as_deref()
            .is_some_and(|id| id.trim().is_empty())
        || (matches!(
            outcome.status,
            SubmissionStatus::Submitted
                | SubmissionStatus::Finalized
                | SubmissionStatus::Expired
                | SubmissionStatus::Failed
        ) && outcome.withdrawal_id.is_none())
        || outcome
            .last_http_status
            .is_some_and(|code| reqwest::StatusCode::from_u16(code).is_err())
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn load_scan_state(
    connection: &rusqlite::Connection,
    initial_cursor: ScanCursor,
) -> Result<ScanState, StoreError> {
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
            .map(decode_canonical)
            .transpose()?,
    };
    validate_scan_state(&state, initial_cursor)?;
    Ok(state)
}

fn validate_scan_state(state: &ScanState, initial_cursor: ScanCursor) -> Result<(), StoreError> {
    match &state.authenticated_parent {
        Some(parent) if state.cursor.next_block.checked_sub(1) != Some(parent.block_num()) => {
            Err(StoreError::Invalid)
        }
        None if state.cursor != initial_cursor => Err(StoreError::Invalid),
        _ => Ok(()),
    }
}

fn validate_discovery_records(
    candidates: &[BurnCandidate],
    burns: &[DiscoveredBurn],
    cursor: ScanCursor,
    initial_cursor: ScanCursor,
) -> Result<(), StoreError> {
    if candidates.iter().any(|candidate| {
        candidate.creation_block() < initial_cursor.next_block
            || candidate.creation_block() >= cursor.next_block
    }) || burns.iter().any(|burn| {
        burn.creation_block() < initial_cursor.next_block
            || burn.creation_block() >= burn.consumption_block()
            || burn.consumption_block() >= cursor.next_block
    }) {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn load_candidates(
    connection: &rusqlite::Connection,
    faucet_account_id: AccountId,
) -> Result<Vec<BurnCandidate>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT note_id, nullifier, note, creation_block
             FROM burn_candidates ORDER BY creation_block, note_id",
        )
        .map_err(classify_error)?;
    let rows = statement
        .query_map([], |row| {
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
            BurnCandidate::try_new(
                note,
                decode_block_number(creation_block)?,
                faucet_account_id,
            )
            .map_err(|_| StoreError::Invalid)?,
        );
    }
    Ok(candidates)
}

fn load_burns(
    connection: &rusqlite::Connection,
    faucet_account_id: AccountId,
    include_all: bool,
) -> Result<Vec<DiscoveredBurn>, StoreError> {
    // Expired work is eligible again; its old request remains saved until a fresh one replaces it.
    let mut statement = connection
        .prepare(
            "SELECT note_id, nullifier, note, creation_block, consumption_block,
                    burn_tx_id FROM burns
             WHERE ?1 OR (status != 'REFUSED' AND NOT EXISTS (
                  SELECT 1 FROM submissions WHERE submissions.note_id = burns.note_id
                     AND submissions.status != 'EXPIRED'
             ))",
        )
        .map_err(classify_error)?;
    let rows = statement
        .query_map([include_all], |row| {
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
            DiscoveredBurn::try_new(
                note,
                creation_block,
                consumption_block,
                burn_tx_id,
                faucet_account_id,
            )
            .map_err(|_| StoreError::Invalid)?,
        );
    }
    Ok(burns)
}

fn insert_candidate(
    transaction: &Transaction<'_>,
    candidate: &BurnCandidate,
) -> Result<(), StoreError> {
    let note_id = candidate.note_id().to_bytes();
    let nullifier = candidate.nullifier().to_bytes();
    let note = candidate.note().to_bytes();
    let creation_block = i64::from(candidate.creation_block().as_u32());

    // A promoted note cannot become a candidate again.
    let overlaps_burn = exists(
        transaction,
        "SELECT EXISTS (SELECT 1 FROM burns WHERE note_id = ?1 OR nullifier = ?2)",
        params![note_id, nullifier],
    )?;
    if overlaps_burn {
        return Err(StoreError::Conflict);
    }

    transaction
        .execute(
            "INSERT INTO burn_candidates (note_id, nullifier, note, creation_block)
             VALUES (?1, ?2, ?3, ?4)",
            params![note_id, nullifier, note, creation_block],
        )
        .map_err(classify_write_error)?;
    Ok(())
}

fn insert_burn(transaction: &Transaction<'_>, burn: &DiscoveredBurn) -> Result<(), StoreError> {
    let note_id = burn.note_id().to_bytes();
    let nullifier = burn.nullifier().to_bytes();
    let note = burn.note().to_bytes();
    let creation_block = i64::from(burn.creation_block().as_u32());
    let consumption_block = i64::from(burn.consumption_block().as_u32());
    let burn_tx_id = burn.burn_tx_id().to_bytes();

    let overlaps_candidate = exists(
        transaction,
        "SELECT EXISTS (
            SELECT 1 FROM burn_candidates WHERE note_id = ?1 OR nullifier = ?2
        )",
        params![note_id, nullifier],
    )?;
    if overlaps_candidate {
        let exact = exists(
            transaction,
            "SELECT EXISTS (SELECT 1 FROM burn_candidates
             WHERE note_id = ?1 AND nullifier = ?2 AND note = ?3 AND creation_block = ?4)",
            params![note_id, nullifier, note, creation_block],
        )?;
        if !exact {
            return Err(StoreError::Conflict);
        }
    }

    // Promotion is atomic: once the burn is queued, the same note is no longer a candidate.
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
    transaction
        .execute("DELETE FROM burn_candidates WHERE note_id = ?1", [&note_id])
        .map_err(classify_error)?;
    Ok(())
}

fn decode_note(
    note_bytes: &[u8],
    note_id_bytes: &[u8],
    nullifier_bytes: &[u8],
) -> Result<PublicOutputNote, StoreError> {
    let note = decode_canonical::<PublicOutputNote>(note_bytes)?;
    let note_id = decode_canonical::<NoteId>(note_id_bytes)?;
    let nullifier = decode_canonical::<Nullifier>(nullifier_bytes)?;
    if note.id() != note_id || note.as_note().nullifier() != nullifier {
        return Err(StoreError::Invalid);
    }
    Ok(note)
}

fn decode_block_number(value: i64) -> Result<BlockNumber, StoreError> {
    Ok(BlockNumber::from(
        u32::try_from(value).map_err(|_| StoreError::Invalid)?,
    ))
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, StoreError>
where
    T: Deserializable + Serializable,
{
    let value = T::read_from_bytes(bytes).map_err(|_| StoreError::Invalid)?;
    if value.to_bytes() != bytes {
        return Err(StoreError::Invalid);
    }
    Ok(value)
}

fn exists<P: Params>(
    connection: &rusqlite::Connection,
    sql: &str,
    params: P,
) -> Result<bool, StoreError> {
    connection
        .query_row(sql, params, |row| row.get(0))
        .map_err(classify_error)
}

fn classify_write_error(error: rusqlite::Error) -> StoreError {
    match error {
        rusqlite::Error::SqliteFailure(sqlite_error, _)
            if matches!(
                sqlite_error.extended_code,
                rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                    | rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            ) =>
        {
            StoreError::Conflict
        }
        other => classify_error(other),
    }
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
