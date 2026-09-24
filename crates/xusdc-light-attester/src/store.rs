//! Durable discovery state and the single-writer store boundary.

use std::path::Path;
use std::time::Duration;

use alloy_primitives::B256;
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

use crate::burn::{BurnCandidate, DiscoveredBurn};
use crate::submission::{HoldReason, SavedSubmission, SubmissionStatus};
use crate::verify::validate_saved_request;

const DISCOVERED: &str = "DISCOVERED";
const REFUSED: &str = "REFUSED";
const CAP_REJECTED: &str = "CAP_REJECTED";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BurnHoldReason {
    PrepareRejected,
}

impl BurnHoldReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PrepareRejected => "prepare_rejected",
        }
    }
}

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

    pub(crate) fn can_submit_burn(
        &self,
        note_id: NoteId,
        amount: u64,
        now_ms: i64,
        window_ms: i64,
        limit: u64,
    ) -> anyhow::Result<bool> {
        Ok(amount <= limit
            && can_submit_burn(&self.connection, note_id, amount, now_ms, window_ms, limit)?)
    }

    /// The exact signed request and its capacity reservation commit before any POST.
    pub(crate) fn admit_submission(
        &mut self,
        record: &SavedSubmission,
        amount: u64,
        now_ms: i64,
        window_ms: i64,
        limit: u64,
    ) -> anyhow::Result<bool> {
        let transaction = self.connection.transaction().map_err(classify_error)?;
        if amount > limit
            || !can_submit_burn(
                &transaction,
                record.note_id,
                amount,
                now_ms,
                window_ms,
                limit,
            )?
        {
            return Ok(false);
        }
        reserve_capacity(&transaction, record.note_id, amount, now_ms)?;
        save_submission(&transaction, record)?;
        transaction.commit().map_err(classify_error)?;
        Ok(true)
    }

    /// An uncertain POST may arrive at Circle again, so refresh its existing reservation first.
    /// The per-burn cap is not applied again here: it was passed at admission, and lowering it
    /// afterwards must not strand a request Circle may already hold. For the same reason, a
    /// reservation still inside the window is renewed without checking the limit again; an
    /// expired one is checked against the reservations still inside the window.
    pub(crate) fn renew_submission(
        &mut self,
        note_id: NoteId,
        now_ms: i64,
        window_ms: i64,
        limit: u64,
    ) -> anyhow::Result<bool> {
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let (amount, admitted_at_ms) = transaction
            .query_row(
                "SELECT reservation_amount, admitted_at_ms
                 FROM burns JOIN submissions USING (note_id)
                 WHERE note_id = ?1 AND submissions.status = 'SUBMITTING'
                    AND withdrawal_id IS NULL",
                [note_id.to_bytes()],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(classify_error)?;
        if !inside_window(now_ms, admitted_at_ms, window_ms)
            && !can_submit_burn(&transaction, note_id, amount, now_ms, window_ms, limit)?
        {
            return Ok(false);
        }
        reserve_capacity(&transaction, note_id, amount, now_ms)?;
        transaction.commit().map_err(classify_error)?;
        Ok(true)
    }

    pub(crate) fn record_cap_rejection(&mut self, note_id: NoteId) -> anyhow::Result<()> {
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let removed = transaction
            .execute(
                "DELETE FROM submissions WHERE note_id = ?1
                    AND status = 'SUBMITTING' AND withdrawal_id IS NULL",
                [note_id.to_bytes()],
            )
            .map_err(classify_error)?;
        let updated = transaction
            .execute(
                "UPDATE burns SET status = 'CAP_REJECTED' WHERE note_id = ?1
                    AND status = 'DISCOVERED' AND admitted_at_ms IS NOT NULL",
                [note_id.to_bytes()],
            )
            .map_err(classify_error)?;
        if removed != 1 || updated != 1 {
            bail!(CONFLICT);
        }
        // Circle refused this attempt: release its charge, retain its cooldown, discard its bytes.
        transaction.commit().map_err(classify_error)
    }

    /// Releases every burn hold and every withdrawal hold in one transaction, and returns how many
    /// burns and withdrawals it released.
    pub(crate) fn release_all_holds(&mut self) -> anyhow::Result<(usize, usize)> {
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let burns = transaction
            .execute(
                "UPDATE burns SET hold_reason = NULL WHERE hold_reason IS NOT NULL",
                [],
            )
            .map_err(classify_error)?;
        // A held withdrawal is started over instead of resent. Circle refuses a signed request
        // that has expired, and asks for the burn to be signed again with the same burn id.
        // Signing again cannot pay twice: Circle matches withdrawals by burn id, answers a repeat
        // of an accepted request with 409 and its existing withdrawal, and refuses a new request
        // whose transfer spec differs, for example after a fee change. The new request passes the
        // same checks against the burn, so the recipient, chain and burned amount cannot change;
        // only Circle's fee can, within the ceiling.
        let withdrawals = transaction
            .execute(
                "DELETE FROM submissions WHERE status = 'HELD' AND hold_reason = 'http_rejected'
                    AND withdrawal_id IS NULL",
                [],
            )
            .map_err(classify_error)?;
        transaction.commit().map_err(classify_error)?;
        Ok((burns, withdrawals))
    }

    pub(crate) fn hold_burn(&self, note_id: NoteId, reason: BurnHoldReason) -> anyhow::Result<()> {
        let updated = self
            .connection
            .execute(
                "UPDATE burns SET hold_reason = ?2
                 WHERE note_id = ?1 AND status IN ('DISCOVERED', 'CAP_REJECTED')
                    AND (hold_reason IS NULL OR hold_reason = ?2)
                    AND NOT EXISTS (SELECT 1 FROM submissions WHERE note_id = ?1
                        AND status != 'EXPIRED')",
                params![note_id.to_bytes(), reason.as_str()],
            )
            .map_err(classify_error)?;
        (updated == 1)
            .then_some(())
            .ok_or_else(|| anyhow!(CONFLICT))
    }

    pub(crate) fn release_burn_hold(&self, note_id: NoteId) -> anyhow::Result<()> {
        let updated = self
            .connection
            .execute(
                "UPDATE burns SET hold_reason = NULL
                 WHERE note_id = ?1 AND hold_reason IS NOT NULL",
                [note_id.to_bytes()],
            )
            .map_err(classify_error)?;
        (updated == 1)
            .then_some(())
            .ok_or_else(|| anyhow!(CONFLICT))
    }

    pub(crate) fn submission(&self, note_id: NoteId) -> anyhow::Result<Option<SavedSubmission>> {
        Ok(load_submissions(&self.connection, Some(note_id), None)?.pop())
    }

    pub(crate) fn submissions_to_recover(&self) -> anyhow::Result<Vec<SavedSubmission>> {
        load_submissions(&self.connection, None, Some(SubmissionStatus::Submitting))
    }

    pub(crate) fn submissions_to_poll(&self) -> anyhow::Result<Vec<SavedSubmission>> {
        load_submissions(&self.connection, None, Some(SubmissionStatus::Submitted))
    }

    pub(crate) fn save_submission_outcome(&self, outcome: &SavedSubmission) -> anyhow::Result<()> {
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
        (updated == 1)
            .then_some(())
            .ok_or_else(|| anyhow!(CONFLICT))
    }

    pub(crate) fn retry_held_submission(&self, note_id: NoteId) -> anyhow::Result<()> {
        // Keep the saved ID and bytes: recovery resumes GET if an ID is already known.
        let updated = self
            .connection
            .execute(
                "UPDATE submissions SET status = 'SUBMITTING', hold_reason = NULL
             WHERE note_id = ?1 AND status = 'HELD' AND hold_reason = 'http_rejected'",
                [note_id.to_bytes()],
            )
            .map_err(classify_error)?;
        (updated == 1)
            .then_some(())
            .ok_or_else(|| anyhow!(CONFLICT))
    }

    /// Records a burn whose withdrawal payload does not decode, without changing its evidence or
    /// scan progress.
    pub(crate) fn refuse_burn(&mut self, note_id: NoteId) -> anyhow::Result<()> {
        let updated = self
            .connection
            .execute(
                "UPDATE burns SET status = ?1
             WHERE note_id = ?2 AND status IN ('DISCOVERED', 'CAP_REJECTED')
                AND NOT EXISTS (SELECT 1 FROM submissions WHERE note_id = ?2)",
                params![REFUSED, note_id.to_bytes()],
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

fn can_submit_burn(
    connection: &rusqlite::Connection,
    note_id: NoteId,
    amount: u64,
    now_ms: i64,
    window_ms: i64,
    limit: u64,
) -> anyhow::Result<bool> {
    if now_ms < 0 || window_ms <= 0 {
        bail!(INVALID);
    }
    let (status, hold, previous_amount, admitted_at) = connection
        .query_row(
            "SELECT status, hold_reason, reservation_amount, admitted_at_ms
             FROM burns WHERE note_id = ?1",
            [note_id.to_bytes()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<u64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .map_err(classify_error)?;
    if previous_amount.is_some_and(|previous| previous != amount) {
        bail!(CONFLICT);
    }
    if hold.is_some()
        || status == REFUSED
        || (status == CAP_REJECTED
            && inside_window(now_ms, admitted_at.context(INVALID)?, window_ms))
    {
        return Ok(false);
    }

    // Count each burn once. A replacement or retry renews this burn's existing charge.
    let mut statement = connection
        .prepare(
            "SELECT reservation_amount, admitted_at_ms FROM burns
             WHERE note_id != ?1 AND status != 'CAP_REJECTED'
                AND reservation_amount IS NOT NULL",
        )
        .map_err(classify_error)?;
    let mut rows = statement
        .query([note_id.to_bytes()])
        .map_err(classify_error)?;
    let mut total = u128::from(amount);
    while let Some(row) = rows.next().map_err(classify_error)? {
        if inside_window(now_ms, row.get(1).map_err(classify_error)?, window_ms) {
            total += u128::from(row.get::<_, u64>(0).map_err(classify_error)?);
            if total > u128::from(limit) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn inside_window(now_ms: i64, admitted_at_ms: i64, window_ms: i64) -> bool {
    // A backwards clock keeps reservations live; exactly one window old stops counting.
    i128::from(now_ms) - i128::from(admitted_at_ms) < i128::from(window_ms)
}

fn reserve_capacity(
    connection: &rusqlite::Connection,
    note_id: NoteId,
    amount: u64,
    now_ms: i64,
) -> anyhow::Result<()> {
    let updated = connection
        .execute(
            "UPDATE burns SET status = 'DISCOVERED', reservation_amount = ?2,
                admitted_at_ms = MAX(COALESCE(admitted_at_ms, ?3), ?3)
             WHERE note_id = ?1 AND status IN ('DISCOVERED', 'CAP_REJECTED')
                AND hold_reason IS NULL",
            params![note_id.to_bytes(), amount, now_ms],
        )
        .map_err(classify_error)?;
    (updated == 1)
        .then_some(())
        .ok_or_else(|| anyhow!(CONFLICT))
}

fn save_submission(
    connection: &rusqlite::Connection,
    record: &SavedSubmission,
) -> anyhow::Result<()> {
    validate_submission(record)?;
    // Only a fresh authorization can replace a confirmed failure, never an uncertain send.
    let written = connection
        .execute(
            "INSERT INTO submissions (
                note_id, endpoint, body, transfer_spec_hash, use_circle_forwarding, status
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'SUBMITTING')
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
    (written == 1)
        .then_some(())
        .ok_or_else(|| anyhow!(CONFLICT))
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
            hold_reason TEXT CHECK (hold_reason IN ('http_rejected')),
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
            status TEXT NOT NULL
                CHECK (status IN ('CANDIDATE', 'DISCOVERED', 'REFUSED', 'CAP_REJECTED')),
            hold_reason TEXT CHECK (hold_reason IN ('prepare_rejected')),
            reservation_amount INTEGER CHECK (reservation_amount >= 0),
            admitted_at_ms INTEGER CHECK (admitted_at_ms >= 0),
            CHECK ((status = 'CANDIDATE') = (consumption_block IS NULL)),
            CHECK ((consumption_block IS NULL) = (burn_tx_id IS NULL)),
            CHECK ((reservation_amount IS NULL) = (admitted_at_ms IS NULL)),
            CHECK (status != 'CAP_REJECTED' OR admitted_at_ms IS NOT NULL)
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
            hold_reason, reservation_amount, admitted_at_ms FROM burns LIMIT 0",
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
        }
    }
}

fn load_submissions(
    connection: &rusqlite::Connection,
    note_id: Option<NoteId>,
    status: Option<SubmissionStatus>,
) -> anyhow::Result<Vec<SavedSubmission>> {
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
            _ => bail!(INVALID),
        };
        let hold_reason = match row
            .get::<_, Option<String>>(7)
            .map_err(classify_error)?
            .as_deref()
        {
            None => None,
            Some("http_rejected") => Some(HoldReason::HttpRejected),
            _ => bail!(INVALID),
        };
        let record = SavedSubmission {
            note_id: decode_canonical(&row.get::<_, Vec<u8>>(0).map_err(classify_error)?)?,
            endpoint: row.get(1).map_err(classify_error)?,
            body: row.get(2).map_err(classify_error)?,
            transfer_spec_hash: B256::from(row.get::<_, [u8; 32]>(3).map_err(classify_error)?),
            use_circle_forwarding: match row.get::<_, i64>(4).map_err(classify_error)? {
                0 => false,
                1 => true,
                _ => bail!(INVALID),
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
             WHERE note_id = ?1 AND status = 'DISCOVERED' AND reservation_amount IS NOT NULL)",
            [record.note_id.to_bytes()],
        )? {
            bail!(INVALID);
        }
        records.push(record);
    }
    Ok(records)
}

fn validate_submission(record: &SavedSubmission) -> anyhow::Result<()> {
    let endpoint = reqwest::Url::parse(&record.endpoint).context(INVALID)?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || endpoint.path() != "/v1/withdraw"
        || !validate_saved_request(record)
    {
        bail!(INVALID);
    }
    validate_submission_outcome(record)
}

fn validate_submission_outcome(outcome: &SavedSubmission) -> anyhow::Result<()> {
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
        bail!(INVALID);
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
    include_all: bool,
) -> anyhow::Result<Vec<DiscoveredBurn>> {
    // Expired work is eligible again; its old request remains saved until a fresh one replaces it.
    let mut statement = connection
        .prepare(
            "SELECT note_id, nullifier, note, creation_block, consumption_block,
                    burn_tx_id FROM burns
             WHERE status != 'CANDIDATE' AND (?1 OR (
                 status != 'REFUSED' AND hold_reason IS NULL AND NOT EXISTS (
                     SELECT 1 FROM submissions WHERE submissions.note_id = burns.note_id
                        AND submissions.status != 'EXPIRED'
                 )
             ))
             ORDER BY creation_block, note_id",
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
            if matches!(
                sqlite_error.extended_code,
                rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                    | rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            )
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
