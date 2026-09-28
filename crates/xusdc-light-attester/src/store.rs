//! Durable discovery state and the single-writer store boundary.

use std::path::Path;
use std::time::Duration;

use alloy_primitives::B256;
use anyhow::{anyhow, bail, ensure, Context};
use miden_objects::prost::Message;
use miden_objects::{proto, DecodeMessageExt};
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::{PublicOutputNote, TransactionId};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::Word;
use reqwest::Url;
use rusqlite::{params, OptionalExtension, Params, Transaction};

use crate::burn::{BurnCandidate, DiscoveredBurn};
use crate::submission::{is_well_formed_id, HoldReason, SavedSubmission, SubmissionStatus};
use crate::verify::validate_saved_request;

const DISCOVERED: &str = "DISCOVERED";
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

/// The store's migrations in order: running the first `n` brings a new store to version `n`. A
/// layout change adds its numbered file here, and [`STORE_VERSION`] follows.
const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_initial.sql")];

/// The layout version this attester writes, kept in SQLite's `user_version`.
pub(crate) const STORE_VERSION: u32 = MIGRATIONS.len() as u32;
/// Why a store this attester cannot bring to [`STORE_VERSION`] is refused. It is left as it was.
pub(crate) const CANNOT_UPGRADE: &str = "attester store cannot be upgraded; start a new store";

/// What one row of a burn's submission history records. Each kind is stored under its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr)]
enum EventKind {
    /// A newly signed request, saved before it is sent.
    #[strum(serialize = "AUTHORIZED")]
    Authorized,
    /// Circle's answer, or a lost reply, when it changes the request's recorded state.
    #[strum(serialize = "OUTCOME")]
    Outcome,
    /// An operator queued a held request to be sent again.
    #[strum(serialize = "OPERATOR_RETRY")]
    OperatorRetry,
    /// A request about to be sent again renewed its reservation.
    #[strum(serialize = "RESERVATION_RENEWED")]
    ReservationRenewed,
    /// Circle refused a first send because its withdrawal limit was reached; the request is gone.
    #[strum(serialize = "CAP_REJECTED")]
    CapRejected,
    /// Circle refused to prepare the burn, which now waits for an operator.
    #[strum(serialize = "BURN_HELD")]
    BurnHeld,
    /// An operator released the burn's hold; the row keeps the hold's reason.
    #[strum(serialize = "BURN_RELEASED")]
    BurnReleased,
}

impl EventKind {
    /// Whether the row keeps the signed request itself: only a new authorization does.
    fn keeps_request(self) -> bool {
        matches!(self, Self::Authorized)
    }

    /// Whether the row sets the burn's reservation against the withdrawal limit.
    fn keeps_reservation(self) -> bool {
        matches!(self, Self::Authorized | Self::ReservationRenewed)
    }
}

/// The history row that holds a burn's reservation against the withdrawal limit: the burn's latest
/// row that sets one. The burns table keeps a copy, checked whenever the store opens.
const LATEST_RESERVATION: &str = "SELECT seq FROM submission_events
    WHERE submission_events.note_id = burns.note_id AND reservation_amount IS NOT NULL
    ORDER BY seq DESC LIMIT 1";

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
    /// Where this store started scanning, saved when it was created.
    initial_cursor: ScanCursor,
    faucet_account_id: AccountId,
}

impl Store {
    /// Opens the store at `path`, or creates it there starting at `initial_cursor`. An existing
    /// store keeps the scan start it was created with, so changing the configured deployment block
    /// later cannot turn notes it already saved into conflicts.
    pub(crate) fn open_or_create(
        path: &Path,
        faucet_account_id: AccountId,
        initial_cursor: ScanCursor,
        trusted_anchor: TrustedAnchor,
    ) -> anyhow::Result<Self> {
        let exists = path.try_exists().context(INVALID)?;
        // A new store keeps its anchor and scan start for good, so a bad pair is refused before
        // anything is created and the corrected config can use the same path.
        if !exists && trusted_anchor.block_num > initial_cursor.next_block {
            bail!("trusted anchor must not be after the scan start");
        }

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

        let initial_cursor = if exists {
            open_existing(&mut connection, faucet_account_id, trusted_anchor)?
        } else {
            initialize_store(
                &mut connection,
                faucet_account_id,
                initial_cursor,
                trusted_anchor,
            )?;
            initial_cursor
        };

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
        // A burn admitted before keeps the later of its admission times: reservations never move
        // back.
        let admitted_at_ms = latest_reservation(&transaction, record.note_id)?
            .map_or(now_ms, |(_, admitted_at_ms)| admitted_at_ms.max(now_ms));
        reserve_capacity(&transaction, record.note_id, amount, admitted_at_ms)?;
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
                &format!(
                    "SELECT reservation.reservation_amount, reservation.admitted_at_ms
                     FROM burns JOIN submissions ON submissions.note_id = burns.note_id
                     JOIN submission_events AS reservation
                        ON reservation.seq = ({LATEST_RESERVATION})
                     WHERE burns.note_id = ?1 AND submissions.status = ?2
                        AND submissions.withdrawal_id IS NULL"
                ),
                params![note_id.to_bytes(), SubmissionStatus::Submitting.as_ref()],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(classify_error)?;
        if !inside_window(now_ms, admitted_at_ms, window_ms)
            && !can_submit_burn(&transaction, note_id, amount, now_ms, window_ms, limit)?
        {
            return Ok(false);
        }
        reserve_capacity(&transaction, note_id, amount, admitted_at_ms.max(now_ms))?;
        record_event(&transaction, note_id, EventKind::ReservationRenewed)?;
        transaction.commit().map_err(classify_error)?;
        Ok(true)
    }

    /// Circle refused the first send of `rejected` because its withdrawal limit was reached. The
    /// burn stops counting against the limit and its signed bytes are discarded, but its
    /// reservation keeps it waiting until its window passes. Circle's answer goes into the burn's
    /// history before the request is deleted.
    pub(crate) fn record_cap_rejection(
        &mut self,
        rejected: &SavedSubmission,
    ) -> anyhow::Result<()> {
        let note_id = rejected.note_id.to_bytes();
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let answered = transaction
            .execute(
                "UPDATE submissions SET last_http_status = ?2, last_response = ?3, last_error = ?4
                 WHERE note_id = ?1 AND status = ?5 AND withdrawal_id IS NULL",
                params![
                    note_id,
                    rejected.last_http_status,
                    rejected.last_response,
                    rejected.last_error,
                    SubmissionStatus::Submitting.as_ref()
                ],
            )
            .map_err(classify_error)?;
        ensure!(answered == 1, CONFLICT);
        let updated = transaction
            .execute(
                "UPDATE burns SET status = 'CAP_REJECTED' WHERE note_id = ?1
                    AND status = 'DISCOVERED' AND admitted_at_ms IS NOT NULL",
                [&note_id],
            )
            .map_err(classify_error)?;
        ensure!(updated == 1, CONFLICT);
        record_event(&transaction, rejected.note_id, EventKind::CapRejected)?;
        let removed = transaction
            .execute("DELETE FROM submissions WHERE note_id = ?1", [&note_id])
            .map_err(classify_error)?;
        ensure!(removed == 1, CONFLICT);
        transaction.commit().map_err(classify_error)
    }

    pub(crate) fn hold_burn(
        &mut self,
        note_id: NoteId,
        reason: BurnHoldReason,
    ) -> anyhow::Result<()> {
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let updated = transaction
            .execute(
                "UPDATE burns SET hold_reason = ?2
                 WHERE note_id = ?1 AND status IN ('DISCOVERED', 'CAP_REJECTED')
                    AND (hold_reason IS NULL OR hold_reason = ?2)
                    AND NOT EXISTS (SELECT 1 FROM submissions WHERE note_id = ?1
                        AND status != ?3)",
                params![
                    note_id.to_bytes(),
                    reason.as_str(),
                    SubmissionStatus::Expired.as_ref()
                ],
            )
            .map_err(classify_error)?;
        ensure!(updated == 1, CONFLICT);
        record_event(&transaction, note_id, EventKind::BurnHeld)?;
        transaction.commit().map_err(classify_error)
    }

    pub(crate) fn release_burn_hold(&mut self, note_id: NoteId) -> anyhow::Result<()> {
        let transaction = self.connection.transaction().map_err(classify_error)?;
        // Recorded before the hold is cleared, so the history keeps its reason.
        record_event(&transaction, note_id, EventKind::BurnReleased)?;
        let updated = transaction
            .execute(
                "UPDATE burns SET hold_reason = NULL
                 WHERE note_id = ?1 AND hold_reason IS NOT NULL",
                [note_id.to_bytes()],
            )
            .map_err(classify_error)?;
        ensure!(updated == 1, CONFLICT);
        transaction.commit().map_err(classify_error)
    }

    /// The saved submission for `note_id`, if there is one.
    #[cfg(test)]
    pub(crate) fn submission(&self, note_id: NoteId) -> anyhow::Result<Option<SavedSubmission>> {
        Ok(select_submissions(&self.connection, Some(note_id), None)?.pop())
    }

    /// The submissions still being sent, which recovery resumes.
    pub(crate) fn submissions_to_recover(&self) -> anyhow::Result<Vec<SavedSubmission>> {
        select_submissions(&self.connection, None, Some(SubmissionStatus::Submitting))
    }

    /// The submissions Circle accepted that are not final yet, which polling checks.
    pub(crate) fn submissions_to_poll(&self) -> anyhow::Result<Vec<SavedSubmission>> {
        select_submissions(&self.connection, None, Some(SubmissionStatus::Submitted))
    }

    /// Save the latest reply. Add a history event if the status, withdrawal ID, HTTP status, or
    /// error changed. Keep the signed request and any known withdrawal ID.
    pub(crate) fn update_submission_outcome(
        &mut self,
        outcome: &SavedSubmission,
    ) -> anyhow::Result<()> {
        validate_submission_outcome(outcome)?;
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let updated = transaction
            .execute(
                "UPDATE submissions SET status = ?1, withdrawal_id = ?2, hold_reason = ?3,
                last_http_status = ?4, last_response = ?5, last_error = ?6
             WHERE note_id = ?7",
                params![
                    outcome.status.as_ref(),
                    outcome.withdrawal_id,
                    outcome.hold_reason.map(HoldReason::as_str),
                    outcome.last_http_status,
                    outcome.last_response,
                    outcome.last_error,
                    outcome.note_id.to_bytes(),
                ],
            )
            .map_err(classify_error)?;
        ensure!(updated == 1, CONFLICT);
        if !repeats_latest_outcome(&transaction, outcome)? {
            record_event(&transaction, outcome.note_id, EventKind::Outcome)?;
        }
        transaction.commit().map_err(classify_error)
    }

    /// Puts a held withdrawal back to be sent, and records that in the burn's history. Its saved
    /// request and any known withdrawal ID stay, so recovery asks Circle for its status instead of
    /// posting it again once the ID is known.
    pub(crate) fn retry_held_submission(&mut self, note_id: NoteId) -> anyhow::Result<()> {
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let updated = transaction
            .execute(
                "UPDATE submissions SET status = ?2, hold_reason = NULL
             WHERE note_id = ?1 AND status = ?3 AND hold_reason = ?4",
                params![
                    note_id.to_bytes(),
                    SubmissionStatus::Submitting.as_ref(),
                    SubmissionStatus::Held.as_ref(),
                    HoldReason::HttpRejected.as_str()
                ],
            )
            .map_err(classify_error)?;
        ensure!(updated == 1, CONFLICT);
        record_event(&transaction, note_id, EventKind::OperatorRetry)?;
        transaction.commit().map_err(classify_error)
    }

    #[cfg(test)]
    pub(crate) fn discovered_burns(&self) -> anyhow::Result<Vec<DiscoveredBurn>> {
        load_burns(&self.connection, self.faucet_account_id, true)
    }

    /// Filters discovered burns by verified waiting depth.
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
    let (status, hold) = connection
        .query_row(
            "SELECT status, hold_reason FROM burns WHERE note_id = ?1",
            [note_id.to_bytes()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .map_err(classify_error)?;
    let previous = latest_reservation(connection, note_id)?;
    if previous.is_some_and(|(previous_amount, _)| previous_amount != amount) {
        bail!(CONFLICT);
    }
    if hold.is_some()
        || (status == CAP_REJECTED
            && inside_window(now_ms, previous.context(INVALID)?.1, window_ms))
    {
        return Ok(false);
    }

    // Count each burn once, at its latest reservation. A replacement or retry renews this burn's
    // existing charge.
    let mut statement = connection
        .prepare(&format!(
            "SELECT reservation.reservation_amount, reservation.admitted_at_ms
             FROM burns JOIN submission_events AS reservation
                ON reservation.seq = ({LATEST_RESERVATION})
             WHERE burns.note_id != ?1 AND burns.status != 'CAP_REJECTED'"
        ))
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

/// A burn's reservation against the withdrawal limit, from its history: the amount and admission
/// time of its latest row that sets one.
fn latest_reservation(
    connection: &rusqlite::Connection,
    note_id: NoteId,
) -> anyhow::Result<Option<(u64, i64)>> {
    connection
        .query_row(
            &format!(
                "SELECT reservation.reservation_amount, reservation.admitted_at_ms
                 FROM burns JOIN submission_events AS reservation
                    ON reservation.seq = ({LATEST_RESERVATION})
                 WHERE burns.note_id = ?1"
            ),
            [note_id.to_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(classify_error)
}

/// Writes the burn's copy of its reservation; the caller records the history row that holds it.
fn reserve_capacity(
    connection: &rusqlite::Connection,
    note_id: NoteId,
    amount: u64,
    admitted_at_ms: i64,
) -> anyhow::Result<()> {
    let updated = connection
        .execute(
            "UPDATE burns SET status = 'DISCOVERED', reservation_amount = ?2, admitted_at_ms = ?3
             WHERE note_id = ?1 AND status IN ('DISCOVERED', 'CAP_REJECTED')
                AND hold_reason IS NULL",
            params![note_id.to_bytes(), amount, admitted_at_ms],
        )
        .map_err(classify_error)?;
    ensure!(updated == 1, CONFLICT);
    Ok(())
}

/// Saves a signed request before it is sent, and records it in the burn's history. It can replace
/// only an expired withdrawal; any other saved submission, a failed one included, stays as it is.
fn save_submission(
    connection: &rusqlite::Connection,
    record: &SavedSubmission,
) -> anyhow::Result<()> {
    validate_submission(record)?;
    let written = connection
        .execute(
            "INSERT INTO submissions (
                note_id, endpoint, body, transfer_spec_hash, use_circle_forwarding, status
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (note_id) DO UPDATE SET
                endpoint = excluded.endpoint, body = excluded.body,
                transfer_spec_hash = excluded.transfer_spec_hash,
                use_circle_forwarding = excluded.use_circle_forwarding,
                status = ?6, withdrawal_id = NULL, hold_reason = NULL,
                last_http_status = NULL, last_response = NULL, last_error = NULL
             WHERE submissions.status = ?7 AND submissions.withdrawal_id IS NOT NULL",
            params![
                record.note_id.to_bytes(),
                record.endpoint.as_str(),
                record.body,
                record.transfer_spec_hash.as_slice(),
                record.use_circle_forwarding,
                SubmissionStatus::Submitting.as_ref(),
                SubmissionStatus::Expired.as_ref(),
            ],
        )
        .map_err(classify_write_error)?;
    ensure!(written == 1, CONFLICT);
    record_event(connection, record.note_id, EventKind::Authorized)
}

fn initialize_store(
    connection: &mut rusqlite::Connection,
    faucet_account_id: AccountId,
    initial_cursor: ScanCursor,
    trusted_anchor: TrustedAnchor,
) -> anyhow::Result<()> {
    let transaction = connection.transaction().map_err(classify_error)?;
    upgrade(&transaction, 0)?;
    transaction
        .execute(
            "INSERT INTO attester_state (
                singleton,
                faucet_account_id,
                anchor_block,
                anchor_commitment,
                scan_start,
                next_block,
                authenticated_parent
             ) VALUES (1, ?1, ?2, ?3, ?4, ?4, NULL)",
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

/// Brings an existing store to [`STORE_VERSION`] and checks it in one transaction, so a store that
/// fails a check, or an upgrade that fails part way, is left as it was. Returns the scan start the
/// store was created with.
fn open_existing(
    connection: &mut rusqlite::Connection,
    faucet_account_id: AccountId,
    trusted_anchor: TrustedAnchor,
) -> anyhow::Result<ScanCursor> {
    let transaction = connection.transaction().map_err(classify_error)?;
    let version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(classify_error)?;
    match version {
        STORE_VERSION => {}
        // A store written before stores had a version is not carried forward.
        0 => bail!(CANNOT_UPGRADE),
        _ if version > STORE_VERSION => {
            bail!("attester store version {version} is newer than this attester's {STORE_VERSION}")
        }
        _ => upgrade(&transaction, version)?,
    }
    let initial_cursor = validate_store(&transaction, faucet_account_id, trusted_anchor)?;
    transaction.commit().map_err(classify_error)?;
    Ok(initial_cursor)
}

/// Runs the migrations after `version` in order and records the new version.
fn upgrade(connection: &rusqlite::Connection, version: u32) -> anyhow::Result<()> {
    for sql in &MIGRATIONS[version as usize..] {
        connection.execute_batch(sql).map_err(classify_error)?;
    }
    set_version(connection)
}

/// Appends one row to a burn's history, recording the burn as it now stands: its status and hold
/// and, when it has one, its submission; only some kinds keep the request or the reservation.
/// History belongs to the burn, which is never deleted, so the burn must be one the store knows.
fn record_event(
    connection: &rusqlite::Connection,
    note_id: NoteId,
    kind: EventKind,
) -> anyhow::Result<()> {
    let recorded = connection
        .execute(
            "INSERT INTO submission_events (
                note_id, recorded_at, kind, status, withdrawal_id, body, transfer_spec_hash,
                http_status, response, error, endpoint, hold_reason, reservation_amount,
                admitted_at_ms, burn_status, burn_hold_reason
             )
             SELECT burns.note_id, unixepoch(), ?2, submissions.status,
                submissions.withdrawal_id, iif(?3, submissions.body, NULL),
                submissions.transfer_spec_hash, submissions.last_http_status,
                submissions.last_response, submissions.last_error,
                iif(?3, submissions.endpoint, NULL), submissions.hold_reason,
                iif(?4, burns.reservation_amount, NULL), iif(?4, burns.admitted_at_ms, NULL),
                burns.status, burns.hold_reason
             FROM burns LEFT JOIN submissions ON submissions.note_id = burns.note_id
             WHERE burns.note_id = ?1",
            params![
                note_id.to_bytes(),
                kind.as_ref(),
                kind.keeps_request(),
                kind.keeps_reservation()
            ],
        )
        .map_err(classify_error)?;
    ensure!(recorded == 1, CONFLICT);
    Ok(())
}

/// Return true if the latest outcome since authorization or operator retry matches the status,
/// withdrawal ID, HTTP status, and error. Record the first reply after an operator retry. Ignore
/// response body changes when those fields stay the same.
fn repeats_latest_outcome(
    connection: &rusqlite::Connection,
    outcome: &SavedSubmission,
) -> anyhow::Result<bool> {
    exists(
        connection,
        "SELECT EXISTS (SELECT 1 FROM submission_events
         WHERE seq = (SELECT MAX(seq) FROM submission_events
                WHERE note_id = ?1 AND kind = ?2 AND seq > (SELECT COALESCE(MAX(seq), 0)
                    FROM submission_events WHERE note_id = ?1 AND kind IN (?3, ?4)))
            AND status = ?5 AND withdrawal_id IS ?6 AND http_status IS ?7 AND error IS ?8)",
        params![
            outcome.note_id.to_bytes(),
            EventKind::Outcome.as_ref(),
            EventKind::Authorized.as_ref(),
            EventKind::OperatorRetry.as_ref(),
            outcome.status.as_ref(),
            outcome.withdrawal_id,
            outcome.last_http_status,
            outcome.last_error,
        ],
    )
}

fn set_version(connection: &rusqlite::Connection) -> anyhow::Result<()> {
    connection
        .pragma_update(None, "user_version", STORE_VERSION)
        .map_err(classify_error)
}

/// Checks an existing store and returns the scan start it was created with.
fn validate_store(
    connection: &rusqlite::Connection,
    faucet_account_id: AccountId,
    trusted_anchor: TrustedAnchor,
) -> anyhow::Result<ScanCursor> {
    validate_store_format(connection)?;

    // A saved withdrawal ID goes into a status URL, so each must still be a UUID.
    let mut statement = connection
        .prepare("SELECT withdrawal_id FROM submissions WHERE withdrawal_id IS NOT NULL")
        .map_err(classify_error)?;
    for id in statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(classify_error)?
    {
        ensure!(is_well_formed_id(&id.map_err(classify_error)?), INVALID);
    }

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

    let (stored_faucet, anchor_block, anchor_commitment, scan_start) = connection
        .query_row(
            "SELECT faucet_account_id, anchor_block, anchor_commitment, scan_start
             FROM attester_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
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
    let initial_cursor = ScanCursor {
        next_block: decode_block_number(scan_start)?,
    };
    if trusted_anchor.block_num > initial_cursor.next_block {
        bail!(INVALID);
    }
    let state = load_scan_state(connection, initial_cursor)?;
    load_candidates(connection, faucet_account_id, "", [])?;
    load_burns(connection, faucet_account_id, true)?;
    if state
        .authenticated_parent
        .as_ref()
        .is_some_and(|parent| parent.block_num() < trusted_anchor.block_num)
    {
        bail!(INVALID);
    }

    // Each burn's copy of its reservation must be the one its history holds.
    ensure!(
        !exists(
            connection,
            &format!(
                "SELECT EXISTS (SELECT 1 FROM burns
                 WHERE (reservation_amount, admitted_at_ms) IS NOT (
                    SELECT reservation_amount, admitted_at_ms FROM submission_events
                    WHERE seq = ({LATEST_RESERVATION})
                 ))"
            ),
            [],
        )?,
        INVALID
    );

    Ok(initial_cursor)
}

fn validate_store_format(connection: &rusqlite::Connection) -> anyhow::Result<()> {
    let quick_check = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .map_err(classify_error)?;
    if quick_check != "ok" {
        // SQLite names what it found, such as a failed CHECK constraint.
        return Err(anyhow!(quick_check).context(INVALID));
    }
    for probe in [
        "SELECT singleton, faucet_account_id, anchor_block, anchor_commitment, scan_start,
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

impl HoldReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::HttpRejected => "http_rejected",
        }
    }
}

/// Load saved submissions in note order. Apply `note_id` and `status` filters when supplied. Reject
/// the store if a selected row fails validation.
fn select_submissions(
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
            status.as_ref().map(SubmissionStatus::as_ref)
        ])
        .map_err(classify_error)?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(classify_error)? {
        let status: SubmissionStatus = row
            .get::<_, String>(5)
            .map_err(classify_error)?
            .parse()
            .context(INVALID)?;
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
            endpoint: Url::parse(&row.get::<_, String>(1).map_err(classify_error)?)
                .context(INVALID)?,
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
    let endpoint = &record.endpoint;
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
            .is_some_and(|id| !is_well_formed_id(id))
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
    include_submitted: bool,
) -> anyhow::Result<Vec<DiscoveredBurn>> {
    // Expired work is eligible again; its old request remains saved until a fresh one replaces it.
    let mut statement = connection
        .prepare(
            "SELECT note_id, nullifier, note, creation_block, consumption_block,
                    burn_tx_id FROM burns
             WHERE status = 'DISCOVERED' AND (?1 OR (
                 hold_reason IS NULL AND NOT EXISTS (
                     SELECT 1 FROM submissions WHERE submissions.note_id = burns.note_id
                        AND submissions.status != ?2
                 )
             ))
             ORDER BY creation_block, note_id",
        )
        .map_err(classify_error)?;
    let expired = SubmissionStatus::Expired.as_ref();
    let rows = statement
        .query_map(params![include_submitted, expired], |row| {
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
            "UPDATE burns SET consumption_block = ?2, burn_tx_id = ?3, status = ?4
             WHERE note_id = ?1 AND status = 'CANDIDATE'",
            params![note_id, consumption_block, burn_tx_id, DISCOVERED],
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

#[cfg(test)]
mod migration_tests;
