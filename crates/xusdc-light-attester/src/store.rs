//! Durable discovery state and the single-writer store boundary.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use alloy_primitives::B256;
use anyhow::{anyhow, bail, ensure, Context};
use miden_objects::prost::Message;
use miden_objects::{proto, DecodeMessageExt};
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::PublicOutputNote;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::Word;
use reqwest::Url;
use rusqlite::{params, OpenFlags, Params, Transaction};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

use crate::burn::{BurnCandidate, DiscoveredBurn};
use crate::circle::circle_message;
use crate::submission::{is_well_formed_id, HoldReason, SavedSubmission, SubmissionStatus};
use crate::verify::validate_saved_request;

/// Why a burn waits for an operator. The store keeps each reason as its fixed number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter)]
pub(crate) enum BurnHoldReason {
    PrepareRejected = 1,
    TooSmallToForward = 2,
}

impl BurnHoldReason {
    pub(crate) fn code(self) -> i64 {
        self as i64
    }

    /// The reason a stored number stands for.
    fn from_code(code: i64) -> Option<Self> {
        Self::iter().find(|reason| reason.code() == code)
    }
}

/// A held burn or held withdrawal as `release-holds` lists it: one line, the note ID first, so an
/// edited copy of the list can be passed back with `--note-ids-file`.
#[derive(Debug, PartialEq, Eq)]
pub struct Hold {
    pub note_id: NoteId,
    /// "burn" for a held burn, "withdrawal" for a held withdrawal.
    pub kind: &'static str,
    pub reason: String,
    pub http_status: Option<u16>,
    /// Circle's bounded, single-line message when the current hold has one.
    pub circle_message: Option<String>,
}

impl fmt::Display for Hold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}",
            self.note_id,
            self.kind,
            self.reason,
            self.http_status
                .map_or_else(|| "-".into(), |status| status.to_string()),
            self.circle_message.as_deref().unwrap_or("-")
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HoldEntry {
    pub(crate) note_id: String,
    pub(crate) kind: String,
    pub(crate) reason: String,
    pub(crate) http_status: Option<u16>,
    pub(crate) circle_message: Option<String>,
    pub(crate) event_seq: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct ReleaseSelection {
    pub(crate) note_id: NoteId,
    pub(crate) expected_event_seq: i64,
    pub(crate) circle_not_accepted: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReleaseError {
    #[error("invalid selection")]
    Invalid,
    #[error("hold changed since it was listed")]
    Conflict,
    #[error("check Circle before releasing a signed withdrawal")]
    CircleCheck,
    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

/// The store's migrations in order: running the first `n` brings a new store to version `n`. A
/// layout change adds its numbered file here, and [`STORE_VERSION`] follows.
const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_initial.sql"),
    include_str!("../migrations/0002_scan_from_the_anchor.sql"),
    include_str!("../migrations/0003_drop_unused_burn_columns.sql"),
];

/// The layout version this attester writes, kept in SQLite's `user_version`.
pub(crate) const STORE_VERSION: u32 = MIGRATIONS.len() as u32;
/// Why a store this attester cannot bring to [`STORE_VERSION`] is refused. It is left as it was.
pub(crate) const CANNOT_UPGRADE: &str = "attester store cannot be upgraded; start a new store";

/// What one row of a burn's history records. Each kind is stored under its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr)]
enum EventKind {
    /// A newly signed request, saved before it is sent.
    #[strum(serialize = "AUTHORIZED")]
    Authorized,
    /// Circle's answer, or a lost reply, when it changes the request's recorded state.
    #[strum(serialize = "OUTCOME")]
    Outcome,
    /// The burn was put on hold, for example because Circle refused to prepare it, and now waits
    /// for an operator.
    #[strum(serialize = "BURN_HELD")]
    BurnHeld,
    /// An operator released the burn's hold; the row keeps the hold's reason.
    #[strum(serialize = "BURN_RELEASED")]
    BurnReleased,
    /// An operator released a held request, which is deleted so that the burn is prepared and
    /// signed again.
    #[strum(serialize = "OPERATOR_RELEASE")]
    OperatorRelease,
}

impl EventKind {
    /// Whether the row keeps the signed request itself: only a new authorization does.
    fn keeps_request(self) -> bool {
        matches!(self, Self::Authorized)
    }
}

pub(crate) const INVALID: &str = "attester store is invalid";
pub(crate) const CONFLICT: &str = "authenticated evidence conflicts with the attester store";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustedAnchor {
    pub(crate) block_num: BlockNumber,
    pub(crate) commitment: Word,
}

/// The work the attester has not finished, as the alerts count it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Progress {
    /// Burns held before submission.
    pub(crate) burns_held: u64,
    /// Withdrawals held after Circle rejected them.
    pub(crate) withdrawals_held: u64,
    /// Withdrawals Circle reported as failed.
    pub(crate) withdrawals_failed: u64,
    /// Withdrawals being sent, or accepted by Circle and not final yet.
    pub(crate) withdrawals_pending: u64,
    /// Consumed burns that are not paid out yet, leaving out the held and failed ones.
    pub(crate) burns_unfinished: u64,
    /// The block that consumed the oldest unfinished burn.
    pub(crate) oldest_unfinished_burn: Option<BlockNumber>,
}

pub(crate) struct Store {
    connection: rusqlite::Connection,
    faucet_account_id: AccountId,
}

// SQLite is built into this binary with URI file names always on, so a path starting with "file:"
// would be read as a URI, and a URI can turn off locking. Starting a relative path with "./" makes
// SQLite read it as a plain file name.
fn plain_file_name(path: &Path) -> PathBuf {
    if path.is_relative() {
        Path::new(".").join(path)
    } else {
        path.to_owned()
    }
}

impl Store {
    /// Opens the store at `path`, or creates it there for this faucet and trusted anchor. A new
    /// store has no checkpoint until the anchor is saved as its first one.
    pub(crate) fn open_or_create(
        path: &Path,
        faucet_account_id: AccountId,
        trusted_anchor: TrustedAnchor,
    ) -> anyhow::Result<Self> {
        let path = plain_file_name(path);
        let exists = path.try_exists().context(INVALID)?;

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut connection =
            rusqlite::Connection::open_with_flags(path, flags).map_err(classify_error)?;
        lock_exclusively(&connection)?;

        if exists {
            open_existing(&mut connection, faucet_account_id, trusted_anchor)?;
        } else {
            initialize_store(&mut connection, faucet_account_id, trusted_anchor)?;
        }

        Ok(Self {
            connection,
            faucet_account_id,
        })
    }

    /// Opens an existing store without creating or initializing one.
    pub(crate) fn open_existing(
        path: &Path,
        faucet_account_id: AccountId,
        trusted_anchor: TrustedAnchor,
    ) -> anyhow::Result<Self> {
        let path = plain_file_name(path);
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut connection =
            rusqlite::Connection::open_with_flags(path, flags).map_err(classify_error)?;
        lock_exclusively(&connection)?;
        open_existing(&mut connection, faucet_account_id, trusted_anchor)?;

        Ok(Self {
            connection,
            faucet_account_id,
        })
    }

    /// The checkpoint: the header of the last authenticated block, which the next block is
    /// authenticated against. `None` until the trusted anchor is saved as the first one.
    pub(crate) fn checkpoint(&self) -> anyhow::Result<Option<BlockHeader>> {
        load_checkpoint(&self.connection)
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

    /// Saves a signed request before it is sent, and records it in the burn's history. It can
    /// replace only an expired withdrawal; any other saved submission, a failed one included, stays
    /// as it is.
    pub(crate) fn save_submission(&mut self, record: &SavedSubmission) -> anyhow::Result<()> {
        validate_submission(record)?;
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let written = transaction
            .execute(
                "INSERT INTO submissions (
                note_id, endpoint, body, transfer_spec_hash, status
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (note_id) DO UPDATE SET
                endpoint = excluded.endpoint, body = excluded.body,
                transfer_spec_hash = excluded.transfer_spec_hash,
                status = ?5, withdrawal_id = NULL, hold_reason = NULL,
                last_http_status = NULL, last_response = NULL, last_error = NULL
             WHERE submissions.status = ?6 AND submissions.withdrawal_id IS NOT NULL",
                params![
                    record.note_id.to_bytes(),
                    record.endpoint.as_str(),
                    record.body,
                    record.transfer_spec_hash.as_slice(),
                    SubmissionStatus::Submitting.as_ref(),
                    SubmissionStatus::Expired.as_ref(),
                ],
            )
            .map_err(classify_write_error)?;
        ensure!(written == 1, CONFLICT);
        record_event(&transaction, record.note_id, EventKind::Authorized, None)?;
        transaction.commit().map_err(classify_error)
    }

    /// Releases the named holds in one transaction, and returns how many burns and withdrawals it
    /// released. Each release is recorded in the burn's history first, so the history keeps the
    /// hold's reason. A note ID without a releasable hold fails the whole call, and nothing is
    /// released.
    pub(crate) fn release_holds(&mut self, note_ids: &[NoteId]) -> anyhow::Result<(usize, usize)> {
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let (mut burns, mut withdrawals) = (0, 0);
        // A burn named twice is released once.
        for note_id in note_ids.iter().copied().collect::<BTreeSet<_>>() {
            // Naming a withdrawal in the offline command confirms Circle did not accept it.
            let (burn, withdrawal) = Self::release_hold(&transaction, note_id, true)?
                .with_context(|| format!("note {note_id} has no releasable hold"))?;
            burns += burn;
            withdrawals += withdrawal;
        }
        transaction.commit().map_err(classify_error)?;
        Ok((burns, withdrawals))
    }

    pub(crate) fn release_checked(
        &mut self,
        selection: &ReleaseSelection,
    ) -> Result<(usize, usize), ReleaseError> {
        let note_id = selection.note_id;
        if selection.expected_event_seq <= 0 {
            return Err(ReleaseError::Invalid);
        }
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let note = note_id.to_bytes();
        let revision: Option<i64> = transaction
            .query_row(
                "SELECT MAX(seq) FROM submission_events WHERE note_id = ?1",
                [&note],
                |row| row.get(0),
            )
            .map_err(classify_error)?;
        let revision = match revision {
            Some(revision) => revision,
            // Holding a note writes a history row, so a note without one was never held: the
            // selection names no hold, rather than one that changed.
            None => {
                if exists(
                    &transaction,
                    "SELECT EXISTS (
                        SELECT 1 FROM burns WHERE note_id = ?1 AND hold_reason IS NOT NULL
                        UNION ALL
                        SELECT 1 FROM submissions WHERE note_id = ?1 AND status = ?2
                    )",
                    params![note, SubmissionStatus::Held.as_ref()],
                )? {
                    return Err(ReleaseError::Store(anyhow!(INVALID)));
                }
                return Err(ReleaseError::Invalid);
            }
        };
        // Only a revision that moved means the hold changed since it was listed.
        if revision != selection.expected_event_seq {
            return Err(ReleaseError::Conflict);
        }
        // Every change to a hold writes a history row, so at the listed revision a note with
        // nothing to release never had a releasable hold: the selection is wrong, and listing
        // again would not show it.
        let released = Self::release_hold(&transaction, note_id, selection.circle_not_accepted)?
            .ok_or(ReleaseError::Invalid)?;
        transaction.commit().map_err(classify_error)?;
        Ok(released)
    }

    /// Releases the note's hold and returns how many burns and withdrawals it released, or `None`
    /// when the note has nothing to release. What that means is the caller's to say: on the live
    /// path a selection that names no hold, offline a note the operator should not have named.
    fn release_hold(
        transaction: &Transaction<'_>,
        note_id: NoteId,
        circle_not_accepted: bool,
    ) -> Result<Option<(usize, usize)>, ReleaseError> {
        let note = note_id.to_bytes();
        let held = params![
            note,
            SubmissionStatus::Held.as_ref(),
            HoldReason::HttpRejected.as_ref()
        ];
        if exists(
            transaction,
            "SELECT EXISTS (SELECT 1 FROM burns
                 WHERE note_id = ?1 AND hold_reason IS NOT NULL)",
            [&note],
        )? {
            record_event(transaction, note_id, EventKind::BurnReleased, None)?;
            let burns = transaction
                .execute(
                    "UPDATE burns SET hold_reason = NULL WHERE note_id = ?1",
                    [&note],
                )
                .map_err(classify_error)?;
            Ok(Some((burns, 0)))
        } else if exists(
            transaction,
            "SELECT EXISTS (SELECT 1 FROM submissions WHERE note_id = ?1 AND status = ?2
                    AND hold_reason = ?3 AND withdrawal_id IS NULL)",
            held,
        )? {
            if !circle_not_accepted {
                return Err(ReleaseError::CircleCheck);
            }
            // Release only after checking this withdrawal with Circle. Remove the saved
            // request so the next cycle can prepare and sign again. An expired signed request
            // cannot be reused.
            record_event(transaction, note_id, EventKind::OperatorRelease, None)?;
            let deleted = transaction
                .execute("DELETE FROM submissions WHERE note_id = ?1", [&note])
                .map_err(classify_error)?;
            if deleted != 1 {
                return Err(ReleaseError::Store(anyhow!(CONFLICT)));
            }
            Ok(Some((0, 1)))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn holds_page(&self, after: Option<NoteId>) -> anyhow::Result<Vec<HoldEntry>> {
        let mut statement = self.connection.prepare(
            "SELECT note_id, kind, burn_reason, withdrawal_reason, http_status, response,
                (SELECT MAX(seq) FROM submission_events WHERE note_id = holds.note_id) AS revision
             FROM (
                SELECT b.note_id, 'burn' AS kind, b.hold_reason AS burn_reason,
                    NULL AS withdrawal_reason,
                    CASE WHEN e.status IS NULL THEN e.http_status END AS http_status,
                    CASE WHEN e.status IS NULL THEN e.response END AS response
                FROM burns b LEFT JOIN submission_events e ON e.seq = (
                    SELECT MAX(seq) FROM submission_events WHERE note_id = b.note_id AND kind = 'BURN_HELD'
                ) WHERE b.hold_reason IS NOT NULL
                UNION ALL
                SELECT note_id, 'withdrawal', NULL, hold_reason, last_http_status, last_response
                FROM submissions WHERE status = ?2
             ) holds WHERE (?1 IS NULL OR note_id > ?1) ORDER BY note_id LIMIT 101"
        ).map_err(classify_error)?;
        let mut rows = statement
            .query(params![
                after.map(|id| id.to_bytes()),
                SubmissionStatus::Held.as_ref()
            ])
            .map_err(classify_error)?;
        let mut holds = Vec::new();
        while let Some(row) = rows.next().map_err(classify_error)? {
            let kind: String = row.get(1).map_err(classify_error)?;
            let reason = if kind == "burn" {
                format!(
                    "{:?}",
                    BurnHoldReason::from_code(row.get(2).map_err(classify_error)?)
                        .context(INVALID)?
                )
            } else {
                let reason: Option<String> = row.get(3).map_err(classify_error)?;
                reason
                    .map(|reason| {
                        reason
                            .parse::<HoldReason>()
                            .map(|reason| format!("{reason:?}"))
                            .map_err(|_| anyhow!(INVALID))
                    })
                    .transpose()?
                    .unwrap_or_else(|| "-".into())
            };
            let response: Option<Vec<u8>> = row.get(5).map_err(classify_error)?;
            let event_seq: i64 = row
                .get::<_, Option<i64>>(6)
                .map_err(classify_error)?
                .context(INVALID)?;
            ensure!(event_seq > 0, INVALID);
            holds.push(HoldEntry {
                note_id: decode_canonical::<NoteId>(
                    &row.get::<_, Vec<u8>>(0).map_err(classify_error)?,
                )?
                .to_string(),
                kind,
                reason,
                http_status: row.get(4).map_err(classify_error)?,
                circle_message: response.as_deref().and_then(one_line_circle_message).map(
                    |message| {
                        // The live client prints this external text in an operator's terminal.
                        message
                            .chars()
                            .filter(|character| !character.is_control())
                            .collect()
                    },
                ),
                event_seq,
            });
        }
        Ok(holds)
    }

    /// Every held burn and held withdrawal: burns first, each group in note order.
    pub(crate) fn holds(&self) -> anyhow::Result<Vec<Hold>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT burns.note_id, burns.hold_reason, held.status,
                    held.http_status, held.response
                 FROM burns
                 LEFT JOIN submission_events AS held ON held.seq = (
                    SELECT MAX(seq) FROM submission_events
                    WHERE note_id = burns.note_id AND kind = 'BURN_HELD'
                 )
                 WHERE burns.hold_reason IS NOT NULL
                 ORDER BY burns.note_id",
            )
            .map_err(classify_error)?;
        let mut rows = statement.query([]).map_err(classify_error)?;
        let mut holds = Vec::new();
        while let Some(row) = rows.next().map_err(classify_error)? {
            let reason =
                BurnHoldReason::from_code(row.get(1).map_err(classify_error)?).context(INVALID)?;
            let old_submission_snapshot = row
                .get::<_, Option<String>>(2)
                .map_err(classify_error)?
                .is_some();
            let (http_status, circle_message) = if old_submission_snapshot {
                (None, None)
            } else {
                let response: Option<Vec<u8>> = row.get(4).map_err(classify_error)?;
                (
                    row.get(3).map_err(classify_error)?,
                    response.as_deref().and_then(one_line_circle_message),
                )
            };
            holds.push(Hold {
                note_id: decode_canonical(&row.get::<_, Vec<u8>>(0).map_err(classify_error)?)?,
                kind: "burn",
                reason: format!("{reason:?}"),
                http_status,
                circle_message,
            });
        }
        for held in select_submissions(&self.connection, None, Some(SubmissionStatus::Held))? {
            holds.push(Hold {
                note_id: held.note_id,
                kind: "withdrawal",
                reason: held
                    .hold_reason
                    .map_or_else(|| "-".into(), |reason| format!("{reason:?}")),
                http_status: held.last_http_status,
                circle_message: held
                    .last_response
                    .as_deref()
                    .and_then(one_line_circle_message),
            });
        }
        Ok(holds)
    }

    pub(crate) fn hold_burn(
        &mut self,
        note_id: NoteId,
        reason: BurnHoldReason,
        response: Option<(u16, &[u8])>,
    ) -> anyhow::Result<()> {
        let transaction = self.connection.transaction().map_err(classify_error)?;
        let updated = transaction
            .execute(
                "UPDATE burns SET hold_reason = ?2
                 WHERE note_id = ?1",
                params![note_id.to_bytes(), reason.code()],
            )
            .map_err(classify_error)?;
        ensure!(updated == 1, CONFLICT);
        let (http_status, response) = match response {
            Some((status, body)) => (Some(status), Some(body)),
            None => (None, None),
        };
        let recorded = transaction
            .execute(
                "INSERT INTO submission_events (
                    note_id, recorded_at, kind, http_status, response, burn_hold_reason
                 ) VALUES (?1, unixepoch(), ?2, ?3, ?4, ?5)",
                params![
                    note_id.to_bytes(),
                    EventKind::BurnHeld.as_ref(),
                    http_status,
                    response,
                    reason.code()
                ],
            )
            .map_err(classify_error)?;
        ensure!(recorded == 1, CONFLICT);
        transaction.commit().map_err(classify_error)
    }

    /// The saved submission for `note_id`, if there is one.
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

    /// Save the latest reply. Add a history event if the status, withdrawal ID, HTTP status,
    /// error, or the status Circle reports changed. Keep the signed request and any known withdrawal ID.
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
                    outcome.hold_reason.as_ref().map(HoldReason::as_ref),
                    outcome.last_http_status,
                    outcome.last_response,
                    outcome.last_error,
                    outcome.note_id.to_bytes(),
                ],
            )
            .map_err(classify_error)?;
        ensure!(updated == 1, CONFLICT);
        let circle_status = circle_status(outcome.last_response.as_deref());
        if !repeats_latest_outcome(&transaction, outcome, circle_status.as_deref())? {
            record_event(
                &transaction,
                outcome.note_id,
                EventKind::Outcome,
                circle_status.as_deref(),
            )?;
        }
        transaction.commit().map_err(classify_error)
    }

    /// The note's latest history row, which is the revision a release selection names.
    #[cfg(test)]
    pub(crate) fn revision(&self, note_id: NoteId) -> anyhow::Result<Option<i64>> {
        self.connection
            .query_row(
                "SELECT MAX(seq) FROM submission_events WHERE note_id = ?1",
                [note_id.to_bytes()],
                |row| row.get(0),
            )
            .map_err(classify_error)
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
        let Some(checkpoint) = self.checkpoint()? else {
            return Ok(Vec::new());
        };
        let Some(last_depth_safe_block) = checkpoint.block_num().checked_sub(minimum_depth_blocks)
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

    /// The held, failed, pending and unfinished work, in one read.
    pub(crate) fn progress(&self) -> anyhow::Result<Progress> {
        // An unfinished burn was consumed and is not held, and its withdrawal, if it has one, is
        // neither final nor held nor failed. Expired work counts, since it is prepared again.
        self.connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM burns WHERE hold_reason IS NOT NULL),
                    (SELECT COUNT(*) FROM submissions WHERE status = ?1),
                    (SELECT COUNT(*) FROM submissions WHERE status = ?2),
                    (SELECT COUNT(*) FROM submissions WHERE status IN (?3, ?4)),
                    COUNT(*),
                    MIN(burns.consumption_block)
                 FROM burns LEFT JOIN submissions ON submissions.note_id = burns.note_id
                 WHERE burns.consumption_block IS NOT NULL AND burns.hold_reason IS NULL
                    AND (submissions.status IS NULL OR submissions.status NOT IN (?1, ?2, ?5))",
                params![
                    SubmissionStatus::Held.as_ref(),
                    SubmissionStatus::Failed.as_ref(),
                    SubmissionStatus::Submitting.as_ref(),
                    SubmissionStatus::Submitted.as_ref(),
                    SubmissionStatus::Finalized.as_ref(),
                ],
                |row| {
                    Ok(Progress {
                        burns_held: row.get(0)?,
                        withdrawals_held: row.get(1)?,
                        withdrawals_failed: row.get(2)?,
                        withdrawals_pending: row.get(3)?,
                        burns_unfinished: row.get(4)?,
                        oldest_unfinished_burn: row
                            .get::<_, Option<u32>>(5)?
                            .map(BlockNumber::from),
                    })
                },
            )
            .map_err(classify_error)
    }

    /// Saves one authenticated block: the burn candidates and burns found in it, and its header
    /// as the new checkpoint.
    pub(crate) fn save_scan_progress(
        &mut self,
        candidates: &[BurnCandidate],
        burns: &[DiscoveredBurn],
        checkpoint: &BlockHeader,
    ) -> anyhow::Result<()> {
        validate_discovery_records(candidates, burns, checkpoint.block_num())?;

        // One block's evidence and its verified header commit as one unit. A crash therefore
        // either records that complete block or scans it again from the previous checkpoint.
        let transaction = self.connection.transaction().map_err(classify_error)?;

        for candidate in candidates {
            insert_candidate(&transaction, candidate)?;
        }
        for burn in burns {
            insert_burn(&transaction, burn)?;
        }

        let updated = transaction
            .execute(
                "UPDATE attester_state SET checkpoint = ?1 WHERE singleton = 1",
                [proto::blockchain::BlockHeader::from(checkpoint).encode_to_vec()],
            )
            .map_err(classify_error)?;
        if updated != 1 {
            bail!(INVALID);
        }

        transaction.commit().map_err(classify_error)
    }
}

fn one_line_circle_message(response: &[u8]) -> Option<String> {
    circle_message(response).map(|message| message.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Keeps the exclusive connection lock for the store's lifetime so a second process cannot create
/// a competing cursor or submission queue.
fn lock_exclusively(connection: &rusqlite::Connection) -> anyhow::Result<()> {
    connection
        .busy_timeout(Duration::ZERO)
        .map_err(classify_error)?;
    connection
        .pragma_update(None, "locking_mode", "EXCLUSIVE")
        .map_err(classify_error)?;
    connection
        .execute_batch("BEGIN EXCLUSIVE; COMMIT;")
        .map_err(classify_error)
}

fn initialize_store(
    connection: &mut rusqlite::Connection,
    faucet_account_id: AccountId,
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
                checkpoint
             ) VALUES (1, ?1, ?2, ?3, NULL)",
            params![
                faucet_account_id.to_bytes(),
                i64::from(trusted_anchor.block_num.as_u32()),
                trusted_anchor.commitment.to_bytes(),
            ],
        )
        .map_err(classify_error)?;
    transaction.commit().map_err(classify_error)
}

/// Brings an existing store to [`STORE_VERSION`] and checks it in one transaction, so a store that
/// fails a check, or an upgrade that fails part way, is left as it was.
fn open_existing(
    connection: &mut rusqlite::Connection,
    faucet_account_id: AccountId,
    trusted_anchor: TrustedAnchor,
) -> anyhow::Result<()> {
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
    validate_store(&transaction, faucet_account_id, trusted_anchor)?;
    transaction.commit().map_err(classify_error)
}

/// Runs the migrations after `version` in order and records the new version.
fn upgrade(connection: &rusqlite::Connection, version: u32) -> anyhow::Result<()> {
    for sql in &MIGRATIONS[version as usize..] {
        connection.execute_batch(sql).map_err(classify_error)?;
    }
    set_version(connection)
}

/// The status Circle reports in a withdrawal reply, when the reply has one. Several of Circle's
/// statuses are saved as one submission status, so the history keeps Circle's own word too. A
/// request is answered with a list of one withdrawal, and a status check with the withdrawal.
fn circle_status(response: Option<&[u8]>) -> Option<String> {
    let reply: serde_json::Value = serde_json::from_slice(response?).ok()?;
    let withdrawal = reply.get(0).unwrap_or(&reply);
    withdrawal.get("status")?.as_str().map(str::to_owned)
}

/// Appends one row to a burn's history, recording the burn as it now stands: its hold and, when it
/// has one, its submission; only some kinds keep the request, and only an outcome has a status
/// reported by Circle.
/// History belongs to the burn, which is never deleted, so the burn must be one the store knows.
fn record_event(
    connection: &rusqlite::Connection,
    note_id: NoteId,
    kind: EventKind,
    circle_status: Option<&str>,
) -> anyhow::Result<()> {
    let recorded = connection
        .execute(
            "INSERT INTO submission_events (
                note_id, recorded_at, kind, status, withdrawal_id, body, transfer_spec_hash,
                http_status, response, error, endpoint, hold_reason, burn_hold_reason, circle_status
             )
             SELECT burns.note_id, unixepoch(), ?2, submissions.status,
                submissions.withdrawal_id, iif(?3, submissions.body, NULL),
                submissions.transfer_spec_hash, submissions.last_http_status,
                submissions.last_response, submissions.last_error,
                iif(?3, submissions.endpoint, NULL), submissions.hold_reason, burns.hold_reason, ?4
             FROM burns LEFT JOIN submissions ON submissions.note_id = burns.note_id
             WHERE burns.note_id = ?1",
            params![
                note_id.to_bytes(),
                kind.as_ref(),
                kind.keeps_request(),
                circle_status
            ],
        )
        .map_err(classify_error)?;
    ensure!(recorded == 1, CONFLICT);
    Ok(())
}

/// Return true if the latest outcome since authorization matches the status, withdrawal ID, HTTP
/// status, error, and the status Circle reports. Ignore other response body changes when those
/// fields stay the same.
fn repeats_latest_outcome(
    connection: &rusqlite::Connection,
    outcome: &SavedSubmission,
    circle_status: Option<&str>,
) -> anyhow::Result<bool> {
    exists(
        connection,
        "SELECT EXISTS (SELECT 1 FROM submission_events
         WHERE seq = (SELECT MAX(seq) FROM submission_events
                WHERE note_id = ?1 AND kind = ?2 AND seq > (SELECT COALESCE(MAX(seq), 0)
                    FROM submission_events WHERE note_id = ?1 AND kind = ?3))
            AND status = ?4 AND withdrawal_id IS ?5 AND http_status IS ?6 AND error IS ?7
            AND circle_status IS ?8)",
        params![
            outcome.note_id.to_bytes(),
            EventKind::Outcome.as_ref(),
            EventKind::Authorized.as_ref(),
            outcome.status.as_ref(),
            outcome.withdrawal_id,
            outcome.last_http_status,
            outcome.last_error,
            circle_status,
        ],
    )
}

fn set_version(connection: &rusqlite::Connection) -> anyhow::Result<()> {
    connection
        .pragma_update(None, "user_version", STORE_VERSION)
        .map_err(classify_error)
}

/// Checks an existing store against the configured faucet and trusted anchor.
fn validate_store(
    connection: &rusqlite::Connection,
    faucet_account_id: AccountId,
    trusted_anchor: TrustedAnchor,
) -> anyhow::Result<()> {
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
    let checkpoint = load_checkpoint(connection)?;
    load_candidates(connection, faucet_account_id, "", [])?;
    load_burns(connection, faucet_account_id, true)?;
    if checkpoint.is_some_and(|checkpoint| checkpoint.block_num() < trusted_anchor.block_num) {
        bail!(INVALID);
    }

    Ok(())
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
        "SELECT singleton, faucet_account_id, anchor_block, anchor_commitment, checkpoint
            FROM attester_state LIMIT 0",
        "SELECT note_id, nullifier, note, creation_block, consumption_block, hold_reason
            FROM burns LIMIT 0",
        "SELECT note_id, endpoint, body, transfer_spec_hash, status, withdrawal_id,
            hold_reason, last_http_status, last_response, last_error FROM submissions LIMIT 0",
        "SELECT seq, note_id, recorded_at, kind, status, withdrawal_id, body, transfer_spec_hash,
            http_status, response, error, endpoint, hold_reason, burn_hold_reason, circle_status
            FROM submission_events LIMIT 0",
    ] {
        connection.prepare(probe).map_err(classify_error)?;
    }

    Ok(())
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
            status, withdrawal_id, hold_reason,
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
            .get::<_, String>(4)
            .map_err(classify_error)?
            .parse()
            .context(INVALID)?;
        let hold_reason: Option<HoldReason> = row
            .get::<_, Option<String>>(6)
            .map_err(classify_error)?
            .map(|reason| reason.parse())
            .transpose()
            .context(INVALID)?;
        let record = SavedSubmission {
            note_id: decode_canonical(&row.get::<_, Vec<u8>>(0).map_err(classify_error)?)?,
            endpoint: Url::parse(&row.get::<_, String>(1).map_err(classify_error)?)
                .context(INVALID)?,
            body: row.get(2).map_err(classify_error)?,
            transfer_spec_hash: B256::from(row.get::<_, [u8; 32]>(3).map_err(classify_error)?),
            status,
            withdrawal_id: row.get(5).map_err(classify_error)?,
            hold_reason,
            last_http_status: row.get(7).map_err(classify_error)?,
            last_response: row.get(8).map_err(classify_error)?,
            last_error: row.get(9).map_err(classify_error)?,
        };
        validate_submission(&record)?;
        if !exists(
            connection,
            "SELECT EXISTS (SELECT 1 FROM burns
             WHERE note_id = ?1 AND consumption_block IS NOT NULL)",
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

fn load_checkpoint(connection: &rusqlite::Connection) -> anyhow::Result<Option<BlockHeader>> {
    connection
        .query_row(
            "SELECT checkpoint FROM attester_state WHERE singleton = 1",
            [],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .map_err(classify_error)?
        .as_deref()
        .map(decode_header)
        .transpose()
}

/// Nothing saved with a block can come from a later one, and a burn is consumed after it is
/// created.
fn validate_discovery_records(
    candidates: &[BurnCandidate],
    burns: &[DiscoveredBurn],
    block: BlockNumber,
) -> anyhow::Result<()> {
    if candidates
        .iter()
        .any(|candidate| candidate.creation_block() > block)
        || burns.iter().any(|burn| {
            burn.creation_block() >= burn.consumption_block() || burn.consumption_block() > block
        })
    {
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
             FROM burns WHERE consumption_block IS NULL {filter}
             ORDER BY creation_block, note_id"
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
            "SELECT note_id, nullifier, note, creation_block, consumption_block FROM burns
             WHERE consumption_block IS NOT NULL AND (?1 OR (
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
            ))
        })
        .map_err(classify_error)?;

    let mut burns = Vec::new();
    for row in rows {
        let (note_id, nullifier, note, creation_block, consumption_block) =
            row.map_err(classify_error)?;
        let note = decode_note(&note, &note_id, &nullifier)?;
        let creation_block = decode_block_number(creation_block)?;
        let consumption_block = decode_block_number(consumption_block)?;
        burns.push(
            DiscoveredBurn::new(note, creation_block, consumption_block, faucet_account_id)
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
            "INSERT INTO burns (note_id, nullifier, note, creation_block)
             VALUES (?1, ?2, ?3, ?4)",
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

    // Promotion turns the exact saved candidate into this burn in place, one row per note.
    let promoted = transaction
        .execute(
            "UPDATE burns SET consumption_block = ?2
             WHERE note_id = ?1 AND consumption_block IS NULL",
            params![note_id, consumption_block],
        )
        .map_err(classify_write_error)?;
    if promoted == 1 {
        return Ok(());
    }

    // Any other record of this note or its nullifier clashes with the table's keys.
    transaction
        .execute(
            "INSERT INTO burns (note_id, nullifier, note, creation_block, consumption_block)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![note_id, nullifier, note, creation_block, consumption_block],
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
