//! Immutable withdrawal snapshots and durable progress for each export destination.

use anyhow::{ensure, Context};
use miden_protocol::note::NoteId;
use rusqlite::{params, OptionalExtension};

use super::{classify_error, decode_canonical, exists, Store, CONFLICT, INVALID};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportRecord {
    pub(crate) note_id: NoteId,
    pub(crate) withdrawal_id: Option<String>,
    pub(crate) revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportBatch {
    pub(crate) after: i64,
    pub(crate) records: Vec<ExportRecord>,
}

impl Store {
    /// The newest authorization or outcome for each changed note, oldest revision first.
    /// A destination without a cursor includes finalized withdrawals from the complete history.
    pub(crate) fn export_batch(
        &self,
        destination: &str,
        limit: usize,
    ) -> anyhow::Result<ExportBatch> {
        ensure!(
            !destination.is_empty(),
            "export destination must not be empty"
        );
        ensure!(limit > 0, "export batch limit must be positive");
        let limit = i64::try_from(limit).context("export batch limit is too large")?;
        let after = self
            .connection
            .query_row(
                "SELECT after_seq FROM withdrawal_export_cursors WHERE destination = ?1",
                [destination],
                |row| row.get(0),
            )
            .optional()
            .map_err(classify_error)?
            .unwrap_or(0);
        let mut statement = self
            .connection
            .prepare(
                "SELECT event.note_id, event.withdrawal_id, event.seq
                 FROM submission_events event
                 WHERE event.seq > ?1 AND event.kind IN ('AUTHORIZED', 'OUTCOME')
                    AND NOT EXISTS (
                        SELECT 1 FROM submission_events newer
                        WHERE newer.note_id = event.note_id AND newer.seq > event.seq
                            AND newer.kind IN ('AUTHORIZED', 'OUTCOME')
                    )
                 ORDER BY event.seq LIMIT ?2",
            )
            .map_err(classify_error)?;
        let mut rows = statement
            .query(params![after, limit])
            .map_err(classify_error)?;
        let mut records = Vec::new();
        while let Some(row) = rows.next().map_err(classify_error)? {
            let withdrawal_id: Option<String> = row.get(1).map_err(classify_error)?;
            ensure!(
                withdrawal_id
                    .as_deref()
                    .is_none_or(super::is_well_formed_id),
                INVALID
            );
            records.push(ExportRecord {
                note_id: decode_canonical(&row.get::<_, Vec<u8>>(0).map_err(classify_error)?)?,
                withdrawal_id,
                revision: row.get(2).map_err(classify_error)?,
            });
        }
        Ok(ExportBatch { after, records })
    }

    /// Acknowledge the last record in the worker's contiguous successful prefix. Use its snapshot
    /// revision, so changes written while the batch was in flight remain pending.
    pub(crate) fn ack_export(
        &mut self,
        destination: &str,
        expected: i64,
        completed: i64,
    ) -> anyhow::Result<()> {
        ensure!(
            !destination.is_empty(),
            "export destination must not be empty"
        );
        ensure!(expected >= 0 && completed > expected, CONFLICT);
        let transaction = self.connection.transaction().map_err(classify_error)?;
        ensure!(
            exists(
                &transaction,
                "SELECT EXISTS (SELECT 1 FROM submission_events
                 WHERE seq = ?1 AND kind IN ('AUTHORIZED', 'OUTCOME'))",
                [completed],
            )?,
            CONFLICT
        );
        transaction
            .execute(
                "INSERT INTO withdrawal_export_cursors (destination, after_seq) VALUES (?1, 0)
                 ON CONFLICT (destination) DO NOTHING",
                [destination],
            )
            .map_err(classify_error)?;
        let updated = transaction
            .execute(
                "UPDATE withdrawal_export_cursors SET after_seq = ?3
                 WHERE destination = ?1 AND after_seq = ?2",
                params![destination, expected, completed],
            )
            .map_err(classify_error)?;
        ensure!(updated == 1, CONFLICT);
        transaction.commit().map_err(classify_error)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use miden_protocol::account::AccountId;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::block::{BlockHeader, BlockNumber};
    use miden_protocol::note::{Note, NoteAttachment};
    use miden_protocol::transaction::{OutputNote, RawOutputNote};
    use miden_protocol::utils::serde::Serializable;
    use miden_protocol::{Felt, Word};
    use miden_standards::note::BurnNote;
    use miden_usdcx::note::xreserve_burn::XUsdcBurnAttachment;
    use miden_usdcx::xreserve::encoding::{CircleDomain, ForeignChainAddress, XReserveBurnItems};
    use reqwest::Url;

    use super::*;
    use crate::burn::BurnCandidate;
    use crate::store::{record_event, BurnHoldReason, EventKind, TrustedAnchor, STORE_VERSION};
    use crate::submission::{HoldReason, SavedSubmission, SubmissionStatus};

    const DESTINATION: &str = "s3://exports/withdrawals/";
    const OLD_ID: &str = "6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e70";
    const NEW_ID: &str = "6149dc3d-71bf-4d57-8cc1-5e2d4c0a8e71";

    fn faucet() -> AccountId {
        AccountId::from_hex("0xbb405fd9fe431bd1135a292de098cb").unwrap()
    }

    fn anchor() -> TrustedAnchor {
        TrustedAnchor {
            block_num: BlockNumber::GENESIS,
            commitment: Word::empty(),
        }
    }

    fn open(path: &std::path::Path) -> Store {
        Store::open_or_create(path, faucet(), anchor()).unwrap()
    }

    fn add_burn(store: &mut Store, serial: u64) -> NoteId {
        let withdrawal = XUsdcBurnAttachment::new(XReserveBurnItems {
            dest_domain: CircleDomain::new(9),
            dest_recipient: ForeignChainAddress::new([0xab; 32]),
        });
        let note: Note = BurnNote::builder()
            .sender(faucet())
            .asset(FungibleAsset::new(faucet(), 100).unwrap())
            .serial_number(Word::new([
                Felt::new(serial).unwrap(),
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
            ]))
            .attachment(NoteAttachment::from(&withdrawal))
            .build()
            .unwrap()
            .into();
        let OutputNote::Public(note) = RawOutputNote::Full(note).into_output_note().unwrap() else {
            panic!("the burn fixture is public")
        };
        let burn = BurnCandidate::new(note, 1u32.into(), faucet())
            .unwrap()
            .into_discovered(2u32.into());
        let note_id = burn.note_id();
        store
            .save_scan_progress(&[], &[burn], &BlockHeader::mock(2u32, None, None, &[]))
            .unwrap();
        note_id
    }

    fn event(store: &Store, note_id: NoteId, kind: &str, id: Option<&str>) -> i64 {
        store
            .connection
            .execute(
                "INSERT INTO submission_events (note_id, recorded_at, kind, withdrawal_id)
                 VALUES (?1, 0, ?2, ?3)",
                params![note_id.to_bytes(), kind, id],
            )
            .unwrap();
        store.connection.last_insert_rowid()
    }

    fn record(note_id: NoteId, id: Option<&str>, revision: i64) -> ExportRecord {
        ExportRecord {
            note_id,
            withdrawal_id: id.map(str::to_owned),
            revision,
        }
    }

    fn seed_submission(store: &Store, note_id: NoteId) -> SavedSubmission {
        let saved = SavedSubmission {
            note_id,
            endpoint: Url::parse("https://circle.invalid/v1/withdraw").unwrap(),
            body: vec![1],
            transfer_spec_hash: B256::ZERO,
            status: SubmissionStatus::Submitting,
            withdrawal_id: None,
            hold_reason: None,
            last_http_status: None,
            last_response: None,
            last_error: None,
        };
        // Export tests need persisted snapshots, without constructing or signing a request.
        store
            .connection
            .execute(
                "INSERT INTO submissions (note_id, endpoint, body, transfer_spec_hash, status)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    note_id.to_bytes(),
                    saved.endpoint.as_str(),
                    saved.body,
                    saved.transfer_spec_hash.as_slice(),
                    saved.status.as_ref(),
                ],
            )
            .unwrap();
        record_event(&store.connection, note_id, EventKind::Authorized, None).unwrap();
        saved
    }

    fn table_contents(store: &Store, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
        let mut statement = store
            .connection
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
            .unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get(column))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap();
        rows.map(Result::unwrap).collect()
    }

    #[test]
    fn coalesces_latest_relevant_history_rows_in_bounded_revision_order() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("store.sqlite3"));
        let first = add_burn(&mut store, 1);
        let second = add_burn(&mut store, 2);
        let third = add_burn(&mut store, 3);
        event(&store, first, "AUTHORIZED", None);
        event(&store, first, "OUTCOME", Some(OLD_ID));
        let second_revision = event(&store, second, "AUTHORIZED", None);
        let first_revision = event(&store, first, "OUTCOME", Some(NEW_ID));
        event(&store, first, "BURN_HELD", Some(OLD_ID));
        let third_revision = event(&store, third, "OUTCOME", Some(OLD_ID));
        event(&store, second, "OPERATOR_RELEASE", Some(NEW_ID));

        let batch = store.export_batch(DESTINATION, 2).unwrap();
        assert_eq!(
            batch,
            ExportBatch {
                after: 0,
                records: vec![
                    record(second, None, second_revision),
                    record(first, Some(NEW_ID), first_revision),
                ],
            }
        );
        store
            .ack_export(DESTINATION, batch.after, first_revision)
            .unwrap();
        assert_eq!(
            store.export_batch(DESTINATION, 2).unwrap(),
            ExportBatch {
                after: first_revision,
                records: vec![record(third, Some(OLD_ID), third_revision)],
            }
        );
    }

    #[test]
    fn authorization_clears_an_old_id_and_a_later_outcome_replaces_it() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("store.sqlite3"));
        let note = add_burn(&mut store, 1);
        let old_revision = event(&store, note, "OUTCOME", Some(OLD_ID));
        let old_snapshot = store.export_batch(DESTINATION, 1).unwrap();
        store.ack_export(DESTINATION, 0, old_revision).unwrap();
        let null_revision = event(&store, note, "AUTHORIZED", None);
        let null_snapshot = store.export_batch(DESTINATION, 1).unwrap();
        assert_eq!(null_snapshot.records, [record(note, None, null_revision)]);
        store
            .ack_export(DESTINATION, old_revision, null_revision)
            .unwrap();
        let new_revision = event(&store, note, "OUTCOME", Some(NEW_ID));
        assert_eq!(
            store.export_batch(DESTINATION, 1).unwrap().records,
            [record(note, Some(NEW_ID), new_revision)]
        );
        assert_eq!(
            old_snapshot.records,
            [record(note, Some(OLD_ID), old_revision)]
        );
        assert_eq!(null_snapshot.records, [record(note, None, null_revision)]);
    }

    #[test]
    fn old_snapshot_ack_leaves_newer_null_and_replacement_events_pending() {
        for replacement in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let mut store = open(&directory.path().join("store.sqlite3"));
            let note = add_burn(&mut store, 1);
            let old_revision = event(&store, note, "OUTCOME", Some(OLD_ID));
            let batch = store.export_batch(DESTINATION, 1).unwrap();
            let null_revision = event(&store, note, "AUTHORIZED", None);
            let latest = if replacement {
                record(
                    note,
                    Some(NEW_ID),
                    event(&store, note, "OUTCOME", Some(NEW_ID)),
                )
            } else {
                record(note, None, null_revision)
            };

            store
                .ack_export(DESTINATION, batch.after, batch.records[0].revision)
                .unwrap();
            assert_eq!(
                store.export_batch(DESTINATION, 1).unwrap(),
                ExportBatch {
                    after: old_revision,
                    records: vec![latest],
                }
            );
        }
    }

    #[test]
    fn successful_prefix_leaves_failed_and_unsent_notes_for_retry_and_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.sqlite3");
        let mut store = open(&path);
        let notes = [1, 2, 3].map(|serial| add_burn(&mut store, serial));
        let revisions = notes.map(|note| event(&store, note, "OUTCOME", Some(OLD_ID)));
        let batch = store.export_batch(DESTINATION, 2).unwrap();
        assert_eq!(batch.records.len(), 2);
        // The first PUT succeeded, the second failed, and the third was not sent.
        store
            .ack_export(DESTINATION, batch.after, revisions[0])
            .unwrap();
        let pending = store.export_batch(DESTINATION, 2).unwrap();
        assert_eq!(
            pending.records,
            [
                record(notes[1], Some(OLD_ID), revisions[1]),
                record(notes[2], Some(OLD_ID), revisions[2]),
            ]
        );
        // A batch with no confirmed success leaves the same durable work pending.
        assert_eq!(store.export_batch(DESTINATION, 2).unwrap(), pending);
        drop(store);
        let mut reopened = open(&path);
        assert_eq!(reopened.export_batch(DESTINATION, 2).unwrap(), pending);
        reopened
            .ack_export(DESTINATION, pending.after, revisions[2])
            .unwrap();
        assert!(reopened
            .export_batch(DESTINATION, 2)
            .unwrap()
            .records
            .is_empty());
    }

    #[test]
    fn ack_requires_the_expected_cursor_and_a_relevant_forward_revision() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("store.sqlite3"));
        let note = add_burn(&mut store, 1);
        let first = event(&store, note, "AUTHORIZED", None);
        let second = event(&store, note, "OUTCOME", Some(OLD_ID));
        let unrelated = event(&store, note, "BURN_RELEASED", Some(OLD_ID));
        for (expected, completed) in [
            (first, second),
            (-1, first),
            (0, 0),
            (0, unrelated),
            (0, unrelated + 1),
        ] {
            assert!(store.ack_export(DESTINATION, expected, completed).is_err());
            assert_eq!(store.export_batch(DESTINATION, 1).unwrap().after, 0);
        }
        let cursors: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM withdrawal_export_cursors",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursors, 0, "failed initial CAS must not create a cursor");
        store.ack_export(DESTINATION, 0, first).unwrap();
        assert!(store.ack_export(DESTINATION, 0, second).is_err());
        assert!(store.ack_export(DESTINATION, first, first).is_err());
        assert_eq!(store.export_batch(DESTINATION, 1).unwrap().after, first);
        store.ack_export(DESTINATION, first, second).unwrap();
        assert_eq!(store.export_batch(DESTINATION, 1).unwrap().after, second);
    }

    #[test]
    fn each_destination_backfills_finalized_history_independently() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("store.sqlite3"));
        let note = add_burn(&mut store, 1);
        let mut saved = seed_submission(&store, note);
        saved.status = SubmissionStatus::Finalized;
        saved.withdrawal_id = Some(OLD_ID.into());
        store.update_submission_outcome(&saved).unwrap();
        let batch = store.export_batch(DESTINATION, 1).unwrap();
        store
            .ack_export(DESTINATION, 0, batch.records[0].revision)
            .unwrap();
        assert!(store
            .export_batch(DESTINATION, 1)
            .unwrap()
            .records
            .is_empty());
        for destination in ["s3://other/withdrawals/", "s3://exports/another-prefix/"] {
            assert_eq!(store.export_batch(destination, 1).unwrap(), batch);
        }
    }

    #[test]
    fn duplicate_201_and_409_outcomes_keep_one_latest_mapping() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("store.sqlite3"));
        let note = add_burn(&mut store, 1);
        let mut saved = seed_submission(&store, note);
        saved.status = SubmissionStatus::Submitted;
        saved.withdrawal_id = Some(OLD_ID.into());
        saved.last_http_status = Some(201);
        store.update_submission_outcome(&saved).unwrap();
        let created = store.export_batch(DESTINATION, 2).unwrap();
        store.update_submission_outcome(&saved).unwrap();
        assert_eq!(store.export_batch(DESTINATION, 2).unwrap(), created);
        saved.last_http_status = Some(409);
        store.update_submission_outcome(&saved).unwrap();
        let conflict = store.export_batch(DESTINATION, 2).unwrap();
        assert_eq!(conflict.records.len(), 1);
        assert_eq!(conflict.records[0].withdrawal_id.as_deref(), Some(OLD_ID));
        assert!(conflict.records[0].revision > created.records[0].revision);
        store.update_submission_outcome(&saved).unwrap();
        assert_eq!(store.export_batch(DESTINATION, 2).unwrap(), conflict);
    }

    #[test]
    fn releasing_a_null_id_hold_does_not_resurrect_an_earlier_id() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("store.sqlite3"));
        let note = add_burn(&mut store, 1);
        event(&store, note, "OUTCOME", Some(OLD_ID));
        let mut saved = seed_submission(&store, note);
        saved.status = SubmissionStatus::Held;
        saved.hold_reason = Some(HoldReason::HttpRejected);
        saved.last_http_status = Some(400);
        store.update_submission_outcome(&saved).unwrap();
        let null = store.export_batch(DESTINATION, 1).unwrap();
        assert_eq!(null.records[0].withdrawal_id, None);
        assert_eq!(store.release_holds(&[note]).unwrap(), (0, 1));
        assert_eq!(store.export_batch(DESTINATION, 1).unwrap(), null);
        store
            .ack_export(DESTINATION, 0, null.records[0].revision)
            .unwrap();
        assert!(store
            .export_batch(DESTINATION, 1)
            .unwrap()
            .records
            .is_empty());
    }

    #[test]
    fn populated_version_four_migration_preserves_history_and_exclusive_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.sqlite3");
        let mut store = open(&path);
        let note = add_burn(&mut store, 1);
        let mut saved = seed_submission(&store, note);
        saved.status = SubmissionStatus::Finalized;
        saved.withdrawal_id = Some(OLD_ID.into());
        saved.last_http_status = Some(201);
        store.update_submission_outcome(&saved).unwrap();
        let waiting = add_burn(&mut store, 2);
        let mut expired = seed_submission(&store, waiting);
        expired.status = SubmissionStatus::Expired;
        expired.withdrawal_id = Some(NEW_ID.into());
        store.update_submission_outcome(&expired).unwrap();
        store
            .connection
            .execute(
                "UPDATE burns SET withdrawal_limit_retry_at = 1234 WHERE note_id = ?1",
                [waiting.to_bytes()],
            )
            .unwrap();
        let held = add_burn(&mut store, 3);
        store
            .hold_burn(held, BurnHoldReason::TooSmallToForward, None)
            .unwrap();
        let history = store.export_batch(DESTINATION, 10).unwrap();
        let checkpoint = store.checkpoint().unwrap();
        let contents = [
            "attester_state",
            "burns",
            "submissions",
            "submission_events",
        ]
        .map(|table| (table, table_contents(&store, table)));
        // Version 5 adds only this table; remove it to restore the populated version-4 layout.
        store
            .connection
            .execute_batch("DROP TABLE withdrawal_export_cursors; PRAGMA user_version = 4;")
            .unwrap();
        drop(store);

        let mut migrated = Store::open_existing(&path, faucet(), anchor()).unwrap();
        assert_eq!(migrated.checkpoint().unwrap(), checkpoint);
        assert_eq!(migrated.discovered_burns().unwrap().len(), 3);
        for (table, rows) in contents {
            assert_eq!(table_contents(&migrated, table), rows, "{table}");
        }
        let version: u32 = migrated
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, STORE_VERSION);
        assert_eq!(migrated.export_batch(DESTINATION, 10).unwrap(), history);
        assert!(Store::open_existing(&path, faucet(), anchor()).is_err());
        let other = rusqlite::Connection::open(&path).unwrap();
        assert!(other
            .query_row(
                "SELECT COUNT(*) FROM withdrawal_export_cursors",
                [],
                |row| row.get::<_, i64>(0)
            )
            .is_err());
        drop(other);
        migrated
            .ack_export(DESTINATION, 0, history.records.last().unwrap().revision)
            .unwrap();
        drop(migrated);
        assert!(open(&path)
            .export_batch(DESTINATION, 10)
            .unwrap()
            .records
            .is_empty());
    }

    #[test]
    fn invalid_batch_bounds_and_destinations_do_not_change_progress() {
        let directory = tempfile::tempdir().unwrap();
        let store = open(&directory.path().join("store.sqlite3"));
        assert!(store.export_batch(DESTINATION, 0).is_err());
        if usize::BITS > 63 {
            assert!(store.export_batch(DESTINATION, usize::MAX).is_err());
        }
        assert!(store.export_batch("", 1).is_err());
        assert_eq!(
            store.export_batch(DESTINATION, 1).unwrap(),
            ExportBatch {
                after: 0,
                records: vec![]
            }
        );
    }
}
