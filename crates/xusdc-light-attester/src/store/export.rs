//! Immutable withdrawal snapshots and durable progress for each export destination.

use anyhow::{ensure, Context};
use miden_protocol::note::NoteId;
use rusqlite::{params, OptionalExtension};

use super::{classify_error, decode_canonical, Store, INVALID};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportRecord {
    pub(crate) note_id: NoteId,
    pub(crate) withdrawal_id: Option<String>,
    /// Sequence of this immutable submission event.
    pub(crate) revision: i64,
}

impl Store {
    /// Read authorizations and outcomes in order, starting after the destination's last upload.
    /// A saved recovery ID is private until Circle confirms the withdrawal's identity and status.
    pub(crate) fn export_batch(
        &self,
        destination: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<ExportRecord>> {
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
                "SELECT note_id,
                        CASE WHEN status IN ('SUBMITTED', 'FINALIZED', 'EXPIRED', 'FAILED')
                             THEN withdrawal_id END,
                        seq
                 FROM submission_events
                 WHERE seq > ?1 AND kind IN ('AUTHORIZED', 'OUTCOME')
                 ORDER BY seq LIMIT ?2",
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
        Ok(records)
    }

    /// Acknowledge the last record in the worker's contiguous successful prefix. Use its snapshot
    /// revision, so changes written while the batch was in flight remain pending.
    pub(crate) fn ack_export(
        &mut self,
        destination: &str,
        last_uploaded_seq: i64,
    ) -> anyhow::Result<()> {
        ensure!(
            !destination.is_empty(),
            "export destination must not be empty"
        );
        self.connection
            .execute(
                "INSERT INTO withdrawal_export_cursors (destination, after_seq) VALUES (?1, ?2)
                 ON CONFLICT (destination) DO UPDATE
                 SET after_seq = MAX(withdrawal_export_cursors.after_seq, excluded.after_seq)",
                params![destination, last_uploaded_seq],
            )
            .map_err(classify_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use alloy_primitives::B256;
    use miden_protocol::account::AccountId;
    use miden_protocol::block::{BlockHeader, BlockNumber};
    use miden_protocol::utils::serde::Serializable;
    use miden_protocol::Word;
    use opentelemetry::trace::{SpanId, Status, TracerProvider as _};
    use opentelemetry::KeyValue;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use reqwest::Url;
    use tokio::sync::Notify;
    use tracing::dispatcher::with_default;
    use tracing_opentelemetry::OpenTelemetryLayer;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;
    use crate::attester::export::ExportRuntime;
    use crate::export::tests::{wait_until, PreparedS3, Reply};
    use crate::export::{ExportConfig, Exporter};
    use crate::store::EventKind::{Authorized, BurnHeld, OperatorRelease, Outcome};
    use crate::store::{record_event, EventKind, TrustedAnchor, STORE_VERSION};
    use crate::submission::SubmissionStatus::{Expired, Finalized, Held, Submitted, Submitting};
    use crate::submission::{HoldReason, SavedSubmission, SubmissionStatus};
    use crate::tests::{discovered_burn, serial};

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

    fn add_burn(store: &mut Store, index: u64) -> NoteId {
        let burn = discovered_burn(100, serial(index), 9);
        let note_id = burn.note_id();
        store
            .save_scan_progress(&[], &[burn], &BlockHeader::mock(2u32, None, None, &[]))
            .unwrap();
        note_id
    }

    fn event(
        store: &Store,
        note_id: NoteId,
        kind: EventKind,
        status: Option<SubmissionStatus>,
        id: Option<&str>,
    ) -> i64 {
        store
            .connection
            .execute(
                "INSERT INTO submission_events (note_id, recorded_at, kind, status, withdrawal_id)
                 VALUES (?1, 0, ?2, ?3, ?4)",
                params![
                    note_id.to_bytes(),
                    kind.as_ref(),
                    status.as_ref().map(SubmissionStatus::as_ref),
                    id,
                ],
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
            status: Submitting,
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
        record_event(&store.connection, note_id, Authorized, None).unwrap();
        saved
    }

    fn runtime(sink: &PreparedS3) -> ExportRuntime {
        let config = ExportConfig::from_url(DESTINATION).unwrap();
        let exporter = Exporter::with_client(config.clone(), sink.client());
        ExportRuntime::with_exporter(config, exporter)
    }

    #[tokio::test(start_paused = true)]
    async fn runtime_saves_uploaded_snapshots_and_retries_failed_progress_after_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.sqlite3");
        let mut store = open(&path);
        let note = add_burn(&mut store, 1);
        let old_uploaded_seq = event(&store, note, Outcome, Some(Expired), Some(OLD_ID));
        let released = Arc::new(Notify::new());
        let sink = PreparedS3::answering([
            Reply::Block(released.clone()),
            Reply::Success,
            Reply::Success,
        ]);
        let spans = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(spans.clone())
            .build();
        let subscriber = tracing::Dispatch::new(
            tracing_subscriber::registry().with(OpenTelemetryLayer::new(provider.tracer("test"))),
        );
        let saved_progress = |store: &Store| {
            store
                .connection
                .query_row(
                    "SELECT after_seq FROM withdrawal_export_cursors WHERE destination = ?1",
                    [DESTINATION],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .unwrap()
        };
        let mut export = runtime(&sink);
        with_default(&subscriber, || export.checkpoint(&mut store));
        wait_until(|| sink.active_count() == 1).await;
        let newer = event(&store, note, Authorized, Some(Submitting), None);
        released.notify_one();
        wait_until(|| {
            with_default(&subscriber, || export.checkpoint(&mut store));
            saved_progress(&store) == Some(old_uploaded_seq)
        })
        .await;
        assert!(spans.get_finished_spans().unwrap().is_empty());
        export.shutdown().await;
        drop(store);
        let mut store = open(&path);
        assert_eq!(saved_progress(&store), Some(old_uploaded_seq));
        let pending = store.export_batch(DESTINATION, 10).unwrap();
        assert_eq!(pending, [record(note, None, newer)]);

        store.connection.execute_batch(
            "CREATE TEMP TRIGGER reject_export_progress BEFORE INSERT ON withdrawal_export_cursors
             BEGIN SELECT RAISE(ABORT, 'test progress write failed'); END;"
        ).unwrap();
        let mut export = runtime(&sink);
        wait_until(|| {
            with_default(&subscriber, || export.checkpoint(&mut store));
            !spans.get_finished_spans().unwrap().is_empty()
        })
        .await;
        assert_eq!(saved_progress(&store), Some(old_uploaded_seq));
        assert_eq!(store.export_batch(DESTINATION, 10).unwrap(), pending);
        let finished = spans.get_finished_spans().unwrap();
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0].name, "attester.export");
        assert_eq!(finished[0].status, Status::error("store"));
        assert!(finished[0]
            .attributes
            .contains(&KeyValue::new("failure.class", "actionable")));
        assert!(format!("{:?}", finished[0].events).contains("test progress write failed"));
        store
            .connection
            .execute_batch("DROP TRIGGER reject_export_progress")
            .unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        wait_until(|| {
            with_default(&subscriber, || export.checkpoint(&mut store));
            store.export_batch(DESTINATION, 10).unwrap().is_empty()
        })
        .await;
        assert_eq!(sink.count(), 3);
        assert_eq!(spans.get_finished_spans().unwrap().len(), 1);
        export.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_acks_successful_prefix_and_reports_s3_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.sqlite3");
        let mut store = open(&path);
        let notes = [1, 2, 3].map(|index| add_burn(&mut store, index));
        let revisions =
            notes.map(|note| event(&store, note, Outcome, Some(Finalized), Some(OLD_ID)));
        let pending = [
            record(notes[1], Some(OLD_ID), revisions[1]),
            record(notes[2], Some(OLD_ID), revisions[2]),
        ];
        let sink = PreparedS3::answering([
            Reply::Success,
            Reply::Denied,
            Reply::Success,
            Reply::Success,
        ]);
        let mut export = runtime(&sink);
        let spans = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(spans.clone())
            .build();
        let subscriber = tracing::Dispatch::new(
            tracing_subscriber::registry().with(OpenTelemetryLayer::new(provider.tracer("test"))),
        );
        let parent = with_default(&subscriber, || tracing::info_span!("attester.cycle"));
        wait_until(|| {
            with_default(&subscriber, || {
                parent.in_scope(|| export.checkpoint(&mut store))
            });
            !spans.get_finished_spans().unwrap().is_empty()
        })
        .await;
        assert_eq!(sink.count(), 2, "stop sending at the first failed upload");
        assert_eq!(store.export_batch(DESTINATION, 10).unwrap(), pending);
        let finished = spans.get_finished_spans().unwrap();
        let [span] = finished.as_slice() else {
            panic!("expected one finished export span")
        };
        assert_eq!(span.name, "attester.export");
        assert_eq!(span.parent_span_id, SpanId::INVALID);
        assert_eq!(span.status, Status::error("s3_export"));
        assert!(span
            .attributes
            .contains(&KeyValue::new("failure.class", "actionable")));
        assert!(span
            .attributes
            .contains(&KeyValue::new("failure.kind", "s3_export")));
        let details = format!("{span:?}");
        assert!(details.contains("AccessDenied"));
        // With this generic SDK error, check what the exporter adds to the span.
        for request_detail in [
            OLD_ID,
            &notes[1].to_hex(),
            DESTINATION,
            "Credential=",
            "Signature=",
            "withdrawal_id",
        ] {
            assert!(
                !details.contains(request_detail),
                "export span included {request_detail}"
            );
        }
        drop(parent);
        assert_eq!(spans.get_finished_spans().unwrap()[1].status, Status::Unset);
        export.shutdown().await;
        drop(store);

        let mut store = open(&path);
        assert_eq!(store.export_batch(DESTINATION, 10).unwrap(), pending);
        let mut export = runtime(&sink);
        wait_until(|| {
            export.checkpoint(&mut store);
            store.export_batch(DESTINATION, 10).unwrap().is_empty()
        })
        .await;
        assert_eq!(sink.count(), 4, "retry the failed and unsent uploads");
        // A replayed acknowledgement cannot move durable progress backwards.
        store.ack_export(DESTINATION, revisions[0]).unwrap();
        assert!(store.export_batch(DESTINATION, 10).unwrap().is_empty());
        export.shutdown().await;
    }

    #[test]
    fn reads_authorizations_and_outcomes_in_order_across_batches() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("store.sqlite3"));
        let first = add_burn(&mut store, 1);
        let second = add_burn(&mut store, 2);
        let expired = event(&store, first, Outcome, Some(Expired), Some(OLD_ID));
        event(&store, second, BurnHeld, None, None);
        let authorized = event(&store, first, Authorized, Some(Submitting), None);
        let second_held = event(&store, second, Outcome, Some(Held), None);
        event(&store, second, OperatorRelease, Some(Held), None);
        let replacement = event(&store, first, Outcome, Some(Submitted), Some(NEW_ID));

        assert_eq!(
            store.export_batch(DESTINATION, 2).unwrap(),
            [
                record(first, Some(OLD_ID), expired),
                record(first, None, authorized),
            ]
        );
        store.ack_export(DESTINATION, authorized).unwrap();
        assert_eq!(
            store.export_batch(DESTINATION, 2).unwrap(),
            [
                record(second, None, second_held),
                record(first, Some(NEW_ID), replacement),
            ]
        );
    }

    #[test]
    fn each_destination_backfills_finalized_history_independently() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("store.sqlite3"));
        let note = add_burn(&mut store, 1);
        let mut saved = seed_submission(&store, note);
        saved.status = Finalized;
        saved.withdrawal_id = Some(OLD_ID.into());
        store.update_submission_outcome(&saved).unwrap();
        let batch = store.export_batch(DESTINATION, 10).unwrap();
        let finalized = batch.last().unwrap();
        assert_eq!(finalized.withdrawal_id.as_deref(), Some(OLD_ID));
        store.ack_export(DESTINATION, finalized.revision).unwrap();
        assert!(store.export_batch(DESTINATION, 1).unwrap().is_empty());
        for destination in ["s3://other/withdrawals/", "s3://exports/another-prefix/"] {
            assert_eq!(store.export_batch(destination, 10).unwrap(), batch);
        }
    }

    #[test]
    fn releasing_a_null_id_hold_does_not_resurrect_an_earlier_id() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("store.sqlite3"));
        let note = add_burn(&mut store, 1);
        event(&store, note, Outcome, Some(Expired), Some(OLD_ID));
        let mut saved = seed_submission(&store, note);
        saved.status = Held;
        saved.hold_reason = Some(HoldReason::HttpRejected);
        saved.last_http_status = Some(400);
        store.update_submission_outcome(&saved).unwrap();
        let batch = store.export_batch(DESTINATION, 10).unwrap();
        let held = batch.last().unwrap();
        assert_eq!(held.withdrawal_id, None);
        store.ack_export(DESTINATION, held.revision).unwrap();
        assert_eq!(store.release_holds(&[note]).unwrap(), (0, 1));
        assert!(store.export_batch(DESTINATION, 1).unwrap().is_empty());
    }

    #[test]
    fn populated_version_four_migration_backfills_finalized_and_null_mappings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("store.sqlite3");
        let mut store = open(&path);
        let note = add_burn(&mut store, 1);
        let mut saved = seed_submission(&store, note);
        saved.status = Finalized;
        saved.withdrawal_id = Some(OLD_ID.into());
        saved.last_http_status = Some(201);
        store.update_submission_outcome(&saved).unwrap();
        let waiting = add_burn(&mut store, 2);
        seed_submission(&store, waiting);
        let history = store.export_batch(DESTINATION, 10).unwrap();
        assert_eq!(
            history
                .iter()
                .map(|row| (row.note_id, row.withdrawal_id.as_deref()))
                .collect::<Vec<_>>(),
            [(note, None), (note, Some(OLD_ID)), (waiting, None)]
        );
        // Version 5 adds only this table; remove it to restore the populated version-4 layout.
        store
            .connection
            .execute_batch("DROP TABLE withdrawal_export_cursors; PRAGMA user_version = 4;")
            .unwrap();
        drop(store);

        let migrated = Store::open_existing(&path, faucet(), anchor()).unwrap();
        let version: u32 = migrated
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, STORE_VERSION);
        assert_eq!(migrated.export_batch(DESTINATION, 10).unwrap(), history);
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
        assert!(store.export_batch(DESTINATION, 1).unwrap().is_empty());
    }
}
