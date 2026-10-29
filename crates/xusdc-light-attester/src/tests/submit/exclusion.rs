//! Durable operator suspension of a saved hash mismatch, using equivalent synthetic requests.
use super::*;
use crate::config::Config;
use crate::store::{BurnHoldReason, ReleaseError, ReleaseSelection, STORE_VERSION};
use miden_protocol::note::NoteId;
use rusqlite::types::Value as SqlValue;

const REASON: &str = "automatic processing suspended pending settlement review";

fn exclude(args: &mut TestArgs, id: NoteId) {
    args.append("--persist-burn-exclusion", id.to_hex());
    args.append("--burn-exclusion-reason", REASON);
}

fn rows(ledger: &Ledger, index: usize, table: &str, columns: &str) -> Vec<Vec<SqlValue>> {
    let disk = read_store(&ledger.path());
    let mut query = disk
        .prepare(&format!(
            "SELECT {columns} FROM {table} WHERE note_id = ?1 ORDER BY rowid"
        ))
        .unwrap();
    let width = query.column_count();
    query
        .query_map([ledger.burns[index].note_id().to_bytes()], |row| {
            (0..width).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

const BURN_COLUMNS: &str = "note_id, nullifier, note, creation_block, consumption_block, hold_reason, withdrawal_limit_retry_at";

async fn try_start(
    ledger: &Ledger,
    config: Config,
    blocks: Vec<SignedBlock>,
) -> anyhow::Result<Attester> {
    let (circle, _) = ScriptedCircle::new(ledger.path(), vec![]);
    Attester::start(
        config,
        Box::new(TestChain::new(blocks, scan_limits(3, 3)).0),
        Box::new(circle),
        development_pair().await,
    )
    .await
}

/// Make a genuine released schema, populated with the real domain fixtures already exercised.
fn released_store(ledger: &Ledger) {
    let source = ledger.directory.path().join("fixture-source.sqlite3");
    std::fs::rename(ledger.path(), &source).unwrap();
    let disk = Connection::open(ledger.path()).unwrap();
    for sql in [
        include_str!("../../../migrations/0001_initial.sql"),
        include_str!("../../../migrations/0002_scan_from_the_anchor.sql"),
        include_str!("../../../migrations/0003_drop_unused_burn_columns.sql"),
        include_str!("../../../migrations/0004_withdrawal_limit_retry.sql"),
    ] {
        disk.execute_batch(sql).unwrap();
    }
    disk.execute("ATTACH DATABASE ?1 AS fixture", [source.to_str().unwrap()])
        .unwrap();
    disk.execute_batch(&format!(
        "INSERT INTO attester_state SELECT * FROM fixture.attester_state;
        INSERT INTO burns SELECT {BURN_COLUMNS} FROM fixture.burns;
        INSERT INTO submissions SELECT * FROM fixture.submissions;
        INSERT INTO submission_events SELECT * FROM fixture.submission_events;
        PRAGMA user_version = 4;"
    ))
    .unwrap();
    assert_eq!(
        disk.prepare("SELECT * FROM burns").unwrap().column_count(),
        7
    );
}

#[tokio::test]
async fn persistent_burn_exclusion_saved_mismatch_upgrade_and_restart() {
    let ledger = Ledger::new().await;
    let mismatch = |i| {
        let mut value = ledger.response(i, "finalized");
        value["transferSpecHashes"][0] = json!(format!("0x{}", "ff".repeat(32)));
        reply(200, value)
    };
    let conflict = |i| {
        reply(
            409,
            json!({"conflict": {
                "withdrawalId": ledger.response(i, "finalized")["withdrawalId"],
                "burnTxId": ledger.burns[i].note_id().to_hex()
            }}),
        )
    };
    let (mut attester, requests) = ledger
        .start(vec![
            conflict(0),
            mismatch(0),
            mismatch(0),
            conflict(2),
            mismatch(2),
        ])
        .await;
    // Sign the synthetic requests with real development keys, never KMS credentials.
    for index in [0, 2] {
        let prepared = read_prepared(RawResponse::new(
            StatusCode::OK,
            serde_json::to_vec(&ledger.prepared_response(index)).unwrap(),
        ))
        .unwrap();
        let signed = prepared
            .verify(&ledger.burns[index], &attester.config)
            .unwrap()
            .sign(&development_pair().await)
            .await
            .unwrap();
        attester
            .submit_signed_withdrawal(&signed, &mut false)
            .await
            .unwrap();
        if index == 0 {
            recover(&mut attester).await.unwrap();
        }
    }
    let saved = ledger.record(&attester, 0);
    assert_eq!(saved.status, SubmissionStatus::Submitting);
    assert!(saved.withdrawal_id.is_some());
    assert_eq!(
        saved.last_error.as_deref(),
        Some("response does not identify the saved withdrawal")
    );
    assert_eq!(requests.lock().unwrap().len(), 5);
    let before = rows(&ledger, 0, "submissions", "*");
    let evidence = rows(&ledger, 0, "burns", BURN_COLUMNS);
    let history = rows(&ledger, 0, "submission_events", "*");
    let checkpoint = attester.store.checkpoint().unwrap();
    drop(attester);
    released_store(&ledger);
    assert_eq!(super::super::support::store_version(&ledger.path()), 4);
    exclude(
        &mut ledger.config.lock().unwrap(),
        ledger.burns[0].note_id(),
    );
    // First invocation upgrades schema 4; repeated arguments and omitted arguments both retain it.
    for invocation in 0..3 {
        if invocation == 2 {
            let mut args = ledger.config.lock().unwrap();
            args.remove("--persist-burn-exclusion");
            args.remove("--burn-exclusion-reason");
        }
        let mut replies = vec![mismatch(2)];
        if invocation == 0 {
            replies.extend([
                reply(200, ledger.prepared_response(1)),
                reply(201, json!([ledger.response(1, "finalized")])),
            ]);
        }
        let (pair, calls) = signers(None).await;
        let (mut attester, requests, _) = ledger.runtime(replies, pair).await;
        assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
        assert_eq!(ledger.record(&attester, 0), saved);
        assert_eq!(
            ledger.record(&attester, 1).status,
            SubmissionStatus::Finalized
        );
        assert_eq!(ledger.record(&attester, 2).last_error, saved.last_error);
        assert_eq!(
            ledger.record(&attester, 2).status,
            SubmissionStatus::Submitting
        );
        assert_eq!(
            counts(&calls),
            if invocation == 0 { [1, 1] } else { [0, 0] }
        );
        let observed = requests.lock().unwrap();
        assert_eq!(
            observed[0],
            ObservedRequest::Lookup {
                endpoint: ENDPOINT.into(),
                id: ledger.response(2, "finalized")["withdrawalId"]
                    .as_str()
                    .unwrap()
                    .into()
            }
        );
        assert_eq!(observed.len(), if invocation == 0 { 3 } else { 1 });
        if invocation == 0 {
            assert_eq!(observed[1], ObservedRequest::Prepare);
            assert_eq!(
                observed[2],
                ObservedRequest::Submit {
                    endpoint: ENDPOINT.into(),
                    body: ledger.record(&attester, 1).body,
                }
            );
        }
        assert_eq!(rows(&ledger, 0, "submissions", "*"), before);
        assert_eq!(rows(&ledger, 0, "burns", BURN_COLUMNS), evidence);
        let events = rows(&ledger, 0, "submission_events", "*");
        assert_eq!(&events[..history.len()], history);
        assert_eq!(events.len(), history.len() + 1);
        assert_eq!(
            ledger.history(0).last(),
            Some(&event("OPERATOR_EXCLUDED", SubmissionStatus::Submitting))
        );
        assert_eq!(attester.store.checkpoint().unwrap(), checkpoint);
        let progress = attester.store.progress().unwrap();
        assert_eq!(
            (
                progress.burns_excluded,
                progress.withdrawals_pending,
                progress.burns_unfinished
            ),
            (1, 1, 1)
        );
        assert_eq!(
            super::super::support::store_version(&ledger.path()),
            STORE_VERSION
        );
    }
}

#[tokio::test]
async fn persistent_burn_exclusion_selectors_and_atomicity() {
    use SubmissionStatus::{Expired, Submitted, Submitting};
    for state in [
        None,
        Some((Expired, true)),
        Some((Submitting, false)),
        Some((Submitting, true)),
        Some((Submitted, true)),
    ] {
        let ledger = Ledger::new().await;
        let id = ledger.burns[0].note_id();
        let mut store = ledger.open_store().unwrap();
        if let Some((status, known)) = state {
            let mut saved = ledger
                .signed(0)
                .await
                .submission(ENDPOINT.parse().unwrap())
                .unwrap();
            store.save_submission(&saved).unwrap();
            saved.status = status;
            saved.withdrawal_id = known.then(|| ID.into());
            store.update_submission_outcome(&saved).unwrap();
        }
        store.persist_burn_exclusions(&[id, id], REASON).unwrap();
        assert!(store.submissions_to_recover().unwrap().is_empty());
        assert!(store.submissions_to_poll().unwrap().is_empty());
        assert_eq!(
            store
                .burns_ready_for_withdrawal(3u32.into(), 1)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(store.discovered_burns().unwrap().len(), 3);
        assert_eq!(store.submission(id).unwrap().is_some(), state.is_some());
        assert_eq!(store.progress().unwrap().burns_excluded, 1);
    }
    let ledger = Ledger::new().await;
    let ids: Vec<_> = ledger
        .ordered_indices()
        .iter()
        .map(|&i| ledger.burns[i].note_id())
        .collect();
    ledger.sql(&format!(
        "CREATE TRIGGER fail_exclusion BEFORE INSERT ON submission_events
        WHEN NEW.kind = 'OPERATOR_EXCLUDED' AND NEW.note_id = x'{}'
        BEGIN SELECT RAISE(ABORT, 'forced exclusion event failure'); END;",
        hex::encode(ids[1].to_bytes())
    ));
    let mut store = ledger.open_store().unwrap();
    let error = store
        .persist_burn_exclusions(&ids[..2], REASON)
        .unwrap_err();
    assert!(format!("{error:#}").contains("forced exclusion event failure"));
    assert!(store.burn_exclusions().unwrap().is_empty());
    assert_eq!(ledger.stored("SELECT COUNT(*) FROM submission_events"), 0);
    drop(store);
    ledger.sql("DROP TRIGGER fail_exclusion");
    ledger.sql(&format!(
        "UPDATE burns SET consumption_block = NULL WHERE note_id = x'{}'",
        hex::encode(ids[1].to_bytes())
    ));
    let mut store = ledger.open_store().unwrap();
    for bad in [
        ids[1],
        NoteId::try_from_hex(&miden_protocol::Word::empty().to_hex()).unwrap(),
    ] {
        let error = store
            .persist_burn_exclusions(&[ids[0], bad], REASON)
            .unwrap_err();
        assert!(error.to_string().contains("not a known consumed burn"));
        assert!(store.burn_exclusions().unwrap().is_empty());
    }
    store.persist_burn_exclusions(&[ids[2]], REASON).unwrap();
    let error = store
        .persist_burn_exclusions(&[ids[0], ids[2]], "different")
        .unwrap_err();
    assert!(error.to_string().contains("different exclusion reason"));
    store
        .persist_burn_exclusions(&[ids[2], ids[2]], REASON)
        .unwrap();
    assert_eq!(store.burn_exclusions().unwrap(), [(ids[2], REASON.into())]);
    assert_eq!(ledger.stored("SELECT COUNT(*) FROM submission_events"), 1);
    drop(store);
    // A reason's SQL byte bound alone cannot enforce normalization or reject controls.
    for reason in [" ", " padded ", "a\nb"] {
        Connection::open(ledger.path())
            .unwrap()
            .execute(
                "UPDATE burns SET exclusion_reason = ?1 WHERE exclusion_reason IS NOT NULL",
                [reason],
            )
            .unwrap();
        let error = ledger.open_store().err().unwrap();
        assert!(format!("{error:#}").contains(INVALID));
    }
}

#[tokio::test]
async fn persistent_burn_exclusion_startup_boundaries_and_fifo() {
    let ledger = Ledger::new().await;
    let [a, b, c] = ledger.fresh_indices.clone().try_into().unwrap();
    let mut args = ledger.config.lock().unwrap().clone();
    exclude(&mut args, ledger.burns[a].note_id());
    let error = try_start(&ledger, args.load(), ledger.fork_blocks.clone())
        .await
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("diverged"));
    assert!(ledger
        .open_store()
        .unwrap()
        .burn_exclusions()
        .unwrap()
        .is_empty());
    let mut missing = args.clone();
    let missing_path = ledger.directory.path().join("missing.sqlite3");
    missing.replace("--store-path", missing_path.as_os_str());
    assert!(format!(
        "{:#}",
        try_start(&ledger, missing.load(), ledger.blocks.clone())
            .await
            .err()
            .unwrap()
    )
    .contains("failed to open attester store"));
    assert!(!missing_path.exists());
    ledger.sql(&format!(
        "UPDATE burns SET withdrawal_limit_retry_at = 9999999999 WHERE note_id IN (x'{}', x'{}')",
        hex::encode(ledger.burns[a].note_id().to_bytes()),
        hex::encode(ledger.burns[b].note_id().to_bytes())
    ));
    // The first exclusion commits even though the other active waiter still requires settings.
    let error = try_start(&ledger, args.load(), ledger.blocks.clone())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("store has withdrawals waiting"));
    let store = ledger.open_store().unwrap();
    assert_eq!(
        store.first_limit_wait().unwrap().unwrap().note_id,
        ledger.burns[b].note_id()
    );
    assert_eq!(store.progress().unwrap().withdrawal_limit_waiting, 1);
    drop(store);
    args.append(
        "--persist-burn-exclusion",
        ledger.burns[b].note_id().to_hex(),
    );
    *ledger.config.lock().unwrap() = args;
    let (mut attester, _) = ledger
        .start(vec![
            reply(200, ledger.prepared_response(c)),
            reply(201, json!([ledger.response(c, "finalized")])),
        ])
        .await;
    assert!(attester.run_one_cycle().await.unwrap().submit.is_ok());
    assert_eq!(
        ledger.record(&attester, c).status,
        SubmissionStatus::Finalized
    );
    assert!(attester.store.first_limit_wait().unwrap().is_none());
    let progress = attester.store.progress().unwrap();
    assert_eq!(
        (
            progress.burns_excluded,
            progress.burns_unfinished,
            progress.withdrawals_pending,
            progress.withdrawal_limit_waiting
        ),
        (2, 0, 0, 0)
    );
    assert!(progress.oldest_unfinished_burn.is_none());
    assert_eq!(
        ledger.stored("SELECT COUNT(*) FROM burns WHERE withdrawal_limit_retry_at = 9999999999"),
        2
    );
}

#[tokio::test]
async fn persistent_burn_exclusion_cannot_hide_invalid_requests_or_release_evidence() {
    for mutation in [
        "body = X'00'",
        "endpoint = 'http://circle.invalid/v1/withdraw'",
    ] {
        for retained in [false, true] {
            let ledger = Ledger::new().await;
            let (mut attester, _) = ledger
                .start(vec![reply(400, json!({"message": "rejected"}))])
                .await;
            ledger.submit(&mut attester, 0).await.unwrap();
            if retained {
                attester
                    .store
                    .persist_burn_exclusions(&[ledger.burns[0].note_id()], REASON)
                    .unwrap();
            }
            drop(attester);
            ledger.sql(&format!("UPDATE submissions SET {mutation}"));
            let mut args = ledger.config.lock().unwrap().clone();
            if !retained {
                exclude(&mut args, ledger.burns[0].note_id());
            }
            let error = try_start(&ledger, args.load(), ledger.blocks.clone())
                .await
                .err()
                .unwrap();
            assert!(format!("{error:#}").contains(INVALID));
            assert_eq!(
                ledger.stored("SELECT COUNT(*) FROM burns WHERE exclusion_reason IS NOT NULL"),
                i64::from(retained)
            );
        }
    }
    let ledger = Ledger::new().await;
    let (mut attester, _) = ledger
        .start(vec![reply(400, json!({"message": "rejected"}))])
        .await;
    ledger.submit(&mut attester, 0).await.unwrap();
    let ids = [ledger.burns[0].note_id(), ledger.burns[1].note_id()];
    attester
        .store
        .hold_burn(ids[1], BurnHoldReason::PrepareRejected, None)
        .unwrap();
    attester
        .store
        .persist_burn_exclusions(&ids, REASON)
        .unwrap();
    let saved = rows(&ledger, 0, "submissions", "*");
    for id in ids {
        assert!(matches!(attester.store.release_checked(&ReleaseSelection {
            note_id: id, expected_event_seq: attester.store.revision(id).unwrap().unwrap(), circle_not_accepted: true,
        }), Err(ReleaseError::Excluded(note)) if note == id));
        let error = attester.store.release_holds(&[id]).unwrap_err();
        assert!(
            matches!(error.downcast_ref::<ReleaseError>(), Some(ReleaseError::Excluded(note)) if *note == id)
        );
    }
    assert_eq!(rows(&ledger, 0, "submissions", "*"), saved);
    assert_eq!(attester.store.holds().unwrap().len(), 2);
    drop(attester);
    // Active selectors still reject an orphan instead of silently dropping it in a join.
    ledger.sql("PRAGMA foreign_keys = OFF; UPDATE submissions SET status = 'SUBMITTING', hold_reason = NULL; DELETE FROM burns;");
    let store = ledger.open_store().unwrap();
    assert_eq!(
        store.submissions_to_recover().unwrap_err().to_string(),
        INVALID
    );
}
