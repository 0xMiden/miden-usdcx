//! **Schema v1 → v2 migration.**
//!
//! Schema v2 added the terminal `rejected` status token and bumped `STORE_SCHEMA_VERSION` 1 → 2. A
//! store that accepted only version 0 (fresh) or exactly 2 — with no migration — would leave an
//! operator upgrading a durable relayer with their existing v1 nonce log and cursor REFUSED at
//! open, and deleting the file to recover would discard exactly the replay-prevention state the
//! component exists to preserve.
//!
//! The table layout did not change and every v1 status token is a subset of v2's, so the migration
//! is a version re-stamp that preserves the data. These tests prove a populated v1 store opens,
//! keeps its nonce records and its cursor, and ends stamped v2 — while an unknown FUTURE version is
//! still refused.

mod idempotency_fixtures;

use std::sync::Arc;

use assert_matches::assert_matches;
use idempotency_fixtures::{message_hash, nonce, open_at, store_path, tx_id, ManualClock};
use tempfile::TempDir;
use xreserve_deposit_relayer::{
    error::RelayerError,
    idempotency::{Clock, IdempotencyStore, SubmissionStatus, STORE_SCHEMA_VERSION},
};

/// The schema version a v1-era build stamped.
const V1: u32 = 1;

/// Re-stamps `path`'s `user_version` to `version`, leaving the byte-identical table layout
/// untouched — so the file is indistinguishable from one a build of that version actually wrote.
fn stamp_version(path: &std::path::Path, version: u32) {
    let raw = rusqlite::Connection::open(path).expect("raw open");
    raw.pragma_update(None, "user_version", version)
        .expect("stamp version");
    drop(raw);
}

fn user_version(path: &std::path::Path) -> u32 {
    let raw = rusqlite::Connection::open(path).expect("raw open");
    raw.pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read version")
}

/// A populated v1 store opens, MIGRATES to the current version, and preserves both its nonce
/// records and its domain cursor. This is the upgrade path an operator takes; failing it would
/// strand a running relayer or force it to discard its replay-prevention state.
#[test]
fn a_populated_v1_store_migrates_and_preserves_its_records_and_cursor() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    // write a populated store (a submitted nonce + a domain cursor), then re-stamp it back to v1 so
    // it looks exactly like a file a base build wrote (the layout is identical; only the token set
    // and the version stamp differ)
    {
        let store = open_at(&path, &clock);
        store
            .claim_nonce(&nonce(1), &message_hash(1))
            .expect("claim");
        store
            .record_submission(&nonce(1), tx_id(1))
            .expect("-> submitted");
        store.advance_cursor(7, "cursor-page-xyz").expect("cursor");
    }
    stamp_version(&path, V1);
    assert_eq!(user_version(&path), V1, "the file is now stamped v1");

    // reopen through the store: it must migrate, not refuse
    let store = open_at(&path, &clock);

    let record = store
        .record(&nonce(1))
        .expect("read")
        .expect("the migrated store still holds the nonce");
    assert_eq!(record.status(), SubmissionStatus::Submitted);
    assert_eq!(record.submitted_tx_id(), Some(&tx_id(1)));

    let cursor = store
        .read_cursor(7)
        .expect("read")
        .expect("the migrated store still holds the cursor");
    assert_eq!(cursor.page_after(), "cursor-page-xyz");

    assert_eq!(
        user_version(&path),
        STORE_SCHEMA_VERSION,
        "the file must be re-stamped to the current version after migration"
    );
}

/// The migration is idempotent: a store migrated to the current version reopens cleanly a second
/// time (it is now v2, so it is the plain reopen path). A migration that re-ran or re-refused would
/// be a startup deadlock.
#[test]
fn a_migrated_store_reopens_without_re_migrating() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    {
        let store = open_at(&path, &clock);
        store
            .claim_nonce(&nonce(1), &message_hash(1))
            .expect("claim");
    }
    stamp_version(&path, V1);

    drop(open_at(&path, &clock)); // first open migrates
    let store = open_at(&path, &clock); // second open is the plain v2 path

    assert_eq!(
        store
            .record(&nonce(1))
            .expect("read")
            .expect("present")
            .status(),
        SubmissionStatus::Pending
    );
    assert_eq!(user_version(&path), STORE_SCHEMA_VERSION);
}

/// A version NEWER than this build knows is still REFUSED — migration is for the known past, never
/// a blind acceptance of an unknown layout the current code might misread.
#[test]
fn a_future_schema_version_is_still_refused() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    {
        let store = open_at(&path, &clock);
        store
            .claim_nonce(&nonce(1), &message_hash(1))
            .expect("claim");
    }
    let future = STORE_SCHEMA_VERSION + 1;
    stamp_version(&path, future);

    let err = IdempotencyStore::open_with_clock(&path, ManualClock::at(1_000) as Arc<dyn Clock>)
        .expect_err("a future schema must be refused, not migrated");
    assert_matches!(err, RelayerError::UnsupportedStoreSchema { found, expected } => {
        assert_eq!(found, future);
        assert_eq!(expected, STORE_SCHEMA_VERSION);
    });
}
