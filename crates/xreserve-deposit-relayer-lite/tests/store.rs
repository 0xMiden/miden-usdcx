//! The store: T-S1 … T-S5.
//!
//! Every case opens a REAL database on a temporary directory. "Survives a restart" is only provable
//! against a file a second, independent handle can reopen, so no test here uses an in-memory
//! database.
//!
//! Crash-atomicity, torn-file recovery and a 100k-entry scale test are deliberately ABSENT: SQLite
//! owns the first two, and membership is an indexed lookup so nothing is parsed into memory at
//! boot. Testing those would be testing SQLite.

use rusqlite::Connection;
use xreserve_deposit_relayer_lite::store::Store;

fn nonce(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// T-S1 — what was written survives the handle being dropped and the file reopened.
#[test]
fn the_store_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");

    {
        let store = Store::open(&path).unwrap();
        store.mark_submitted(&nonce(1)).unwrap();
        store.set_cursor("cursor-after-page-1").unwrap();
    } // the handle is dropped: everything below reads the FILE, not this process's memory

    let reopened = Store::open(&path).unwrap();
    assert!(reopened.is_submitted(&nonce(1)).unwrap());
    assert_eq!(
        reopened.cursor().unwrap().as_deref(),
        Some("cursor-after-page-1")
    );
}

/// T-S2 — a first boot creates the file and reports an empty state rather than failing.
#[test]
fn a_first_boot_starts_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    assert!(!path.exists());

    let store = Store::open(&path).unwrap();

    assert!(path.exists());
    assert!(!store.is_submitted(&nonce(1)).unwrap());
    assert_eq!(store.cursor().unwrap(), None);
}

/// T-S3 — re-marking is a no-op, not an error.
///
/// This is load-bearing for an at-least-once relayer: after a crash it re-observes a deposit it
/// already recorded, and must be able to say so twice.
#[test]
fn re_marking_a_nonce_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("state.db")).unwrap();

    store.mark_submitted(&nonce(9)).unwrap();
    store.mark_submitted(&nonce(9)).unwrap();

    assert!(store.is_submitted(&nonce(9)).unwrap());
}

/// T-S4 — the cursor is replaced, never accumulated: the table holds exactly one row forever.
#[test]
fn the_cursor_never_accumulates_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let store = Store::open(&path).unwrap();

    store.set_cursor("first").unwrap();
    store.set_cursor("second").unwrap();
    store.set_cursor("third").unwrap();

    assert_eq!(store.cursor().unwrap().as_deref(), Some("third"));

    let rows: i64 = Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM cursor", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1, "the cursor table must hold exactly one row");
}

/// T-S5 — a store from a future schema version is REFUSED.
///
/// Never treated as empty: an empty store would re-submit every historical deposit.
#[test]
fn a_future_schema_version_refuses_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");

    Store::open(&path).unwrap();
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 99i64)
        .unwrap();

    let error = Store::open(&path).unwrap_err().to_string();
    assert!(
        error.contains("schema version 99"),
        "the refusal must name the version it found, got: {error}"
    );
}
