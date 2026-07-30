//! `tests/idempotency_durable_path.rs` — the store REFUSES a path that is not a durable file.
//!
//! The seam's whole contract is that the submitted-nonce log and the `Link` cursor survive a
//! restart, and the module says in as many words that there is no in-memory mode. But SQLite has
//! several spellings for a database that lives only as long as the connection, and they are
//! ordinary *filenames* — so an operator's config file, a typo, or a copied snippet could hand one
//! in:
//!
//! * `:memory:` — an in-memory database, gone when the connection closes;
//! * an **empty** filename — a private temporary database, which SQLite deletes on close;
//! * a `file:` **URI** with `mode=memory` (or `cache=shared` variants of it) — never written to
//!   disk. These are read as URIs rather than as filenames because the pinned `libsqlite3-sys`
//!   compiles SQLite with `-DSQLITE_USE_URI`, which enables URI interpretation for every connection
//!   — so it is not something the open flags can switch off.
//!
//! Every one of them would have opened cleanly, accepted a claim, accepted a cursor advance — and
//! lost both on restart. A store that can lose the cursor is exactly what this component must not
//! be, and "the operator should not type that" is not an engineering control. So the constructor
//! refuses them, before any state is written.
//!
//! The refusal has two independent doors, and the cases below exercise both:
//!
//! * the **reserved names** (`:memory:`, an empty filename) are refused before anything is opened;
//! * every other ephemeral spelling is caught AFTER the open, by asking SQLite where the database
//!   actually landed (`pragma_database_list` reports no file for one that is not on disk). That
//!   door is the load-bearing one for the URI forms, and it cannot be replaced by clearing
//!   `SQLITE_OPEN_URI`: the pinned `libsqlite3-sys` compiles SQLite with `-DSQLITE_USE_URI`, so URI
//!   filenames are interpreted no matter what the open flags say.
//!
//! What is NOT refused is a URI that is perfectly durable — `file:` + a real path writes a real
//! file, and locking an operator out of it would be a guard punishing syntax instead of the thing
//! that actually hurts. The positive tests pin that boundary from the other side.

use std::sync::Arc;

use assert_matches::assert_matches;
use rstest::rstest;
use tempfile::TempDir;
use xreserve_deposit_relayer::{
    error::RelayerError,
    idempotency::{Clock, IdempotencyStore, SystemClock},
};

/// Every SQLite spelling of "a database that is not a file". Each is refused by the constructor.
///
/// The first group is the reserved names (door 1). `:MEMORY:` and a padded `:memory: ` are in the
/// table on purpose: SQLite itself would create files with those literal names, but an operator who
/// writes them means the in-memory database — and a guard that can be walked past by holding down
/// shift is not a guard.
///
/// The `file:` group is the one door 1 cannot judge (a `file:` URI may be perfectly durable): those
/// are caught after the open, by SQLite reporting that the database has no file behind it.
#[rstest]
#[case::in_memory(":memory:")]
#[case::in_memory_uppercase(":MEMORY:")]
#[case::in_memory_padded(" :memory: ")]
#[case::empty("")]
#[case::whitespace("   ")]
#[case::uri_shared_memory("file::memory:")]
#[case::uri_named_memory("file:idempotency?mode=memory")]
#[case::uri_memory_shared_cache("file:idempotency?mode=memory&cache=shared")]
#[case::uri_memory_with_a_real_looking_path("file:/tmp/xusdc-idempotency.sqlite3?mode=memory")]
fn an_ephemeral_or_uri_store_path_is_refused(#[case] path: &str) {
    let err = IdempotencyStore::open(path)
        .expect_err("a path that is not a durable file must be refused at construction");

    // it is not retryable: retrying an operator's bad configuration forever, in a loop, is how a
    // relayer wedges without saying anything
    assert!(!err.is_retryable());

    assert_matches!(err, RelayerError::EphemeralStorePath { path: rejected, .. } => {
        assert_eq!(rejected, path, "the error must name the path it refused");
    });
}

/// The refusal is the CONSTRUCTOR's job, not a warning after the fact: no store exists, so nothing
/// can be claimed into it and nothing can be silently lost from it.
#[test]
fn an_in_memory_store_cannot_be_opened_at_all() {
    assert_matches!(
        IdempotencyStore::open(":memory:"),
        Err(RelayerError::EphemeralStorePath { .. })
    );
    assert_matches!(
        IdempotencyStore::open_with_clock(":memory:", Arc::new(SystemClock) as Arc<dyn Clock>),
        Err(RelayerError::EphemeralStorePath { .. }),
        "the clock-injecting constructor is the one the poll loop calls — it must refuse too"
    );
}

/// What the refusal is FOR, demonstrated on the real thing. This is the same sequence the auditor's
/// probe ran — claim a nonce, advance the cursor, restart — except against a durable path, where it
/// must hold. If `:memory:` were accepted, this exact sequence would come back empty, and the
/// relayer would re-scan the window and re-mint every nonce in it.
#[test]
fn a_real_file_path_is_accepted_and_keeps_the_cursor_across_a_restart() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("idempotency.sqlite3");

    {
        let store = IdempotencyStore::open(&path).expect("a real file path is accepted");
        store
            .claim_nonce(&[7; 32], &[8; 32])
            .expect("the claim succeeds");
        store
            .advance_cursor(7, "resume-me")
            .expect("the cursor advances");
    } // the restart

    let restarted = IdempotencyStore::open(&path).expect("the store reopens");

    assert_eq!(
        restarted
            .read_cursor(7)
            .expect("read")
            .expect("the cursor did not survive — the store is not durable")
            .page_after(),
        "resume-me"
    );
    assert!(
        restarted
            .is_nonce_submitted(&[7; 32])
            .expect("lookup succeeds"),
        "the nonce log did not survive — the store is not durable"
    );
}

/// The premise of the whole guard, checked against the pinned SQLite rather than assumed: a
/// `mode=memory` URI really does open a database that writes nothing and loses everything on close.
///
/// If SQLite ever stopped behaving this way, this test would fail — and that is the point. The
/// guard exists because of this behaviour; a test that only asserted "the store says no" would keep
/// passing long after the reason had evaporated, and nobody would know whether the refusal was
/// still earning its keep.
#[test]
fn a_memory_uri_really_does_lose_everything_and_the_store_refuses_it() {
    const EPHEMERAL: &str = "file:xusdc-idempotency-probe?mode=memory";

    // the same pinned SQLite the store is built on, opened the way rusqlite opens it by default
    let raw = rusqlite::Connection::open(EPHEMERAL).expect("sqlite opens the uri happily");
    raw.execute_batch(
        "CREATE TABLE cursor_probe (token TEXT); INSERT INTO cursor_probe VALUES ('resume-me');",
    )
    .expect("and accepts writes");

    let file: String = raw
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get(0),
        )
        .expect("pragma reads");
    assert!(
        file.is_empty(),
        "sqlite reports a file (`{file}`) for a mode=memory uri — the durability check's premise \
         has changed and the guard needs revisiting"
    );
    drop(raw);

    let reopened = rusqlite::Connection::open(EPHEMERAL).expect("reopens");
    let surviving: i64 = reopened
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name = 'cursor_probe'",
            [],
            |row| row.get(0),
        )
        .expect("pragma reads");
    assert_eq!(
        surviving, 0,
        "the written data survived the close — this is exactly what the store must never accept"
    );

    //...and that is the path the store refuses. (No file is left behind: nothing was ever written.)
    assert_matches!(
        IdempotencyStore::open(EPHEMERAL),
        Err(RelayerError::EphemeralStorePath { .. })
    );
}

/// A `file:` URI that names a REAL file is durable, and is accepted. The guard rejects databases
/// that vanish, not a syntax: refusing every URI would lock out an operator whose config is unusual
/// but perfectly safe — and would be a rule nobody could explain from first principles.
#[test]
fn a_uri_that_names_a_real_file_is_accepted_and_is_durable() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("idempotency.sqlite3");
    let uri = format!("file:{}", path.display());

    let store = IdempotencyStore::open(&uri).expect("a uri naming a real file is durable");
    store
        .advance_cursor(3, "uri-cursor")
        .expect("the cursor advances");
    drop(store);

    assert!(
        std::fs::metadata(&path).is_ok_and(|meta| meta.len() > 0),
        "the uri did not write the file it named"
    );

    // reopened by its PLAIN path: the same database, so the uri really did land here
    let reopened = IdempotencyStore::open(&path).expect("reopens by plain path");
    assert_eq!(
        reopened
            .read_cursor(3)
            .expect("read")
            .expect("the cursor persisted")
            .page_after(),
        "uri-cursor"
    );
}

/// A file whose NAME merely resembles a special one is still a file, and is accepted. The guard
/// must reject the databases SQLite treats as ephemeral, not every path with a colon or the word
/// `memory` in it — an over-eager check would lock an operator out of a perfectly good store.
#[rstest]
#[case::contains_memory("memory.sqlite3")]
#[case::mode_memory_in_the_name("idempotency-mode=memory.sqlite3")]
#[case::colon_in_the_name("weird:name.sqlite3")]
fn a_durable_file_whose_name_resembles_a_special_one_is_accepted(#[case] name: &str) {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join(name);

    let store = IdempotencyStore::open(&path).expect("a real file is a real file");
    store
        .advance_cursor(1, "cursor")
        .expect("the store works normally");
    drop(store);

    assert!(
        std::fs::metadata(&path)
            .expect("the store file exists on disk")
            .len()
            > 0,
        "the accepted path produced no file — it was not durable after all"
    );

    let restarted = IdempotencyStore::open(&path).expect("reopens");
    assert_eq!(
        restarted
            .read_cursor(1)
            .expect("read")
            .expect("the cursor persisted")
            .page_after(),
        "cursor"
    );
}
