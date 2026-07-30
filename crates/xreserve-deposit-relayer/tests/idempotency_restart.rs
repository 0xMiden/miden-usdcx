//! `tests/idempotency_restart.rs`: durability across a restart, the per-remote-domain `Link`
//! cursor, and the refusal to read a store this build did not write.
//!
//! Every "restart" here is a real one: the store handle is DROPPED and the same path is reopened
//! with a fresh handle. That is the only way the claim "the cursor survives a restart" means
//! anything — and it is why no test in this crate opens an in-memory database (the store offers
//! none).
//!
//! The cursor is the anti-rescan device: a restart must resume at the persisted `pageAfter` instead
//! of re-walking the window. The crash-ordering test pins the other side of the same coin — a page
//! whose nonces were recorded but whose cursor was NOT advanced is re-scanned on the next start,
//! and the nonce log turns that replay into zero second mint attempts.

mod idempotency_fixtures;

use std::sync::Arc;

use assert_matches::assert_matches;
use idempotency_fixtures::{
    claim, message_hash, nonce, open_at, status_of, store_path, tx_id, ManualClock,
};
use rstest::rstest;
use tempfile::TempDir;
use xreserve_deposit_relayer::{
    error::RelayerError,
    idempotency::{ClaimOutcome, Clock, IdempotencyStore, SubmissionStatus, STORE_SCHEMA_VERSION},
};

// -------------------------------------------------------------------------------------------------
// the cursor
// -------------------------------------------------------------------------------------------------

/// No cursor means "never scanned": the poll starts at the beginning of the window. It must not be
/// confused with an empty cursor (a `pageAfter=` the endpoint would reject).
#[test]
fn a_fresh_store_has_no_cursor() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let store = open_at(&store_path(&dir), &clock);

    assert_matches!(store.read_cursor(0), Ok(None));
    assert_matches!(store.read_cursor(7), Ok(None));
}

/// `advance_cursor` persists the `Link`-header `next` token and REPLACES the previous one: a
/// forward scan has exactly one resume point per domain, not a growing list.
#[test]
fn advance_cursor_persists_and_replaces_the_token() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let store = open_at(&store_path(&dir), &clock);

    let first = store.advance_cursor(7, "Y3Vyc29yLTE=").expect("advance");
    assert_eq!(first.remote_domain(), 7);
    assert_eq!(first.page_after(), "Y3Vyc29yLTE=");
    assert_eq!(first.updated_at(), 1_000);

    clock.advance(15);
    store
        .advance_cursor(7, "Y3Vyc29yLTI=")
        .expect("advance again");

    let cursor = store
        .read_cursor(7)
        .expect("read")
        .expect("a cursor exists");
    assert_eq!(cursor.page_after(), "Y3Vyc29yLTI=");
    assert_eq!(cursor.updated_at(), 1_015);
}

/// Each remote domain scans its own attestation stream, so each carries its own resume point.
/// Advancing one must never move another — that would skip (or replay) a whole domain's window.
#[test]
fn cursors_are_isolated_per_remote_domain() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let store = open_at(&store_path(&dir), &clock);

    store
        .advance_cursor(0, "ethereum-page-3")
        .expect("domain 0");
    store
        .advance_cursor(7, "avalanche-page-9")
        .expect("domain 7");
    store
        .advance_cursor(0, "ethereum-page-4")
        .expect("domain 0 again");

    assert_eq!(
        store
            .read_cursor(0)
            .expect("read")
            .expect("exists")
            .page_after(),
        "ethereum-page-4"
    );
    assert_eq!(
        store
            .read_cursor(7)
            .expect("read")
            .expect("exists")
            .page_after(),
        "avalanche-page-9",
        "advancing domain 0 moved domain 7's cursor"
    );
    assert_matches!(
        store.read_cursor(1),
        Ok(None),
        "an untouched domain gained a cursor"
    );
}

/// An empty (or whitespace) token is not a cursor. Persisting one would be sent as `pageAfter=` (a
/// request the endpoint rejects) or read back as "resume from nothing" — and, worst of all, it
/// would have DESTROYED the real resume point on its way in. So it is refused before the write.
#[rstest]
#[case::empty("")]
#[case::whitespace("   ")]
#[case::newline("\n")]
fn an_empty_cursor_token_is_refused_and_does_not_clobber_the_stored_one(#[case] token: &str) {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let store = open_at(&store_path(&dir), &clock);

    store.advance_cursor(7, "the-real-cursor").expect("advance");

    let err = store
        .advance_cursor(7, token)
        .expect_err("an empty cursor token must be refused");
    assert_matches!(err, RelayerError::EmptyCursor { remote_domain } => {
        assert_eq!(remote_domain, 7);
    });

    assert_eq!(
        store
            .read_cursor(7)
            .expect("read")
            .expect("exists")
            .page_after(),
        "the-real-cursor",
        "the refused advance destroyed the resume point"
    );
}

// -------------------------------------------------------------------------------------------------
// the restart
// -------------------------------------------------------------------------------------------------

/// Everything the seam knows survives the process. Drop the store (the restart), reopen the SAME
/// file with a fresh handle, and the nonce log and the cursor are exactly as they were: status,
/// transaction id, block number, attestation hash, timestamp, resume token.
#[test]
fn the_nonce_log_and_the_cursor_survive_a_restart() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    let before = {
        let store = open_at(&path, &clock);
        claim(&store, &nonce(1), &message_hash(1));
        clock.advance(5);
        store
            .record_submission(&nonce(1), tx_id(7))
            .expect("submit");
        clock.advance(5);
        store.record_commit(&nonce(1), 4_242).expect("commit");
        store.advance_cursor(7, "Y3Vyc29yLTI=").expect("advance");
        store.record(&nonce(1)).expect("read").expect("exists")
    }; // <- the process dies here

    let restarted = open_at(&path, &clock);

    assert!(
        restarted.is_nonce_submitted(&nonce(1)).expect("lookup"),
        "the nonce log did not survive the restart"
    );
    let after = restarted.record(&nonce(1)).expect("read").expect("exists");
    assert_eq!(after, before, "the record changed across the restart");
    assert_eq!(after.status(), SubmissionStatus::Committed);
    assert_eq!(after.submitted_tx_id(), Some(&tx_id(7)));
    assert_eq!(after.block_num(), Some(4_242));
    assert_eq!(after.timestamp(), 1_010);

    let cursor = restarted
        .read_cursor(7)
        .expect("read")
        .expect("the cursor did not survive the restart");
    assert_eq!(cursor.page_after(), "Y3Vyc29yLTI=");
}

/// The point of the cursor: a restart resumes AT the persisted token — it does not re-walk the
/// window from the beginning. The scan is modelled explicitly (a five-page window, a scan that got
/// through two of them), so "did not re-scan" is an assertion about the pages actually visited.
#[test]
fn a_restart_resumes_at_the_persisted_cursor_instead_of_rescanning_the_window() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    let window = ["page-1", "page-2", "page-3", "page-4", "page-5"];
    let pages_after = |cursor: Option<&str>| -> Vec<&str> {
        match cursor {
            None => window.to_vec(),
            Some(cursor) => {
                let seen = window
                    .iter()
                    .position(|page| *page == cursor)
                    .expect("a known page");
                window[seen + 1..].to_vec()
            }
        }
    };

    {
        let store = open_at(&path, &clock);
        assert_eq!(
            pages_after(
                store
                    .read_cursor(7)
                    .expect("read")
                    .as_ref()
                    .map(|cursor| cursor.page_after())
            ),
            window.to_vec(),
            "the first ever scan starts at the beginning of the window"
        );
        store.advance_cursor(7, "page-1").expect("scanned page 1");
        store.advance_cursor(7, "page-2").expect("scanned page 2");
    } // <- the process dies here

    let restarted = open_at(&path, &clock);
    let cursor = restarted
        .read_cursor(7)
        .expect("read")
        .expect("the cursor persisted");
    assert_eq!(cursor.page_after(), "page-2");

    assert_eq!(
        pages_after(Some(cursor.page_after())),
        vec!["page-3", "page-4", "page-5"],
        "the restart re-scanned pages it had already processed"
    );
}

/// The crash-ordering property the poll loop is built on. The relayer records a page's nonces
/// BEFORE it advances the cursor past that page; a crash in between therefore re-scans the page
/// (at-least-once observation) — and the nonce log turns the replay into zero second mint attempts
/// (exactly-once mint).
///
/// The counter is the real assertion: on the replay, `claim_nonce` answers `AlreadySeen` for every
/// nonce on the page, so the mint leg — which runs only on a `Claimed` — is never entered.
#[test]
fn a_crash_before_the_cursor_advance_replays_the_page_with_no_second_mint_attempt() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    let page = [nonce(1), nonce(2), nonce(3)];
    let hashes = [message_hash(1), message_hash(2), message_hash(3)];

    // one pass over the page, shaped like the real poll loop minus the Miden submit: a freshly
    // CLAIMED nonce is a mint attempt, an AlreadySeen one is not
    let process_page = |store: &IdempotencyStore| -> usize {
        let mut mint_attempts = 0;
        for (key, hash) in page.iter().zip(hashes.iter()) {
            match store.claim_nonce(key, hash).expect("the claim answers") {
                ClaimOutcome::Claimed(_) => {
                    mint_attempts += 1;
                    store.record_submission(key, tx_id(0xAA)).expect("submit");
                }
                ClaimOutcome::AlreadySeen(_) => {}
            }
        }
        mint_attempts
    };

    // the store handle is dropped at the end of this block WITHOUT a cursor advance — that drop IS
    // the crash: the page's nonces are durably recorded, the relayer's place in the stream is not
    let first_pass = {
        let store = open_at(&path, &clock);
        process_page(&store)
    };
    assert_eq!(
        first_pass, 3,
        "the first pass must mint every nonce on the page once"
    );

    let restarted = open_at(&path, &clock);
    assert_matches!(
        restarted.read_cursor(7),
        Ok(None),
        "the cursor was advanced before the crash — the page would not be re-scanned at all"
    );

    let second_pass = process_page(&restarted);
    assert_eq!(
        second_pass, 0,
        "the replayed page produced {second_pass} second mint attempt(s) — the log did not dedup"
    );

    for key in &page {
        assert_eq!(status_of(&restarted, key), SubmissionStatus::Submitted);
    }
}

/// The store is a file on disk, at the path it was given — not a cache with a filename.
#[test]
fn the_store_writes_to_the_file_it_was_given() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    let store = open_at(&path, &clock);
    claim(&store, &nonce(1), &message_hash(1));
    store.advance_cursor(7, "cursor").expect("advance");
    drop(store);

    let bytes = std::fs::metadata(&path)
        .expect("the store file exists")
        .len();
    assert!(bytes > 0, "the store file is empty — nothing was persisted");
}

// -------------------------------------------------------------------------------------------------
// a store this build cannot read is REFUSED, never guessed at
// -------------------------------------------------------------------------------------------------

/// A path the store cannot create is a typed error, not a panic: a relayer that cannot open its
/// idempotency store must say so at startup, not unwind inside a poll loop.
#[test]
fn opening_the_store_under_a_missing_directory_is_a_typed_error() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("no").join("such").join("dir").join("s.db");

    let err = IdempotencyStore::open_with_clock(&path, clock as Arc<dyn Clock>)
        .expect_err("an unopenable path must be an error");
    assert_matches!(err, RelayerError::IdempotencyStore(_));
}

/// A status string the store does not know is CORRUPTION — a foreign writer, a partial upgrade, a
/// hand-edited row. Defaulting it to "not submitted" would re-mint an already-minted deposit;
/// defaulting it the other way would strand one. So it is a typed error, and the operator decides.
#[test]
fn an_unknown_status_string_is_a_typed_corruption_error() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    let store = open_at(&path, &clock);
    claim(&store, &nonce(1), &message_hash(1));
    drop(store);

    // reach past the store's API and write a status it cannot know
    let raw = rusqlite::Connection::open(&path).expect("raw open");
    raw.execute("UPDATE submitted_nonce SET status = 'sideways'", [])
        .expect("raw update");
    drop(raw);

    let store = open_at(&path, &clock);
    assert_matches!(
        store.record(&nonce(1)),
        Err(RelayerError::CorruptStoreRecord { .. })
    );
    assert_matches!(
        store.is_nonce_submitted(&nonce(1)),
        Err(RelayerError::CorruptStoreRecord { .. }),
        "an unreadable status must never answer `not submitted` — that mints a duplicate"
    );
    assert_matches!(
        store.claim_nonce(&nonce(1), &message_hash(1)),
        Err(RelayerError::CorruptStoreRecord { .. }),
        "an unreadable status must never be re-claimed — that mints a duplicate"
    );
}

/// A database stamped with a schema version this build does not know is REFUSED at open. Reading a
/// layout written by a different version of the relayer is the one way a store can silently misread
/// (or lose) the cursor.
#[test]
fn a_store_written_by_an_unknown_schema_version_is_refused_at_open() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    let future = STORE_SCHEMA_VERSION + 1;
    let raw = rusqlite::Connection::open(&path).expect("raw open");
    raw.pragma_update(None, "user_version", future)
        .expect("stamp a future schema version");
    drop(raw);

    let err = IdempotencyStore::open_with_clock(&path, clock as Arc<dyn Clock>)
        .expect_err("a foreign schema must be refused");
    assert_matches!(err, RelayerError::UnsupportedStoreSchema { found, expected } => {
        assert_eq!(found, future);
        assert_eq!(expected, STORE_SCHEMA_VERSION);
    });
}

/// A store this build DID write reopens — the version guard must not reject its own files, which
/// would be a startup deadlock.
#[test]
fn a_store_written_by_this_build_reopens() {
    let clock = ManualClock::at(1_000);
    let dir = TempDir::new().expect("temp dir");
    let path = store_path(&dir);

    drop(open_at(&path, &clock));

    let raw = rusqlite::Connection::open(&path).expect("raw open");
    let version: u32 = raw
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read user_version");
    drop(raw);
    assert_eq!(
        version, STORE_SCHEMA_VERSION,
        "the store did not stamp its schema version"
    );

    open_at(&path, &clock);
}
