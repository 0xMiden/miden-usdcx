//! The SQLite store: the file it opens, the CLAIM, and the status transitions.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags};

use super::{
    clock::{Clock, SystemClock},
    record::{ClaimOutcome, IdempotencyRecord, SubmissionStatus, TxId},
    rows::{read_record, store_failed, to_sql_seconds, write_status},
};
use crate::error::RelayerError;

/// The store layout this build speaks, stamped into the file's `user_version`. A file carrying any
/// other version is REFUSED at open ([`RelayerError::UnsupportedStoreSchema`]) rather than read with
/// the wrong layout — silently misreading a cursor is exactly the failure the store exists to
/// prevent, and a migration is an operator's deliberate act, not a side effect of a restart.
///
/// Bumped to 2 when the terminal `rejected` status token was added ([`SubmissionStatus::Rejected`]):
/// a store this build writes can now hold a token an older build's `from_token` would read as
/// corruption, so an older binary opening a newer file must be refused with the clean
/// "unsupported schema" verdict, not left to trip over the unknown token row by row.
pub const STORE_SCHEMA_VERSION: u32 = 2;

/// How long a write waits for a database another process holds before giving up. It exists for the
/// two-relayers-one-file case: the loser of a race for the same nonce must wait for the winner's
/// transaction to commit and then OBSERVE it, rather than fail.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Read-write, create-if-absent — `rusqlite`'s default set minus `SQLITE_OPEN_URI`, which it turns
/// on and this store has no use for.
///
/// **Clearing that flag does not disable URI filenames, and the store does not pretend it does.** The
/// pinned `libsqlite3-sys` compiles the bundled amalgamation with `-DSQLITE_USE_URI`, which enables
/// URI interpretation for every connection regardless of the open flags. So a *filename* like
/// `file:idempotency?mode=memory` really is read as a URI, and really does open a database that is
/// never written to disk — the flag is intent, not enforcement. The enforcement is
/// [`assert_backed_by_a_file`], which asks SQLite where the database actually landed.
const OPEN_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(OpenFlags::SQLITE_OPEN_CREATE)
    .union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// The store's tables. Both are `STRICT` (SQLite enforces the column types, so a foreign writer
/// cannot leave a string where a blob belongs) and both `CHECK` the width of every digest they hold.
///
/// The `status` column deliberately carries NO `CHECK (status IN (…))`. That is not an oversight: the
/// authority on what a status means is [`SubmissionStatus`], and a token it does not know must reach
/// [`RelayerError::CorruptStoreRecord`] — a typed, operator-visible refusal — rather than be bounced
/// at the storage layer of whichever writer produced it. The Rust parser is the one guard, and it is
/// the guard the tests exercise.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS submitted_nonce (
    nonce_key                BLOB    NOT NULL PRIMARY KEY CHECK (length(nonce_key) = 32),
    attestation_message_hash BLOB    NOT NULL CHECK (length(attestation_message_hash) = 32),
    submitted_tx_id          BLOB    CHECK (submitted_tx_id IS NULL OR length(submitted_tx_id) = 32),
    block_num                INTEGER CHECK (block_num IS NULL OR block_num >= 0),
    status                   TEXT    NOT NULL,
    timestamp                INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS domain_cursor (
    remote_domain INTEGER NOT NULL PRIMARY KEY,
    page_after    TEXT    NOT NULL CHECK (length(page_after) > 0),
    updated_at    INTEGER NOT NULL
) STRICT;
";

/// The durable seam: the submitted-nonce log + the per-remote-domain cursor, in one SQLite file.
///
/// The connection is behind a `Mutex` so the store is `Sync` and one `Arc<IdempotencyStore>` can be
/// shared by the poll task and the submit task. Cross-PROCESS serialization is SQLite's own (a
/// `BEGIN IMMEDIATE` write transaction + the crate-private `BUSY_TIMEOUT`) — which is what makes the claim atomic for
/// two relayers pointed at one file, not merely for two tasks in one.
#[derive(Debug)]
pub struct IdempotencyStore {
    pub(super) conn: Mutex<Connection>,
    pub(super) clock: Arc<dyn Clock>,
}

impl IdempotencyStore {
    /// Opens (creating if absent) the store at `path`, on the host's wall clock.
    ///
    /// `path` must be a real file. It is validated (the crate-private `durable_path`) BEFORE anything is opened, and
    /// the opened database is then checked to have a file behind it — because SQLite's names for a
    /// database that vanishes on close (`:memory:`, an empty filename, a `mode=memory` URI) are
    /// ordinary-looking filenames that an operator's config can carry, and every one of them would
    /// have opened cleanly, taken a claim, taken a cursor advance, and lost both on restart.
    ///
    /// # Errors
    /// [`RelayerError::EphemeralStorePath`] — `path` is one of those: it is refused rather than
    /// silently turned into a cache.
    /// [`RelayerError::IdempotencyStore`] — the file cannot be opened or created (a missing parent
    /// directory, a permission, a full disk). A relayer that cannot open its store must fail at
    /// startup, loudly: running without one means re-minting after the next restart.
    /// [`RelayerError::UnsupportedStoreSchema`] — the file was written with a different layout.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RelayerError> {
        Self::open_with_clock(path, Arc::new(SystemClock))
    }

    /// [`Self::open`], with the clock injected — the seam a test drives by hand.
    ///
    /// # Errors
    /// As [`Self::open`].
    pub fn open_with_clock(
        path: impl AsRef<Path>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, RelayerError> {
        let path = path.as_ref();
        durable_path(path)?;

        let conn = Connection::open_with_flags(path, OPEN_FLAGS).map_err(store_failed)?;
        assert_backed_by_a_file(&conn, path)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(store_failed)?;

        // WAL keeps a reader (an operator query, a metrics scrape) from blocking the writer.
        // synchronous = FULL is the point of the whole module: a committed claim, or a committed
        // cursor advance, is fsynced before the call returns, so `kill -9` — or the box losing power
        // — cannot take back a mint the relayer believes it recorded.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(store_failed)?;

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(store_failed)?;

        match version {
            // a file nobody has stamped yet: ours to create
            0 => {
                conn.execute_batch(SCHEMA).map_err(store_failed)?;
                conn.pragma_update(None, "user_version", STORE_SCHEMA_VERSION)
                    .map_err(store_failed)?;
            }
            // our own file
            v if v == STORE_SCHEMA_VERSION => {}
            // a v1 file from a base build: MIGRATE it. The table layout is byte-identical to v2 and
            // every v1 status token (`pending`/`submitted`/`committed`/`already_minted`/`failed`) is a
            // subset of v2's — v2 only ADDED `rejected`, which a v1 file cannot contain — so every v1
            // row is already a valid v2 row and the migration is a version re-stamp, no data
            // transform. It preserves the nonce log and the cursor: an operator upgrading the durable
            // relayer must not lose the replay-prevention state, and deleting the file to recover
            // would discard exactly that. The re-stamp is a single atomic pragma write.
            1 => {
                conn.pragma_update(None, "user_version", STORE_SCHEMA_VERSION)
                    .map_err(store_failed)?;
            }
            // a version this build does not know (a NEWER layout): refuse it rather than read a cursor
            // out of the wrong columns. Migration is for the known past, never a blind accept.
            found => {
                return Err(RelayerError::UnsupportedStoreSchema {
                    found,
                    expected: STORE_SCHEMA_VERSION,
                })
            }
        }

        Ok(Self {
            conn: Mutex::new(conn),
            clock,
        })
    }

    // ---- the claim ------------------------------------------------------------------------------

    /// **The dedup, and the ONLY mint-decision point.** Claims `nonce_key` for this observer,
    /// atomically — the check and the write are ONE `BEGIN IMMEDIATE` transaction, so of two
    /// observers racing on the same nonce exactly one gets [`ClaimOutcome::Claimed`]. The caller
    /// mints on `Claimed` and on nothing else.
    ///
    /// Three cases, one call:
    /// * **unseen** → a fresh `Pending` record. `Claimed`.
    /// * **failed** → the RETRY claim: the record moves `Failed → Pending` (the failed attempt's
    ///   transaction id is kept as evidence) and this observer, alone, owns the retry. `Claimed`.
    ///   This is why there is no `Failed → Submitted` edge: the retry is acquired here, atomically,
    ///   or not at all — reading "not submitted" and then submitting is the race this module exists
    ///   to prevent.
    /// * **anything else** (in flight, submitted, committed, already minted) → `AlreadySeen`, and the
    ///   stored record is not touched: not its status, not its timestamp. The log says when the mint
    ///   happened, not when it was last looked at.
    ///
    /// # Errors
    /// [`RelayerError::NonceMessageHashMismatch`] — the nonce is claimed by an attestation with a
    /// DIFFERENT `messageHash`. At most one of the two describes the deposit that actually happened;
    /// the store keeps the one it recorded and refuses the newcomer (in EVERY status — the retry
    /// claim is not a way in for an impostor), so the operator sees the anomaly.
    /// [`RelayerError::CorruptStoreRecord`] — the existing row cannot be read. It is never treated as
    /// absent: that would re-claim, and re-mint, a nonce that may already be settled.
    /// [`RelayerError::IdempotencyStore`] — the write failed.
    pub fn claim_nonce(
        &self,
        nonce_key: &[u8; 32],
        attestation_message_hash: &[u8; 32],
    ) -> Result<ClaimOutcome, RelayerError> {
        let now = self.clock.unix_seconds();

        self.write(|conn| {
            if let Some(existing) = read_record(conn, nonce_key)? {
                if existing.attestation_message_hash() != attestation_message_hash {
                    return Err(RelayerError::NonceMessageHashMismatch {
                        nonce_key: *nonce_key,
                        stored: *existing.attestation_message_hash(),
                        observed: *attestation_message_hash,
                    });
                }

                if existing.status().blocks_resubmission() {
                    return Ok(ClaimOutcome::AlreadySeen(existing));
                }

                // the retry claim (Failed -> Pending). It goes through the SAME machine edge check as
                // every other transition — the machine is the one authority on what may happen to a
                // mint — and through the same write transaction, so it is as atomic as a first claim
                let reclaimed =
                    apply_transition(conn, &existing, SubmissionStatus::Pending, None, None, now)?;
                return Ok(ClaimOutcome::Claimed(reclaimed));
            }

            let record = IdempotencyRecord {
                nonce_key: *nonce_key,
                attestation_message_hash: *attestation_message_hash,
                submitted_tx_id: None,
                block_num: None,
                status: SubmissionStatus::Pending,
                timestamp: now,
            };

            conn.execute(
                "INSERT INTO submitted_nonce (nonce_key, attestation_message_hash, submitted_tx_id,
                                              block_num, status, timestamp)
                 VALUES (?1, ?2, NULL, NULL, ?3, ?4)",
                rusqlite::params![
                    &record.nonce_key[..],
                    &record.attestation_message_hash[..],
                    record.status.as_token(),
                    to_sql_seconds(record.timestamp)?,
                ],
            )
            .map_err(store_failed)?;

            Ok(ClaimOutcome::Claimed(record))
        })
    }

    /// Whether a second mint attempt for `nonce_key` must NOT be made — true for every status except
    /// [`SubmissionStatus::Failed`], and false for a nonce the store has never seen.
    ///
    /// This is a READ. On its own it is not a dedup: between this call and the mint that follows it,
    /// another observer can claim the same nonce. Decide with [`Self::claim_nonce`]; use this to
    /// answer questions.
    ///
    /// # Errors
    /// [`RelayerError::CorruptStoreRecord`] — the row's status is unreadable. It is NOT reported as
    /// "not submitted": that answer would re-mint a deposit that may already be on chain.
    /// [`RelayerError::IdempotencyStore`] — the read failed.
    pub fn is_nonce_submitted(&self, nonce_key: &[u8; 32]) -> Result<bool, RelayerError> {
        Ok(self
            .record(nonce_key)?
            .is_some_and(|record| record.status().blocks_resubmission()))
    }

    /// The log entry for `nonce_key` — `None` if the store has never seen it. (`None` and
    /// `Some(Pending)` are different states: "never observed" and "mid-flight".)
    ///
    /// # Errors
    /// [`RelayerError::CorruptStoreRecord`], [`RelayerError::IdempotencyStore`].
    pub fn record(&self, nonce_key: &[u8; 32]) -> Result<Option<IdempotencyRecord>, RelayerError> {
        let conn = self.lock();
        read_record(&conn, nonce_key)
    }

    // ---- the transitions ------------------------------------------------------------------------

    /// `Pending → Submitted`: the mint went out in `tx_id`.
    ///
    /// # Errors
    /// [`RelayerError::UnknownNonce`] — the nonce was never claimed. A submission cannot be recorded
    /// against a nonce with no attestation behind it.
    /// [`RelayerError::IllegalStatusTransition`] — from `Submitted` (the double-submit this seam
    /// exists to prevent) or from `Failed` (the retry must be re-CLAIMED first, atomically — see
    /// [`Self::claim_nonce`]).
    pub fn record_submission(
        &self,
        nonce_key: &[u8; 32],
        tx_id: TxId,
    ) -> Result<IdempotencyRecord, RelayerError> {
        self.transition(nonce_key, SubmissionStatus::Submitted, Some(tx_id), None)
    }

    /// `Submitted → Committed`: that transaction is in block `block_num`. Terminal.
    ///
    /// # Errors
    /// [`RelayerError::UnknownNonce`], [`RelayerError::IllegalStatusTransition`] — a commit for a
    /// transaction that was never submitted is refused.
    pub fn record_commit(
        &self,
        nonce_key: &[u8; 32],
        block_num: u32,
    ) -> Result<IdempotencyRecord, RelayerError> {
        self.transition(
            nonce_key,
            SubmissionStatus::Committed,
            None,
            Some(block_num),
        )
    }

    /// `* → AlreadyMinted`: the chain reports the nonce is already in `usedNonces` — the on-chain
    /// safety backstop has fired. Terminal: another attempt could only fail the same assert.
    ///
    /// # Errors
    /// [`RelayerError::UnknownNonce`], [`RelayerError::IllegalStatusTransition`] (a settled record
    /// cannot be re-settled).
    pub fn record_already_minted(
        &self,
        nonce_key: &[u8; 32],
    ) -> Result<IdempotencyRecord, RelayerError> {
        self.transition(nonce_key, SubmissionStatus::AlreadyMinted, None, None)
    }

    /// `Pending | Submitted | Failed → Failed`: the attempt did not mint. The nonce goes back into
    /// the retryable pool — [`Self::is_nonce_submitted`] answers `false` for it again, and the next
    /// [`Self::claim_nonce`] (or a retry driver working [`Self::retryable`]) re-acquires it.
    ///
    /// Any transaction id already recorded is KEPT: it is the evidence of what was sent, and an
    /// operator debugging a failed mint needs it.
    ///
    /// # Errors
    /// [`RelayerError::UnknownNonce`], [`RelayerError::IllegalStatusTransition`] (a committed or
    /// already-minted nonce cannot fail after the fact).
    pub fn record_failure(&self, nonce_key: &[u8; 32]) -> Result<IdempotencyRecord, RelayerError> {
        self.transition(nonce_key, SubmissionStatus::Failed, None, None)
    }

    /// `Pending → Rejected`: the mint was PERMANENTLY refused — a fatal node submit, or a note
    /// unit-04's factory would not build. Terminal, and the deliberate counterpart of
    /// [`Self::record_failure`]: a `Rejected` nonce is NOT re-claimable and NOT in the
    /// [`Self::retryable`] work list, so a permanently-refused transaction is never re-fetched and
    /// re-submitted on a later cycle. That is the whole reason the two are different transitions —
    /// recording a fatal refusal as `Failed` would loop the retry driver on it forever.
    ///
    /// # Errors
    /// [`RelayerError::UnknownNonce`] — the nonce was never claimed.
    /// [`RelayerError::IllegalStatusTransition`] — from any state other than `Pending`: a rejection
    /// can only settle a claimed-but-not-yet-submitted attempt, never overwrite a `Submitted` or an
    /// already-settled record.
    pub fn record_rejected(&self, nonce_key: &[u8; 32]) -> Result<IdempotencyRecord, RelayerError> {
        self.transition(nonce_key, SubmissionStatus::Rejected, None, None)
    }

    /// **Atomically re-stamp a `Failed` row's timestamp — but ONLY while it is still `Failed`.** The
    /// retry driver calls this to rotate a row it just re-attempted to the back of the timestamp-ordered
    /// work list, so a persistently-unfetchable head cannot starve the tail.
    ///
    /// The conditional is the whole point. [`Self::retryable`] is a NON-owning read that two drivers may
    /// observe, and the status machine permits `Pending → Failed` and `Submitted → Failed`. An
    /// unconditional re-stamp would let a late driver drag a row another driver has since CLAIMED
    /// (`Pending`) or SUBMITTED (`Submitted`) back into the retryable pool — losing that driver's mint
    /// and re-advertising the nonce. So the read and the conditional update are ONE `BEGIN IMMEDIATE`
    /// transaction: if the row is no longer `Failed`, nothing is written and `Ok(false)` is returned.
    ///
    /// Returns `Ok(true)` if the row was `Failed` and re-stamped, `Ok(false)` if it is gone or no longer
    /// `Failed` (a concurrent driver owns it — leave it be).
    ///
    /// # Errors
    /// [`RelayerError::CorruptStoreRecord`] — the row is unreadable (a foreign writer / a partial
    /// upgrade); PROPAGATED, never swallowed, because defaulting corruption either way strands or
    /// double-drives the deposit.
    /// [`RelayerError::IdempotencyStore`] — the read or the write failed.
    pub fn touch_failed_timestamp(&self, nonce_key: &[u8; 32]) -> Result<bool, RelayerError> {
        let now = self.clock.unix_seconds();
        self.write(|conn| match read_record(conn, nonce_key)? {
            // still Failed → re-stamp through the machine (the `Failed → Failed` edge re-timestamps).
            // A concurrent transition cannot slip between the read and the write: they are one
            // `BEGIN IMMEDIATE` transaction.
            Some(record) if record.status() == SubmissionStatus::Failed => {
                apply_transition(conn, &record, SubmissionStatus::Failed, None, None, now)?;
                Ok(true)
            }
            // gone, claimed, submitted, or settled — another driver owns it now; do not overwrite it
            _ => Ok(false),
        })
    }

    // ---- internals ------------------------------------------------------------------------------

    /// The ONE place a status changes from outside a claim: read the record, ask the machine whether
    /// the edge exists, write — all inside one write transaction, so a concurrent transition cannot
    /// slip between the check and the write. A refused transition leaves the record untouched (the
    /// transaction rolls back).
    pub(super) fn transition(
        &self,
        nonce_key: &[u8; 32],
        to: SubmissionStatus,
        tx_id: Option<TxId>,
        block_num: Option<u32>,
    ) -> Result<IdempotencyRecord, RelayerError> {
        let now = self.clock.unix_seconds();

        self.write(|conn| {
            let current = read_record(conn, nonce_key)?.ok_or(RelayerError::UnknownNonce {
                nonce_key: *nonce_key,
            })?;

            apply_transition(conn, &current, to, tx_id, block_num, now)
        })
    }

    /// Runs `f` inside a `BEGIN IMMEDIATE` transaction: the write lock is taken UP FRONT, so a
    /// read-then-write (the claim, every transition) cannot interleave with another process's. On any
    /// error the transaction rolls back — a refused claim or a refused transition leaves the store
    /// exactly as it was.
    pub(super) fn write<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, RelayerError>,
    ) -> Result<T, RelayerError> {
        let conn = self.lock();
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(store_failed)?;

        match f(&conn) {
            Ok(value) => {
                conn.execute_batch("COMMIT").map_err(store_failed)?;
                Ok(value)
            }
            Err(err) => {
                // the original error is what the caller needs; a rollback that itself fails (the
                // connection is gone) must not mask it
                let _ = conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    /// The connection, RECOVERING a poisoned lock rather than propagating the panic: a panic in one
    /// caller's transaction (which SQLite rolls back anyway) must not take the whole relayer's store
    /// offline. The state behind the lock is SQLite's, and SQLite's own transaction guarantees it —
    /// there is no half-updated Rust state a poisoned guard would be protecting.
    pub(super) fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Door 1 — the names SQLite reserves, refused before anything is opened.
///
/// Two of SQLite's ephemeral databases are spelled as plain filenames, so they reach the store the
/// same way any config value does:
///
/// * **`:memory:`** — an in-memory database. Gone when the connection closes.
/// * an **empty** filename — a private temporary database, which SQLite deletes on close.
///
/// The comparison trims surrounding whitespace and ignores case. That is deliberately STRICTER than
/// SQLite, which would happily create files literally named `:MEMORY:` or `  ` — because an operator
/// who writes `:MEMORY:` in a config means the in-memory database, and a store that honoured the
/// typo by creating a bizarrely-named file would be obeying the letter of the request while betraying
/// its intent. A path whose name merely RESEMBLES a special one (`memory.sqlite3`,
/// `weird:name.sqlite3`) is a perfectly ordinary file and is accepted: this rejects the two reserved
/// names, not every path with a colon in it.
///
/// The `file:` URI forms are NOT rejected here — a `file:` URI can be a perfectly durable database,
/// and only SQLite can say whether a given one ended up on disk. That is [`assert_backed_by_a_file`]'s
/// job.
///
/// # Errors
/// [`RelayerError::EphemeralStorePath`] — with the path echoed back (the operator has to find it in
/// their config) and the reason SQLite would not have made it durable.
fn durable_path(path: &Path) -> Result<(), RelayerError> {
    let rendered = path.as_os_str().to_string_lossy();
    let normalized = rendered.trim().to_ascii_lowercase();

    let refuse = |detail: &str| {
        Err(RelayerError::EphemeralStorePath {
            path: rendered.to_string(),
            detail: detail.to_string(),
        })
    };

    if normalized.is_empty() {
        refuse(
            "an empty filename opens a private temporary database that sqlite deletes when the \
             connection closes",
        )
    } else if normalized == ":memory:" {
        refuse("`:memory:` opens an in-memory database that vanishes when the connection closes")
    } else {
        Ok(())
    }
}

/// Door 2 — having opened the database, ask SQLite where it actually put it.
///
/// `pragma_database_list` reports an EMPTY file for a database with no file behind it: an in-memory
/// one, a temporary one, or any `file:` URI whose parameters selected one (`mode=memory`, and the
/// `cache=shared` spellings of it). This is the check that ENFORCES durability, because it does not
/// depend on recognizing a spelling — and the spellings cannot be closed off at the flag level: the
/// pinned `libsqlite3-sys` builds SQLite with `-DSQLITE_USE_URI`, so URI filenames are interpreted
/// whatever [`OPEN_FLAGS`] says.
///
/// It is what makes the store's promise checkable rather than assumed: the database the relayer just
/// opened is on disk, or the relayer does not start.
///
/// # Errors
/// [`RelayerError::EphemeralStorePath`] — the open database has no file behind it.
/// [`RelayerError::IdempotencyStore`] — the pragma itself failed.
fn assert_backed_by_a_file(conn: &Connection, path: &Path) -> Result<(), RelayerError> {
    let file: String = conn
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get(0),
        )
        .map_err(store_failed)?;

    if file.trim().is_empty() {
        return Err(RelayerError::EphemeralStorePath {
            path: path.as_os_str().to_string_lossy().to_string(),
            detail: "sqlite opened it with no file behind it — the database would vanish when the \
                     connection closes, taking the nonce log and the cursor with it"
                .to_string(),
        });
    }

    Ok(())
}

/// The machine check + the write, for a record already read inside the caller's transaction. Every
/// status change in the store — the transitions AND the retry claim — funnels through here, so there
/// is exactly one place that can move a mint.
///
/// # Errors
/// [`RelayerError::IllegalStatusTransition`] — the machine has no `current → to` edge.
pub(super) fn apply_transition(
    conn: &Connection,
    current: &IdempotencyRecord,
    to: SubmissionStatus,
    tx_id: Option<TxId>,
    block_num: Option<u32>,
    now: u64,
) -> Result<IdempotencyRecord, RelayerError> {
    if !current.status().can_transition_to(to) {
        return Err(RelayerError::IllegalStatusTransition {
            from: current.status(),
            to,
        });
    }

    write_status(conn, current, to, tx_id, block_num, now)
}
