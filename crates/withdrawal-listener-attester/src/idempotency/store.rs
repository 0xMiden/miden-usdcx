//! The SQLite ledger: the file it opens, the CLAIM, and the status transitions.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension};

use super::{
    clock::{Clock, SystemClock},
    error::{corrupt, store_failed},
    record::{BurnKey, ClaimOutcome, SubmissionRecord, SubmissionStatus},
    LedgerError,
};

/// The ledger layout this build speaks, stamped into the file's `user_version`. A file carrying any
/// other version is REFUSED at open rather than read with the wrong layout.
pub const LEDGER_SCHEMA_VERSION: u32 = 1;

/// How long a write waits for a database another process holds. It exists for the
/// two-listeners-one-file case: the loser of a race for the same burn must WAIT for the winner's
/// transaction to commit and then OBSERVE it, rather than fail (and certainly rather than proceed).
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Read-write, create-if-absent — `rusqlite`'s default set minus `SQLITE_OPEN_URI`, which it turns on
/// and this ledger has no use for.
///
/// **Clearing that flag does not disable URI filenames, and this does not pretend it does.** The
/// pinned `libsqlite3-sys` compiles the bundled amalgamation with `-DSQLITE_USE_URI`, which enables
/// URI interpretation for every connection regardless of the open flags. The flag is intent; the
/// enforcement is [`assert_backed_by_a_file`].
const OPEN_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(OpenFlags::SQLITE_OPEN_CREATE)
    .union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// The ledger's one table. `STRICT`, so SQLite enforces the column types and a foreign writer cannot
/// leave a blob where text belongs.
///
/// The `status` column deliberately carries NO `CHECK (status IN (…))`. The authority on what a status
/// means is [`SubmissionStatus`], and a token it does not know must reach
/// [`LedgerError::CorruptLedgerRecord`] — a typed, operator-visible refusal — rather than be bounced at
/// the storage layer of whichever writer produced it.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS submitted_burn (
    burn_key      TEXT    NOT NULL PRIMARY KEY CHECK (length(burn_key) > 0),
    withdrawal_id TEXT,
    status        TEXT    NOT NULL,
    timestamp     INTEGER NOT NULL
) STRICT;
";

/// The columns [`row_to_record`] reads, in order.
const RECORD_COLUMNS: &str = "burn_key, withdrawal_id, status, timestamp";

/// The durable per-burn submitted-log, in one SQLite file.
///
/// The connection is behind a `Mutex` so the ledger is `Sync` and one `Arc<SubmitLedger>` can be shared
/// by every task that submits. Cross-PROCESS serialization is SQLite's own (a `BEGIN IMMEDIATE` write
/// transaction + a busy timeout) — which is what makes the claim atomic for two listeners pointed at
/// one file, not merely for two tasks in one.
#[derive(Debug)]
pub struct SubmitLedger {
    conn: Mutex<Connection>,
    clock: Arc<dyn Clock>,
}

impl SubmitLedger {
    /// Opens (creating if absent) the ledger at `path`, on the host's wall clock.
    ///
    /// `path` must be a real file, and that is checked TWICE — before opening (the reserved names) and
    /// after (where SQLite actually put the database). Both doors are needed because SQLite's names for
    /// a database that vanishes on close (`:memory:`, an empty filename, a `mode=memory` URI) are
    /// ordinary-looking filenames an operator's config can carry, and every one of them would have
    /// opened cleanly, taken a claim, and lost it on restart — at which point the same burn is
    /// submitted again.
    ///
    /// # Errors
    /// * [`LedgerError::EphemeralStorePath`] — the path is one of those.
    /// * [`LedgerError::Store`] — the file cannot be opened or created.
    /// * [`LedgerError::UnsupportedLedgerSchema`] — the file was written with a different layout.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        Self::open_with_clock(path, Arc::new(SystemClock))
    }

    /// [`Self::open`], with the clock injected — the seam a test drives by hand.
    ///
    /// # Errors
    /// As [`Self::open`].
    pub fn open_with_clock(
        path: impl AsRef<Path>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, LedgerError> {
        let path = path.as_ref();
        durable_path(path)?;

        let conn = Connection::open_with_flags(path, OPEN_FLAGS).map_err(store_failed)?;
        assert_backed_by_a_file(&conn, path)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(store_failed)?;

        // WAL keeps a reader (an operator query, a metrics scrape) from blocking the writer.
        // synchronous = FULL is the point of the whole module: a committed claim is fsynced before the
        // call returns, so `kill -9` — or the box losing power — cannot take back a submission the
        // listener believes it recorded, and thereby authorize a second one.
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
                conn.pragma_update(None, "user_version", LEDGER_SCHEMA_VERSION)
                    .map_err(store_failed)?;
            }
            v if v == LEDGER_SCHEMA_VERSION => {}
            found => {
                return Err(LedgerError::UnsupportedLedgerSchema {
                    found,
                    expected: LEDGER_SCHEMA_VERSION,
                })
            }
        }

        Ok(Self {
            conn: Mutex::new(conn),
            clock,
        })
    }

    // ---- THE CLAIM ------------------------------------------------------------------------------

    /// **The dedup, and the ONLY submit-decision point.** Claims every key in `keys` for this caller,
    /// atomically and all-or-nothing. The caller submits on [`ClaimOutcome::Claimed`] and on nothing
    /// else.
    ///
    /// `pub(crate)`, and that is a fund-safety boundary rather than tidiness. This function IS the
    /// authority to send a burn to Circle. Exposed publicly, any caller — the W9 orchestration being
    /// the concrete one — could claim a burn outside the one code path that then actually submits it,
    /// or race the claim that [`submit_withdraw`](crate::submit::submit_withdraw) is mid-request on.
    /// In-crate, the discipline that `submit_withdraw` is the only caller is checkable in one module;
    /// across a crate boundary it is a convention nobody can enforce.
    ///
    /// The check and the write are ONE `BEGIN IMMEDIATE` transaction, so of two callers racing on the
    /// same burn — two discovery passes, two processes mid-deploy — exactly one gets `Claimed`.
    ///
    /// Per key:
    /// * **unseen** → a fresh [`SubmissionStatus::Pending`] row;
    /// * **failed** → the RE-CLAIM: `Failed → Pending`, this caller alone owns the retry. This is why
    ///   there is no `Failed → Submitted` edge — the retry is acquired HERE, atomically, or not at all;
    ///   reading "not submitted" and then submitting is the read-then-write race the ledger exists to
    ///   prevent;
    /// * **anything else** ([`blocks_resubmission`](SubmissionStatus::blocks_resubmission)) →
    ///   [`ClaimOutcome::AlreadySeen`], the whole set rolls back, and the stored record is not touched:
    ///   not its status, not its timestamp. The log says when the submission happened, not when it was
    ///   last looked at.
    ///
    /// All-or-nothing matters because a `POST /v1/withdraw` carries 1–5 batches and is one indivisible
    /// call: if any burn in it is already accounted for, the request cannot go out, and a partial claim
    /// would then strand the others in `Pending` — which, having no automatic reclaim, means an
    /// operator has to free every one of them by hand.
    ///
    /// # Errors
    /// * [`LedgerError::CorruptLedgerRecord`] — an existing row cannot be read. NEVER treated as
    ///   absent.
    /// * [`LedgerError::IllegalStatusTransition`] — the re-claim edge was refused.
    /// * [`LedgerError::Store`] — the write failed.
    pub(crate) fn claim_burns(&self, keys: &[BurnKey]) -> Result<ClaimOutcome, LedgerError> {
        let now = self.clock.unix_seconds();

        self.write(|conn| {
            let mut claimed = Vec::with_capacity(keys.len());
            for key in keys {
                match read_record(conn, key)? {
                    Some(existing) if existing.status().blocks_resubmission() => {
                        // the ONE refusal — and it aborts the whole set. Returning Ok here would
                        // COMMIT the earlier keys' claims; this must roll back, so the caller's
                        // `write` sees an Err. See `ClaimAborted` below.
                        return Err(ClaimAborted::AlreadySeen(Box::new(existing)));
                    }
                    // Failed: the re-claim, through the same machine edge every transition uses
                    Some(existing) => {
                        let reclaimed =
                            apply_transition(conn, &existing, SubmissionStatus::Pending, None, now)
                                .map_err(ClaimAborted::Ledger)?;
                        claimed.push(reclaimed);
                    }
                    None => {
                        let record = SubmissionRecord {
                            burn_key: key.clone(),
                            withdrawal_id: None,
                            status: SubmissionStatus::Pending,
                            timestamp: now,
                        };
                        conn.execute(
                            "INSERT INTO submitted_burn (burn_key, withdrawal_id, status, timestamp)
                             VALUES (?1, NULL, ?2, ?3)",
                            rusqlite::params![
                                record.burn_key.as_str(),
                                record.status.as_token(),
                                to_sql_seconds(record.timestamp).map_err(ClaimAborted::Ledger)?,
                            ],
                        )
                        .map_err(|e| ClaimAborted::Ledger(store_failed(e)))?;
                        claimed.push(record);
                    }
                }
            }
            Ok(ClaimOutcome::Claimed(claimed))
        })
        // An `AlreadySeen` is not a failure of the ledger — it is an ANSWER. It travels out as an Err
        // only so the write transaction rolls the partial claims back, and is converted here.
        .or_else(|aborted| match aborted {
            ClaimAborted::AlreadySeen(record) => Ok(ClaimOutcome::AlreadySeen(*record)),
            ClaimAborted::Ledger(err) => Err(err),
        })
    }

    /// The ledger entry for `key` — `None` if this burn has never been seen. (`None` and
    /// `Some(Pending)` are different states: "never observed" and "mid-flight".)
    ///
    /// This is a READ. On its own it is NOT a dedup: between this call and the submission that follows
    /// it, another caller can claim the same burn. Decide with [`Self::claim_burns`]; use this to
    /// answer questions.
    ///
    /// # Errors
    /// [`LedgerError::CorruptLedgerRecord`], [`LedgerError::Store`].
    pub fn record(&self, key: &BurnKey) -> Result<Option<SubmissionRecord>, LedgerError> {
        let conn = self.lock();
        read_record(&conn, key).map_err(ClaimAborted::into_ledger)
    }

    // ---- THE TRANSITIONS ------------------------------------------------------------------------

    /// `Pending → Submitted`: Circle answered `201` and the withdrawal exists. The burn is never
    /// re-sent after this.
    ///
    /// # Errors
    /// [`LedgerError::UnknownBurn`], [`LedgerError::IllegalStatusTransition`].
    pub fn record_submission(
        &self,
        key: &BurnKey,
        withdrawal_id: Option<&str>,
    ) -> Result<SubmissionRecord, LedgerError> {
        self.transition(key, SubmissionStatus::Submitted, withdrawal_id)
    }

    /// `Pending | Submitted → Finalized`: the withdrawal reached the ONE terminal success. Terminal.
    ///
    /// # Errors
    /// [`LedgerError::UnknownBurn`], [`LedgerError::IllegalStatusTransition`].
    pub fn record_finalized(
        &self,
        key: &BurnKey,
        withdrawal_id: Option<&str>,
    ) -> Result<SubmissionRecord, LedgerError> {
        self.transition(key, SubmissionStatus::Finalized, withdrawal_id)
    }

    /// `Pending | Submitted → ReconciliationRequired`: an OPERATOR must resolve this burn. Terminal
    /// and blocking — every ambiguity lands here, and what they share is that Circle may already be
    /// releasing the funds.
    ///
    /// # Errors
    /// [`LedgerError::UnknownBurn`], [`LedgerError::IllegalStatusTransition`].
    pub fn record_reconciliation_required(
        &self,
        key: &BurnKey,
        withdrawal_id: Option<&str>,
    ) -> Result<SubmissionRecord, LedgerError> {
        self.transition(key, SubmissionStatus::ReconciliationRequired, withdrawal_id)
    }

    /// `Pending → Failed`: Circle rejected the request deterministically, so nothing was created. The
    /// burn goes back into the re-claimable pool — the next [`Self::claim_burns`] re-acquires it.
    ///
    /// `pub(crate)`, for the same reason as [`Self::claim_burns`] and with a sharper edge: this is the
    /// ONE transition that makes a claimed burn re-claimable again. The status machine already refuses
    /// it from [`SubmissionStatus::Submitted`], but `Pending` is the dangerous state — a burn mid-POST,
    /// which may already have reached Circle. An external caller walking a `Pending` burn to `Failed`
    /// would put it straight back in the pool for a second submission; only the code that owns the
    /// request knows the request deterministically failed, and that code is in this crate.
    ///
    /// # Errors
    /// [`LedgerError::UnknownBurn`]; [`LedgerError::IllegalStatusTransition`] — most importantly from
    /// [`SubmissionStatus::Submitted`]: a burn Circle has ACCEPTED must never become re-claimable.
    pub(crate) fn record_failure(&self, key: &BurnKey) -> Result<SubmissionRecord, LedgerError> {
        self.transition(key, SubmissionStatus::Failed, None)
    }

    // ---- INTERNALS ------------------------------------------------------------------------------

    /// The ONE place a status changes from outside a claim: read the record, ask the machine whether
    /// the edge exists, write — all inside one write transaction, so a concurrent transition cannot
    /// slip between the check and the write. A refused transition leaves the record untouched.
    fn transition(
        &self,
        key: &BurnKey,
        to: SubmissionStatus,
        withdrawal_id: Option<&str>,
    ) -> Result<SubmissionRecord, LedgerError> {
        let now = self.clock.unix_seconds();
        let withdrawal_id = withdrawal_id.map(str::to_string);

        self.write(|conn| {
            let current = read_record(conn, key)?.ok_or_else(|| {
                ClaimAborted::Ledger(LedgerError::UnknownBurn {
                    burn_tx_id: key.as_str().to_string(),
                })
            })?;
            apply_transition(conn, &current, to, withdrawal_id.clone(), now)
                .map_err(ClaimAborted::Ledger)
        })
        .map_err(ClaimAborted::into_ledger)
    }

    /// Runs `f` inside a `BEGIN IMMEDIATE` transaction: the write lock is taken UP FRONT, so a
    /// read-then-write (the claim, every transition) cannot interleave with another process's. On any
    /// error the transaction rolls back — a refused claim or transition leaves the ledger exactly as it
    /// was.
    fn write<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, ClaimAborted>,
    ) -> Result<T, ClaimAborted> {
        let conn = self.lock();
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| ClaimAborted::Ledger(store_failed(e)))?;

        match f(&conn) {
            Ok(value) => {
                conn.execute_batch("COMMIT")
                    .map_err(|e| ClaimAborted::Ledger(store_failed(e)))?;
                Ok(value)
            }
            Err(err) => {
                // the original answer is what the caller needs; a rollback that itself fails (the
                // connection is gone) must not mask it
                let _ = conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    /// The connection, RECOVERING a poisoned lock rather than propagating the panic: a panic in one
    /// caller's transaction (which SQLite rolls back anyway) must not take the whole listener's ledger
    /// offline — and a listener with no ledger is a listener that re-submits. The state behind the lock
    /// is SQLite's, guaranteed by SQLite's own transactions; there is no half-updated Rust state a
    /// poisoned guard would be protecting.
    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The two ways a write transaction ends early.
///
/// [`ClaimOutcome::AlreadySeen`] is an ANSWER, not a failure — but it must ROLL THE TRANSACTION BACK
/// (so a multi-burn claim leaves nothing half-claimed), and the only thing `write` rolls back on is an
/// `Err`. Rather than make `LedgerError` carry a variant that does not mean "error", the two travel out
/// together in this crate-private type and are separated at the surface.
#[derive(Debug)]
enum ClaimAborted {
    AlreadySeen(Box<SubmissionRecord>),
    Ledger(LedgerError),
}

impl ClaimAborted {
    /// For the paths that CANNOT produce an `AlreadySeen` (a read, a transition): the ledger error.
    fn into_ledger(self) -> LedgerError {
        match self {
            Self::Ledger(err) => err,
            // unreachable by construction: only `claim_burns` builds an AlreadySeen
            Self::AlreadySeen(record) => corrupt(format!(
                "internal: an already-seen claim escaped a non-claim path for burn `{}`",
                record.burn_key
            )),
        }
    }
}

/// The machine check + the write, for a record already read inside the caller's transaction. Every
/// status change — the transitions AND the re-claim — funnels through here, so there is exactly one
/// place that can move a burn.
///
/// `withdrawal_id` is set when the transition carries one and otherwise LEFT ALONE: a later transition
/// must not erase the id an operator needs to poll.
///
/// # Errors
/// [`LedgerError::IllegalStatusTransition`] — the machine has no `current → to` edge.
fn apply_transition(
    conn: &Connection,
    current: &SubmissionRecord,
    to: SubmissionStatus,
    withdrawal_id: Option<String>,
    now: u64,
) -> Result<SubmissionRecord, LedgerError> {
    if !current.status().can_transition_to(to) {
        return Err(LedgerError::IllegalStatusTransition {
            from: current.status(),
            to,
        });
    }

    let updated = SubmissionRecord {
        withdrawal_id: withdrawal_id.or_else(|| current.withdrawal_id.clone()),
        status: to,
        timestamp: now,
        ..current.clone()
    };

    conn.execute(
        "UPDATE submitted_burn SET withdrawal_id = ?1, status = ?2, timestamp = ?3
         WHERE burn_key = ?4",
        rusqlite::params![
            updated.withdrawal_id,
            updated.status.as_token(),
            to_sql_seconds(updated.timestamp)?,
            updated.burn_key.as_str(),
        ],
    )
    .map_err(store_failed)?;

    Ok(updated)
}

/// The row for `key`, or `None` if the ledger has never seen it.
///
/// Nothing here trusts the database: a row may have been written by a build with a different layout or
/// by a hand-edited `UPDATE`, so the status token and the timestamp are CHECKED on the way out and a
/// row that does not make sense becomes [`LedgerError::CorruptLedgerRecord`]. There is no safe default
/// — guessing "not submitted" re-releases funds.
fn read_record(conn: &Connection, key: &BurnKey) -> Result<Option<SubmissionRecord>, ClaimAborted> {
    // two nested results, meaning different things: the OUTER is SQLite's (was there a row?), the INNER
    // is ours (does the row make sense?). Flattening the inner one into `None` would report an
    // already-submitted burn as never seen — so it is transposed out, not swallowed.
    let row: Option<Result<SubmissionRecord, LedgerError>> = conn
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM submitted_burn WHERE burn_key = ?1"),
            rusqlite::params![key.as_str()],
            |row| Ok(row_to_record(row)),
        )
        .optional()
        .map_err(store_failed)
        .map_err(ClaimAborted::Ledger)?;

    row.transpose().map_err(ClaimAborted::Ledger)
}

fn row_to_record(row: &rusqlite::Row<'_>) -> Result<SubmissionRecord, LedgerError> {
    let burn_key = BurnKey::new(row.get::<_, String>(0).map_err(store_failed)?);
    let withdrawal_id = row.get::<_, Option<String>>(1).map_err(store_failed)?;
    let token = row.get::<_, String>(2).map_err(store_failed)?;
    let status = SubmissionStatus::parse(&token)
        .ok_or_else(|| corrupt(format!("`{token}` is not a submission status")))?;
    let timestamp = from_sql_seconds(row.get::<_, i64>(3).map_err(store_failed)?)?;

    Ok(SubmissionRecord {
        burn_key,
        withdrawal_id,
        status,
        timestamp,
    })
}

/// SQLite integers are signed 64-bit; the ledger's seconds are unsigned. Both conversions are CHECKED —
/// a timestamp that does not survive the round trip is a corrupt row, never a wrapped number.
fn to_sql_seconds(seconds: u64) -> Result<i64, LedgerError> {
    i64::try_from(seconds).map_err(|_| corrupt(format!("timestamp {seconds} does not fit an i64")))
}

fn from_sql_seconds(seconds: i64) -> Result<u64, LedgerError> {
    u64::try_from(seconds).map_err(|_| corrupt(format!("timestamp {seconds} is negative")))
}

/// Door 1 — the names SQLite reserves, refused before anything is opened.
///
/// Two of SQLite's ephemeral databases are spelled as plain filenames, so they reach the ledger the same
/// way any config value does:
///
/// * **`:memory:`** — an in-memory database, gone when the connection closes;
/// * an **empty** filename — a private temporary database SQLite deletes on close.
///
/// The comparison trims whitespace and ignores case. That is deliberately STRICTER than SQLite, which
/// would happily create files literally named `:MEMORY:` or `  ` — because an operator who writes
/// `:MEMORY:` MEANS the in-memory database, and a ledger that honoured the typo by creating a bizarrely
/// named file would obey the letter of the request while betraying its intent. A path that merely
/// RESEMBLES a special one (`memory.sqlite3`, `weird:name.sqlite3`) is an ordinary file and is accepted.
///
/// The `file:` URI forms are NOT rejected here — a `file:` URI can be perfectly durable, and only SQLite
/// can say whether a given one landed on disk. That is [`assert_backed_by_a_file`]'s job.
fn durable_path(path: &Path) -> Result<(), LedgerError> {
    let rendered = path.as_os_str().to_string_lossy();
    let normalized = rendered.trim().to_ascii_lowercase();

    let refuse = |detail: &str| {
        Err(LedgerError::EphemeralStorePath {
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
/// `pragma_database_list` reports an EMPTY file for a database with no file behind it: an in-memory one,
/// a temporary one, or any `file:` URI whose parameters selected one (`mode=memory`, and the
/// `cache=shared` spellings of it). This is the check that ENFORCES durability, because it does not
/// depend on recognizing a spelling — and the spellings cannot be closed off at the flag level: the
/// pinned `libsqlite3-sys` builds SQLite with `-DSQLITE_USE_URI`, so URI filenames are interpreted
/// whatever [`OPEN_FLAGS`] says.
///
/// It is what makes the ledger's promise checkable rather than assumed: the database the listener just
/// opened is on disk, or the listener does not start.
fn assert_backed_by_a_file(conn: &Connection, path: &Path) -> Result<(), LedgerError> {
    let file: String = conn
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get(0),
        )
        .map_err(store_failed)?;

    if file.trim().is_empty() {
        return Err(LedgerError::EphemeralStorePath {
            path: path.as_os_str().to_string_lossy().to_string(),
            detail: "sqlite opened it with no file behind it — the database would vanish when the \
                     connection closes, taking the submitted-burn log with it, and the next run would \
                     submit every burn again"
                .to_string(),
        });
    }

    Ok(())
}

// TESTS
// ================================================================================================
//
// In their own file (G3: tests live in their own module/file, not inline with the implementation),
// and inside the crate because they drive the `pub(crate)` transitions `tests/` cannot reach.
//
// `#[path]` because `store.rs` is a leaf module: without it a child would have to live at
// `store/store_tests.rs`, burying the file one directory away from the code it tests for no reason
// other than rustc's lookup rule.
#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;
