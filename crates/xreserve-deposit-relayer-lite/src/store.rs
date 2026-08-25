//! The durable state: which deposits have been handed to the chain, and where we are in Circle's
//! feed.
//!
//! Two relations, one of which never exceeds a single row. There is no submission state machine and
//! no claim protocol: a nonce is in `submitted` or it is not. That single bit is a **fee
//! optimization** — it stops the relayer re-submitting a deposit the faucet would refuse — and not
//! a safety mechanism, because the authoritative replay guard is the faucet's on-chain
//! `usedNonces` assert.
//!
//! `mark_submitted` is called per attestation, the moment a submit is accepted, so a crash loses at
//! most the one in-flight submit. SQLite's transaction provides that; there is no write protocol
//! here to get wrong.

use std::path::Path;

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OptionalExtension};
use tracing::instrument;

/// The on-disk schema version, stamped in `PRAGMA user_version`. There is exactly one schema and no
/// upgrade path: a file from a future version is refused rather than guessed at.
const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS submitted (
    nonce BLOB NOT NULL PRIMARY KEY CHECK (length(nonce) = 32)
) STRICT;

CREATE TABLE IF NOT EXISTS cursor (
    id         INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
    page_after TEXT    NOT NULL CHECK (length(page_after) > 0)
) STRICT;
";

/// The submitted-nonce set plus the feed cursor, in one SQLite file.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens (creating if absent) the store at `path`.
    ///
    /// # Errors
    /// The file cannot be opened, or it carries a `user_version` this build does not know — which
    /// is refused rather than treated as empty, because an empty store would re-submit every
    /// historical deposit.
    #[instrument(name = "store.open", fields(path = %path.display()))]
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening the store at `{}`", path.display()))?;

        // WAL keeps a reader from blocking the writer. `journal_mode` answers with a row, so it is
        // a query rather than a pragma update.
        conn.query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        })
        .context("enabling WAL on the store")?;

        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .context("reading the store's schema version")?;

        match version {
            // a fresh file: create the schema and stamp it
            0 => {
                conn.execute_batch(SCHEMA)
                    .context("creating the store schema")?;
                conn.pragma_update(None, "user_version", SCHEMA_VERSION)
                    .context("stamping the store schema version")?;
            }
            v if v == SCHEMA_VERSION => {}
            other => bail!(
                "the store at `{}` has schema version {other}, but this build only knows version \
                 {SCHEMA_VERSION}",
                path.display()
            ),
        }

        Ok(Self { conn })
    }

    /// Whether this deposit has already been handed to the chain.
    #[instrument(level = "trace", name = "store.is_submitted", skip_all)]
    pub fn is_submitted(&self, nonce: &[u8; 32]) -> Result<bool> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM submitted WHERE nonce = ?1",
                [&nonce[..]],
                |row| row.get(0),
            )
            .optional()
            .context("reading the submitted-nonce set")?;

        Ok(found.is_some())
    }

    /// Records that this deposit has been handed to the chain.
    ///
    /// Re-marking an already-recorded nonce is a no-op, not an error: an at-least-once relayer
    /// re-observes a deposit after a crash and must be able to say so twice.
    #[instrument(level = "trace", name = "store.mark_submitted", skip_all)]
    pub fn mark_submitted(&self, nonce: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO submitted (nonce) VALUES (?1)",
                [&nonce[..]],
            )
            .context("recording a submitted nonce")?;

        Ok(())
    }

    /// Where the last completed scan got to, or `None` on a first boot.
    #[instrument(level = "trace", name = "store.cursor", skip_all)]
    pub fn cursor(&self) -> Result<Option<String>> {
        self.conn
            .query_row("SELECT page_after FROM cursor WHERE id = 0", [], |row| {
                row.get(0)
            })
            .optional()
            .context("reading the feed cursor")
    }

    /// Moves the cursor. The table holds one row forever — this replaces it.
    #[instrument(level = "debug", name = "store.set_cursor", skip(self))]
    pub fn set_cursor(&self, page_after: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO cursor (id, page_after) VALUES (0, ?1)
                 ON CONFLICT(id) DO UPDATE SET page_after = excluded.page_after",
                [page_after],
            )
            .context("advancing the feed cursor")?;

        Ok(())
    }
}
