use crate::{config::Config, message::Message};
use alloy_primitives::B256;
use anyhow::{ensure, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
};

pub(crate) struct Store {
    pub db: Connection,
    // Fields drop in declaration order: SQLite must close before ownership ends.
    _lock: OwnershipLock,
}
struct OwnershipLock(File);
impl Drop for OwnershipLock {
    fn drop(&mut self) {
        // flock belongs to the open-file description. A descriptor inherited by a
        // concurrent fork can retain it briefly before exec, even after our close.
        // Release our ownership explicitly; the final close remains the fallback.
        let _ = self.0.unlock();
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Job {
    pub domain: u32,
    pub transaction: String,
}
#[derive(Clone, Debug)]
pub(crate) struct Pending {
    pub message: Message,
    pub eoa_nonce: u64,
    pub raw: Vec<u8>,
    pub hash: B256,
    pub created: i64,
}
impl Store {
    #[cfg(test)]
    pub fn retained_owner_descriptor(&self) -> std::io::Result<File> {
        self._lock.0.try_clone()
    }
    pub fn open(config: &Config, initialize: bool) -> Result<Self> {
        let path = &config.journal;
        let canonical = if path.exists() {
            path.canonicalize()?
        } else {
            path.parent()
                .context("journal parent missing")?
                .canonicalize()?
                .join(path.file_name().context("journal filename missing")?)
        };
        let mut sidecar = canonical.as_os_str().to_owned();
        sidecar.push(".ownership.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(sidecar)?;
        lock.try_lock().context("journal already owned")?;
        // Guard immediately so every later initialization/error path also unlocks.
        let lock = OwnershipLock(lock);
        if initialize {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .context("initialization requires nonexistent journal")?;
        }
        let mut db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        if initialize {
            let tx = db.transaction()?;
            tx.execute_batch(SCHEMA)?;
            tx.execute(
                "INSERT INTO meta (id, identity, next_nonce, halt, iris_after)
                 VALUES (1, ?, 0, NULL, 0)",
                [config.identity()?],
            )?;
            for source in &config.sources {
                tx.execute(
                    "INSERT INTO sources (domain, cursor, halt) VALUES (?, 'null', NULL)",
                    [source.domain],
                )?;
            }
            tx.commit()?;
        }
        ensure!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))? == 10,
            "unrecognized journal schema"
        );
        let identity: String =
            db.query_row("SELECT identity FROM meta WHERE id=1", [], |r| r.get(0))?;
        ensure!(
            identity == config.identity()?,
            "journal configuration identity mismatch"
        );
        ensure!(
            db.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? == "ok",
            "journal integrity failure"
        );
        ensure!(
            !db.prepare("PRAGMA foreign_key_check")?
                .query([])?
                .next()?
                .is_some(),
            "journal foreign key failure"
        );
        let store = Self { db, _lock: lock };
        ensure!(
            store.next_nonce()? <= i64::MAX as u64,
            "journal nonce overflow"
        );
        let pending = store.pending()?;
        let pending_messages: u64 = store.db.query_row(
            "SELECT count(*) FROM messages WHERE state='pending'",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            pending_messages == u64::from(pending.is_some()),
            "journal pending continuity mismatch"
        );
        if let Some(p) = pending {
            crate::arc::validate_saved(config, &p, store.next_nonce()?)?;
        }
        Ok(store)
    }
    pub fn next_nonce(&self) -> Result<u64> {
        Ok(self
            .db
            .query_row("SELECT next_nonce FROM meta WHERE id=1", [], |r| r.get(0))?)
    }
    pub fn halted(&self) -> Result<bool> {
        Ok(self
            .db
            .query_row("SELECT halt IS NOT NULL FROM meta WHERE id=1", [], |r| {
                r.get(0)
            })?)
    }
    pub fn halt(&self, reason: &'static str) -> Result<()> {
        if self.db.execute(
            "UPDATE meta SET halt=? WHERE id=1 AND halt IS NULL",
            [reason],
        )? == 1
        {
            if let Some(pending) = self.pending()? {
                tracing::error!(stage="sender_halt",reason,domain=pending.message.domain,source_tx=%pending.message.transaction,cctp_nonce=%pending.message.nonce,eoa_nonce=pending.eoa_nonce,arc_tx=%pending.hash,"sender halted; manual recovery required");
            } else {
                tracing::error!(
                    stage = "sender_halt",
                    reason,
                    eoa_nonce = self.next_nonce()?,
                    "sender halted; manual recovery required"
                );
            }
        }
        Ok(())
    }
    pub fn source_halt(&self, domain: u32, reason: &'static str) -> Result<()> {
        if self.db.execute(
            "UPDATE sources SET halt=? WHERE domain=? AND halt IS NULL",
            params![reason, domain],
        )? == 1
        {
            tracing::error!(
                stage = "source_halt",
                reason,
                domain,
                "source history halted"
            );
        }
        Ok(())
    }
    pub fn cursor(&self, domain: u32) -> Result<Option<Value>> {
        let (cursor, halt): (String, Option<String>) = self.db.query_row(
            "SELECT cursor,halt FROM sources WHERE domain=?",
            [domain],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(if halt.is_some() {
            None
        } else {
            Some(serde_json::from_str(&cursor)?)
        })
    }
    pub fn capacity(&self, config: &Config) -> Result<bool> {
        let count = reserved_work(&self.db)?;
        Ok(count < config.queue_capacity)
    }
    pub fn page(
        &mut self,
        config: &Config,
        domain: u32,
        page: &crate::discovery::Page,
    ) -> Result<bool> {
        if !self.capacity(config)? {
            return Ok(false);
        }
        let tx = self.db.transaction()?;
        let mut transitions = Vec::new();
        for candidate in &page.transactions {
            ensure!(
                !candidate.positions.is_empty() && candidate.positions.len() <= 1000,
                "invalid candidate count"
            );
            let positions = serde_json::to_string(&candidate.positions)?;
            let old: Option<String> = tx
                .query_row(
                    "SELECT positions FROM source_txs WHERE domain=? AND hash=?",
                    params![domain, candidate.transaction],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(old) = old {
                if old != positions
                    && manual(
                        &tx,
                        domain,
                        &candidate.transaction,
                        "source position conflict",
                    )?
                {
                    transitions.push((
                        domain,
                        candidate.transaction.clone(),
                        "source position conflict",
                    ));
                }
            } else {
                tx.execute(
                    "INSERT INTO source_txs
                        (domain, hash, positions, expected, state, next_poll, reason)
                     VALUES (?, ?, ?, ?, ?, 0, ?)",
                    params![
                        domain,
                        candidate.transaction,
                        positions,
                        candidate.positions.len(),
                        if candidate.manual {
                            "manual"
                        } else {
                            "pending"
                        },
                        if candidate.manual {
                            Some("unsupported helper event")
                        } else {
                            None
                        }
                    ],
                )?;
                if candidate.manual {
                    transitions.push((
                        domain,
                        candidate.transaction.clone(),
                        "unsupported helper event",
                    ));
                }
            }
        }
        let count = reserved_work(&tx)?;
        if count > config.queue_capacity {
            return Ok(false);
        }
        tx.execute(
            "UPDATE sources SET cursor=? WHERE domain=? AND halt IS NULL",
            params![serde_json::to_string(&page.cursor)?, domain],
        )?;
        tx.commit()?;
        for (domain, hash, reason) in transitions {
            log_manual(domain, &hash, reason);
        }
        Ok(true)
    }
    pub fn due(&self, now: i64) -> Result<Option<Job>> {
        Ok(self
            .db
            .query_row(
                "SELECT t.domain, t.hash
             FROM source_txs t
             JOIN sources s ON s.domain = t.domain
             WHERE t.state = 'pending'
               AND s.halt IS NULL
               AND t.next_poll <= ?
               AND (SELECT iris_after FROM meta WHERE id = 1) <= ?
             ORDER BY t.next_poll, t.rowid
             LIMIT 1",
                params![now, now],
                |row| {
                    Ok(Job {
                        domain: row.get("domain")?,
                        transaction: row.get("hash")?,
                    })
                },
            )
            .optional()?)
    }
    pub fn postpone(&self, job: &Job, time: i64) -> Result<()> {
        self.db.execute(
            "UPDATE source_txs SET next_poll=? WHERE domain=? AND hash=?",
            params![time, job.domain, job.transaction],
        )?;
        Ok(())
    }
    pub fn cooldown(&self, time: i64) -> Result<()> {
        self.db
            .execute("UPDATE meta SET iris_after=? WHERE id=1", [time])?;
        Ok(())
    }
    pub fn manual(&self, job: &Job, reason: &'static str) -> Result<()> {
        if manual(&self.db, job.domain, &job.transaction, reason)? {
            log_manual(job.domain, &job.transaction, reason);
        }
        Ok(())
    }
    pub fn admit(&mut self, job: &Job, messages: &[Message], now: i64) -> Result<()> {
        // Union validated reply messages by global CCTP nonce. The source occurrence count
        // bounds admission; a nonce/content conflict quarantines both owners atomically.
        let tx = self.db.transaction()?;
        let expected: usize = tx.query_row(
            "SELECT expected FROM source_txs WHERE domain=? AND hash=? AND state='pending'",
            params![job.domain, job.transaction],
            |r| r.get(0),
        )?;
        let mut fresh = BTreeMap::<B256, &Message>::new();
        let mut conflict = None;
        for message in messages {
            ensure!(
                message.domain == job.domain && message.transaction == job.transaction,
                "message owner mismatch"
            );
            let old: Option<(u32, String, Vec<u8>)> = tx
                .query_row(
                    "SELECT domain,source_tx,message FROM messages WHERE nonce=?",
                    [message.nonce.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            if let Some((domain, hash, bytes)) = old {
                if domain != job.domain || hash != job.transaction || bytes != message.bytes {
                    conflict = Some((domain, hash));
                    break;
                }
            } else if let Some(prior) = fresh.insert(message.nonce, message) {
                if prior.bytes != message.bytes {
                    conflict = Some((job.domain, job.transaction.clone()));
                    break;
                }
            }
        }
        let count: usize = tx.query_row(
            "SELECT count(*) FROM messages WHERE domain=? AND source_tx=?",
            params![job.domain, job.transaction],
            |r| r.get(0),
        )?;
        let mut transitions = Vec::new();
        if conflict.is_some() || count + fresh.len() > expected {
            if manual(
                &tx,
                job.domain,
                &job.transaction,
                "Circle nonce/count conflict",
            )? {
                transitions.push((
                    job.domain,
                    job.transaction.clone(),
                    "Circle nonce/count conflict",
                ));
            }
            if let Some((domain, hash)) = conflict {
                if manual(&tx, domain, &hash, "Circle nonce/owner conflict")? {
                    transitions.push((domain, hash, "Circle nonce/owner conflict"));
                }
            }
        } else {
            for message in fresh.values() {
                tx.execute(
                    "INSERT INTO messages
                        (nonce, domain, source_tx, message, attestation, state, next_try)
                     VALUES (?, ?, ?, ?, ?, 'queued', 0)",
                    params![
                        message.nonce.to_string(),
                        job.domain,
                        job.transaction,
                        message.bytes,
                        message.attestation
                    ],
                )?;
            }
            // Source 'complete' means every expected unique message was admitted,
            // not that Arc settlement or Miden delivery has happened.
            tx.execute(
                "UPDATE source_txs SET state=?,next_poll=? WHERE domain=? AND hash=?",
                params![
                    if count + fresh.len() == expected {
                        "complete"
                    } else {
                        "pending"
                    },
                    now + 15,
                    job.domain,
                    job.transaction
                ],
            )?;
        }
        tx.commit()?;
        for (domain, hash, reason) in transitions {
            log_manual(domain, &hash, reason);
        }
        Ok(())
    }
    pub fn ready(&self, now: i64) -> Result<Option<Message>> {
        Ok(self
            .db
            .query_row(
                "SELECT m.nonce, m.domain, m.source_tx, m.message, m.attestation
             FROM messages m
             JOIN source_txs t ON t.domain = m.domain AND t.hash = m.source_tx
             JOIN sources s ON s.domain = m.domain
             WHERE m.state = 'queued'
               AND m.next_try <= ?
               AND t.state != 'manual'
               AND s.halt IS NULL
             ORDER BY m.next_try, m.rowid
             LIMIT 1",
                [now],
                read_message,
            )
            .optional()?)
    }
    pub fn postpone_message(&self, nonce: B256, time: i64) -> Result<()> {
        self.db.execute(
            "UPDATE messages SET next_try=? WHERE nonce=? AND state='queued'",
            params![time, nonce.to_string()],
        )?;
        Ok(())
    }
    pub fn received(&self, nonce: B256) -> Result<()> {
        // 'received' records finalized used-CCTP-nonce suppression of an unsigned
        // sponsorship. It is not our receipt, an xReserve intent or Miden delivery.
        self.db.execute(
            "UPDATE messages SET state='received' WHERE nonce=? AND state='queued'",
            [nonce.to_string()],
        )?;
        Ok(())
    }
    pub fn pending(&self) -> Result<Option<Pending>> {
        Ok(self
            .db
            .query_row(
                "SELECT m.nonce, m.domain, m.source_tx, m.message, m.attestation,
                    p.eoa_nonce, p.raw, p.hash, p.created
             FROM pending p
             JOIN messages m ON m.nonce = p.nonce
             WHERE p.id = 1",
                [],
                |row| {
                    let hash: String = row.get("hash")?;
                    let hash = hash.parse().map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok(Pending {
                        message: read_message(row)?,
                        eoa_nonce: row.get("eoa_nonce")?,
                        raw: row.get("raw")?,
                        hash,
                        created: row.get("created")?,
                    })
                },
            )
            .optional()?)
    }

    pub fn save_pending(&mut self, p: &Pending) -> Result<()> {
        let tx = self.db.transaction()?;
        ensure!(
            tx.query_row(
                "SELECT next_nonce FROM meta WHERE id=1 AND halt IS NULL",
                [],
                |r| r.get::<_, u64>(0)
            )? == p.eoa_nonce,
            "sender nonce mismatch"
        );
        tx.execute(
            "INSERT INTO pending (id, nonce, eoa_nonce, raw, hash, created)
             VALUES (1, ?, ?, ?, ?, ?)",
            params![
                p.message.nonce.to_string(),
                p.eoa_nonce,
                p.raw,
                p.hash.to_string(),
                p.created
            ],
        )?;
        ensure!(
            tx.execute(
                "UPDATE messages SET state='pending' WHERE nonce=? AND state='queued'",
                [p.message.nonce.to_string()]
            )? == 1,
            "message not queued"
        );
        tx.commit()?;
        Ok(())
    }
    pub fn settle(&mut self, p: &Pending, success: bool) -> Result<()> {
        let next = p
            .eoa_nonce
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .context("sender nonce overflow")?;
        let tx = self.db.transaction()?;
        ensure!(
            tx.execute(
                "DELETE FROM pending WHERE id=1 AND hash=?",
                [p.hash.to_string()]
            )? == 1,
            "pending receipt mismatch"
        );
        // 'success' is our finalized helper receipt. 'reverted' is terminal manual
        // work: the paid EOA nonce advances, but this message never re-arms itself.
        tx.execute(
            "UPDATE messages SET state=? WHERE nonce=?",
            params![
                if success { "success" } else { "reverted" },
                p.message.nonce.to_string()
            ],
        )?;
        tx.execute("UPDATE meta SET next_nonce=? WHERE id=1", [next])?;
        tx.commit()?;
        if !success {
            tracing::error!(stage="settlement",reason="paid_revert",domain=p.message.domain,source_tx=%p.message.transaction,cctp_nonce=%p.message.nonce,eoa_nonce=p.eoa_nonce,arc_tx=%p.hash,"finalized helper transaction reverted; automatic retry disabled");
        }
        Ok(())
    }
}
fn read_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<Message> {
    let nonce: String = row.get(0)?;
    Ok(Message {
        nonce: nonce.parse().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        domain: row.get(1)?,
        transaction: row.get(2)?,
        bytes: row.get(3)?,
        attestation: row.get(4)?,
    })
}
fn log_manual(domain: u32, hash: &str, reason: &'static str) {
    tracing::error!(
        stage = "source_manual",
        reason,
        domain,
        source_tx = hash,
        "source transaction requires manual review"
    );
}
fn manual(db: &Connection, domain: u32, hash: &str, reason: &'static str) -> Result<bool> {
    let previous: String = db.query_row(
        "SELECT state FROM source_txs WHERE domain=? AND hash=?",
        params![domain, hash],
        |row| row.get(0),
    )?;
    db.execute(
        "UPDATE source_txs SET state='manual',reason=? WHERE domain=? AND hash=?",
        params![reason, domain, hash],
    )?;
    db.execute(
        "UPDATE messages SET state='manual' WHERE domain=? AND source_tx=? AND state='queued'",
        params![domain, hash],
    )?;
    Ok(previous != "manual")
}
// Missing messages from active sources reserve occurrence slots. Admitted queued
// and pending messages occupy those slots until terminal; the same reservation
// must not be counted again when Circle supplies its message.
fn reserved_work(db: &Connection) -> rusqlite::Result<usize> {
    db.query_row(
        "SELECT
            (SELECT coalesce(sum(
                t.expected - (SELECT count(*) FROM messages m
                              WHERE m.domain = t.domain AND m.source_tx = t.hash)
            ), 0) FROM source_txs t WHERE t.state = 'pending')
            + (SELECT count(*) FROM messages WHERE state IN ('queued', 'pending'))",
        [],
        |row| row.get(0),
    )
}

const SCHEMA: &str = "
CREATE TABLE meta (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    identity TEXT NOT NULL,
    next_nonce INTEGER NOT NULL,
    halt TEXT,
    iris_after INTEGER NOT NULL
);
CREATE TABLE sources (
    domain INTEGER PRIMARY KEY,
    cursor TEXT NOT NULL,
    halt TEXT
);
CREATE TABLE source_txs (
    domain INTEGER NOT NULL REFERENCES sources(domain),
    hash TEXT NOT NULL,
    positions TEXT NOT NULL,
    expected INTEGER NOT NULL,
    state TEXT NOT NULL,
    next_poll INTEGER NOT NULL,
    reason TEXT,
    PRIMARY KEY(domain, hash)
);
CREATE TABLE messages (
    nonce TEXT PRIMARY KEY,
    domain INTEGER NOT NULL,
    source_tx TEXT NOT NULL,
    message BLOB NOT NULL,
    attestation BLOB NOT NULL,
    state TEXT NOT NULL,
    next_try INTEGER NOT NULL,
    FOREIGN KEY(domain, source_tx) REFERENCES source_txs(domain, hash)
);
CREATE TABLE pending (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    nonce TEXT NOT NULL UNIQUE REFERENCES messages(nonce),
    eoa_nonce INTEGER NOT NULL,
    raw BLOB NOT NULL,
    hash TEXT NOT NULL,
    created INTEGER NOT NULL
);
PRAGMA user_version = 10;
";
