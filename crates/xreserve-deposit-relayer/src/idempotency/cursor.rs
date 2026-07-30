//! The per-remote-domain resume point: where the forward `Link` scan of a domain's attestation
//! stream left off.

use rusqlite::OptionalExtension;

use super::{
    rows::{corrupt, from_sql_seconds, store_failed, to_sql_seconds},
    store::IdempotencyStore,
};
use crate::error::RelayerError;

/// A remote domain's resume point: the `pageAfter` token of the last `Link` page the relayer
/// finished, and when it was stored.
///
/// The token is opaque — Circle's, base64, ordered by nothing the relayer can inspect — so the
/// store keeps exactly one per domain and REPLACES it. There is no "highest cursor wins" rule to be
/// had, and inventing one would be a fiction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub(super) remote_domain: u32,
    pub(super) page_after: String,
    pub(super) updated_at: u64,
}

impl Cursor {
    pub fn remote_domain(&self) -> u32 {
        self.remote_domain
    }

    /// The token to feed into the next [`crate::circle::pagination::BatchQuery::forward`].
    pub fn page_after(&self) -> &str {
        &self.page_after
    }

    /// When the cursor was last advanced (Unix seconds, from the store's
    /// [`Clock`](crate::idempotency::Clock)).
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }
}

impl IdempotencyStore {
    /// The resume point for `remote_domain` — `None` if the domain has never been scanned, which
    /// means "start at the beginning of the window" (NOT "resume from an empty cursor").
    ///
    /// # Errors
    /// [`RelayerError::CorruptStoreRecord`], [`RelayerError::IdempotencyStore`].
    pub fn read_cursor(&self, remote_domain: u32) -> Result<Option<Cursor>, RelayerError> {
        let conn = self.lock();

        conn.query_row(
            "SELECT remote_domain, page_after, updated_at FROM domain_cursor
             WHERE remote_domain = ?1",
            rusqlite::params![remote_domain],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(store_failed)?
        .map(|(domain, page_after, updated_at)| {
            Ok(Cursor {
                remote_domain: u32::try_from(domain)
                    .map_err(|_| corrupt(format!("remote domain {domain} is not a u32")))?,
                page_after,
                updated_at: from_sql_seconds(updated_at)?,
            })
        })
        .transpose()
    }

    /// Persists `page_after` as `remote_domain`'s resume point, REPLACING the previous one. Domains
    /// are independent: advancing one never moves another.
    ///
    /// Call it only AFTER every nonce on the page has been claimed — see the module docs on
    /// ordering. A crash between the two re-scans the page, which the nonce log absorbs; the
    /// reverse order would skip it, which nothing absorbs.
    ///
    /// # Errors
    /// [`RelayerError::EmptyCursor`] — an empty or whitespace-only token. It is not a resume point,
    /// and writing it would have DESTROYED the real one on its way in, so it is refused before the
    /// write.
    /// [`RelayerError::IdempotencyStore`] — the write failed.
    pub fn advance_cursor(
        &self,
        remote_domain: u32,
        page_after: &str,
    ) -> Result<Cursor, RelayerError> {
        if page_after.trim().is_empty() {
            return Err(RelayerError::EmptyCursor { remote_domain });
        }

        let now = self.clock.unix_seconds();
        let conn = self.lock();

        // one statement, so it is atomic on its own: the upsert either replaces the resume point or
        // creates it, and there is no window in which the domain has none
        conn.execute(
            "INSERT INTO domain_cursor (remote_domain, page_after, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(remote_domain) DO UPDATE SET page_after = excluded.page_after,
                                                      updated_at = excluded.updated_at",
            rusqlite::params![remote_domain, page_after, to_sql_seconds(now)?],
        )
        .map_err(store_failed)?;

        Ok(Cursor {
            remote_domain,
            page_after: page_after.to_string(),
            updated_at: now,
        })
    }
}
