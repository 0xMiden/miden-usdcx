//! The two liveness paths: freeing a claim a crash stranded, and finding the mints that still owe a
//! retry.
//!
//! Both exist because of the same asymmetry. The on-chain `usedNonces` assert makes a duplicate mint
//! *impossible*, so a redundant attempt costs a wasted transaction — while a mint this store forgets
//! to retry is a deposit that never arrives. Every trade here is made in that direction.

use super::{
    record::{IdempotencyRecord, SubmissionStatus},
    rows::{digest, row_to_record, store_failed, to_sql_seconds, RECORD_COLUMNS},
    store::{apply_transition, IdempotencyStore},
};
use crate::error::RelayerError;

impl IdempotencyStore {
    /// Frees the claims a crash stranded: `Pending` records older than `older_than_seconds` become
    /// `Failed` (i.e. re-claimable through [`IdempotencyStore::claim_nonce`]), and their nonces are
    /// returned.
    ///
    /// A relayer that dies between the claim and the submit leaves a `Pending` record that nothing
    /// retries — the deposit is stranded, the worst thing this store can do. Reclaiming carries a
    /// bounded risk in the other direction: if the original attempt DID reach the chain, the retry
    /// burns a transaction on the on-chain nonce assert and the record settles at
    /// [`SubmissionStatus::AlreadyMinted`]. That is the trade the whole module is built on.
    ///
    /// It touches nothing else — not a young `Pending` (its submit may be in flight this second), and
    /// not a `Submitted` (its transaction may still land; whether to abandon it is the submit leg's
    /// decision, made against the chain, not this store's against a clock). Re-running it is a no-op:
    /// a record it already freed is `Failed`, not `Pending`.
    ///
    /// # Errors
    /// [`RelayerError::CorruptStoreRecord`], [`RelayerError::IdempotencyStore`].
    pub fn reclaim_stale_pending(
        &self,
        older_than_seconds: u64,
    ) -> Result<Vec<[u8; 32]>, RelayerError> {
        let now = self.clock.unix_seconds();
        let cutoff = now.saturating_sub(older_than_seconds);

        self.write(|conn| {
            let stale: Vec<[u8; 32]> = conn
                .prepare(
                    "SELECT nonce_key FROM submitted_nonce
                     WHERE status = ?1 AND timestamp < ?2
                     ORDER BY timestamp, nonce_key",
                )
                .map_err(store_failed)?
                .query_map(
                    rusqlite::params![
                        SubmissionStatus::Pending.as_token(),
                        to_sql_seconds(cutoff)?
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(store_failed)?
                .map(|key| {
                    key.map_err(store_failed)
                        .and_then(|key| digest(&key, "nonce_key"))
                })
                .collect::<Result<_, _>>()?;

            // the UPDATE goes through the machine like every other status change, inside this same
            // transaction: a Pending that a submit leg moved out from under us between the SELECT and
            // here is refused by the edge check rather than silently re-failed
            for nonce_key in &stale {
                let current = super::rows::read_record(conn, nonce_key)?.ok_or(
                    RelayerError::UnknownNonce {
                        nonce_key: *nonce_key,
                    },
                )?;
                apply_transition(conn, &current, SubmissionStatus::Failed, None, None, now)?;
            }

            Ok(stale)
        })
    }

    /// The retry driver's work list: the `Failed` records, oldest first, at most `limit` of them.
    ///
    /// It exists because the cursor only moves FORWARD. A mint whose attempt failed sits on a page
    /// the poll has already passed, so no re-poll will ever re-observe its attestation — without this
    /// list, a failed deposit would be stranded exactly as surely as a forgotten `Pending`. Each
    /// record carries the `attestation_message_hash` its attestation can be re-fetched by (Circle's
    /// by-`depositMessageHash` endpoint), which is what the retry needs to rebuild the mint.
    ///
    /// This is a READ, and the caller does NOT act on it directly: it re-acquires each nonce through
    /// [`IdempotencyStore::claim_nonce`], which is the atomic step. Two retry drivers may therefore
    /// read the same work list, and still exactly one of them will mint each nonce.
    ///
    /// # Errors
    /// [`RelayerError::CorruptStoreRecord`], [`RelayerError::IdempotencyStore`].
    pub fn retryable(&self, limit: usize) -> Result<Vec<IdempotencyRecord>, RelayerError> {
        let conn = self.lock();

        let records: Vec<IdempotencyRecord> = conn
            .prepare(&format!(
                "SELECT {RECORD_COLUMNS} FROM submitted_nonce
                 WHERE status = ?1
                 ORDER BY timestamp, nonce_key
                 LIMIT ?2"
            ))
            .map_err(store_failed)?
            .query_map(
                rusqlite::params![
                    SubmissionStatus::Failed.as_token(),
                    i64::try_from(limit).unwrap_or(i64::MAX),
                ],
                |row| Ok(row_to_record(row)),
            )
            .map_err(store_failed)?
            .map(|row| row.map_err(store_failed).and_then(|record| record))
            .collect::<Result<_, _>>()?;

        Ok(records)
    }
}
