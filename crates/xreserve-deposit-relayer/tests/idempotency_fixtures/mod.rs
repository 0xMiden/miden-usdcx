//! `tests/idempotency_fixtures/mod.rs` — the shared fixtures of the idempotency-seam suites
//! (`idempotency_claim`, `idempotency_status_machine`, `idempotency_restart`, `idempotency_tx_id`).
//!
//! Two things live here, and both exist so the suites can assert on EXACT values rather than on
//! coincidences:
//!
//! * [`ManualClock`] — the store's [`Clock`], moved by hand. A record's `timestamp` is then a
//!   checkable number, which is what makes "the re-observation did NOT rewrite the record" a real
//!   assertion (the clock moved; the stored value must not have).
//! * a store on a REAL file in a `tempfile` directory ([`fresh_store`] / [`open_at`]). Every
//!   "restart" in these suites is a genuine drop-and-reopen of the same path — the only way
//!   durability means anything. No suite ever opens an in-memory database; the store deliberately
//!   offers none.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tempfile::TempDir;
use xreserve_deposit_relayer::{
    error::RelayerError,
    idempotency::{
        ClaimOutcome, Clock, IdempotencyRecord, IdempotencyStore, SubmissionStatus, TxId,
    },
};

/// A clock the test moves by hand.
#[derive(Debug)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn at(seconds: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(seconds)))
    }

    /// Moves the clock forward. Every call site that advances it is a place where an unwanted
    /// rewrite of a stored record would become visible.
    pub fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn unix_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The one distinguishable DepositIntent nonce (DC-1 field 9) a test keys on.
pub fn nonce(tag: u8) -> [u8; 32] {
    [tag; 32]
}

/// The attestation envelope's `messageHash` (`keccak256(payload)`, DC-2) bound to that nonce.
pub fn message_hash(tag: u8) -> [u8; 32] {
    [tag.wrapping_add(0x80); 32]
}

pub fn tx_id(tag: u8) -> TxId {
    TxId::new([tag; 32])
}

/// The store file inside `dir` — the same path every "restart" reopens.
pub fn store_path(dir: &TempDir) -> PathBuf {
    dir.path().join("idempotency.sqlite3")
}

pub fn open_at(path: &Path, clock: &Arc<ManualClock>) -> IdempotencyStore {
    IdempotencyStore::open_with_clock(path, clock.clone() as Arc<dyn Clock>)
        .expect("the store opens on its path")
}

/// A store + the directory that owns its file (the `TempDir` must outlive the store, so it is
/// returned alongside it).
pub fn fresh_store(clock: &Arc<ManualClock>) -> (TempDir, IdempotencyStore) {
    let dir = TempDir::new().expect("temp dir");
    let store = open_at(&store_path(&dir), clock);
    (dir, store)
}

/// The store's view of a nonce's status — the assertion most tests end on.
pub fn status_of(store: &IdempotencyStore, key: &[u8; 32]) -> SubmissionStatus {
    store
        .record(key)
        .expect("the record reads back")
        .expect("the record exists")
        .status()
}

/// Claims `key` and asserts the claim was FRESH — the setup step of any test that then does
/// something to an owned record. Returns the claimed record.
pub fn claim(store: &IdempotencyStore, key: &[u8; 32], hash: &[u8; 32]) -> IdempotencyRecord {
    match store.claim_nonce(key, hash).expect("the claim answers") {
        ClaimOutcome::Claimed(record) => record,
        ClaimOutcome::AlreadySeen(record) => {
            panic!(
                "expected a fresh claim, got an already-seen {}",
                record.status()
            )
        }
    }
}

/// Drives a claimed nonce into `target` using ONLY the store's legal transitions — the setup helper
/// for every status-dependent test.
///
/// `Failed` is reached the way production reaches it (a submission that did not mint), and a
/// re-`Pending` is reached the way production reaches it (a retry CLAIM of a failed record) — the
/// helper never reaches behind the API to plant a status, so a test built on it cannot pass against
/// a store whose machine does not actually support the path.
pub fn drive_to(store: &IdempotencyStore, key: &[u8; 32], target: SubmissionStatus) {
    match target {
        SubmissionStatus::Pending => {}
        SubmissionStatus::Submitted => {
            store
                .record_submission(key, tx_id(1))
                .expect("pending -> submitted");
        }
        SubmissionStatus::Committed => {
            store
                .record_submission(key, tx_id(1))
                .expect("pending -> submitted");
            store
                .record_commit(key, 42)
                .expect("submitted -> committed");
        }
        SubmissionStatus::AlreadyMinted => {
            store
                .record_submission(key, tx_id(1))
                .expect("pending -> submitted");
            store
                .record_already_minted(key)
                .expect("submitted -> already minted");
        }
        SubmissionStatus::Failed => {
            store.record_failure(key).expect("pending -> failed");
        }
    }

    assert_eq!(
        status_of(store, key),
        target,
        "the setup helper must land the record in {target}"
    );
}

/// The transitions the status-machine tables exercise, applied through the store's public API.
#[derive(Debug, Clone, Copy)]
pub enum Transition {
    Submit,
    Commit,
    AlreadyMinted,
    Fail,
}

impl Transition {
    pub fn apply(
        self,
        store: &IdempotencyStore,
        key: &[u8; 32],
    ) -> Result<SubmissionStatus, RelayerError> {
        let record = match self {
            Self::Submit => store.record_submission(key, tx_id(9))?,
            Self::Commit => store.record_commit(key, 99)?,
            Self::AlreadyMinted => store.record_already_minted(key)?,
            Self::Fail => store.record_failure(key)?,
        };
        Ok(record.status())
    }

    /// The status this transition targets — the `to` a rejection must name.
    pub fn target(self) -> SubmissionStatus {
        match self {
            Self::Submit => SubmissionStatus::Submitted,
            Self::Commit => SubmissionStatus::Committed,
            Self::AlreadyMinted => SubmissionStatus::AlreadyMinted,
            Self::Fail => SubmissionStatus::Failed,
        }
    }
}
