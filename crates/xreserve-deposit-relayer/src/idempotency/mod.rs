//! The idempotency seam — the one-directional joint between the relayer's Circle half and its Miden
//! half.
//!
//! Everything upstream of this module is *observation*: Circle publishes an attestation, the poll
//! walks the `Link`-paginated stream, the envelope binds `messageHash == keccak256(payload)` and the
//! DepositIntent decodes. Everything downstream is *action*: a mint note is built and a Miden
//! transaction is submitted. The seam is what stops an observation seen twice from becoming an action
//! taken twice, and what stops a restart from losing the place it had reached.
//!
//! It holds exactly two things:
//!
//! * the **submitted-nonce log** — one [`IdempotencyRecord`] per DepositIntent `nonce` (DC-1 field
//!   9), carrying the attestation's `messageHash`, the Miden transaction the mint went out in, the
//!   block it committed in, and where it sits in the [`SubmissionStatus`] machine;
//! * the **per-remote-domain cursor** — the opaque `pageAfter` token from Circle's `Link` header
//!   ([`crate::circle::pagination`]), so a restarted relayer resumes at the page it had reached
//!   instead of re-walking the whole window.
//!
//! # This is a LIVENESS backstop. It is not a safety one.
//!
//! The authoritative defence against a double mint is on-chain: `xreserve_mint` asserts the nonce is
//! absent from `usedNonces` and sets it, in the same transaction that mints (R-MINT-15,
//! INV-MINT-SECURITY). That assert is what makes a second mint *impossible*. This store makes a
//! second mint *attempt* not happen — a different, weaker, still worthwhile job: a duplicate attempt
//! burns a transaction on an assert that must fail, and a lost cursor re-walks (or skips) a window of
//! attestations.
//!
//! So a bug here can **withhold** a mint (a nonce parked in a status nothing retries) or **waste** a
//! transaction (an attempt the chain rejects). It cannot authorize one. Every decision below follows
//! from preferring the wasted transaction to the withheld mint — most visibly in
//! [`SubmissionStatus::Failed`], which is re-claimable rather than terminal, and in
//! [`IdempotencyStore::reclaim_stale_pending`], which frees a claim stranded by a crash.
//!
//! # Dedup is a claim, not a lookup
//!
//! "Ask whether the nonce was submitted, then record that it was" is a read-then-write race: two
//! observers (two poll tasks; two relayer processes during a deploy overlap) can both read *no* and
//! both mint. [`IdempotencyStore::claim_nonce`] is therefore the single atomic step — the check and
//! the write are one `BEGIN IMMEDIATE` transaction against a nonce that is the table's PRIMARY KEY —
//! and it is the ONLY mint-decision point: **a caller mints on [`ClaimOutcome::Claimed`] and on
//! nothing else.**
//!
//! That applies to a RETRY as much as to a first attempt. A failed nonce is re-acquired by the same
//! `claim_nonce`, which moves it out of [`SubmissionStatus::Failed`] back into an owned
//! [`SubmissionStatus::Pending`] and hands the caller a `Claimed` — so exactly one observer retries
//! it. There is deliberately no other way out of `Failed`: submitting straight from a failed record
//! is refused ([`RelayerError::IllegalStatusTransition`]), because that path is precisely the
//! read-then-write race, and leaving it open would mean the safe API and the unsafe one sit side by
//! side. [`IdempotencyStore::is_nonce_submitted`] remains as a *read* (an operator query, a metric, a
//! pre-flight filter); it is not, on its own, a dedup.
//!
//! # Ordering: record the nonce, THEN advance the cursor
//!
//! The poll loop must claim every nonce on a page BEFORE it advances the cursor past that page. A
//! crash in between then re-scans the page (at-least-once observation), and the nonce log turns the
//! replay into zero second attempts (exactly-once *mint*). The reverse order would lose a page's
//! attestations on the same crash — a silently withheld mint, the one thing §8.4 forbids.
//!
//! Because the cursor only ever moves forward, a mint that keeps failing cannot be rediscovered by
//! polling: its page is behind us. [`IdempotencyStore::retryable`] is the work list that closes that
//! loop — the failed records, oldest first, each carrying the `messageHash` its attestation can be
//! re-fetched by.
//!
//! # Persistence: SQLite
//!
//! The spec leaves the technology `RIV`. It is **SQLite** (via `rusqlite`; one file, WAL +
//! `synchronous = FULL`), because the atomic claim above is a property a JSON/bincode file's
//! read-modify-write cannot provide, and because the cursor must survive `kill -9` and not merely a
//! clean shutdown. The full rationale, and the alternatives weighed, are in the crate's
//! `PERSISTENCE-CHOICE.md` (guarded by `tests/persistence_choice_doc.rs`).
//!
//! There is deliberately no in-memory mode — and that is ENFORCED, not merely declared. SQLite's
//! ephemeral databases (`:memory:`, an empty filename, a `file:…?mode=memory` URI) are spelled as
//! ordinary filenames, so an operator's config could hand one in, and it would open cleanly, take a
//! claim, take a cursor advance, and lose both on the next restart — a cache wearing the store's
//! name. [`IdempotencyStore::open`] therefore refuses the reserved names outright and, after opening,
//! asks SQLite where the database actually landed: a database with no file behind it is
//! [`RelayerError::EphemeralStorePath`], and the relayer does not start. (The second check is the
//! load-bearing one for the URI forms: the pinned `libsqlite3-sys` compiles SQLite with
//! `-DSQLITE_USE_URI`, so URI filenames are interpreted regardless of the open flags.)
//!
//! # Layout
//!
//! [`clock`] the time source (injectable, so a test can assert an exact `timestamp`); [`record`] the
//! value types and the status machine; [`store`] the SQLite store, the claim, and the transitions;
//! [`cursor`] the per-domain resume point; [`recovery`] the two liveness paths (the stale-claim
//! reclaim and the retry work list); [`rows`] the row↔record codec that refuses a row it cannot read.

mod clock;
mod cursor;
mod record;
mod recovery;
mod rows;
mod store;

pub use clock::{Clock, SystemClock};
pub use cursor::Cursor;
pub use record::{ClaimOutcome, IdempotencyRecord, SubmissionStatus, TxId};
pub use store::{IdempotencyStore, STORE_SCHEMA_VERSION};

// re-exported into the module docs' link scope
#[allow(unused_imports)]
use crate::error::RelayerError;
