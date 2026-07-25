//! The **per-burn idempotency ledger** — the durable seam that stops one burn from being submitted to
//! Circle twice.
//!
//! Everything upstream of this module is *observation*: a public burn note is discovered, its payload
//! decodes, Circle prepares the intents, the B5 gate compares them field-by-field, the attesters sign.
//! Everything downstream is *action*: `POST /v1/withdraw`, and Circle releases native USDC on the
//! source chain. This ledger is what stops an observation seen twice — a re-discovered note, a retry
//! driver, a restarted process, two overlapping deploys — from becoming a release taken twice.
//!
//! # This is a SAFETY property here, not a liveness backstop
//!
//! The distinction from the deposit relayer's `idempotency` seam (which this module deliberately
//! mirrors) is the whole reason to read this paragraph. On the relayer's side, the authoritative
//! defence against a double mint is ON-CHAIN: `xreserve_mint` asserts the nonce is absent from
//! `usedNonces` in the same transaction that mints (`R-MINT-15`, `INV-MINT-SECURITY`). Its store only
//! makes a second *attempt* not happen; a bug there wastes a transaction, it cannot authorize one.
//!
//! **There is no such backstop on this side.** The only other guard against a duplicate withdrawal is
//! Circle's `409` on a `burnTxId` already tied to an active withdrawal (`CIRCLE-API-SURFACE.md:20`:
//! "no idempotency-key header documented … `409` … provides dedup") — and §10.10's rule is that a
//! `409` must be RECOVERED or RECONCILED, never answered by re-sending. So a bug here can authorize a
//! second submission, which is exactly the double-release W7 exists to foreclose. Every decision below
//! therefore prefers a **withheld** withdrawal (an operator investigates) to a **duplicated** one — the
//! opposite of the relayer's bias, and the reason this ledger has no automatic stale-claim reclaim.
//!
//! # Dedup is a claim, not a lookup
//!
//! "Ask whether the burn was submitted, then record that it was" is a read-then-write race: two
//! observers (two discovery passes; two processes during a deploy overlap) can both read *no* and both
//! submit. [`SubmitLedger::claim_burns`] is therefore the single atomic step — the check and the write
//! are ONE `BEGIN IMMEDIATE` transaction against a burn that is the table's PRIMARY KEY — and it is
//! the ONLY submit-decision point: **a caller submits on [`ClaimOutcome::Claimed`] and on nothing
//! else.** [`SubmitLedger::record`] is a *read* (an operator query, a metric); on its own it is not a
//! dedup.
//!
//! The claim is **all-or-nothing across a request's batches**: a `POST /v1/withdraw` carries 1–5
//! batches, each with its own `burnTxId`, and a partial claim would strand the other burns in
//! [`SubmissionStatus::Pending`] forever after the request was refused for one of them.
//!
//! # `Pending` blocks, and there is no automatic reclaim. That is deliberate.
//!
//! A burn stuck in `Pending` — claimed, then the process died mid-request — is AMBIGUOUS: the POST may
//! have reached Circle. The relayer reclaims such a claim automatically, because its chain-level assert
//! makes the retry safe. Here, an automatic reclaim would be an automatic blind re-send: precisely the
//! footgun. So `Pending` blocks resubmission, and the way out is an operator reconciling the burn
//! against `GET /v1/withdrawal/{id}` — not a timer.
//!
//! # The key is the `burnTxId`
//!
//! It is the stable per-burn identity ACROSS invocations (it is derived from the burn itself, not from
//! this process's state) and it is the identity Circle's own `409` dedup is keyed on
//! (`CIRCLE-API-SURFACE.md:74`) — so "the ledger says already submitted" and "Circle says already
//! submitted" cannot mean two different things. Whether a Miden transaction id is what Circle will
//! accept there is `DEV-7`, still OPEN; this ledger keys on whatever `burnTxId` the batch carries and
//! asserts nothing about that question.
//!
//! # Persistence: SQLite
//!
//! Mirrors the relayer's recorded choice (`crates/xreserve-deposit-relayer/PERSISTENCE-CHOICE.md`): the
//! atomic claim above is a property a JSON file's read-modify-write cannot provide, and the log must
//! survive `kill -9`, not merely a clean shutdown. There is deliberately no in-memory mode, and that is
//! ENFORCED rather than declared — see [`SubmitLedger::open`].
//!
//! # Layout
//!
//! `clock` the time source (injectable, so a test can assert an exact timestamp); `record` the value
//! types and the status machine; `store` the SQLite ledger, the claim, and the transitions; `error` the
//! refusals.

mod clock;
mod error;
mod record;
mod store;

pub use clock::{Clock, SystemClock};
pub use error::LedgerError;
pub use record::{BurnKey, ClaimOutcome, SubmissionRecord, SubmissionStatus};
pub use store::{SubmitLedger, LEDGER_SCHEMA_VERSION};
