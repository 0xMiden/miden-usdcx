//! `xreserve-deposit-relayer` — the Phase-4 P4-RELAYER deposit-attestation relayer (CMP-C1).
//!
//! The relayer is the off-chain, partner-operated service that turns a published Circle deposit
//! attestation into a Miden `XReserveMintNote`. It is a **liveness** service: it never verifies the
//! attestation, never reduces amounts, and never decides whether a mint is authorized — the
//! authoritative parse, amount reduction, nonce assert-then-set, keccak hashing, attester-allowlist
//! check, ECDSA verification, and supply write all happen on-chain in `xreserve_mint` (§1.2). A
//! relayer bug can only withhold a mint, never authorize one.
//!
//! This crate is built in slices. The first slice shipped the crate scaffold (config / error /
//! observability skeletons + the async entry point) and the off-chain DepositIntent structural
//! decoder ([`validate::deposit_intent`]) — the fast-fail mirror of the on-chain D5a parse. The
//! second added the attestation-envelope binding ([`validate::envelope`]): `messageHash ==
//! keccak256(payload)` by RAW keccak (DC-2, INV-DEPOSIT-ATTESTATION-RAW-KECCAK) and the 65-byte
//! `r‖s‖v` shape check — binding and shape only, NEVER an off-chain signature verification.
//!
//! The third slice completed the **Circle-facing half** ([`circle`]): the HTTP transport with its
//! auth-header injection point (no credential is hardcoded — `Q-API-AUTH` is OPEN), the rate governor
//! (5 QPS/IP, 35 QPS global), the exponential backoff, the HTTP-status policy (404 retries, 400
//! rejects without retry, 5xx retries and alerts), the three attestation fetch shapes, and `GET
//! /v1/info` discovery. It is exercised end to end against a schema-exact mock Circle server; no
//! Circle endpoint is contacted live (§11 — every live Circle leg is `REQUIRES CIRCLE
//! CONFIRMATION`).
//!
//! This slice ships the **idempotency seam** ([`idempotency`]) — the one-directional joint between
//! that Circle half and the Miden half still to come: a durable submitted-nonce log, the
//! per-remote-domain `Link` cursor a restart resumes from, and the `SubmissionStatus` machine that
//! joins them (SQLite; the choice is recorded in `PERSISTENCE-CHOICE.md`). It dedups so that an
//! attestation observed twice is minted at most once — a LIVENESS backstop, never a safety one: the
//! authoritative duplicate defence stays the on-chain `usedNonces` assert-then-set.
//!
//! This slice opens the **Miden-facing half** ([`miden`]): the mint-note builder, which turns a
//! validated attestation into the production `XReserveMintNote` in the exact wire form the faucet's
//! `receive_and_mint` shim consumes, and the advice-map witness that note's attachments are
//! resolved from — keyed the way the faucet's on-chain reader keys it, not the way the pre-F5 spec
//! paraphrased it (RIV-ADVICE-KEY; the reconciliation is recorded in `RIV-ADVICE-KEY.md`). The real
//! submit leg (`TransactionRequestBuilder` + `submit_new_transaction` against a node) is the next
//! slice; [`miden::advice::AdviceMapSink`] is the seam it plugs into.

pub mod circle;
pub mod config;
pub mod error;
pub mod idempotency;
pub mod miden;
pub mod observability;
pub mod validate;

pub use error::RelayerError;
