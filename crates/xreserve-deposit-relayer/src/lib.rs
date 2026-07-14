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
//! The fourth slice shipped the **idempotency seam** ([`idempotency`]) — the one-directional joint
//! between that Circle half and the Miden half: a durable submitted-nonce log, the
//! per-remote-domain `Link` cursor a restart resumes from, and the `SubmissionStatus` machine that
//! joins them (SQLite; the choice is recorded in `PERSISTENCE-CHOICE.md`). It dedups so that an
//! attestation observed twice is minted at most once — a LIVENESS backstop, never a safety one: the
//! authoritative duplicate defence stays the on-chain `usedNonces` assert-then-set.
//!
//! This slice opens the **Miden-facing half** ([`miden`]): [`miden::build_mint_note`] turns a
//! validated attestation plus the operator-configured attester key into the `XReserveMintNote` the
//! faucet consumes. It is a DELEGATION — unit-04's `XReserveMintNote::create` owns every byte of the
//! note's wire form and this crate restates none of it — and it stages no witness data for the
//! consuming transaction, because it cannot: that transaction is the network's (the faucet is a
//! keyless network account) and its witness provider is rebuilt from the note's own attachments. The
//! Miden SUBMIT leg is what remains, and it waits on a `miden-client` release for v0.16.

pub mod circle;
pub mod config;
pub mod error;
pub mod idempotency;
pub mod miden;
pub mod observability;
pub mod validate;

pub use error::RelayerError;
