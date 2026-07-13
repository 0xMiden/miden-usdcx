//! `xreserve-deposit-relayer` — the Phase-4 P4-RELAYER deposit-attestation relayer (CMP-C1).
//!
//! The relayer is the off-chain, partner-operated service that turns a published Circle deposit
//! attestation into a Miden `XReserveMintNote`. It is a **liveness** service: it never verifies the
//! attestation, never reduces amounts, and never decides whether a mint is authorized — the
//! authoritative parse, amount reduction, nonce assert-then-set, keccak hashing, attester-allowlist
//! check, ECDSA verification, and supply write all happen on-chain in `xreserve_mint` (§1.2). A
//! relayer bug can only withhold a mint, never authorize one.
//!
//! This crate is built in slices. This first slice ships the crate scaffold (config / error /
//! observability skeletons + the async entry point) and the off-chain DepositIntent structural
//! decoder ([`validate::deposit_intent`]) — the fast-fail mirror of the on-chain D5a parse. The
//! Circle HTTP client, the messageHash/envelope checks, the idempotency seam, the mint-note
//! builder, and the Miden submit leg land in later slices.

pub mod config;
pub mod error;
pub mod observability;
pub mod validate;

pub use error::RelayerError;
