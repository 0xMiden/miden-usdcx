//! `xreserve-deposit-relayer` — the off-chain deposit-attestation relayer service.
//!
//! The relayer is the off-chain, partner-operated service that turns a published Circle deposit
//! attestation into a Miden `XUsdcMintNote`. It is a **liveness** service: it never verifies the
//! attestation, never reduces amounts, and never decides whether a mint is authorized — the
//! authoritative parse, amount reduction, nonce assert-then-set, keccak hashing, attester-allowlist
//! check, signature verification, and supply write all happen on-chain, inside the faucet's mint
//! policy and the standard mint procedure it gates. A relayer bug can only withhold a mint, never
//! authorize one.
//!
//! The crate's parts, from the wire inward:
//!
//! * The off-chain DepositIntent structural decoder ([`validate::deposit_intent`]) — the fast-fail
//!   mirror of the on-chain parse — alongside the config / error / observability scaffolding
//!   and the async entry point.
//! * The attestation-envelope binding ([`validate::envelope`]): `messageHash ==
//!   keccak256(payload)` by RAW keccak (not EIP-712) and the 65-byte
//!   `r‖s‖v` shape check — binding and shape only, NEVER an off-chain signature verification.
//! * The **Circle-facing half** ([`circle`]): the HTTP transport with its auth-header injection
//!   point (no credential is hardcoded — Circle documents no auth scheme), the rate governor (5
//!   QPS/IP, 35 QPS
//!   global), the exponential backoff, the HTTP-status policy (404 retries, 400 rejects without
//!   retry, 5xx retries and alerts), the three attestation fetch shapes, and `GET /v1/info`
//!   discovery. It is exercised end to end against a schema-exact mock Circle server; no Circle
//!   endpoint is contacted live (every live Circle leg is `REQUIRES CIRCLE CONFIRMATION`).
//! * The **idempotency seam** ([`idempotency`]) — the one-directional joint between that Circle
//!   half and the Miden half: a durable submitted-nonce log, the per-remote-domain `Link` cursor a
//!   restart resumes from, and the `SubmissionStatus` machine that joins them (SQLite). It dedups
//!   so that an attestation observed twice is
//!   minted at most once — a LIVENESS backstop, never a safety one: the authoritative duplicate
//!   defence stays the on-chain `usedNonces` assert-then-set.
//! * The **Miden-facing half** ([`miden`]): [`miden::build_mint_note`] turns a validated
//!   attestation plus the operator-configured attester key into the `XUsdcMintNote` the faucet
//!   consumes. It is a DELEGATION — the shared encoding crate's `XUsdcMintNote::create` owns
//!   every byte of the note's wire form and this crate restates none of it — and it stages no
//!   witness data for the consuming transaction, because it cannot: that transaction is the
//!   network's (the faucet is a keyless network account) and its witness provider is rebuilt from
//!   the note's own attachments.
//! * The wiring ([`cycle`]): [`cycle::run_relayer_cycle`] is the eight-step
//!   poll→validate→build→submit→track pipeline, and [`cycle::run_relayer_loop`] runs it. Its
//!   subject is the no-silent-drops obligation — **no fetched attestation is ever silently
//!   dropped** — which is held structurally rather than by convention: the per-attestation step
//!   returns a [`cycle::CycleEntry`] and not a `Result`, so there is no `?` that can skip a
//!   recording, and every reason is derived from a typed value, so an entry with nothing to say is
//!   not constructible.
//!
//! The Miden SUBMIT leg is the one thing still open, and it is open ON PURPOSE: it is a PORT
//! ([`cycle::MintSubmit`]) with no production implementation, because implementing it needs a
//! `miden-client` for v0.16 and there is no such release. The orchestration composes against the
//! port; the adapter is a later slice, proven against a real local node.
//! Nothing here fakes it — [`cycle::production_submit_port`] refuses by name and the binary fails
//! at startup on it, because a relayer that started with a no-op submit would look healthy in every
//! log and every metric except the chain's (the Circle API may be mocked; Miden behaviour must not
//! be faked for final acceptance).

pub mod circle;
pub mod config;
pub mod cycle;
pub mod error;
pub mod idempotency;
pub mod miden;
pub mod observability;
pub mod validate;

pub use error::RelayerError;
