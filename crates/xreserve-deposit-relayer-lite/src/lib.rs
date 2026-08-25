//! A minimal deposit relayer: poll Circle, build the mint note, submit it.
//!
//! The relayer is a liveness service. It never decides whether a mint is authorized — the
//! DepositIntent parse, the amount reduction, the nonce replay guard, the attester-allowlist check
//! and the ECDSA verification all happen on-chain, inside the faucet's mint policy. A bug here can
//! withhold a mint; it cannot authorize one.
//!
//! Delivery is **at-least-once**. The faucet's on-chain `usedNonces` assert is the authoritative
//! replay guard, so a duplicate submit is refused rather than minted twice. The [`store`] is
//! therefore a duplicate *filter* — it saves fees, it does not provide safety — and everything the
//! sibling crate builds on top of exactly-once delivery (a submission state machine, a claim
//! protocol, a crash-recovery sweep, a re-fetch retry queue) is absent by design.
//!
//! The pieces, from the wire inward:
//!
//! * [`circle`] — one paginated GET, decoded per element, with the `messageHash ==
//!   keccak256(payload)` binding check.
//! * [`store`] — the submitted-nonce set and the feed cursor, in one SQLite file.
//! * [`mint`] — the validated attestation plus the configured attester key, handed to
//!   `xusdc-encoding`'s note builder, which owns every byte of the note's wire form.
//! * [`submit`] — the seam at a Miden node. It has no production implementation yet; see the module
//!   docs for why that is a refusal rather than a stub.
//! * [`cycle`] — the poll → decode → dedup → build → submit loop.

pub mod circle;
pub mod config;
pub mod cycle;
pub mod mint;
pub mod store;
pub mod submit;
