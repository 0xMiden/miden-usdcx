//! The Miden-facing half of the relayer: it turns a validated Circle attestation into the
//! production `XReserveMintNote` and hands the faucet the witness it needs to verify it.
//!
//! The split from the Circle-facing half is one-directional (§7 of the component spec): this half
//! consumes a validated `(payload, signature, pubkey)` triple and never calls Circle, never
//! re-decides authorization, and never verifies the ECDSA signature — that happens on-chain at D5d.
//! It builds a note and publishes a witness; a bug here can only withhold a mint, never authorize
//! one.
//!
//! - [`mint_note_builder`] — the note itself (the exact post-F5 wire form).
//! - [`advice`] — the advice-map witness the note's attachments are resolved from, keyed the way
//!   the faucet's on-chain reader keys it (RIV-ADVICE-KEY; see `RIV-ADVICE-KEY.md`).
//!
//! The real `submit` leg (`TransactionRequestBuilder` + `submit_new_transaction` against a node)
//! lands in the next slice; [`advice::AdviceMapSink`] is the seam it plugs into.

pub mod advice;
pub mod mint_note_builder;
