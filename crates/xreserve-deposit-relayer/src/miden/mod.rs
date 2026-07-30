//! The Miden-facing half of the relayer — currently one thing: turning a VALIDATED Circle
//! attestation into the mint note the faucet consumes ([`mint_note`]).
//!
//! # What this half is, and what it deliberately is not
//!
//! It is a **translation layer, not a definition layer.** Every byte of the note's wire form
//! belongs to `XUsdcMintNote::create` in the shared encoding crate, and this module restates none
//! of it: the faucet that CONSUMES the note and the library that BUILDS it are two halves of one
//! contract, and a relayer that re-derived a single offset would be a second, silently drifting
//! definition of it.
//!
//! It builds **no witness data for anybody else's transaction.** The mint note is consumed by a
//! NETWORK transaction — the faucet is a keyless network account, so the network's ntx-builder
//! assembles that transaction, and it rebuilds the witness provider from the note's ATTACHMENTS
//! (the faucet's shim looks the attestation up under the ATTACHMENT's own content commitment).
//! There is no provider the relayer can reach, at any protocol version, so there is nothing here
//! to stage into one, and an executable gate keeps that rejected staging surface out of the crate.
//!
//! The SUBMIT leg — handing the built note to a Miden node — is a later slice and needs a
//! `miden-client`, which has no v0.16 release; `miden-client` is deliberately absent from this
//! crate's dependencies.

pub mod mint_note;

pub use mint_note::{build_mint_note, AttesterPubkey};
