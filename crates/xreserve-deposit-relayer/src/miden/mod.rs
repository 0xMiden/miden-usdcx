//! The Miden-facing half of the relayer — currently one thing: turning a VALIDATED Circle
//! attestation into the mint note the faucet consumes ([`mint_note`]).
//!
//! # What this half is, and what it deliberately is not
//!
//! It is a **translation layer, not a definition layer.** The mint note's wire form — the
//! u32-LE-packed DepositIntent storage (DC-1), the scheme-1 attestation attachment, the scheme-2
//! `NetworkAccountTarget` routing bind (F5), the forced `NoteType::Public`, the account-target tag,
//! the compiled note script and its pinned root — is unit-04's, whole and entire
//! (`XUsdcMintNote::create`, `crates/xusdc-encoding/src/note/xreserve_mint.rs`). This module
//! consumes it BY REFERENCE and restates none of it (single-owner rule): the faucet that must
//! CONSUME the note and the library that BUILDS it are two halves of one contract, and a relayer
//! that re-derived a single offset would be a second, silently drifting definition of it.
//!
//! It builds **no witness data for anybody else's transaction.** The mint note is consumed by a
//! NETWORK transaction — the faucet is a keyless network account, so the network's ntx-builder
//! assembles that transaction, and it rebuilds the witness provider from the note's ATTACHMENTS.
//! There is no provider the relayer can reach, at any protocol version, so there is nothing here to
//! stage into one. (`RIV-ADVICE-KEY.md` records the related finding — that the faucet's shim looks
//! the attestation up under the ATTACHMENT's own content commitment, not the note commitment the
//! component spec paraphrases — and `tests/relayer_has_no_advice_surface.rs` is the executable gate
//! that keeps the rejected staging surface out of the crate.)
//!
//! The SUBMIT leg — handing the built note to a Miden node — is a later slice and needs a
//! `miden-client`, which has no v0.16 release; `miden-client` is deliberately absent from this
//! crate's dependencies.

pub mod mint_note;

pub use mint_note::{build_mint_note, AttesterPubkey};
