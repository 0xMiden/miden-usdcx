//! `XReserveBurnNote` (CMP-B2, DC-7): the Circle-facing public burn-event note.
//!
//! A withdrawing xUSDC holder creates this note carrying the burned xUSDC; Circle's off-chain
//! withdrawal attester discovers it by its FIXED full-32-bit tag (`SyncNotes` exact-match) and
//! reads its `NoteStorage.items` payload `(amount, destDomain, destRecipient, salt)` to release
//! USDC on the source chain.
//!
//! Per `DECISION-CMP-B2` (RATIFIED): this is a FRESH note following the N-11 / `P2idNote`
//! pattern, NOT a struct extension of the stock `BurnNote` (which is a sealed unit struct that
//! hardcodes an empty payload + an account-target tag). It REUSES the stock burn consume script
//! (`BurnNote::script()` → `faucet::receive_and_burn` → the CMP-A10 burn policy), mandates
//! `NoteType::Public`, sets the fixed xUSDC burn tag, and writes the DC-7 items via the 04 codec
//! `encode_burn_note_items` (consumed by reference). The destination payload is off-chain
//! observability — there is no on-chain burn-items parser, hence no custom consume MASM.

use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteRecipient, NoteScript, NoteScriptRoot, NoteStorage, NoteTag, NoteType,
    PartialNoteMetadata,
};
use miden_standards::note::BurnNote;

use crate::xreserve::encoding::{encode_burn_note_items, XReserveBurnItems, BURN_NOTE_ITEMS_FELTS};

/// The fixed, enumerated xUSDC burn-event note tag (DC-7). It is a FULL 32-bit exact-match value
/// (Circle's `SyncNotes` discovery is exact equality, not a prefix). ASCII `"BURN"`. The low 18
/// bits are nonzero, so it can never collide with a `NoteTag::with_account_target` faucet tag
/// (which zeroes the low 18 bits) — structurally an enumerated use-case tag, not per-faucet
/// routing. PLACEHOLDER pending Q-BUR-1 / Circle confirmation; not a Circle-owned value.
pub const FIXED_XUSDC_BURN_TAG: u32 = 0x4255_524E;

/// The public burn-event note (CMP-B2). A unit-struct factory in the N-11 idiom.
pub struct XReserveBurnNote;

impl XReserveBurnNote {
    /// Number of `NoteStorage.items` felts in the DC-7 payload (18), owned by the 04 codec.
    pub const NUM_STORAGE_ITEMS: usize = BURN_NOTE_ITEMS_FELTS;

    /// Returns the (reused) stock burn note consume script — targets `faucet::receive_and_burn`.
    pub fn script() -> NoteScript {
        BurnNote::script()
    }

    /// Returns the (reused) stock burn note script root.
    pub fn script_root() -> NoteScriptRoot {
        BurnNote::script_root()
    }

    /// Builds an `XReserveBurnNote`: `NoteType::Public`, the fixed xUSDC burn tag,
    /// `metadata.sender = sender` (the depositor), `NoteAssets` = the burned xUSDC
    /// `FungibleAsset` (`amount` issued by `faucet_id`), and `NoteStorage.items` = the DC-7
    /// encoding of `items`. The note's amount is single-sourced from `items.amount`.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        items: XReserveBurnItems,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let serial_num = rng.draw_word();

        // DC-7 payload → NoteStorage.items via the 04 codec (consumed by reference; no re-impl).
        let storage = NoteStorage::new(encode_burn_note_items(&items))?;
        // Reuse the STOCK burn consume script (→ faucet::receive_and_burn → CMP-A10).
        let recipient = NoteRecipient::new(serial_num, BurnNote::script(), storage);

        // Public mandate (R-BURN-6, no note_type parameter) + the fixed xUSDC burn tag;
        // metadata.sender = the depositor (destination fields stay in NoteStorage; anti-ASG-13).
        let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
            .with_tag(NoteTag::new(FIXED_XUSDC_BURN_TAG));

        // NoteAssets = the burned xUSDC asset; amount single-sourced from items.amount so the
        // recorded amount and the burned asset can never diverge.
        let asset = FungibleAsset::new(faucet_id, u64::from(items.amount))
            .map_err(|err| NoteError::other_with_source("invalid burned xUSDC asset", err))?;
        let vault = NoteAssets::new(vec![asset.into()])?;

        Ok(Note::new(vault, metadata, recipient))
    }
}
