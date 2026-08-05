//! `XReserveBurnNote`: the Circle-facing public burn-event note.
//!
//! A withdrawing xUSDC holder creates this note carrying the burned xUSDC; Circle's off-chain
//! withdrawal attester discovers it by its FIXED full-32-bit tag (`SyncNotes` exact-match) and
//! reads its `NoteStorage.items` payload `(amount, destDomain, destRecipient, salt)` to release
//! USDC on the source chain.
//!
//! It is built as a standalone note factory. What it does reuse is the standard burn consume
//! script, so consuming one of these notes runs `faucet::receive_and_burn` and the faucet's active
//! burn policy exactly as any other burn would. The note is forced public, carries the fixed xUSDC
//! burn tag, and writes its payload through the shared codec so the listener decodes precisely what
//! was encoded.
//!
//! Nothing on-chain reads that payload. The destination fields exist purely so the burn is legible
//! off-chain, which is what makes the note evidence rather than just an accounting entry.

use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachments, NoteRecipient, NoteScript, NoteScriptRoot, NoteStorage,
    NoteTag, NoteType, PartialNoteMetadata,
};
use miden_standards::note::BurnNote;

use crate::xreserve::encoding::{encode_burn_note_items, XReserveBurnItems, BURN_NOTE_ITEMS_FELTS};

/// The fixed tag every xUSDC burn note carries — ASCII `"BURN"`.
///
/// The off-chain listener discovers burn notes by asking the node for this exact 32-bit value, so
/// it has to be a constant shared by every burn note rather than anything per-account. Its low 18
/// bits are non-zero, which means it can never be mistaken for an account-target tag: those are
/// built with the low 18 bits zeroed. It identifies a use case, not a destination.
///
/// The specific value is provisional and awaits Circle's confirmation — it is not a value Circle
/// has assigned.
pub const FIXED_XUSDC_BURN_TAG: u32 = 0x4255_524E;

/// The public burn-event note. A standalone unit-struct note factory.
pub struct XReserveBurnNote;

impl XReserveBurnNote {
    /// Number of `NoteStorage.items` felts in the burn-note payload (18), owned by the shared-encoding codec.
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
    /// `FungibleAsset` (`amount` issued by `faucet_id`), and `NoteStorage.items` = the shared-codec
    /// encoding of `items`. The note's amount is single-sourced from `items.amount`.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        items: XReserveBurnItems,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let serial_num = rng.draw_word();

        // the shared codec is the same routine the off-chain attester decodes with, so encode and
        // decode cannot drift apart
        let storage = NoteStorage::new(encode_burn_note_items(&items))?;
        let recipient = NoteRecipient::new(serial_num, BurnNote::script(), storage);

        // the burn note is always Public — there is no note_type parameter. The withdrawal
        // destination stays in NoteStorage, so the listener reads it from the payload rather than
        // inferring it from a metadata field.
        let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
            .with_tag(NoteTag::new(FIXED_XUSDC_BURN_TAG));

        // the amount is single-sourced from items.amount so the recorded amount and the burned asset
        // can never diverge
        let asset = FungibleAsset::new(faucet_id, u64::from(items.amount))
            .map_err(|err| NoteError::other_with_source("invalid burned xUSDC asset", err))?;
        let vault = NoteAssets::new(vec![asset.into()])?;

        // routing only: the stock consume script ignores attachments, and the burn stays gated by
        // receive_and_burn and the burn policy.
        let attachments =
            NoteAttachments::new(vec![super::network_routing_attachment(faucet_id)?])?;

        Ok(Note::with_attachments(
            vault,
            metadata,
            recipient,
            attachments,
        ))
    }
}
