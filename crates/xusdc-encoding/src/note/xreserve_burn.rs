//! `XReserveBurnNote`: the Circle-facing public burn-event note.
//!
//! A withdrawing xUSDC holder creates this note carrying the burned xUSDC; Circle's off-chain
//! withdrawal attester discovers it by its FIXED full-32-bit tag (`SyncNotes` exact-match) and
//! reads its evidence-attachment payload `(amount, destDomain, destRecipient, salt)` to release
//! USDC on the source chain.
//!
//! It is built as a standalone note factory. What it does reuse is the standard burn consume
//! script — which pins `NoteStorage` to exactly the burned asset's eight felts — so consuming one
//! of these notes runs `faucet::receive_and_burn` and the faucet's active burn policy exactly as
//! any other burn would. The note is forced public, carries the fixed xUSDC burn tag, and writes
//! its payload through the shared codec into the scheme-6 evidence attachment, so the listener
//! decodes precisely what was encoded.
//!
//! Nothing on-chain reads that payload. The destination fields exist purely so the burn is legible
//! off-chain, which is what makes the note evidence rather than just an accounting entry.

use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteRecipient,
    NoteScript, NoteScriptRoot, NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::{Felt, Word};
use miden_standards::note::BurnNote;

use crate::xreserve::encoding::{XReserveBurnItems, BURN_NOTE_ITEMS_FELTS};

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

/// The burn-evidence attachment scheme (u16, project-chosen: clear of the reserved "none" value 1,
/// the standard values 2 `NetworkAccountTarget` / 3 `Pswap`, and the project's mint transport 4).
/// It carries the withdrawal payload `(amount, destDomain, destRecipient, salt)` the off-chain
/// listener reads — the stock burn script pins `NoteStorage` to exactly the burned asset's eight
/// felts, so the evidence rides as an attachment, zero-padded to the word boundary. Nothing
/// on-chain reads it. Not a Circle-owned value.
pub const XUSDC_BURN_EVIDENCE_ATTACHMENT_SCHEME: u16 = 6;

/// The public burn-event note. A standalone unit-struct note factory.
pub struct XReserveBurnNote;

impl XReserveBurnNote {
    /// Number of `NoteStorage.items` felts: the stock burn script's canonical eight-felt asset
    /// layout (the withdrawal payload rides in the scheme-6 evidence attachment, not in storage).
    pub const NUM_STORAGE_ITEMS: usize = 8;

    /// Number of felts in the evidence attachment's payload (18, before word padding), owned by
    /// the shared-encoding codec.
    pub const EVIDENCE_PAYLOAD_FELTS: usize = BURN_NOTE_ITEMS_FELTS;

    /// Returns the (reused) stock burn note consume script — targets `faucet::receive_and_burn`.
    pub fn script() -> NoteScript {
        BurnNote::script()
    }

    /// Returns the (reused) stock burn note script root.
    pub fn script_root() -> NoteScriptRoot {
        BurnNote::script_root()
    }

    /// Convenience constructor over the [`XReserveBurnItems`] payload (a thin delegator to the
    /// [`builder`](Self::builder)); retained because the frozen conformance suites pin this signature.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        items: XReserveBurnItems,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        Self::builder()
            .sender(sender)
            .faucet_id(faucet_id)
            .items(items)
            .rng(rng)
            .build()
    }
}

#[bon::bon]
impl XReserveBurnNote {
    /// Builds an `XReserveBurnNote` via a `bon` builder
    /// (`XReserveBurnNote::builder().sender(..).faucet_id(..).items(..).rng(..).build()`):
    /// `NoteType::Public`, the fixed xUSDC burn tag, `metadata.sender = sender` (the depositor),
    /// `NoteAssets` = the burned xUSDC `FungibleAsset` (`amount` issued by `faucet_id`),
    /// `NoteStorage.items` = that same asset's canonical eight felts (the stock burn script asserts
    /// exactly this layout and that it matches the carried asset), and the scheme-6 evidence
    /// attachment = the shared-codec encoding of `items` (the withdrawal payload the off-chain
    /// listener reads). The note's amount is single-sourced from `items.amount`.
    #[builder]
    pub fn new<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        items: XReserveBurnItems,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let serial_num = rng.draw_word();

        // the amount is single-sourced from items.amount so the recorded amount and the burned asset
        // can never diverge
        let asset = FungibleAsset::new(faucet_id, u64::from(items.amount))
            .map_err(|err| NoteError::other_with_source("invalid burned xUSDC asset", err))?;
        let asset = Asset::from(asset);
        let vault = NoteAssets::new(vec![asset])?;

        // the stock burn script requires storage to be exactly the burned asset's eight felts and
        // asserts they match the carried asset
        let storage = NoteStorage::new(asset.as_elements().to_vec())?;
        let recipient = NoteRecipient::new(serial_num, BurnNote::script(), storage);

        // the burn note is always Public — there is no note_type parameter. The withdrawal
        // destination rides in the evidence attachment, so the listener reads it from the payload
        // rather than inferring it from a metadata field.
        let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
            .with_tag(NoteTag::new(FIXED_XUSDC_BURN_TAG));

        // the evidence attachment: the shared codec is the same routine the off-chain attester
        // decodes with, so encode and decode cannot drift apart. Attachment content is
        // word-granular, so the payload is zero-padded from 18 to 20 felts; the decoder reads
        // exactly the first EVIDENCE_PAYLOAD_FELTS.
        let mut evidence = items.encode();
        while !evidence.len().is_multiple_of(4) {
            evidence.push(Felt::from(0u32));
        }
        let words: Vec<Word> = evidence
            .chunks_exact(4)
            .map(|chunk| Word::new([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        let evidence_attachment = NoteAttachment::with_words(
            NoteAttachmentScheme::new(XUSDC_BURN_EVIDENCE_ATTACHMENT_SCHEME)?,
            words,
        )?;

        // the evidence attachment plus the scheme-2 routing bind; the stock consume script ignores
        // both, and the burn stays gated by receive_and_burn and the burn policy.
        let attachments = NoteAttachments::new(vec![
            evidence_attachment,
            super::network_routing_attachment(faucet_id)?,
        ])?;

        Ok(Note::with_attachments(
            vault,
            metadata,
            recipient,
            attachments,
        ))
    }

    /// The withdrawal payload felts carried by `note`'s scheme-6 evidence attachment (exactly the
    /// [`Self::EVIDENCE_PAYLOAD_FELTS`] the codec decodes; the word-boundary padding is dropped),
    /// or `None` if the note carries no well-formed evidence attachment.
    pub fn evidence_items(note: &Note) -> Option<Vec<Felt>> {
        let scheme = NoteAttachmentScheme::new(XUSDC_BURN_EVIDENCE_ATTACHMENT_SCHEME).ok()?;
        let attachment = note
            .attachments()
            .iter()
            .find(|a| a.attachment_scheme() == scheme)?;
        let elements = attachment.as_elements();
        if elements.len() < Self::EVIDENCE_PAYLOAD_FELTS {
            return None;
        }
        Some(elements[..Self::EVIDENCE_PAYLOAD_FELTS].to_vec())
    }
}
