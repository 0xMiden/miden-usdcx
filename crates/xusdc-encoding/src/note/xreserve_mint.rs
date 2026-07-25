//! `XReserveMintNote` (CMP-B1): the production mint note — carries a signed Circle
//! DepositIntent to the faucet, whose network transaction consumes it and drives the fully-gated
//! `xreserve_mint::mint` (D5a→D5e) end to end.
//!
//! Transport layout (DC-1/DC-2/DC-3):
//! - `NoteStorage.items` = the u32-LE-packed DepositIntent preimage — the shared-encoding codec
//!   [`deposit_intent_to_packed_felts`] consumed BY REFERENCE (60 header felts +
//!   ⌈hookDataLen/4⌉ hookData felts, ≤ 1024).
//! - TWO [`NoteAttachments`] attachments (F5): (1) the scheme-1 attestation
//!   ([`XRESERVE_MINT_ATTACHMENT_SCHEME`]) = 11 words `[feeAmount(8 limbs, MVP zero — DEV-8),
//!   pubkey(16 affine felts — vm#3342, the v16 DC-2 supersession), signature(17), pad(3)]`,
//!   matching the frozen `mint` advice contract `[feeAmount(8), pubkey(16), signature(17)]`
//!   (`xreserve_mint.masm` doc; byte→felt packing reuses the shared-encoding codec
//!   [`affine_pubkey_felts`] / [`signature_felts`] by reference); and
//!   (2) the scheme-2 `NetworkAccountTarget` routing bind to the faucet network account
//!   (`NoteExecutionHint::Always`, routing-only). The entry shim asserts exactly one scheme-1
//!   attestation + one scheme-2 target (`eq.2`) and hash-verifies the attestation content by its
//!   found index (F5).
//! - `NoteType::Public` is FORCED (network-tx observability mandate); the tag is the faucet
//!   account-target tag (`NoteTag::with_account_target` — burn notes carry the fixed
//!   `0x4255524E` tag instead precisely so mint notes own the account-target routing identity).
//! - The note script (`asm/standards/notes/xreserve_mint_note.masm`) `call`s the account-side
//!   `receive_and_mint` note-entry wrapper, which stages storage into the account call frame,
//!   hash-verifies the attachment content, surfaces it to the advice stack, and
//!   `exec.xreserve_mint::mint`s. Its root is pinned as [`XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX`]
//!   (`masm-rust-constant-parity`; the parity test recompiles and compares).
//!
//! Like the sibling [`super::xreserve_burn::XReserveBurnNote`] this is a standalone unit-struct
//! factory; the one divergence is the CUSTOM note script + pinned root (burn reuses the stock
//! `BurnNote` script; mint has no stock analog — stock `mint_and_send` is denied, R-MINT-16).

use std::sync::{Arc, LazyLock};

use miden_protocol::account::AccountId;
use miden_protocol::assembly::{Linkage, Path as MasmPath};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteRecipient,
    NoteScript, NoteScriptRoot, NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_standards::StandardsLib;

use crate::xreserve::encoding::{
    affine_pubkey_felts, deposit_intent_to_packed_felts, signature_felts,
};

/// The mint-note attestation attachment scheme (u16, project-chosen; 0 is reserved, ≤ 65534).
/// Declared identically in `xreserve_mint_note_entry.masm` (`masm-rust-constant-parity` via
/// `constant_parity.rs`); the wrapper's `find_attachment` fail-closes on a mismatch. Not a
/// Circle-owned value.
pub const XRESERVE_MINT_ATTACHMENT_SCHEME: u16 = 1;

/// The attachment word count: `[feeAmount(8), pubkey(16), signature(17), pad(3)]` = 44 felts
/// (the pubkey is the 16-felt affine form since the v16 migration — vm#3342,
/// MIGRATION-V16-ALPHA2.md S16). Declared identically in `xreserve_mint_note_entry.masm`
/// (parity-pinned).
pub const XRESERVE_MINT_ATTACHMENT_NUM_WORDS: usize = 11;

/// The PINNED mint-note script root (`masm-rust-constant-parity`): the MAST root of the compiled
/// `xreserve_mint_note.masm` with the xreserve library linked. It binds transitively to
/// `receive_and_mint`'s MAST digest, so ANY edit of the note script or the wrapper trips the
/// parity assertion (`XReserveMintNote::script_root() == pinned`) and forces a conscious re-pin.
/// Re-pinned when `DEPOSIT_SCALE_EXP` moved 6 -> 0 (DEV-5 answered: 6-decimal wire == 6-decimal
/// asset, so the mint applies no rescale). A MASM `const` is a compile-time literal, so
/// `push.DEPOSIT_SCALE_EXP` in `receive_and_mint` assembles to `push.0` instead of `push.6`,
/// moving that proc's MAST digest and transitively this script root — from
/// `0x85c8cfd61de921bd272d7e39766447b52ad04febd868e2c64f1ab442bf0c37b8` to the value below. The
/// move is attributable to the value flip ALONE: re-deriving with the same source but the value
/// restored to 6 reproduces the previous root exactly.
pub const XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x530e20b39e77a111f00a162835823ff503202d05c182b98728387853e07d19d5";

/// The mint-note consume script source.
const MINT_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../asm/standards/notes/xreserve_mint_note.masm");

/// The compiled mint-note script: the `xreserve` component library is assembled from the shipped
/// tree and linked so `call.note_entry::receive_and_mint` resolves to the SAME proc installed on
/// the faucet account (the agglayer claim-note precedent; the in-repo assembler recipe mirrors
/// the test harness' `assemble_xreserve_lib`).
static MINT_NOTE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let assembler = TransactionKernel::assembler()
        .with_package(Arc::new(StandardsLib::default().into()), Linkage::Dynamic)
        .expect("the standards library links into the xreserve assembler")
        .with_warnings_as_errors(true);
    let library = *assembler
        .assemble_library_from_root(
            crate::xreserve_asm_dir().join("mod.masm"),
            Some(MasmPath::new("xreserve")),
        )
        .expect("the shipped xreserve component library assembles");
    CodeBuilder::new()
        .with_dynamically_linked_library(&library)
        .expect("the xreserve library links into the mint-note script assembler")
        .compile_note_script(MINT_NOTE_SCRIPT_SRC)
        .expect("the mint-note script compiles")
});

/// The Circle deposit attestation crossing the note boundary (DC-2/DC-3): the raw 65-byte
/// `r‖s‖v` ECDSA signature over `keccak256(payload)` and the raw 33-byte compressed SEC1
/// candidate pubkey. Lengths are type-enforced; felt packing happens in [`XReserveMintNote`]
/// via the shared-encoding codec by reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintAttestation {
    signature: [u8; 65],
    pubkey: [u8; 33],
}

impl MintAttestation {
    /// Bundles a raw 65-byte `r‖s‖v` signature with the 33-byte compressed candidate pubkey.
    pub fn new(signature: [u8; 65], pubkey: [u8; 33]) -> Self {
        Self { signature, pubkey }
    }

    /// The raw 65-byte `r‖s‖v` signature (`v` carried, unused on-chain).
    pub fn signature(&self) -> &[u8; 65] {
        &self.signature
    }

    /// The raw 33-byte compressed SEC1 candidate pubkey.
    pub fn pubkey(&self) -> &[u8; 33] {
        &self.pubkey
    }
}

/// The production mint note (CMP-B1). A standalone unit-struct note factory.
pub struct XReserveMintNote;

impl XReserveMintNote {
    /// The custom mint-note consume script (compiled from
    /// `asm/standards/notes/xreserve_mint_note.masm` with the xreserve component library linked).
    pub fn script() -> NoteScript {
        MINT_NOTE_SCRIPT.clone()
    }

    /// The mint-note script root (must equal the pinned
    /// [`XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX`]; parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        MINT_NOTE_SCRIPT.root()
    }

    /// The pinned root constant as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned mint-note script root hex is a valid word"),
        )
    }

    /// Creates the production mint note: `sender` is the producer/relayer account, `faucet_id`
    /// the consuming faucet (account-target tag), `deposit_intent` the RAW DepositIntent payload
    /// bytes (validated + packed via the shared-encoding codec by reference — structural rejects and the
    /// 1024-felt bound surface as [`NoteError`] with the codec error as source), `attestation`
    /// the raw sig + candidate pubkey (packed 17 + 16 felts into the scheme-1 attestation attachment
    /// after the MVP-zero feeAmount limbs — DEV-8, hardcoded: a non-zero fee would only ever trap
    /// the F2 guard on-chain). The note carries TWO attachments (F5): that scheme-1 attestation plus
    /// the scheme-2 `NetworkAccountTarget` routing bind to `faucet_id` (`NoteExecutionHint::Always`).
    /// Asset-less; `NoteType::Public` forced.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        deposit_intent: &[u8],
        attestation: &MintAttestation,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let items = deposit_intent_to_packed_felts(deposit_intent).map_err(|source| {
            NoteError::other_with_source("deposit intent payload rejected by the 04 codec", source)
        })?;
        let storage = NoteStorage::new(items)?;
        let serial_num = rng.draw_word();
        let recipient = NoteRecipient::new(serial_num, Self::script(), storage);
        let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(faucet_id));
        // F5: two attachments — the scheme-1 attestation (hash-verified by the shim) + the scheme-2
        // NetworkAccountTarget routing bind to the faucet network account (routing only; the shim's
        // `eq.2` accepts exactly these two). Requires a PUBLIC faucet id.
        let target =
            NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always).map_err(|err| {
                NoteError::other_with_source("faucet id is not a public network account", err)
            })?;
        let attachments = NoteAttachments::new(vec![
            Self::attestation_attachment(attestation)?,
            NoteAttachment::from(target),
        ])?;
        Ok(Note::with_attachments(
            NoteAssets::new(vec![])?,
            metadata,
            recipient,
            attachments,
        ))
    }

    /// Builds the scheme-1 attestation attachment: 44 felts
    /// `[feeAmount(8 zero limbs), pubkey(16 affine felts), signature(17), pad(3)]` as 11 words —
    /// the exact order `mint` pops from the advice stack (element-0-first `adv.push_mapval` pop
    /// order, pinned by the transport canary). The 33-byte compressed wire pubkey is
    /// decompressed to its affine coordinates here (vm#3342; an off-curve key rejects — it
    /// could never verify on-chain).
    fn attestation_attachment(attestation: &MintAttestation) -> Result<NoteAttachment, NoteError> {
        let mut felts: Vec<Felt> = Vec::with_capacity(44);
        felts.extend([Felt::from(0u32); 8]);
        felts.extend(affine_pubkey_felts(attestation.pubkey()).map_err(|source| {
            NoteError::other_with_source("attestation pubkey rejected by the 04 codec", source)
        })?);
        felts.extend(signature_felts(attestation.signature()));
        felts.extend([Felt::from(0u32); 3]);
        let words: Vec<Word> = felts
            .chunks_exact(4)
            .map(|chunk| Word::new([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        debug_assert_eq!(words.len(), XRESERVE_MINT_ATTACHMENT_NUM_WORDS);
        NoteAttachment::with_words(
            NoteAttachmentScheme::new(XRESERVE_MINT_ATTACHMENT_SCHEME)?,
            words,
        )
    }
}
