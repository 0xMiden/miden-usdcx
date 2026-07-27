//! `XUsdcMintNote` (CMP-B1, Wave-1 S1 recomposition): the production mint-note FACTORY for the
//! xUSDC faucet — a STOCK miden-standards [`MintNote`] carrying the Circle-signed transport as
//! attachments. The former custom `XReserveMintNote` (bespoke script + note-storage preimage +
//! transport shim) is DELETED: the stock MINT script drives the stock
//! `FungibleFaucet::mint_and_send`, and the ENTIRE attestation gate lives in the faucet's active
//! attestation mint policy (`xreserve::mint_policy::check_policy`), which hash-verifies these
//! attachments and enforces the ASSERT-MATCH binding against the storage this factory builds.
//!
//! Transport layout:
//! - STOCK [`MintNoteStorage::FungiblePublic`]: the P2ID output-note recipe (target = the
//!   intent's `remoteRecipient` account, serial = the canonical nonce key — the policy re-derives
//!   and `assert_eqw`s the full recipe), the [`FungibleAsset`] of the ATTESTED reduced amount for
//!   the target faucet, and the output-note tag targeting the attested recipient.
//! - THREE [`NoteAttachments`] attachments: (1) the scheme-4 DepositIntent preimage
//!   ([`XUSDC_MINT_INTENT_ATTACHMENT_SCHEME`]) — the u32-LE-packed felts of the RAW payload,
//!   zero-padded to the word boundary (the policy re-derives the exact felt length from the
//!   embedded hookDataLen and binds it to the committed word count); (2) the scheme-5 attestation
//!   ([`XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME`]) = 11 words `[feeAmount(8 limbs, MVP zero —
//!   DEV-8), pubkey(16 affine felts — vm#3342), signature(17), pad(3)]`, the frozen advice order
//!   the D5b/D5d stages consume (packing reuses the shared-encoding codec
//!   [`affine_pubkey_felts`] / [`signature_felts`] by reference); and (3) the scheme-2
//!   `NetworkAccountTarget` routing bind to the faucet network account
//!   (`NoteExecutionHint::Always`, routing-only). Schemes 4/5 clear the reserved value 1 and the
//!   standard values 2/3 (rider A8); the policy asserts exactly these three attachments.
//! - The stock `MintNote` conversion FORCES `NoteType::Public` and tags the note itself with the
//!   faucet account target (`NoteTag::with_account_target(faucet_id)` — network routing).
//!
//! The relayer stages NO advice: attachment content is public note data the executor feeds to
//! the advice provider; the policy hash-verifies it against the note-committed commitments.

use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAttachment, NoteAttachmentScheme, NoteScript, NoteScriptRoot, NoteTag,
};
use miden_protocol::{Felt, Word};
use miden_standards::note::{
    MintNote, MintNoteStorage, NetworkAccountTarget, NoteExecutionHint, P2idNoteStorage,
};

use crate::xreserve::encoding::{
    affine_pubkey_felts, bytes32_to_account_id, bytes32_to_storage_map_key,
    deposit_intent_to_packed_felts, parse_deposit_intent_header, signature_felts,
    uint256_to_asset_amount,
};

/// The mint-note DepositIntent attachment scheme (u16, project-chosen; rider A8: >= 4, clear of
/// the reserved "none" value 1 and the standard values 2 `NetworkAccountTarget` / 3 `Pswap`).
/// Declared identically in `mint_policy.masm` (`masm-rust-constant-parity` via
/// `constant_parity.rs`); the policy's `find_attachment` fail-closes on a mismatch. Not a
/// Circle-owned value.
pub const XUSDC_MINT_INTENT_ATTACHMENT_SCHEME: u16 = 4;

/// The mint-note attestation attachment scheme (rider A8; see the intent scheme above).
/// Declared identically in `mint_policy.masm` (parity-pinned).
pub const XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME: u16 = 5;

/// The attestation attachment word count: `[feeAmount(8), pubkey(16), signature(17), pad(3)]`
/// = 44 felts (the pubkey is the 16-felt affine form since the v16 migration — vm#3342,
/// MIGRATION-V16-ALPHA2.md S16). Declared identically in `mint_policy.masm` (parity-pinned).
pub const XUSDC_MINT_ATTESTATION_NUM_WORDS: usize = 11;

/// The DC-5 uint256 -> AssetAmount decimal scale the faucet applies. DEV-5 (cap / scale / dust)
/// remains Circle-OPEN; the faucet ships the PROVISIONAL scale-0 position because Circle's on-wire
/// deposit `amount` is 6-decimal smallest units and xUSDC is 6-decimal, so the reduction is the
/// identity. Declared identically in `mint_policy.masm` (`DEPOSIT_SCALE_EXP`, parity-pinned); this
/// factory reduces the attested amount with the SAME scale so the storage it builds passes the
/// policy's ASSERT-MATCH amount compare.
pub const XUSDC_DEPOSIT_SCALE_EXP: u32 = 0;

/// The Circle deposit attestation crossing the note boundary (DC-2/DC-3): the raw 65-byte
/// `r‖s‖v` ECDSA signature over `keccak256(payload)` and the raw 33-byte compressed SEC1
/// candidate pubkey. Lengths are type-enforced; felt packing happens in [`XUsdcMintNote`]
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

/// The production mint-note factory (CMP-B1): builds the STOCK [`MintNote`] carrying the xUSDC
/// attested transport. A standalone unit-struct factory like its siblings; the note script is the
/// STOCK standards MINT script (no custom root to pin — [`Self::script_root`] delegates to
/// [`MintNote::script_root`], which is what the note-script allowlist row 1 holds).
pub struct XUsdcMintNote;

impl XUsdcMintNote {
    /// The STOCK standards MINT note script the transport rides on.
    pub fn script() -> NoteScript {
        MintNote::script()
    }

    /// The STOCK MINT note script root (the allowlist row-1 identity).
    pub fn script_root() -> NoteScriptRoot {
        MintNote::script_root()
    }

    /// Creates the production mint note: `sender` is the producer/relayer account, `faucet_id`
    /// the consuming faucet, `deposit_intent` the RAW Circle-signed DepositIntent payload bytes
    /// (validated + packed via the shared-encoding codec by reference — structural rejects
    /// surface as [`NoteError`] with the codec error as source), `attestation` the raw sig +
    /// candidate pubkey. The storage embeds the ATTESTED values (P2ID recipe to the intent's
    /// `remoteRecipient` with the nonce-key serial; the scale-0-reduced amount as a
    /// [`FungibleAsset`] of `faucet_id`; the recipient's account-target tag) so the faucet's
    /// attestation policy accepts it under the ASSERT-MATCH binding. Asset-less on the wire;
    /// `NoteType::Public` forced by the stock conversion.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        deposit_intent: &[u8],
        attestation: &MintAttestation,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let header = parse_deposit_intent_header(deposit_intent).map_err(|source| {
            NoteError::other_with_source("deposit intent payload rejected by the 04 codec", source)
        })?;
        // the attested output-note ingredients: recipient account, reduced amount, nonce-key
        // serial — the SAME derivations the on-chain policy re-computes and assert-matches.
        let recipient_id = bytes32_to_account_id(&header.remote_recipient).map_err(|source| {
            NoteError::other_with_source(
                "deposit intent remoteRecipient is not a valid account id",
                source,
            )
        })?;
        let amount =
            uint256_to_asset_amount(uint256_le_limbs(&header.amount), XUSDC_DEPOSIT_SCALE_EXP)
                .map_err(|source| {
                    NoteError::other_with_source(
                        "deposit intent amount rejected by the 04 reducer",
                        source,
                    )
                })?;
        let asset = FungibleAsset::new(faucet_id, u64::from(amount))
            .map_err(|source| NoteError::other_with_source("attested amount", source))?;
        let serial = Word::from(bytes32_to_storage_map_key(&header.nonce));
        let recipient = P2idNoteStorage::new(recipient_id).into_recipient(serial);
        let tag = NoteTag::with_account_target(recipient_id);
        let storage = MintNoteStorage::new_fungible_public(recipient, asset, tag)?;
        let target =
            NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always).map_err(|err| {
                NoteError::other_with_source("faucet id is not a public network account", err)
            })?;
        let mint_note = MintNote::builder()
            .sender(sender)
            .mint_storage(storage)
            .serial_number(rng.draw_word())
            .attachment(Self::intent_attachment(deposit_intent)?)
            .attachment(Self::attestation_attachment(attestation)?)
            .attachment(NoteAttachment::from(target))
            .build()?;
        Ok(Note::from(mint_note))
    }

    /// Builds the scheme-4 DepositIntent attachment: the u32-LE-packed payload felts (60 header
    /// felts + ⌈hookDataLen/4⌉ hookData felts, via the shared-encoding codec by reference),
    /// zero-padded to the word boundary — attachment content is word-granular, and the on-chain
    /// policy re-derives the exact felt length from the embedded hookDataLen and binds it to
    /// this attachment's committed word count.
    fn intent_attachment(deposit_intent: &[u8]) -> Result<NoteAttachment, NoteError> {
        let mut felts = deposit_intent_to_packed_felts(deposit_intent).map_err(|source| {
            NoteError::other_with_source("deposit intent payload rejected by the 04 codec", source)
        })?;
        while felts.len() % 4 != 0 {
            felts.push(Felt::from(0u32));
        }
        let words: Vec<Word> = felts
            .chunks_exact(4)
            .map(|chunk| Word::new([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        NoteAttachment::with_words(
            NoteAttachmentScheme::new(XUSDC_MINT_INTENT_ATTACHMENT_SCHEME)?,
            words,
        )
    }

    /// Builds the scheme-5 attestation attachment: 44 felts
    /// `[feeAmount(8 zero limbs), pubkey(16 affine felts), signature(17), pad(3)]` as 11 words —
    /// the exact order the policy's advice re-surfacing hands to the D5b/D5d stages
    /// (element-0-first `adv.push_mapval` pop order, pinned by the transport canary). The
    /// feeAmount limbs are MVP-zero (DEV-8, hardcoded: a non-zero fee would only ever trap the
    /// F2 guard on-chain). The 33-byte compressed wire pubkey is decompressed to its affine
    /// coordinates here (vm#3342; an off-curve key rejects — it could never verify on-chain).
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
        debug_assert_eq!(words.len(), XUSDC_MINT_ATTESTATION_NUM_WORDS);
        NoteAttachment::with_words(
            NoteAttachmentScheme::new(XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME)?,
            words,
        )
    }
}

/// The 8 u32-LE packed limbs of a big-endian uint256 wire field (limb i = LE-u32 of wire bytes
/// `[4i, 4i+4)`) — the limb form the shared-encoding reducer consumes.
fn uint256_le_limbs(bytes: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| {
        u32::from_le_bytes(
            bytes[4 * i..4 * i + 4]
                .try_into()
                .expect("4-byte window of a 32-byte field"),
        )
    })
}
