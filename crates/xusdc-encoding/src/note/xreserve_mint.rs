//! `XUsdcMintNote`: builds the note that carries a Circle-attested deposit to the faucet.
//!
//! There is no custom mint note script. The note is a standard [`MintNote`] driving the standard
//! `mint_and_send`; everything specific to xUSDC rides along as attachments. The authorization
//! decision lives entirely in the faucet's active mint policy, which re-derives the note's contents
//! from the attested payload and refuses anything that does not match — so this factory's only job
//! is to produce a note that policy will accept.
//!
//! What that means field by field:
//!
//! - The mint-note storage holds the output note's pay-to-id recipe: target = the intent's
//!   `remoteRecipient`, serial = the key derived from the deposit nonce, asset = the reduced
//!   attested amount, tag = the attested recipient.
//! - Three attachments travel with it, and none of them is note storage. Scheme 4 is the raw
//!   deposit-intent payload, u32-little-endian packed and zero-padded to a word boundary — the
//!   policy re-derives the true felt length from the payload's own `hookDataLen`, so the padding
//!   cannot hide extra data. Scheme 5 is the attestation as eleven words: fee amount (8 felts),
//!   attester public key (16), signature (17), 3 padding felts, in the order the policy reads
//!   them; the fee is zero while relayer fees remain open with Circle. Scheme 2 routes the note to
//!   the faucet's network account.
//! - Converting to a `MintNote` forces the note public and tags it at the faucet, which is what
//!   makes it routable and observable.
//!
//! Nothing is staged on the advice provider: attachment contents are public note data the executor
//! supplies, and the policy hash-verifies each against the commitment the note carries.

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

/// The mint-note DepositIntent attachment scheme (u16, project-chosen: >= 4, clear of
/// the reserved "none" value 1 and the standard values 2 `NetworkAccountTarget` / 3 `Pswap`).
/// Declared identically in `mint_policy.masm`; the policy's `find_attachment` fail-closes on a
/// mismatch. Not a Circle-owned value.
pub const XUSDC_MINT_INTENT_ATTACHMENT_SCHEME: u16 = 4;

/// The mint-note attestation attachment scheme (see the intent scheme above).
/// Declared identically in `mint_policy.masm`.
pub const XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME: u16 = 5;

/// The attestation attachment word count: `[feeAmount(8), pubkey(16), signature(17), pad(3)]`
/// = 44 felts (the pubkey is the 16-felt affine
/// form). Declared identically in `mint_policy.masm`.
pub const XUSDC_MINT_ATTESTATION_NUM_WORDS: usize = 11;

/// The uint256 -> AssetAmount decimal scale the faucet applies. The cap / scale / dust decision
/// stays OPEN, pending Circle confirmation; the faucet ships the PROVISIONAL scale-0 position
/// because Circle's on-wire deposit `amount` is 6-decimal smallest units and xUSDC is 6-decimal, so
/// the reduction is the identity. Declared identically in `mint_policy.masm` as
/// `DEPOSIT_SCALE_EXP`; this factory reduces the attested amount with the SAME scale so the storage
/// it builds passes the policy's ASSERT-MATCH amount compare.
pub const XUSDC_DEPOSIT_SCALE_EXP: u32 = 0;

/// The Circle deposit attestation crossing the note boundary: the raw 65-byte
/// `r‖s‖v` ECDSA signature over `keccak256(payload)` and the raw 33-byte compressed SEC1
/// candidate pubkey. The lengths are enforced by the types themselves; converting these bytes to
/// field elements happens in [`XUsdcMintNote`], through the shared codec.
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

/// The production mint-note factory: builds the STOCK [`MintNote`] carrying the xUSDC
/// attested transport. The note script is the STOCK standards MINT script, so there is no custom
/// root to pin and [`Self::script_root`] delegates to [`MintNote::script_root`].
pub struct XUsdcMintNote;

impl XUsdcMintNote {
    /// The STOCK standards MINT note script the transport rides on.
    pub fn script() -> NoteScript {
        MintNote::script()
    }

    /// The STOCK MINT note script root.
    pub fn script_root() -> NoteScriptRoot {
        MintNote::script_root()
    }

    /// Creates the production mint note: `sender` is the producer/relayer account, `faucet_id`
    /// the consuming faucet, `deposit_intent` the RAW Circle-signed DepositIntent payload bytes
    /// (parsed and packed by the shared codec, so a structurally invalid payload is rejected here
    /// rather than on-chain — it surfaces as a [`NoteError`] carrying the codec's error as its
    /// source), `attestation` the raw signature and
    /// candidate pubkey. The storage embeds the ATTESTED values (P2ID recipe to the intent's
    /// `remoteRecipient` with the nonce-key serial; the scale-0-reduced amount as a
    /// [`FungibleAsset`] of `faucet_id`; the recipient's account-target tag) so the faucet's
    /// attestation policy accepts it under the ASSERT-MATCH binding. Nothing is attached to the
    /// note as an asset — the amount rides in that storage — and the stock conversion forces
    /// `NoteType::Public`.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        deposit_intent: &[u8],
        attestation: &MintAttestation,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let header = parse_deposit_intent_header(deposit_intent).map_err(|source| {
            NoteError::other_with_source(
                "deposit intent payload rejected by the shared codec",
                source,
            )
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
                        "deposit intent amount rejected by the amount reducer",
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
    /// felts plus ⌈hookDataLen/4⌉ hookData felts, packed by the shared codec),
    /// zero-padded to the word boundary — attachment content is word-granular, and the on-chain
    /// policy re-derives the exact felt length from the embedded hookDataLen and binds it to
    /// this attachment's committed word count.
    fn intent_attachment(deposit_intent: &[u8]) -> Result<NoteAttachment, NoteError> {
        let mut felts = deposit_intent_to_packed_felts(deposit_intent).map_err(|source| {
            NoteError::other_with_source(
                "deposit intent payload rejected by the shared codec",
                source,
            )
        })?;
        while !felts.len().is_multiple_of(4) {
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
    /// `[feeAmount(8 zero limbs), pubkey(16 affine felts), signature(17), pad(3)]` as 11 words.
    /// The layout is a contract: the policy hash-verifies these words into one memory region and
    /// hands the amount and attestation-verify stages pointers at these three offsets, so a
    /// reordering here would silently repoint them. The feeAmount limbs are hardcoded to zero,
    /// there being no relayer-fee split yet. The 33-byte compressed wire pubkey is decompressed to
    /// its affine coordinates here, so an off-curve key rejects rather than reaching the chain.
    fn attestation_attachment(attestation: &MintAttestation) -> Result<NoteAttachment, NoteError> {
        let mut felts: Vec<Felt> = Vec::with_capacity(44);
        felts.extend([Felt::from(0u32); 8]);
        felts.extend(affine_pubkey_felts(attestation.pubkey()).map_err(|source| {
            NoteError::other_with_source("attestation pubkey rejected by the shared codec", source)
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
