//! `XUsdcMintNote`: builds the note that carries a Circle-attested deposit to the faucet.
//!
//! The note is a standard [`MintNote`] driving the standard
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
//! - Two attachments travel with it. Scheme 4 is the whole
//!   Circle-signed transport in one attachment: the attestation as eleven words — fee amount
//!   (8 felts), attester public key (16), signature (17), 3 padding felts, in the order the
//!   policy reads them; the fee is zero while relayer fees remain open with Circle — and then the
//!   raw deposit-intent payload, u32-little-endian packed and zero-padded to a word boundary. The
//!   policy re-derives the true felt length from the payload's own `hookDataLen`, so the padding
//!   cannot hide extra data. Scheme 2 routes the note to the faucet's network account.
//!
//!   The attestation comes FIRST because it is fixed-width: that keeps the deposit intent's
//!   starting offset a constant instead of a function of `hookDataLen`, which is what lets the
//!   policy read every sub-region at a constant offset — and what keeps the Circle-signed byte
//!   extent 1:1 identifiable inside the merged attachment.

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
    bytes32_to_account_id, bytes32_to_packed_u32_limbs, bytes32_to_storage_map_key,
    uint256_to_asset_amount, DepositIntent, DepositIntentHeader, PublicKey, Signature,
};

/// The mint-note transport attachment scheme (u16, project-chosen: >= 4, clear of
/// the reserved "none" value 1 and the standard values 2 `NetworkAccountTarget` / 3 `Pswap`).
/// This attachment carries both the attestation and the DepositIntent preimage.
pub const XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME: u16 = 4;

/// The attestation section word count: `[feeAmount(8), pubkey(16), signature(17), pad(3)]`
/// = 44 felts.
pub const XUSDC_MINT_ATTESTATION_NUM_WORDS: usize = 11;

/// Word offset of the DepositIntent sub-region inside the transport attachment: past the
/// fixed-width attestation.
pub const XUSDC_MINT_TRANSPORT_INTENT_WORD_OFF: usize = XUSDC_MINT_ATTESTATION_NUM_WORDS;

/// The uint256 -> AssetAmount decimal scale the faucet applies. The cap / scale / dust decision
/// stays OPEN, pending Circle confirmation; the faucet ships the PROVISIONAL scale-0 position
/// because Circle's on-wire deposit `amount` is 6-decimal smallest units and xUSDC is 6-decimal, so
/// the reduction is the identity. This factory reduces the attested amount with the SAME scale the
/// faucet applies, so the storage it builds passes the policy's ASSERT-MATCH amount compare.
pub const XUSDC_DEPOSIT_SCALE_EXP: u32 = 0;

/// The Circle deposit attestation crossing the note boundary: the raw 65-byte
/// `r‖s‖v` ECDSA signature over `keccak256(payload)` and the raw 33-byte compressed SEC1
/// candidate pubkey.
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

/// The mint note's dedicated note-storage type — the attested output-note recipe the faucet's
/// attestation policy assert-matches. It is DERIVED from the typed inputs (the DepositIntent header
/// together with the consuming faucet id), never caller-supplied, so the storage cannot diverge from
/// the attested values. It wraps the stock [`MintNoteStorage`] (a private field with read-only
/// accessors, per the standards `PswapNoteStorage` pattern) rather than exposing a second copy of the
/// recipe.
pub struct XUsdcMintNoteStorage {
    storage: MintNoteStorage,
}

impl XUsdcMintNoteStorage {
    /// Derives the mint-note storage from the attested DepositIntent `header` and the consuming
    /// `faucet_id`: the P2ID recipe to the intent's `remoteRecipient` (serial = the nonce-derived
    /// key), the scale-reduced attested amount as a [`FungibleAsset`] of the faucet, and the
    /// recipient's account-target tag.
    ///
    /// # Errors
    ///
    /// [`NoteError`] if `remoteRecipient` is not a valid account id, the amount is out of range, or
    /// the mint storage cannot be assembled.
    pub fn from_attested(
        header: &DepositIntentHeader,
        faucet_id: AccountId,
    ) -> Result<Self, NoteError> {
        let recipient_id = bytes32_to_account_id(&header.remote_recipient).map_err(|source| {
            NoteError::other_with_source(
                "deposit intent remoteRecipient is not a valid account id",
                source,
            )
        })?;
        let amount = uint256_to_asset_amount(
            bytes32_to_packed_u32_limbs(&header.amount),
            XUSDC_DEPOSIT_SCALE_EXP,
        )
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
        Ok(Self { storage })
    }

    /// A read-only view of the derived stock mint storage.
    pub fn as_mint_storage(&self) -> &MintNoteStorage {
        &self.storage
    }

    /// Consumes into the stock [`MintNoteStorage`] the [`MintNote`] builder installs.
    pub fn into_mint_storage(self) -> MintNoteStorage {
        self.storage
    }
}

/// The mint-note factory: builds the [`MintNote`] carrying the xUSDC
/// attested transport.
pub struct XUsdcMintNote;

impl XUsdcMintNote {
    /// The [`MintNote`] script the transport rides on.
    pub fn script() -> NoteScript {
        MintNote::script()
    }

    /// The [`MintNote`] script root.
    pub fn script_root() -> NoteScriptRoot {
        MintNote::script_root()
    }

    /// Convenience constructor over the RAW Circle-signed DepositIntent payload bytes (a thin
    /// delegator to the [`builder`](Self::builder)); retained because the frozen conformance suites
    /// pin this signature. New callers should prefer the typed builder, which takes a
    /// [`DepositIntent`].
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        deposit_intent: &[u8],
        attestation: &MintAttestation,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        Self::builder()
            .sender(sender)
            .faucet_id(faucet_id)
            .deposit_intent(DepositIntent::new(deposit_intent))
            .attestation(attestation)
            .rng(rng)
            .build()
    }
}

#[bon::bon]
impl XUsdcMintNote {
    /// Builds the production mint note via a `bon` builder
    /// (`XUsdcMintNote::builder().sender(..).faucet_id(..).deposit_intent(..).attestation(..).rng(..).build()`):
    /// `sender` is the producer/relayer account, `faucet_id` the consuming faucet, `deposit_intent`
    /// the typed [`DepositIntent`] payload (parsed and packed by the shared codec, so a structurally
    /// invalid payload is rejected here rather than on-chain — it surfaces as a [`NoteError`] carrying
    /// the codec's error as its source), `attestation` the raw signature and candidate pubkey. The
    /// storage embeds the ATTESTED values (P2ID recipe to the intent's `remoteRecipient` with the
    /// nonce-key serial; the scale-0-reduced amount as a [`FungibleAsset`] of `faucet_id`; the
    /// recipient's account-target tag) so the faucet's attestation policy accepts it under the
    /// ASSERT-MATCH binding.
    #[builder]
    pub fn new<'a, R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        deposit_intent: DepositIntent<'a>,
        attestation: &MintAttestation,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let header = deposit_intent.parse_header().map_err(|source| {
            NoteError::other_with_source(
                "deposit intent payload rejected by the shared codec",
                source,
            )
        })?;
        // the attested output-note recipe, encapsulated in the mint note's dedicated storage type —
        // the SAME derivations the on-chain policy re-computes and assert-matches.
        let storage = XUsdcMintNoteStorage::from_attested(&header, faucet_id)?;
        let target =
            NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always).map_err(|err| {
                NoteError::other_with_source("faucet id is not a public network account", err)
            })?;
        let mint_note = MintNote::builder()
            .sender(sender)
            .mint_storage(storage.into_mint_storage())
            .serial_number(rng.draw_word())
            .attachment(Self::transport_attachment(deposit_intent, attestation)?)
            .attachment(NoteAttachment::from(target))
            .build()?;
        Ok(Note::from(mint_note))
    }

    /// Builds the scheme-4 transport attachment — the whole Circle-signed payload in one
    /// attachment, in two sections:
    ///
    /// 1. 44 felts `[feeAmount(8 zero limbs), pubkey(16 affine felts), signature(17), pad(3)]`.
    /// 2. the u32-LE-packed DepositIntent payload (60 header felts plus ⌈hookDataLen/4⌉ hookData
    ///    felts, packed by the shared codec), zero-padded to the word boundary.
    ///
    /// The layout is a contract: the policy hash-verifies these words into one memory region and
    /// hands each verify stage a pointer at a constant offset into it, so a reordering here would
    /// silently repoint them. In particular section 2's offset is what identifies the
    /// Circle-signed byte extent — the attester signed exactly the `240 + hookDataLen` bytes that
    /// pack into it, and the policy keccaks exactly those. Attachment content is word-granular,
    /// and the policy re-derives the exact felt length from the embedded hookDataLen and binds it
    /// to this attachment's committed word count, so the trailing padding cannot hide data.
    ///
    /// The feeAmount limbs are hardcoded to zero, there being no relayer-fee split yet. The
    /// 33-byte compressed wire pubkey is decompressed to its affine coordinates here, so an
    /// off-curve key rejects rather than reaching the chain.
    fn transport_attachment(
        deposit_intent: DepositIntent<'_>,
        attestation: &MintAttestation,
    ) -> Result<NoteAttachment, NoteError> {
        let mut felts: Vec<Felt> = Vec::new();

        felts.extend([Felt::from(0u32); 8]);
        felts.extend(
            PublicKey::new(*attestation.pubkey())
                .to_affine_felts()
                .map_err(|source| {
                    NoteError::other_with_source(
                        "attestation pubkey rejected by the shared codec",
                        source,
                    )
                })?,
        );
        felts.extend(Signature::new(*attestation.signature()).to_felts());
        felts.extend([Felt::from(0u32); 3]);
        debug_assert_eq!(felts.len(), XUSDC_MINT_TRANSPORT_INTENT_WORD_OFF * 4);

        felts.extend(deposit_intent.to_packed_felts().map_err(|source| {
            NoteError::other_with_source(
                "deposit intent payload rejected by the shared codec",
                source,
            )
        })?);
        while !felts.len().is_multiple_of(4) {
            felts.push(Felt::from(0u32));
        }

        let words: Vec<Word> = felts
            .chunks_exact(4)
            .map(|chunk| Word::new([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        NoteAttachment::with_words(
            NoteAttachmentScheme::new(XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME)?,
            words,
        )
    }
}
