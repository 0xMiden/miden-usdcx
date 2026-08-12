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
//! - Two attachments travel with it. Scheme 4 is the whole transport in one attachment: the
//!   attestation as nine words — attester public key (16 felts), signature (17), 3 padding felts,
//!   in the order the policy reads them — and then the carried mint payload, zero-padded to a word
//!   boundary. The policy re-derives the true felt length from the payload's own `hookDataLen`, so
//!   the padding cannot hide extra data. Scheme 2 routes the note to the faucet's network account.
//!
//!   The attestation comes FIRST because it is fixed-width: that keeps the payload's starting
//!   offset a constant instead of a function of `hookDataLen`, which is what lets the policy read
//!   every sub-region at a constant offset. The Circle-signed DepositIntent itself does not
//!   travel — the faucet rebuilds it from the carried payload plus its own state.

use miden_protocol::account::AccountId;
use miden_protocol::asset::{AssetAmount, FungibleAsset};
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
    DepositIntent, MintIntent, PublicKey, Signature, BYTES_PER_PACKED_FELT, MAX_HOOK_DATA_LEN,
    MINT_INTENT_FELTS,
};

/// The mint-note transport attachment scheme (u16, project-chosen: >= 4, clear of
/// the reserved "none" value 1 and the standard values 2 `NetworkAccountTarget` / 3 `Pswap`).
/// This attachment carries both the attestation and the DepositIntent preimage.
pub const XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME: u16 = 4;

/// The attestation section word count: `[pubkey(16), signature(17), pad(3)]` = 36 felts (the
/// pubkey is the 16-felt affine form). The operator `feeAmount` is not carried at all — the faucet
/// writes a zero fee into the preimage it rebuilds, so a non-zero one is inexpressible.
pub const XUSDC_MINT_ATTESTATION_NUM_WORDS: usize = 9;

/// Word offset of the carried mint payload inside the transport attachment: past the fixed-width
/// attestation. Constant by construction — see the module docs on why the attestation goes first.
pub const XUSDC_MINT_TRANSPORT_PAYLOAD_WORD_OFF: usize = XUSDC_MINT_ATTESTATION_NUM_WORDS;

// The codec's hookData ceiling must equal this transport's capacity (the per-attachment word cap
// minus the attestation and the carried payload, in bytes).
const _: () = assert!(
    MAX_HOOK_DATA_LEN
        == (NoteAttachment::MAX_NUM_WORDS as usize
            - XUSDC_MINT_ATTESTATION_NUM_WORDS
            - MINT_INTENT_FELTS / 4)
            * 4
            * BYTES_PER_PACKED_FELT,
    "the codec's MAX_HOOK_DATA_LEN must equal the mint transport's hookData capacity"
);

/// The uint256 -> AssetAmount decimal scale the faucet applies. The cap / scale / dust decision
/// stays OPEN, pending Circle confirmation; the faucet ships the PROVISIONAL scale-0 position
/// because Circle's on-wire deposit `amount` is 6-decimal smallest units and xUSDC is 6-decimal, so
/// the reduction is the identity. This factory reduces the attested amount with the SAME scale the
/// faucet applies, so the storage it builds passes the policy's ASSERT-MATCH amount compare.
pub const XUSDC_DEPOSIT_SCALE_EXP: u32 = 0;

/// The Circle deposit attestation crossing the note boundary: the [`Signature`] over
/// `keccak256(payload)` and the candidate attester [`PublicKey`].
///
/// It holds the two shared-codec newtypes rather than their byte forms, so the raw arrays are
/// named once — where they arrive from Circle — and every use site downstream already has the
/// thing rather than bytes that have to be re-interpreted as it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositAttestation {
    signature: Signature,
    pubkey: PublicKey,
}

impl DepositAttestation {
    /// Bundles the `r‖s‖v` signature with the compressed candidate pubkey.
    pub fn new(signature: Signature, pubkey: PublicKey) -> Self {
        Self { signature, pubkey }
    }

    /// The `r‖s‖v` signature (`v` carried, unused on-chain).
    pub fn signature(&self) -> Signature {
        self.signature
    }

    /// The compressed SEC1 candidate pubkey.
    pub fn pubkey(&self) -> PublicKey {
        self.pubkey
    }
}

/// The mint note's dedicated note-storage type — the attested output-note recipe the faucet's
/// attestation policy assert-matches. It is DERIVED from the typed inputs (the decoded
/// [`MintIntent`] together with the consuming faucet id), never caller-supplied, so the storage
/// cannot diverge from the attested values. It wraps the stock [`MintNoteStorage`] (a private field
/// with read-only accessors, per the standards `PswapNoteStorage` pattern) rather than exposing a
/// second copy of the recipe.
pub struct XUsdcMintNoteStorage {
    storage: MintNoteStorage,
}

impl XUsdcMintNoteStorage {
    /// Derives the mint-note storage from the decoded `intent`, its scale-reduced `amount` and the
    /// consuming `faucet_id`: the P2ID recipe to the intent's `remoteRecipient` (serial = the
    /// nonce-derived key), the amount as a [`FungibleAsset`] of the faucet, and the recipient's
    /// account-target tag.
    ///
    /// The recipient and the serial come off the already-decoded intent rather than being decoded
    /// a second time out of the raw header, which is what makes this derivation total: the intent
    /// only exists because those two fields already decoded.
    ///
    /// # Errors
    ///
    /// [`NoteError`] if the amount is out of range for the faucet, or the mint storage cannot be
    /// assembled.
    pub fn from_attested(
        intent: &MintIntent,
        amount: AssetAmount,
        faucet_id: AccountId,
    ) -> Result<Self, NoteError> {
        let recipient_id = intent.remote_recipient();
        let asset = FungibleAsset::new(faucet_id, u64::from(amount))
            .map_err(|source| NoteError::other_with_source("attested amount", source))?;
        let serial = Word::from(intent.nonce().to_storage_map_key());
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

/// The Circle deposit a mint note carries: the decoded [`MintIntent`] together with the
/// [`DepositAttestation`] that authorizes it.
///
/// This is the scheme-4 transport attachment in domain form. It converts into the
/// [`NoteAttachment`] the faucet hash-verifies, the way the standards [`NetworkAccountTarget`]
/// converts into the scheme-2 routing one.
pub struct XUsdcDeposit {
    intent: MintIntent,
    attestation: DepositAttestation,
}

impl XUsdcDeposit {
    /// Bundles a decoded intent with the attestation over the payload it was decoded from.
    pub fn new(intent: MintIntent, attestation: DepositAttestation) -> Self {
        Self {
            intent,
            attestation,
        }
    }

    /// The carried mint payload.
    pub fn intent(&self) -> &MintIntent {
        &self.intent
    }

    /// The attestation travelling beside it.
    pub fn attestation(&self) -> DepositAttestation {
        self.attestation
    }
}

impl TryFrom<&XUsdcDeposit> for NoteAttachment {
    type Error = NoteError;

    /// Builds the scheme-4 transport attachment — everything the faucet needs to rebuild and
    /// verify the Circle-signed message, in three sections:
    ///
    /// 1. 36 felts `[pubkey(16 affine felts), signature(17), pad(3)]`.
    /// 2. the 24-felt carried mint payload (`DC-14`).
    /// 3. the u32-LE-packed hookData, zero-padded to the word boundary.
    ///
    /// The layout is a contract: the policy hash-verifies these words into one memory region and
    /// reads each section at a constant offset into it, so a reordering here would silently
    /// repoint them. The DepositIntent itself is NOT carried — the faucet rebuilds it from
    /// section 2 plus its own state, which is what makes the addressing fields unforgeable.
    ///
    /// # Errors
    ///
    /// [`NoteError`] if the candidate pubkey does not decompress to a curve point. The conversion
    /// is fallible for that reason alone; the key is deliberately NOT validated earlier, so the
    /// rejection keeps surfacing from the same place it always has.
    fn try_from(deposit: &XUsdcDeposit) -> Result<Self, Self::Error> {
        let mut felts: Vec<Felt> = Vec::new();

        felts.extend(
            deposit
                .attestation
                .pubkey()
                .to_affine_felts()
                .map_err(|source| {
                    NoteError::other_with_source(
                        "attestation pubkey rejected by the shared codec",
                        source,
                    )
                })?,
        );
        felts.extend(deposit.attestation.signature().to_felts());
        felts.extend([Felt::from(0u32); 3]);
        debug_assert_eq!(felts.len(), XUSDC_MINT_TRANSPORT_PAYLOAD_WORD_OFF * 4);

        felts.extend(deposit.intent.to_felts());
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

/// The mint note carrying the xUSDC attested transport: a [`MintNote`] whose two attachments are
/// the scheme-4 deposit and the scheme-2 routing bind.
///
/// It holds its parts — every one of them already decoded and already validated — and converts
/// into a protocol [`Note`] with `Note::try_from`.
pub struct XUsdcMintNote {
    sender: AccountId,
    storage: XUsdcMintNoteStorage,
    serial_number: Word,
    deposit: XUsdcDeposit,
    network_account_target: NetworkAccountTarget,
}

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
        attestation: &DepositAttestation,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        Note::try_from(
            Self::builder()
                .sender(sender)
                .faucet_id(faucet_id)
                .deposit_intent(DepositIntent::new(deposit_intent))
                .attestation(attestation)
                .generate_serial_number(rng)
                .build()?,
        )
    }
}

#[bon::bon]
impl XUsdcMintNote {
    /// Builds the production mint note via a `bon` builder
    /// (`XUsdcMintNote::builder().sender(..).faucet_id(..).deposit_intent(..).attestation(..).generate_serial_number(..).build()`):
    /// `sender` is the producer/relayer account, `faucet_id` the consuming faucet, `deposit_intent`
    /// the typed [`DepositIntent`] payload (parsed and packed by the shared codec, so a structurally
    /// invalid payload is rejected here rather than on-chain — it surfaces as a [`NoteError`] carrying
    /// the codec's error as its source), `attestation` the signature and candidate pubkey. The
    /// storage embeds the ATTESTED values (P2ID recipe to the intent's `remoteRecipient` with the
    /// nonce-key serial; the scale-0-reduced amount as a [`FungibleAsset`] of `faucet_id`; the
    /// recipient's account-target tag) so the faucet's attestation policy accepts it under the
    /// ASSERT-MATCH binding.
    #[builder]
    pub fn new<'a>(
        sender: AccountId,
        faucet_id: AccountId,
        deposit_intent: DepositIntent<'a>,
        attestation: &'a DepositAttestation,
        serial_number: Word,
    ) -> Result<Self, NoteError> {
        let header = deposit_intent.parse_header().map_err(|source| {
            NoteError::other_with_source(
                "deposit intent payload rejected by the shared codec",
                source,
            )
        })?;
        // compress to what the note actually carries. This rejects every intent this faucet could
        // not rebuild byte-for-byte, which on-chain would only ever surface as a bad signature.
        let payload =
            MintIntent::from_deposit_intent(&deposit_intent, faucet_id).map_err(|source| {
                NoteError::other_with_source(
                    "deposit intent cannot be carried by the mint transport",
                    source,
                )
            })?;
        let amount = header
            .reduced_amount(XUSDC_DEPOSIT_SCALE_EXP)
            .map_err(|source| {
                NoteError::other_with_source(
                    "deposit intent amount rejected by the amount reducer",
                    source,
                )
            })?;
        // the attested output-note recipe, encapsulated in the mint note's dedicated storage type —
        // the SAME derivations the on-chain policy re-computes and assert-matches.
        let storage = XUsdcMintNoteStorage::from_attested(&payload, amount, faucet_id)?;
        let network_account_target =
            NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always).map_err(|err| {
                NoteError::other_with_source("faucet id is not a public network account", err)
            })?;
        Ok(Self {
            sender,
            storage,
            serial_number,
            deposit: XUsdcDeposit::new(payload, *attestation),
            network_account_target,
        })
    }
}

// BUILDER EXTENSIONS
// ================================================================================================

impl<'a, S: x_usdc_mint_note_builder::State> XUsdcMintNoteBuilder<'a, S>
where
    S::SerialNumber: x_usdc_mint_note_builder::IsUnset,
{
    /// Draws a serial number from `rng` and sets it on the builder — the stock
    /// `MintNote::generate_serial_number` shape.
    pub fn generate_serial_number(
        self,
        rng: &mut impl FeltRng,
    ) -> XUsdcMintNoteBuilder<'a, x_usdc_mint_note_builder::SetSerialNumber<S>> {
        self.serial_number(rng.draw_word())
    }
}

// CONVERSIONS
// ================================================================================================

impl TryFrom<XUsdcMintNote> for Note {
    type Error = NoteError;

    /// Assembles the stock [`MintNote`] and converts it into a protocol [`Note`]: the derived mint
    /// storage, the drawn serial, then the two attachments in their frozen order — the scheme-4
    /// deposit first (fixed-width attestation ahead of the variable payload), the scheme-2 routing
    /// bind second.
    ///
    /// # Errors
    ///
    /// [`NoteError`] if the deposit's candidate pubkey does not decompress to a curve point, or if
    /// the attachments exceed their protocol limit.
    fn try_from(note: XUsdcMintNote) -> Result<Self, Self::Error> {
        let mint_note = MintNote::builder()
            .sender(note.sender)
            .mint_storage(note.storage.into_mint_storage())
            .serial_number(note.serial_number)
            .attachment(NoteAttachment::try_from(&note.deposit)?)
            .attachment(NoteAttachment::from(note.network_account_target))
            .build()?;
        Ok(Note::from(mint_note))
    }
}
