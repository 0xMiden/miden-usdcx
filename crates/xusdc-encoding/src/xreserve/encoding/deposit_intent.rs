//! Circle's DepositIntent: the message that authorizes one mint, and the bytes it travels in.
//!
//! The wire form is a fixed 240-byte big-endian header followed by variable-length hookData. On
//! Miden it is carried as u32-little-endian-packed field elements, four wire bytes per element, so
//! the header occupies exactly 60 of them. Every field sits at a fixed offset, which is what lets
//! the MASM writer address fields directly instead of encoding sequentially.
//!
//! This module owns the BYTE format, in both directions: [`Serializable`] writes it and
//! [`Deserializable`] reads it. Its sibling `mint_intent` owns the felt format, and the two
//! conversions between the types. Nothing outside this module reads a wire offset — every access
//! goes through [`deposit_intent_field_offset`].
//!
//! Decoding owns the STRUCTURAL checks — the ones answering "is this a well-formed DepositIntent
//! at all": the magic sentinel, the version, that the payload is not truncated, that the declared
//! total length equals 240 plus the declared hookData length, and that the amount, `localToken`
//! and `localDepositor` fields are non-zero.
//!
//! Validation order matters and is fixed, because the faucet's checks run in the same order and the
//! two must reject identically — a payload that fails here must fail on-chain for the same reason,
//! or off-chain pre-validation would pass work to the chain that then fails.
//!
//! What decoding deliberately does NOT do is narrow the fields Circle leaves open. `remoteToken`
//! and `remoteRecipient` are opaque bytes32 in Circle's own encoding, and how a Miden AccountId is
//! packed into them is an unsettled Miden-side decision (`DEV-10`); whether every source domain
//! keeps `localToken` / `localDepositor` address-shaped is likewise open (`Q-EVM-ADDR-1`). Circle's
//! encoder emits well-formed intents that satisfy none of those readings, so narrowing here would
//! make this decoder unable to read Circle's own bytes. The narrowing — and the compare against the
//! faucet that will consume the note — belongs to
//! [`super::mint_intent::MintIntent::from_deposit_intent`], which is the point where the message is
//! being read AS a Miden mint.
//!
//! How large hookData may be is still Circle's to decide. The bound applied here is the protocol's
//! own note-storage limit (`MAX_NOTE_STORAGE_ITEMS`, 1024 field elements — each storage "item" is
//! a single field element), which is the documented default rather than an answer.

use miden_protocol::account::StorageMapKey;
use miden_protocol::asset::AssetAmount;
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::utils::serde::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
};
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS};
use miden_standards::interop::eth::EthAmount;

use super::amount::uint256_to_asset_amount;
use super::bytes32::{bytes32_to_packed_felts, bytes32_to_storage_map_key};
use super::error::EncodingError;

// WIRE-SHAPE CONSTANTS
// ================================================================================================

/// Wire-format constants (the 240-byte header packs to 60 u32-LE felts, 4 bytes per felt).
pub const DEPOSIT_INTENT_HEADER_LEN: usize = 240;
pub const DEPOSIT_INTENT_MAGIC: u32 = 0x5a2e_0acd;
pub const DEPOSIT_INTENT_VERSION: u32 = 1;
pub const DEPOSIT_INTENT_HEADER_FELTS: usize = 60;

/// Bytes per u32-LE-packed field element.
pub const BYTES_PER_PACKED_FELT: usize = 4;

/// A bytes32 wire field, and the widths of the values carried right-aligned inside one: an
/// AccountId as two big-endian u64s, a 20-byte EVM address, an `AssetAmount` as a big-endian u64.
pub const BYTES32_LEN: usize = 32;
pub const ACCOUNT_ID_BYTES: usize = 16;
pub const EVM_ADDRESS_BYTES: usize = 20;
pub const ASSET_AMOUNT_BYTES: usize = 8;

/// The same widths as packed field elements — the form the mint note's carried payload uses.
pub const BYTES32_PACKED_LIMBS: usize = BYTES32_LEN / BYTES_PER_PACKED_FELT;
pub const EVM_ADDRESS_PACKED_LIMBS: usize = EVM_ADDRESS_BYTES / BYTES_PER_PACKED_FELT;

/// The hookData bound: the packed preimage must stay within the protocol's note-storage item
/// limit. The faucet's staging region is sized to the same number, so a payload that passes here
/// always fits on-chain. The exact cap Circle wants is still OPEN (`DEV-6`).
pub const MAX_HOOK_DATA_LEN: usize =
    (MAX_NOTE_STORAGE_ITEMS - DEPOSIT_INTENT_HEADER_FELTS) * BYTES_PER_PACKED_FELT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositIntentField {
    Magic,
    Version,
    Amount,
    RemoteDomain,
    RemoteToken,
    RemoteRecipient,
    LocalToken,
    LocalDepositor,
    MaxFee,
    Nonce,
    HookDataLen,
    HookData,
}

/// Fixed-offset accessor; the offsets are byte positions on the wire.
pub fn deposit_intent_field_offset(field: DepositIntentField) -> usize {
    match field {
        DepositIntentField::Magic => 0,
        DepositIntentField::Version => 4,
        DepositIntentField::Amount => 8,
        DepositIntentField::RemoteDomain => 40,
        DepositIntentField::RemoteToken => 44,
        DepositIntentField::RemoteRecipient => 76,
        DepositIntentField::LocalToken => 108,
        DepositIntentField::LocalDepositor => 140,
        DepositIntentField::MaxFee => 172,
        DepositIntentField::Nonce => 204,
        DepositIntentField::HookDataLen => 236,
        DepositIntentField::HookData => 240,
    }
}

// DEPOSIT NONCE
// ================================================================================================

/// Circle's unique per-deposit nonce.
///
/// It drives two derived values and nothing else: the `usedNonces` replay-guard key and the
/// attested output note's serial number, which are the same Word. Both go through the shared
/// `DC-4` hashing routine, so this type only names the value and delegates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositNonce([u8; BYTES32_LEN]);

impl DepositNonce {
    /// Wraps a raw nonce. Any 32 bytes are a valid nonce — the hashing keeps it total.
    pub const fn new(bytes: [u8; BYTES32_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; BYTES32_LEN] {
        &self.0
    }

    /// The 8 u32-LE-packed limbs the mint note's payload carries.
    pub fn to_packed_felts(&self) -> [Felt; BYTES32_PACKED_LIMBS] {
        bytes32_to_packed_felts(&self.0)
    }

    /// The replay-guard key and output-note serial (`DC-4`).
    pub fn to_storage_map_key(&self) -> StorageMapKey {
        bytes32_to_storage_map_key(&self.0)
    }
}

// HOOK DATA
// ================================================================================================

/// The DepositIntent's opaque trailing payload.
///
/// It is carried because the signature covers it, and for no other reason — nothing on-chain reads
/// it for effects. The length bound is checked here so that everything downstream, including the
/// faucet's fixed staging region, can treat it as already-bounded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookData(Vec<u8>);

impl HookData {
    /// Wraps hookData bytes.
    ///
    /// # Errors
    ///
    /// [`EncodingError::HookDataTooLarge`] past [`MAX_HOOK_DATA_LEN`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, EncodingError> {
        if bytes.len() > MAX_HOOK_DATA_LEN {
            return Err(EncodingError::HookDataTooLarge);
        }
        Ok(Self(bytes))
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The declared wire length. Fits a u32 by the constructor's bound.
    pub fn len_u32(&self) -> u32 {
        u32::try_from(self.0.len()).expect("hook data length is bounded by MAX_HOOK_DATA_LEN")
    }

    /// Whether there is any hookData at all (the common case is none).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The `ceil(len / 4)` u32-LE-packed felts the mint note's payload carries, trailing bytes
    /// zero-filled.
    pub fn to_packed_elements(&self) -> Vec<Felt> {
        bytes_to_packed_u32_elements(&self.0)
    }
}

// DEPOSIT INTENT HEADER
// ================================================================================================

/// The fixed 240-byte header, each field in the type Circle's encoding gives it.
///
/// `magic` and `version` are absent because they are scheme constants, not data: decoding checks
/// them and encoding writes them. `hookDataLen` is absent because it is derived from the hookData
/// itself, which is what makes the declared and actual lengths unable to disagree. The four bytes32
/// fields stay bytes32 for the reason the module docs give.
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct DepositIntentHeader {
    amount: EthAmount,
    remote_domain: u32,
    remote_token: [u8; BYTES32_LEN],
    remote_recipient: [u8; BYTES32_LEN],
    local_token: [u8; BYTES32_LEN],
    local_depositor: [u8; BYTES32_LEN],
    max_fee: EthAmount,
    nonce: DepositNonce,
}

impl DepositIntentHeader {
    /// The deposit amount, as the uint256 Circle states it in.
    pub fn amount(&self) -> EthAmount {
        self.amount
    }

    /// The destination domain the consuming faucet must have configured.
    pub fn remote_domain(&self) -> u32 {
        self.remote_domain
    }

    /// The destination token identifier — opaque here (`DEV-10`).
    pub fn remote_token(&self) -> &[u8; BYTES32_LEN] {
        &self.remote_token
    }

    /// The recipient identifier — opaque here (`DEV-10`).
    pub fn remote_recipient(&self) -> &[u8; BYTES32_LEN] {
        &self.remote_recipient
    }

    /// The deposited token on the source chain (`Q-EVM-ADDR-1`).
    pub fn local_token(&self) -> &[u8; BYTES32_LEN] {
        &self.local_token
    }

    /// The depositor on the source chain (`Q-EVM-ADDR-1`).
    pub fn local_depositor(&self) -> &[u8; BYTES32_LEN] {
        &self.local_depositor
    }

    /// The depositor-authorized fee ceiling, as the uint256 Circle states it in.
    pub fn max_fee(&self) -> EthAmount {
        self.max_fee
    }

    /// The per-deposit nonce.
    pub fn nonce(&self) -> DepositNonce {
        self.nonce
    }

    /// The `amount` field reduced to the units the faucet mints — the value the mint note carries
    /// as its asset and the faucet writes back into the preimage.
    ///
    /// # Errors
    ///
    /// [`EncodingError::FieldNotAssetAmount`] if the wire value does not reduce to a valid
    /// `AssetAmount`.
    pub fn reduced_amount(&self) -> Result<AssetAmount, EncodingError> {
        reduce(self.amount, DepositIntentField::Amount)
    }

    /// The `maxFee` field reduced the same way — the depositor-authorized fee ceiling.
    ///
    /// # Errors
    ///
    /// [`EncodingError::FieldNotAssetAmount`] if the wire value does not reduce to a valid
    /// `AssetAmount`.
    pub fn reduced_max_fee(&self) -> Result<AssetAmount, EncodingError> {
        reduce(self.max_fee, DepositIntentField::MaxFee)
    }
}

/// Reduces one uint256 wire field to the `AssetAmount` it must hold, naming which of the two
/// amount-shaped fields failed rather than only why: the relayer has to tell an unmintable
/// `amount` from an unmintable `maxFee`.
fn reduce(value: EthAmount, field: DepositIntentField) -> Result<AssetAmount, EncodingError> {
    uint256_to_asset_amount(value).map_err(|_| EncodingError::FieldNotAssetAmount { field })
}

// DEPOSIT INTENT
// ================================================================================================

/// A decoded Circle DepositIntent: the typed header plus its trailing hookData.
///
/// Every instance has been through [`Deserializable`] or was assembled from values that already
/// were, so holding one means the structural checks passed and every field is representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositIntent {
    header: DepositIntentHeader,
    hook_data: HookData,
}

impl DepositIntent {
    /// Pairs a header with its hookData.
    pub fn new(header: DepositIntentHeader, hook_data: HookData) -> Self {
        Self { header, hook_data }
    }

    /// The typed header fields.
    pub fn header(&self) -> &DepositIntentHeader {
        &self.header
    }

    /// The opaque trailing payload.
    pub fn hook_data(&self) -> &HookData {
        &self.hook_data
    }

    /// The felt count of the u32-LE-packed preimage: `60 + ceil(hookDataLen / 4)`.
    pub fn preimage_felt_len(&self) -> usize {
        DEPOSIT_INTENT_HEADER_FELTS
            + self
                .hook_data
                .as_bytes()
                .len()
                .div_ceil(BYTES_PER_PACKED_FELT)
    }

    /// The u32-LE-packed on-chain preimage — the felts the attestation's digest is taken over.
    /// Within the protocol's `MAX_NOTE_STORAGE_ITEMS` bound by [`HookData`]'s own invariant.
    pub fn to_preimage_felts(&self) -> Vec<Felt> {
        bytes_to_packed_u32_elements(&self.to_bytes())
    }

    /// The typed decode. Reads exactly one message and leaves whatever follows it in `source`.
    fn read<R: ByteReader>(source: &mut R) -> Result<Self, EncodingError> {
        // the bounds guard necessarily precedes any field read (the TruncatedHeader case)
        let bytes: [u8; DEPOSIT_INTENT_HEADER_LEN] = source
            .read_array()
            .map_err(|_| EncodingError::TruncatedHeader)?;

        if be_u32(&bytes, DepositIntentField::Magic) != DEPOSIT_INTENT_MAGIC {
            return Err(EncodingError::BadMagic);
        }
        if be_u32(&bytes, DepositIntentField::Version) != DEPOSIT_INTENT_VERSION {
            return Err(EncodingError::BadVersion);
        }

        let amount = non_zero_bytes32(&bytes, DepositIntentField::Amount)?;
        let local_token = non_zero_bytes32(&bytes, DepositIntentField::LocalToken)?;
        let local_depositor = non_zero_bytes32(&bytes, DepositIntentField::LocalDepositor)?;

        // the bound is applied to the DECLARED length, before the tail is read, so an adversarial
        // length cannot drive an allocation
        let hook_data_len = be_u32(&bytes, DepositIntentField::HookDataLen) as usize;
        if hook_data_len > MAX_HOOK_DATA_LEN {
            return Err(EncodingError::HookDataTooLarge);
        }
        let hook_data = source
            .read_vec(hook_data_len)
            .map_err(|_| EncodingError::LengthMismatch)?;

        let header = DepositIntentHeader::builder()
            .amount(EthAmount::new(amount))
            .remote_domain(be_u32(&bytes, DepositIntentField::RemoteDomain))
            .remote_token(bytes32_at(&bytes, DepositIntentField::RemoteToken))
            .remote_recipient(bytes32_at(&bytes, DepositIntentField::RemoteRecipient))
            .local_token(local_token)
            .local_depositor(local_depositor)
            .max_fee(EthAmount::new(bytes32_at(
                &bytes,
                DepositIntentField::MaxFee,
            )))
            .nonce(DepositNonce::new(bytes32_at(
                &bytes,
                DepositIntentField::Nonce,
            )))
            .build();

        Ok(Self::new(header, HookData::new(hook_data)?))
    }
}

impl Serializable for DepositIntent {
    /// Writes the canonical message the attestation signs: the 240-byte header at its frozen
    /// offsets, then hookData.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut header = [0u8; DEPOSIT_INTENT_HEADER_LEN];

        write_u32(&mut header, DepositIntentField::Magic, DEPOSIT_INTENT_MAGIC);
        write_u32(
            &mut header,
            DepositIntentField::Version,
            DEPOSIT_INTENT_VERSION,
        );
        write_bytes32(
            &mut header,
            DepositIntentField::Amount,
            self.header.amount.as_bytes(),
        );
        write_u32(
            &mut header,
            DepositIntentField::RemoteDomain,
            self.header.remote_domain,
        );
        write_bytes32(
            &mut header,
            DepositIntentField::RemoteToken,
            &self.header.remote_token,
        );
        write_bytes32(
            &mut header,
            DepositIntentField::RemoteRecipient,
            &self.header.remote_recipient,
        );
        write_bytes32(
            &mut header,
            DepositIntentField::LocalToken,
            &self.header.local_token,
        );
        write_bytes32(
            &mut header,
            DepositIntentField::LocalDepositor,
            &self.header.local_depositor,
        );
        write_bytes32(
            &mut header,
            DepositIntentField::MaxFee,
            self.header.max_fee.as_bytes(),
        );
        write_bytes32(
            &mut header,
            DepositIntentField::Nonce,
            self.header.nonce.as_bytes(),
        );
        write_u32(
            &mut header,
            DepositIntentField::HookDataLen,
            self.hook_data.len_u32(),
        );

        target.write_bytes(&header);
        target.write_bytes(self.hook_data.as_bytes());
    }

    fn get_size_hint(&self) -> usize {
        DEPOSIT_INTENT_HEADER_LEN + self.hook_data.as_bytes().len()
    }
}

impl Deserializable for DepositIntent {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Self::read(source).map_err(DeserializationError::from)
    }
}

impl TryFrom<&[u8]> for DepositIntent {
    type Error = EncodingError;

    /// Decodes a payload that is a DepositIntent and nothing else — the entry point every off-chain
    /// caller takes, because it keeps the specific [`EncodingError`] the payload earned.
    ///
    /// Trailing bytes are a rejection, not a remainder: the payload declares its own total length,
    /// so anything past it means the sender and this decoder disagree about what was signed.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut reader = SliceReader::new(bytes);
        let intent = Self::read(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(EncodingError::LengthMismatch);
        }
        Ok(intent)
    }
}

// HELPERS
// ================================================================================================

/// Reads a big-endian u32 wire field.
fn be_u32(bytes: &[u8; DEPOSIT_INTENT_HEADER_LEN], field: DepositIntentField) -> u32 {
    let offset = deposit_intent_field_offset(field);
    u32::from_be_bytes(
        bytes[offset..offset + BYTES_PER_PACKED_FELT]
            .try_into()
            .expect("4-byte window"),
    )
}

/// Copies a 32-byte wire field.
fn bytes32_at(
    bytes: &[u8; DEPOSIT_INTENT_HEADER_LEN],
    field: DepositIntentField,
) -> [u8; BYTES32_LEN] {
    let offset = deposit_intent_field_offset(field);
    bytes[offset..offset + BYTES32_LEN]
        .try_into()
        .expect("32-byte window")
}

/// Copies a 32-byte wire field the scheme requires to be non-zero.
fn non_zero_bytes32(
    bytes: &[u8; DEPOSIT_INTENT_HEADER_LEN],
    field: DepositIntentField,
) -> Result<[u8; BYTES32_LEN], EncodingError> {
    let value = bytes32_at(bytes, field);
    if value.iter().all(|byte| *byte == 0) {
        return Err(EncodingError::ZeroField { field });
    }
    Ok(value)
}

/// Writes a 4-byte big-endian wire field at its layout offset.
fn write_u32(out: &mut [u8; DEPOSIT_INTENT_HEADER_LEN], field: DepositIntentField, value: u32) {
    let offset = deposit_intent_field_offset(field);
    out[offset..offset + BYTES_PER_PACKED_FELT].copy_from_slice(&value.to_be_bytes());
}

/// Writes a value into a bytes32 wire field, right-aligned behind a leading zero pad. A full
/// 32-byte value fills the field; a narrower one (an amount, a nonce) lands at the end, which is
/// the packaging every one of those fields uses.
fn write_bytes32(
    out: &mut [u8; DEPOSIT_INTENT_HEADER_LEN],
    field: DepositIntentField,
    value: &[u8],
) {
    let start = deposit_intent_field_offset(field) + BYTES32_LEN - value.len();
    out[start..start + value.len()].copy_from_slice(value);
}

// TESTS — TV-DI-1..9
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::load;

    /// TV-DI-1 (happy path, written first): a full header + hookData decodes to the exact per-field
    /// values at the frozen wire offsets.
    #[test]
    fn tv_di_1_positive_parse() {
        let v = load();
        for vec in v.families.di.iter().filter(|v| v.kind == "accept") {
            let bytes = vec.bytes();
            let intent = DepositIntent::try_from(bytes.as_slice())
                .unwrap_or_else(|e| panic!("vector {}: must parse, got {e}", vec.id));
            let header = intent.header();
            let f = vec.fields.as_ref().expect("accept vector carries fields");

            assert_eq!(
                header.remote_domain(),
                f.remote_domain,
                "vector {}: remoteDomain",
                vec.id
            );
            assert_eq!(
                intent.hook_data().len_u32(),
                f.hook_data_len,
                "vector {}: hookDataLen",
                vec.id
            );
            for (name, actual, label) in [
                ("amount", header.amount().as_bytes(), "amount"),
                ("remote_token", header.remote_token(), "remoteToken"),
                (
                    "remote_recipient",
                    header.remote_recipient(),
                    "remoteRecipient",
                ),
                ("local_token", header.local_token(), "localToken"),
                (
                    "local_depositor",
                    header.local_depositor(),
                    "localDepositor",
                ),
                ("max_fee", header.max_fee().as_bytes(), "maxFee"),
                ("nonce", header.nonce().as_bytes(), "nonce"),
            ] {
                assert_eq!(actual, &f.bytes32(name), "vector {}: {label}", vec.id);
            }
        }
    }

    /// The decode and the encode are inverses over every accept vector: what Circle signed is
    /// exactly what this crate writes back. Everything downstream rests on it, because the faucet
    /// verifies the signature over bytes it rebuilds rather than over bytes it was handed.
    #[test]
    fn round_trip_is_byte_exact() {
        let v = load();
        for vec in v.families.di.iter().filter(|v| v.kind == "accept") {
            let bytes = vec.bytes();
            let intent = DepositIntent::try_from(bytes.as_slice()).expect("accept vector decodes");
            assert_eq!(intent.to_bytes(), bytes, "vector {}: round trip", vec.id);
        }
    }

    /// TV-DI-2..6 (negative, parametrized): each structural violation rejects with its
    /// SPECIFIC variant (one named case per frozen harness row).
    #[rstest]
    #[case::tv_di_2_bad_magic("di-rej-bad-magic")]
    #[case::tv_di_3_bad_version("di-rej-bad-version")]
    #[case::tv_di_4_zero_amount("di-rej-zero-amount")]
    #[case::tv_di_5_zero_local_token("di-rej-zero-local-token")]
    #[case::tv_di_5_zero_local_depositor("di-rej-zero-local-depositor")]
    #[case::tv_di_6_length_mismatch("di-rej-length-mismatch")]
    #[case::tv_di_6_truncated_header("di-rej-truncated")]
    fn tv_di_rejects(#[case] id: &str) {
        let v = load();
        let vec = v
            .families
            .di
            .iter()
            .find(|v| v.id == id)
            .expect("vector present");
        let result = DepositIntent::try_from(vec.bytes().as_slice());
        match vec.expected_variant.as_deref() {
            Some("BadMagic") => assert_matches!(result, Err(EncodingError::BadMagic), "{id}"),
            Some("BadVersion") => assert_matches!(result, Err(EncodingError::BadVersion), "{id}"),
            Some("ZeroField:Amount") => assert_matches!(
                result,
                Err(EncodingError::ZeroField {
                    field: DepositIntentField::Amount
                }),
                "{id}"
            ),
            Some("ZeroField:LocalToken") => assert_matches!(
                result,
                Err(EncodingError::ZeroField {
                    field: DepositIntentField::LocalToken
                }),
                "{id}"
            ),
            Some("ZeroField:LocalDepositor") => assert_matches!(
                result,
                Err(EncodingError::ZeroField {
                    field: DepositIntentField::LocalDepositor
                }),
                "{id}"
            ),
            Some("LengthMismatch") => {
                assert_matches!(result, Err(EncodingError::LengthMismatch), "{id}")
            }
            Some("TruncatedHeader") => {
                assert_matches!(result, Err(EncodingError::TruncatedHeader), "{id}")
            }
            other => panic!("vector {id}: unexpected expected_variant {other:?}"),
        }
    }

    /// A payload followed by bytes that are not part of it is refused rather than silently
    /// truncated to the message it claims to be.
    #[test]
    fn trailing_bytes_reject() {
        let v = load();
        let vec = v
            .families
            .di
            .iter()
            .find(|v| v.id == "di-pos-hookdata")
            .expect("vector");
        let mut bytes = vec.bytes();
        bytes.push(0x00);
        assert_matches!(
            DepositIntent::try_from(bytes.as_slice()),
            Err(EncodingError::LengthMismatch)
        );
    }

    /// TV-DI-7 (boundary): the packed header is exactly 60 felts, equals the committed preimage,
    /// stays within the 1024-felt bound, and the overflow vector rejects with `HookDataTooLarge`
    /// (the hookData cap stays OPEN with Circle).
    #[test]
    fn tv_di_7_sixty_felts_and_1024_bound() {
        let v = load();
        for vec in v.families.di.iter().filter(|v| v.kind == "accept") {
            let intent =
                DepositIntent::try_from(vec.bytes().as_slice()).expect("accept vector decodes");
            let felts = intent.to_preimage_felts();
            let expected = vec.preimage_values();
            assert_eq!(
                felts.len(),
                expected.len(),
                "vector {}: total felts",
                vec.id
            );
            assert_eq!(
                felts.len(),
                intent.preimage_felt_len(),
                "vector {}: derived felt length",
                vec.id
            );
            assert_eq!(
                &felts[..DEPOSIT_INTENT_HEADER_FELTS],
                &expected[..DEPOSIT_INTENT_HEADER_FELTS],
                "vector {}: 60-felt header",
                vec.id
            );
            assert_eq!(felts, expected, "vector {}: full preimage", vec.id);
            assert!(
                felts.len() <= MAX_NOTE_STORAGE_ITEMS,
                "vector {}: NoteStorage bound",
                vec.id
            );
        }
        let overflow = v
            .families
            .di
            .iter()
            .find(|v| v.id == "di-rej-hookdata-overflow")
            .expect("vector");
        assert_matches!(
            DepositIntent::try_from(overflow.bytes().as_slice()),
            Err(EncodingError::HookDataTooLarge),
            "hookData past the 1024-felt bound must reject"
        );
    }

    /// TV-DI-8 (determinism/immutability): decoding borrows the input immutably and the
    /// bytes are unchanged afterwards (note-input immutability analogue).
    #[test]
    fn tv_di_8_input_immutable() {
        let v = load();
        let vec = v
            .families
            .di
            .iter()
            .find(|v| v.id == "di-pos-hookdata")
            .expect("vector");
        let bytes = vec.bytes();
        let before = bytes.clone();
        let _ = DepositIntent::try_from(bytes.as_slice());
        assert_eq!(bytes, before, "input must be unchanged by parsing");
    }

    /// TV-DI-9 (layout table): every field offset equals the wire-format byte offset.
    #[test]
    fn tv_di_9_offsets_table() {
        let expected: [(DepositIntentField, usize); 12] = [
            (DepositIntentField::Magic, 0),
            (DepositIntentField::Version, 4),
            (DepositIntentField::Amount, 8),
            (DepositIntentField::RemoteDomain, 40),
            (DepositIntentField::RemoteToken, 44),
            (DepositIntentField::RemoteRecipient, 76),
            (DepositIntentField::LocalToken, 108),
            (DepositIntentField::LocalDepositor, 140),
            (DepositIntentField::MaxFee, 172),
            (DepositIntentField::Nonce, 204),
            (DepositIntentField::HookDataLen, 236),
            (DepositIntentField::HookData, 240),
        ];
        for (field, off) in expected {
            assert_eq!(
                deposit_intent_field_offset(field),
                off,
                "wire offset of {field:?}"
            );
        }
    }

    /// hookData past the bound is refused at construction, so nothing downstream — including the
    /// faucet's fixed staging region — has to re-check it.
    #[test]
    fn hook_data_bound_is_enforced_at_construction() {
        assert_matches!(
            HookData::new(vec![0u8; MAX_HOOK_DATA_LEN + 1]),
            Err(EncodingError::HookDataTooLarge)
        );
        assert!(HookData::new(vec![0u8; MAX_HOOK_DATA_LEN]).is_ok());
    }
}
