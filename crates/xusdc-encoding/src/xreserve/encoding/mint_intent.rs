//! The mint note's carried payload, and the reconstruction of Circle's signed DepositIntent from
//! it (`DC-14`).
//!
//! Circle's DepositIntent does not travel on the mint note. The note carries only the fields the
//! faucet has no other way to learn, and the faucet rebuilds the canonical message itself before
//! hashing it — so a field the faucet writes cannot disagree with the attestation, because a
//! divergent value changes the digest and the signature stops verifying.
//!
//! This module is the off-chain half. [`MintIntent::from_deposit_intent`] compresses a real Circle
//! payload and refuses anything this faucet could not rebuild byte-for-byte;
//! [`MintIntent::to_deposit_intent_bytes`] is the mirror of the MASM writer
//! `xreserve::deposit_intent::rebuild`. What binds the two is the round trip, not a
//! field-by-field comparison — see `TV-DUAL-6` and the reconstruction reference in
//! `docs/spec/ENCODING-COMPONENT-SPEC.md`.
//!
//! Nothing here re-reads a wire offset: every write goes through
//! [`deposit_intent_field_offset`], so the layout has one owner on this side too.

use miden_protocol::account::{AccountId, StorageMapKey};
use miden_protocol::asset::AssetAmount;
use miden_protocol::utils::packed_u32_elements_to_bytes;
use miden_protocol::{Felt, MAX_NOTE_STORAGE_ITEMS};
use miden_standards::interop::eth::EthAddress;

use super::account_id::{account_id_to_bytes32, bytes32_to_account_id};
use super::bytes32::{
    bytes32_to_packed_felts, bytes32_to_storage_map_key, packed_felts_to_bytes32,
};
use super::deposit_intent::{
    deposit_intent_field_offset, DepositIntent, DepositIntentField, DEPOSIT_INTENT_HEADER_FELTS,
    DEPOSIT_INTENT_HEADER_LEN, DEPOSIT_INTENT_MAGIC, DEPOSIT_INTENT_VERSION,
};
use super::error::EncodingError;

// WIRE-SHAPE CONSTANTS
// ================================================================================================

/// Bytes per u32-LE-packed field element.
pub const BYTES_PER_PACKED_FELT: usize = 4;

/// A bytes32 wire field, and the widths of the values carried right-aligned inside one: an
/// AccountId as two big-endian u64s, a 20-byte EVM address, an `AssetAmount` as a big-endian u64.
pub const BYTES32_LEN: usize = 32;
pub const ACCOUNT_ID_BYTES: usize = 16;
pub const EVM_ADDRESS_BYTES: usize = 20;
pub const ASSET_AMOUNT_BYTES: usize = 8;

/// The same widths as packed field elements — the form the carried payload uses.
pub const BYTES32_PACKED_LIMBS: usize = BYTES32_LEN / BYTES_PER_PACKED_FELT;
pub const EVM_ADDRESS_PACKED_LIMBS: usize = EVM_ADDRESS_BYTES / BYTES_PER_PACKED_FELT;

/// An AccountId travels as the two felts the protocol's account-id procedures consume, not as
/// its packed bytes32 form: the faucet has to validate its structure anyway, and two felts is
/// less than the four limbs the packed form would cost.
pub const ACCOUNT_ID_FELTS: usize = 2;

/// The scale `DC-14` is defined at.
///
/// The reconstruction zero-extends a carried `AssetAmount` back into its uint256 field, which is
/// lossless only at scale zero — at any other scale the remainder the reduction dropped is not
/// recoverable, and the rebuilt digest would not match what Circle signed. A non-zero deposit
/// scale therefore needs a new transport, not a new constant value; `constant_parity.rs` pins this
/// against the faucet's `DEPOSIT_SCALE_EXP` so the change fails a test rather than shipping a
/// preimage that can never verify. `DEV-5` stays OPEN.
pub const MINT_INTENT_SCALE_EXP: u32 = 0;

// CARRIED-PAYLOAD FELT OFFSETS
// ================================================================================================

/// Felt offsets within the carried payload. The nonce leads so the widest verbatim run starts
/// word-aligned, and the two single-felt fields trail so every wider field stays contiguous. The
/// MASM twins are in `asm/standards/xreserve/mint_intent.masm`.
pub const MINT_INTENT_NONCE_FELT_OFF: usize = 0;
pub const MINT_INTENT_LOCAL_TOKEN_FELT_OFF: usize =
    MINT_INTENT_NONCE_FELT_OFF + BYTES32_PACKED_LIMBS;
pub const MINT_INTENT_LOCAL_DEPOSITOR_FELT_OFF: usize =
    MINT_INTENT_LOCAL_TOKEN_FELT_OFF + EVM_ADDRESS_PACKED_LIMBS;
pub const MINT_INTENT_REMOTE_RECIPIENT_FELT_OFF: usize =
    MINT_INTENT_LOCAL_DEPOSITOR_FELT_OFF + EVM_ADDRESS_PACKED_LIMBS;
/// The recipient travels as the two felts the protocol's account-id procedures consume, prefix
/// first. The faucet reads the halves individually, so the suffix carries its own offset.
pub const MINT_INTENT_REMOTE_RECIPIENT_SUFFIX_FELT_OFF: usize =
    MINT_INTENT_REMOTE_RECIPIENT_FELT_OFF + 1;
pub const MINT_INTENT_MAX_FEE_FELT_OFF: usize =
    MINT_INTENT_REMOTE_RECIPIENT_FELT_OFF + ACCOUNT_ID_FELTS;
/// maxFee is a single `AssetAmount` felt.
pub const MINT_INTENT_HOOK_DATA_LEN_FELT_OFF: usize = MINT_INTENT_MAX_FEE_FELT_OFF + 1;

/// The payload's 22 content felts padded to the word boundary. hookData follows immediately, so
/// this is also the offset of the first packed hookData felt.
pub const MINT_INTENT_FELTS: usize = 24;

/// The hookData bound: the packed preimage must stay within the protocol's note-storage item
/// limit, exactly as [`super::deposit_intent::DepositIntent::to_packed_felts`] requires. The
/// faucet's staging region is sized to the same number, so a payload that passes here always fits
/// on-chain. The exact cap Circle wants is still OPEN (`DEV-6`).
pub const MAX_HOOK_DATA_LEN: usize =
    (MAX_NOTE_STORAGE_ITEMS - DEPOSIT_INTENT_HEADER_FELTS) * BYTES_PER_PACKED_FELT;

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

    /// The 8 u32-LE-packed limbs the payload carries.
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

    /// The `ceil(len / 4)` u32-LE-packed felts the payload carries, trailing bytes zero-filled.
    pub fn to_packed_felts(&self) -> Vec<Felt> {
        miden_protocol::utils::bytes_to_packed_u32_elements(&self.0)
    }
}

// MINT PAYLOAD
// ================================================================================================

/// Exactly the DepositIntent fields the mint note carries.
///
/// The faucet supplies the rest when it rebuilds the message: `magic` and `version` are scheme
/// constants, `amount` is the note's own asset value, `remoteDomain` its configured domain,
/// `remoteToken` its own account id, and `feeAmount` is always zero.
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct MintIntent {
    nonce: DepositNonce,
    local_token: EthAddress,
    local_depositor: EthAddress,
    remote_recipient: AccountId,
    max_fee: AssetAmount,
    hook_data: HookData,
}

impl MintIntent {
    // COMPRESS
    // --------------------------------------------------------------------------------------------

    /// Compresses a Circle DepositIntent into the felts the mint note carries.
    ///
    /// `faucet_id` is the faucet meant to consume the note, and the intent's `remoteToken` has to
    /// already name it: the faucet writes its own id into the message it rebuilds, so an intent
    /// addressed to a different one rebuilds a different digest and dies on-chain as an invalid
    /// signature. Comparing it here gives that a name before the note is ever submitted.
    ///
    /// # Errors
    ///
    /// Propagates the structural [`EncodingError`]s of the parse, then:
    /// - [`EncodingError::RemoteTokenMismatch`] if the intent is addressed to another faucet.
    /// - [`EncodingError::AccountIdOutOfRange`] / [`EncodingError::NonCanonicalAccountId`] if
    ///   `remoteToken` or `remoteRecipient` is not a well-formed packaged account id.
    /// - [`EncodingError::FieldNotAssetAmount`] if `maxFee` is not representable.
    /// - [`EncodingError::FieldNotEvmAddress`] if `localToken` or `localDepositor` is wider than a
    ///   right-aligned 20-byte address.
    /// - [`EncodingError::HookDataTooLarge`] past [`MAX_HOOK_DATA_LEN`].
    pub fn from_deposit_intent(
        intent: &DepositIntent<'_>,
        faucet_id: AccountId,
    ) -> Result<Self, EncodingError> {
        let header = intent.parse_header()?;

        if bytes32_to_account_id(&header.remote_token)? != faucet_id {
            return Err(EncodingError::RemoteTokenMismatch);
        }

        Ok(Self {
            nonce: DepositNonce::new(header.nonce),
            local_token: evm_address(header.local_token, DepositIntentField::LocalToken)?,
            local_depositor: evm_address(
                header.local_depositor,
                DepositIntentField::LocalDepositor,
            )?,
            remote_recipient: bytes32_to_account_id(&header.remote_recipient)?,
            max_fee: header.reduced_max_fee(MINT_INTENT_SCALE_EXP)?,
            hook_data: HookData::new(intent.hook_data()?.to_vec())?,
        })
    }

    // EXPAND
    // --------------------------------------------------------------------------------------------

    /// Rebuilds the canonical DepositIntent the attestation signed — the Rust mirror of
    /// `xreserve::deposit_intent::rebuild`.
    ///
    /// Infallible: every input is a validated domain type, and every byte of the output is either
    /// written here or a structural zero.
    pub fn to_deposit_intent_bytes(
        &self,
        amount: AssetAmount,
        remote_domain: u32,
        remote_token: AccountId,
    ) -> Vec<u8> {
        let mut out = vec![0u8; DEPOSIT_INTENT_HEADER_LEN + self.hook_data.as_bytes().len()];

        write_u32(&mut out, DepositIntentField::Magic, DEPOSIT_INTENT_MAGIC);
        write_u32(
            &mut out,
            DepositIntentField::Version,
            DEPOSIT_INTENT_VERSION,
        );
        write_bytes32(
            &mut out,
            DepositIntentField::Amount,
            &u64::from(amount).to_be_bytes(),
        );
        write_u32(&mut out, DepositIntentField::RemoteDomain, remote_domain);
        write_bytes32(
            &mut out,
            DepositIntentField::RemoteToken,
            &account_id_to_bytes32(remote_token),
        );
        write_bytes32(
            &mut out,
            DepositIntentField::RemoteRecipient,
            &account_id_to_bytes32(self.remote_recipient),
        );
        write_bytes32(
            &mut out,
            DepositIntentField::LocalToken,
            self.local_token.as_bytes(),
        );
        write_bytes32(
            &mut out,
            DepositIntentField::LocalDepositor,
            self.local_depositor.as_bytes(),
        );
        write_bytes32(
            &mut out,
            DepositIntentField::MaxFee,
            &u64::from(self.max_fee).to_be_bytes(),
        );
        write_bytes32(&mut out, DepositIntentField::Nonce, self.nonce.as_bytes());
        write_u32(
            &mut out,
            DepositIntentField::HookDataLen,
            self.hook_data.len_u32(),
        );
        out[deposit_intent_field_offset(DepositIntentField::HookData)..]
            .copy_from_slice(self.hook_data.as_bytes());

        out
    }

    // CARRIED FELTS
    // --------------------------------------------------------------------------------------------

    /// The carried wire form: the 24 fixed felts followed by the packed hookData. Word padding of
    /// the hookData tail belongs to the attachment builder, not here.
    pub fn to_felts(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(MINT_INTENT_FELTS);
        out.extend_from_slice(&self.nonce.to_packed_felts());
        out.extend(self.local_token.to_elements());
        out.extend(self.local_depositor.to_elements());
        out.push(self.remote_recipient.prefix().as_felt());
        out.push(self.remote_recipient.suffix());
        out.push(Felt::from(self.max_fee));
        out.push(Felt::from(self.hook_data.len_u32()));
        out.resize(MINT_INTENT_FELTS, Felt::from(0u32));
        out.extend(self.hook_data.to_packed_felts());
        out
    }

    /// Inverse of [`Self::to_felts`].
    ///
    /// # Errors
    ///
    /// [`EncodingError::BurnItemsMalformed`] is *not* used here; a payload that is the wrong
    /// length, carries a non-u32 packed limb, or declares a hookData length that disagrees with
    /// the felts present returns [`EncodingError::LengthMismatch`] or
    /// [`EncodingError::LimbNotU32`]. The typed field errors of
    /// [`Self::from_deposit_intent`] apply to `maxFee` and the recipient as well.
    pub fn from_felts(felts: &[Felt]) -> Result<Self, EncodingError> {
        if felts.len() < MINT_INTENT_FELTS {
            return Err(EncodingError::LengthMismatch);
        }

        let hook_data_len = u32_at(felts, MINT_INTENT_HOOK_DATA_LEN_FELT_OFF)?;
        let hook_data_felts = felts.len() - MINT_INTENT_FELTS;
        if hook_data_felts != (hook_data_len as usize).div_ceil(BYTES_PER_PACKED_FELT) {
            return Err(EncodingError::LengthMismatch);
        }
        // the payload block is padded to the word boundary; a non-zero pad is a payload this
        // codec did not produce, and on-chain it would ride inside the hash-committed attachment
        // without ever being read
        for felt in &felts[MINT_INTENT_HOOK_DATA_LEN_FELT_OFF + 1..MINT_INTENT_FELTS] {
            if felt.as_canonical_u64() != 0 {
                return Err(EncodingError::LengthMismatch);
            }
        }

        let nonce_limbs: [Felt; BYTES32_PACKED_LIMBS] = felts
            [MINT_INTENT_NONCE_FELT_OFF..MINT_INTENT_NONCE_FELT_OFF + BYTES32_PACKED_LIMBS]
            .try_into()
            .expect("the length check above guarantees the window");

        let mut hook_data = unpack_bytes(&felts[MINT_INTENT_FELTS..])?;
        hook_data.truncate(hook_data_len as usize);

        Ok(Self {
            nonce: DepositNonce::new(packed_felts_to_bytes32(&nonce_limbs)?),
            local_token: evm_address_from_felts(felts, MINT_INTENT_LOCAL_TOKEN_FELT_OFF)?,
            local_depositor: evm_address_from_felts(felts, MINT_INTENT_LOCAL_DEPOSITOR_FELT_OFF)?,
            remote_recipient: AccountId::try_from_elements(
                felts[MINT_INTENT_REMOTE_RECIPIENT_FELT_OFF + 1],
                felts[MINT_INTENT_REMOTE_RECIPIENT_FELT_OFF],
            )
            .map_err(|_| EncodingError::NonCanonicalAccountId)?,
            max_fee: AssetAmount::new(felts[MINT_INTENT_MAX_FEE_FELT_OFF].as_canonical_u64())
                .map_err(|_| EncodingError::FieldNotAssetAmount {
                    field: DepositIntentField::MaxFee,
                })?,
            hook_data: HookData::new(hook_data)?,
        })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub fn nonce(&self) -> DepositNonce {
        self.nonce
    }

    pub fn local_token(&self) -> EthAddress {
        self.local_token
    }

    pub fn local_depositor(&self) -> EthAddress {
        self.local_depositor
    }

    pub fn remote_recipient(&self) -> AccountId {
        self.remote_recipient
    }

    pub fn max_fee(&self) -> AssetAmount {
        self.max_fee
    }

    pub fn hook_data(&self) -> &HookData {
        &self.hook_data
    }
}

// HELPERS
// ================================================================================================

/// Writes a 4-byte big-endian wire field at its layout offset.
fn write_u32(out: &mut [u8], field: DepositIntentField, value: u32) {
    let off = deposit_intent_field_offset(field);
    out[off..off + BYTES_PER_PACKED_FELT].copy_from_slice(&value.to_be_bytes());
}

/// Writes a value into a bytes32 wire field, right-aligned behind a leading zero pad. A full
/// 32-byte value fills the field; a narrower one (an account id, an address, an amount) lands at
/// the end, which is the packaging every one of those fields uses.
fn write_bytes32(out: &mut [u8], field: DepositIntentField, value: &[u8]) {
    let start = deposit_intent_field_offset(field) + BYTES32_LEN - value.len();
    out[start..start + value.len()].copy_from_slice(value);
}

/// Narrows a bytes32 field to the EVM address it is expected to carry.
fn evm_address(
    value: [u8; BYTES32_LEN],
    field: DepositIntentField,
) -> Result<EthAddress, EncodingError> {
    EthAddress::try_from(value).map_err(|_| EncodingError::FieldNotEvmAddress { field })
}

/// Reads a felt as a u32-LE-packed limb, fail-closed rather than truncating.
fn u32_at(felts: &[Felt], index: usize) -> Result<u32, EncodingError> {
    u32::try_from(felts[index].as_canonical_u64()).map_err(|_| EncodingError::LimbNotU32)
}

/// Unpacks a run of u32-LE-packed limbs back to bytes, guarding each limb first.
fn unpack_bytes(felts: &[Felt]) -> Result<Vec<u8>, EncodingError> {
    for index in 0..felts.len() {
        u32_at(felts, index)?;
    }
    Ok(packed_u32_elements_to_bytes(felts))
}

/// Reads the 5-limb EVM address at a carried-payload offset.
fn evm_address_from_felts(felts: &[Felt], offset: usize) -> Result<EthAddress, EncodingError> {
    let bytes = unpack_bytes(&felts[offset..offset + EVM_ADDRESS_PACKED_LIMBS])?;
    Ok(EthAddress::new(
        bytes
            .try_into()
            .expect("five packed limbs are twenty bytes"),
    ))
}

// TESTS — TV-DUAL-6 (the Rust half; the MASM half is in tests/masm_mint_shell.rs)
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::vectors::{load, MiVector};

    fn accepts() -> impl Iterator<Item = &'static MiVector> {
        load().families.mi.iter().filter(|v| v.kind == "accept")
    }

    /// TV-DUAL-6 (happy path, written first): the reconstruction is exact.
    ///
    /// This is the law the whole transport rests on. Everything the faucet no longer checks, it
    /// checks by rebuilding these bytes and letting the signature verify over them — so if the
    /// round trip is not byte-exact, no mint can ever succeed.
    #[test]
    fn tv_dual_6_round_trip_is_byte_exact() {
        for vec in accepts() {
            let payload = vec.payload();
            let intent = DepositIntent::new(&payload);
            let carried = MintIntent::from_deposit_intent(&intent, vec.faucet_id())
                .unwrap_or_else(|e| panic!("vector {}: compress failed: {e}", vec.id));

            assert_eq!(
                carried.to_deposit_intent_bytes(vec.amount(), vec.remote_domain, vec.faucet_id()),
                payload,
                "vector {}: the rebuilt preimage must equal what Circle signed",
                vec.id
            );
        }
    }

    /// The carried felts and the felts the writer must produce, both pinned to the artifact —
    /// these are the rows the MASM writer is checked against, so a change on this side that the
    /// MASM side does not follow shows up as a vector diff rather than a silent divergence.
    #[test]
    fn tv_dual_6_carried_and_rebuilt_felts_match_the_vectors() {
        for vec in accepts() {
            let payload = vec.payload();
            let intent = DepositIntent::new(&payload);
            let carried = MintIntent::from_deposit_intent(&intent, vec.faucet_id())
                .unwrap_or_else(|e| panic!("vector {}: compress failed: {e}", vec.id));

            assert_eq!(
                carried.to_felts(),
                vec.carried_values(),
                "vector {}: carried felts",
                vec.id
            );

            let rebuilt =
                carried.to_deposit_intent_bytes(vec.amount(), vec.remote_domain, vec.faucet_id());
            assert_eq!(
                DepositIntent::new(&rebuilt)
                    .to_packed_felts()
                    .expect("the rebuilt preimage packs"),
                vec.rebuilt_preimage_values(),
                "vector {}: rebuilt preimage felts",
                vec.id
            );
        }
    }

    /// The felt form is lossless: what the note carries decodes back to the payload that built it.
    #[test]
    fn tv_dual_6_carried_felts_are_lossless() {
        for vec in accepts() {
            let payload = vec.payload();
            let intent = DepositIntent::new(&payload);
            let carried = MintIntent::from_deposit_intent(&intent, vec.faucet_id())
                .unwrap_or_else(|e| panic!("vector {}: compress failed: {e}", vec.id));

            assert_eq!(
                MintIntent::from_felts(&carried.to_felts()).expect("round trip"),
                carried,
                "vector {}: carried felts must round-trip",
                vec.id
            );
        }
    }

    /// Every narrowing DC-14 applies, one vector each, asserting the exact variant. These are the
    /// deposits the transport cannot express — the relayer has to reject them here, because
    /// on-chain they would all fail identically as an invalid signature.
    #[test]
    fn tv_dual_6_rejects_what_the_transport_cannot_carry() {
        let rejects = load().families.mi.iter().filter(|v| v.kind == "reject");
        for vec in rejects {
            let payload = vec.payload();
            let intent = DepositIntent::new(&payload);
            let result = MintIntent::from_deposit_intent(&intent, vec.faucet_id());
            let id = &vec.id;
            match vec.expected_variant.as_deref().expect("reject vector") {
                "FieldNotEvmAddress" => {
                    assert_matches!(
                        result,
                        Err(EncodingError::FieldNotEvmAddress { .. }),
                        "vector {id}"
                    )
                }
                "FieldNotAssetAmount" => {
                    assert_matches!(
                        result,
                        Err(EncodingError::FieldNotAssetAmount { .. }),
                        "vector {id}"
                    )
                }
                "RemoteTokenMismatch" => {
                    assert_matches!(
                        result,
                        Err(EncodingError::RemoteTokenMismatch),
                        "vector {id}"
                    )
                }
                "AccountIdOutOfRange" => {
                    assert_matches!(
                        result,
                        Err(EncodingError::AccountIdOutOfRange),
                        "vector {id}"
                    )
                }
                "NonCanonicalAccountId" => {
                    assert_matches!(
                        result,
                        Err(EncodingError::NonCanonicalAccountId),
                        "vector {id}"
                    )
                }
                other => panic!("vector {id}: unexpected expected_variant {other:?}"),
            }
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

    /// A carried-felt run whose declared hookData length disagrees with the felts present is
    /// refused rather than silently truncated: on-chain that length picks the keccak extent.
    #[test]
    fn from_felts_rejects_a_hook_data_length_lie() {
        let vec = accepts()
            .find(|v| v.id == "mi-pos-empty-hookdata")
            .expect("vector present");
        let mut felts = vec.carried_values();
        felts[MINT_INTENT_HOOK_DATA_LEN_FELT_OFF] = Felt::from(4u32);
        assert_matches!(
            MintIntent::from_felts(&felts),
            Err(EncodingError::LengthMismatch)
        );
    }
}
