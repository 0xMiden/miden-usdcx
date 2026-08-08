//! AccountId ↔ bytes32 family (Rust-primary — there is no MASM leg). The bytes32 packaging is the
//! right-aligned layout that mirrors the protocol's Agglayer embedded-account-id form. It
//! `REQUIRES CIRCLE CONFIRMATION` and `REQUIRES IMPLEMENTATION VALIDATION` — the layout stays an
//! OPEN proposal to Circle.

use miden_protocol::account::AccountId;
use miden_protocol::Felt;
use miden_standards::interop::eth::EthEmbeddedAccountId;

use super::bytes32::bytes32_to_packed_felts;
use super::error::EncodingError;

/// `AddressType::AccountId` discriminant (232 = 0b1110_1000). A bech32 discriminant,
/// NOT part of the bytes32 wire form.
pub const ADDRESS_TYPE_ACCOUNT_ID: u8 = 232;

/// Lossless AccountId → bytes32 packaging — right-aligned:
/// `bytes[0..16] = 0x00` (leading zero pad), `bytes[16..24] = prefix` as u64 big-endian,
/// `bytes[24..32] = suffix` as canonical u64 big-endian.
///
/// This is the stock `EthEmbeddedAccountId::to_bytes32()` form: `EthEmbeddedAccountId` wraps an
/// `AccountId` in the same right-aligned ETH-shaped container (16-byte zero pad, then prefix and
/// suffix as big-endian u64s), so the two are byte-identical, and the on-chain side already reads
/// the stock `eth::bytes32_to_account_id`. Delegating keeps both sides on one definition of the
/// layout; the golden vectors lock the byte-for-byte equality.
pub fn account_id_to_bytes32(id: AccountId) -> [u8; 32] {
    EthEmbeddedAccountId::from_account_id(id).to_bytes32()
}

/// Inverse: rejects a non-zero byte in the leading 16-byte pad region
/// (`AccountIdOutOfRange`); rejects a prefix/suffix that do not form a canonical
/// AccountId — out-of-field felts or a failed `try_from_elements` (`NonCanonicalAccountId`).
/// Round-trip lossless for valid ids.
pub fn bytes32_to_account_id(b: &[u8; 32]) -> Result<AccountId, EncodingError> {
    if b[..16].iter().any(|&byte| byte != 0) {
        return Err(EncodingError::AccountIdOutOfRange);
    }
    let prefix = u64::from_be_bytes(b[16..24].try_into().expect("8-byte slice"));
    let suffix = u64::from_be_bytes(b[24..32].try_into().expect("8-byte slice"));
    // packing into the field must not reduce mod p, then the felts must form a canonical
    // AccountId; `NonCanonicalAccountId` is a unit variant, so the inner `AccountIdError` source
    // cannot be carried
    let prefix_felt = Felt::try_from(prefix).map_err(|_| EncodingError::NonCanonicalAccountId)?;
    let suffix_felt = Felt::try_from(suffix).map_err(|_| EncodingError::NonCanonicalAccountId)?;
    AccountId::try_from_elements(suffix_felt, prefix_felt)
        .map_err(|_| EncodingError::NonCanonicalAccountId)
}

/// A remote (source-chain) address carried as a 32-byte big-endian value — the shape Circle's
/// `xreserve_contract` domain-config field uses.
///
/// This mirrors the stock `miden_standards::interop::eth::EthAddress` newtype pattern (a fixed-width
/// byte array with construction, an accessor, and a field-element packing), but keeps a LOCAL type
/// because the shapes differ: stock `EthAddress` is a 20-byte EVM address, while this value is a full
/// 32-byte `bytes32`, so the stock type cannot hold it without narrowing (its `TryFrom<[u8; 32]>`
/// rejects any value whose leading 12 bytes are non-zero). The packing goes through the shared
/// [`bytes32_to_packed_felts`] codec, so a value packed here is identical to one packed anywhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthBytes32([u8; 32]);

impl EthBytes32 {
    /// Wraps a raw 32-byte big-endian value.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Packs the value into its 8 u32-LE field elements (the shared [`bytes32_to_packed_felts`]
    /// primitive).
    pub fn to_packed_felts(&self) -> [Felt; 8] {
        bytes32_to_packed_felts(&self.0)
    }
}

impl From<[u8; 32]> for EthBytes32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<EthBytes32> for [u8; 32] {
    fn from(value: EthBytes32) -> Self {
        value.0
    }
}

// TESTS — TV-AID-1..3
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::{load, parse_hex32};

    /// TV-AID-1 (happy path, written first): round-trip is lossless for valid ids.
    #[test]
    fn tv_aid_1_roundtrip_lossless() {
        let v = load();
        for vec in v
            .families
            .aid
            .iter()
            .filter(|v| v.expected_variant.is_none())
        {
            let b = parse_hex32(&vec.bytes32);
            let id = bytes32_to_account_id(&b)
                .unwrap_or_else(|e| panic!("vector {}: must decode, got {e}", vec.id));
            assert_eq!(
                account_id_to_bytes32(id),
                b,
                "vector {}: round-trip",
                vec.id
            );
        }
    }

    /// TV-AID-2 (negative): out-of-range bytes and in-region non-canonical ids are
    /// rejected with their specific variants.
    #[rstest]
    #[case::out_of_range("aid-rej-out-of-range")]
    #[case::non_canonical("aid-rej-non-canonical")]
    fn tv_aid_2_rejects(#[case] id: &str) {
        let v = load();
        let vec = v
            .families
            .aid
            .iter()
            .find(|v| v.id == id)
            .expect("vector present");
        let b = parse_hex32(&vec.bytes32);
        let result = bytes32_to_account_id(&b);
        match vec.expected_variant.as_deref() {
            Some("AccountIdOutOfRange") => {
                assert_matches!(
                    result,
                    Err(EncodingError::AccountIdOutOfRange),
                    "vector {id}"
                )
            }
            Some("NonCanonicalAccountId") => {
                assert_matches!(
                    result,
                    Err(EncodingError::NonCanonicalAccountId),
                    "vector {id}"
                )
            }
            other => panic!("vector {id}: unexpected expected_variant {other:?}"),
        }
    }

    /// Reject boundary of the fail-closed decode, per pad byte: a `0x01` at EVERY index of the
    /// leading 16-byte zero pad (not just byte 0, the canonical vector's shape) rejects with the
    /// EXACT `AccountIdOutOfRange`. Byte 15 is the boundary byte of the `b[..16]` sweep — a
    /// weakened `b[..15]` pad check would decode a `b[15] != 0` wire form into a
    /// lossy, non-round-tripping AccountId; the `b15` case catches that weakening.
    #[rstest]
    #[case::b0(0)]
    #[case::b1(1)]
    #[case::b2(2)]
    #[case::b3(3)]
    #[case::b4(4)]
    #[case::b5(5)]
    #[case::b6(6)]
    #[case::b7(7)]
    #[case::b8(8)]
    #[case::b9(9)]
    #[case::b10(10)]
    #[case::b11(11)]
    #[case::b12(12)]
    #[case::b13(13)]
    #[case::b14(14)]
    #[case::b15(15)]
    fn nonzero_pad_byte_rejects_at_every_index(#[case] pad_index: usize) {
        let v = load();
        let vec = v
            .families
            .aid
            .iter()
            .find(|v| v.id == "aid-rt-1")
            .expect("vector present");
        let mut b = parse_hex32(&vec.bytes32);
        b[pad_index] = 0x01;
        assert_matches!(
            bytes32_to_account_id(&b),
            Err(EncodingError::AccountIdOutOfRange),
            "pad byte {pad_index}"
        );
    }

    /// TV-AID-3 (constants/API shape): the address type discriminant is 232 and the API
    /// has no >32-byte / keccak fallback branch (input type is `[u8; 32]` by signature).
    /// The layout itself `REQUIRES CIRCLE CONFIRMATION`.
    #[test]
    fn tv_aid_3_address_type_and_no_fallback() {
        assert_eq!(
            ADDRESS_TYPE_ACCOUNT_ID, 232,
            "AddressType::AccountId discriminant"
        );
        // API-shape check: the converter accepts exactly 32 bytes
        let _shape_check: fn(&[u8; 32]) -> Result<AccountId, EncodingError> = bytes32_to_account_id;
    }

    /// The `AccountIdOutOfRange` Display message must describe the SHIPPED layout — the
    /// account id region is the 16 bytes `bytes[16..32]` (prefix u64 BE + suffix u64
    /// BE) behind a 16-byte zero pad (see the message in `error.rs`).
    #[test]
    fn account_id_out_of_range_message_names_16_byte_region() {
        assert_eq!(
            EncodingError::AccountIdOutOfRange.to_string(),
            "bytes set outside the 16-byte account id region",
            "the AccountIdOutOfRange message must match the shipped 16-byte-pad layout"
        );
    }
}
