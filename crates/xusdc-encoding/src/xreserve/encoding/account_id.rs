//! The bytes32 containers this crate reads and writes but the protocol only half-provides
//! (Rust-primary — there is no MASM leg).
//!
//! Both are the same shape: a value right-aligned in 32 bytes behind a zero pad. An `AccountId`
//! travels in the protocol's Agglayer embedded-account-id form, whose forward direction
//! (`EthEmbeddedAccountId::to_bytes32`) is stock and is called directly — only the DECODE is
//! missing, so that is what the extension trait below adds. An EVM address travels in the EVM's own
//! left-padded container, whose decode (`EthAddress::try_from([u8; 32])`) is stock and the ENCODE
//! is missing.
//!
//! The AccountId layout `REQUIRES CIRCLE CONFIRMATION` and `REQUIRES IMPLEMENTATION VALIDATION` —
//! it stays an OPEN proposal to Circle.

use miden_standards::interop::eth::{AddressConversionError, EthAddress, EthEmbeddedAccountId};

use super::error::EncodingError;

/// `AddressType::AccountId` discriminant (232 = 0b1110_1000). A bech32 discriminant,
/// NOT part of the bytes32 wire form.
pub const ADDRESS_TYPE_ACCOUNT_ID: u8 = 232;

/// The bytes32 decode the protocol does not ship: the inverse of the stock
/// [`EthEmbeddedAccountId::to_bytes32`].
pub trait EthEmbeddedAccountIdExt: Sized {
    /// Decodes the right-aligned bytes32 form — `bytes[0..16] = 0x00`, `bytes[16..24] = prefix` as
    /// u64 big-endian, `bytes[24..32] = suffix` as canonical u64 big-endian.
    ///
    /// The 16-byte zero pad is checked in two halves, because the container is: the leading 12
    /// bytes are this crate's to check, and the stock 20-byte decode owns the remaining four along
    /// with the field and canonicality checks.
    ///
    /// # Errors
    ///
    /// [`EncodingError::AccountIdOutOfRange`] if any pad byte is non-zero;
    /// [`EncodingError::NonCanonicalAccountId`] if the prefix/suffix do not form a canonical
    /// AccountId (an out-of-field felt or a failed `try_from_elements`).
    fn try_from_bytes32(bytes: [u8; 32]) -> Result<Self, EncodingError>;
}

impl EthEmbeddedAccountIdExt for EthEmbeddedAccountId {
    fn try_from_bytes32(bytes: [u8; 32]) -> Result<Self, EncodingError> {
        if bytes[..12] != [0u8; 12] {
            return Err(EncodingError::AccountIdOutOfRange);
        }

        let embedded: [u8; 20] = bytes[12..].try_into().expect("32 minus 12 is 20 bytes");
        Self::try_from(embedded).map_err(|source| match source {
            AddressConversionError::NonZeroBytePrefix => EncodingError::AccountIdOutOfRange,
            // the hex and Word variants belong to entry points this path never takes; a value that
            // is not an account id is what every remaining case means. The variants are unit, so
            // the source cannot be carried.
            _ => EncodingError::NonCanonicalAccountId,
        })
    }
}

/// The bytes32 encode the protocol does not ship: the inverse of the stock
/// `EthAddress::try_from([u8; 32])`.
pub trait EthAddressExt {
    /// The bytes32 container an EVM address travels in: 12 zero bytes then the 20 address bytes.
    ///
    /// The faucet's `xreserve_contract` domain-config field is stored as this container's 8 u32-LE
    /// limbs — not the address's 5 — because the field has no on-chain compare and off-chain
    /// services read the full bytes32 back out of storage.
    fn to_bytes32(&self) -> [u8; 32];
}

impl EthAddressExt for EthAddress {
    fn to_bytes32(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(self.as_bytes());
        bytes
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
            let embedded = EthEmbeddedAccountId::try_from_bytes32(b)
                .unwrap_or_else(|e| panic!("vector {}: must decode, got {e}", vec.id));
            assert_eq!(embedded.to_bytes32(), b, "vector {}: round-trip", vec.id);
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
        let result = EthEmbeddedAccountId::try_from_bytes32(b);
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
    /// EXACT `AccountIdOutOfRange`. The pad is checked in two halves — bytes 0..12 here, bytes
    /// 12..16 by the stock 20-byte decode — so the cases straddle the seam between them: a
    /// weakened check on either half would decode a padded wire form into a lossy,
    /// non-round-tripping AccountId.
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
            EthEmbeddedAccountId::try_from_bytes32(b),
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
        let _shape_check: fn([u8; 32]) -> Result<EthEmbeddedAccountId, EncodingError> =
            EthEmbeddedAccountId::try_from_bytes32;
    }

    /// The EVM-address container round-trips through the stock decode, and leaves the 12 leading
    /// bytes zero — the padding the stock `TryFrom<[u8; 32]>` insists on.
    #[test]
    fn eth_address_bytes32_container_round_trips() {
        let address = EthAddress::new(core::array::from_fn(|i| 0x10 + i as u8));
        let bytes32 = address.to_bytes32();
        assert_eq!(&bytes32[..12], &[0u8; 12], "the leading pad must be zero");
        assert_eq!(
            EthAddress::try_from(bytes32).expect("a padded container decodes"),
            address
        );
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
