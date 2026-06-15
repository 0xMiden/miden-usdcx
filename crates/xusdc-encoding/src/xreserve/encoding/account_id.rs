//! AccountId ↔ bytes32 family, frozen signatures per `COMPONENT-SPEC.md §6.3`
//! (INV-ACCOUNTID-ENCODING; Rust-primary — human decision D-5: no MASM leg this slice).
//! Implemented (routine R3); the bytes32 packaging is the R-B / Agglayer-mirroring
//! layout (DEV-10 draft, human-selected 2026-06-15 — supersedes the prior left-aligned
//! 15-byte/trailing-zero draft). `REQUIRES CIRCLE CONFIRMATION` (DEV-10) and
//! `REQUIRES IMPLEMENTATION VALIDATION` — the layout stays an OPEN proposal to Circle,
//! no approval.

use miden_protocol::Felt;
use miden_protocol::account::AccountId;

use super::error::EncodingError;

/// `AddressType::AccountId` discriminant (EL E-11; pinned source:
/// `miden-protocol/src/address/type.rs` — 232 = 0b1110_1000). A bech32 discriminant,
/// NOT part of the bytes32 wire form.
pub const ADDRESS_TYPE_ACCOUNT_ID: u8 = 232;

/// Lossless AccountId → bytes32 packaging — R-B / Agglayer-mirroring (DEV-10 draft):
/// `bytes[0..16] = 0x00` (leading zero pad), `bytes[16..24] = prefix` as u64 big-endian,
/// `bytes[24..32] = suffix` as canonical u64 big-endian. Mirrors the protocol Agglayer
/// `EthEmbeddedAccountId` form `0x00000000 || prefix(8) || suffix(8)`
/// (`miden-agglayer/src/eth_types/eth_embedded_account_id.rs:117-122`) widened to a
/// 32-byte slot; uses the FULL 8-byte suffix, not `to_bytes()`'s 7-byte form.
pub fn account_id_to_bytes32(id: AccountId) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..24].copy_from_slice(&id.prefix().as_u64().to_be_bytes());
    out[24..32].copy_from_slice(&id.suffix().as_canonical_u64().to_be_bytes());
    out
}

/// Inverse (R-B): rejects a non-zero byte in the leading 16-byte pad region
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
    // AccountId (`try_from_elements(suffix, prefix)`, mirroring the Agglayer precedent
    // `eth_embedded_account_id.rs:86-96`); the frozen unit variant cannot carry the inner
    // `AccountIdError` source (preserve-error-source conflict recorded — frozen wins)
    let prefix_felt = Felt::try_from(prefix).map_err(|_| EncodingError::NonCanonicalAccountId)?;
    let suffix_felt = Felt::try_from(suffix).map_err(|_| EncodingError::NonCanonicalAccountId)?;
    AccountId::try_from_elements(suffix_felt, prefix_felt)
        .map_err(|_| EncodingError::NonCanonicalAccountId)
}

/// The on-chain natural form: the two felts `[prefix, suffix]` directly (no repacking).
pub fn account_id_to_felts(id: AccountId) -> [Felt; 2] {
    [id.prefix().as_felt(), id.suffix()]
}

// TESTS — TV-AID-1..4 (frozen 04 TEST-AND-VERIFICATION-HARNESS §2.3)
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
        for vec in v.families.aid.iter().filter(|v| v.expected_variant.is_none()) {
            let b = parse_hex32(&vec.bytes32);
            let id = bytes32_to_account_id(&b)
                .unwrap_or_else(|e| panic!("vector {}: must decode, got {e}", vec.id));
            assert_eq!(account_id_to_bytes32(id), b, "vector {}: round-trip", vec.id);
        }
    }

    /// TV-AID-2 (negative): out-of-range bytes and in-region non-canonical ids are
    /// rejected with their specific variants.
    #[rstest]
    #[case::out_of_range("aid-rej-out-of-range")]
    #[case::non_canonical("aid-rej-non-canonical")]
    fn tv_aid_2_rejects(#[case] id: &str) {
        let v = load();
        let vec = v.families.aid.iter().find(|v| v.id == id).expect("vector present");
        let b = parse_hex32(&vec.bytes32);
        let result = bytes32_to_account_id(&b);
        match vec.expected_variant.as_deref() {
            Some("AccountIdOutOfRange") => {
                assert_matches!(result, Err(EncodingError::AccountIdOutOfRange), "vector {id}")
            },
            Some("NonCanonicalAccountId") => {
                assert_matches!(result, Err(EncodingError::NonCanonicalAccountId), "vector {id}")
            },
            other => panic!("vector {id}: unexpected expected_variant {other:?}"),
        }
    }

    /// TV-AID-3 (constants/API shape): the address type discriminant is 232 and the API
    /// has no >32-byte / keccak fallback branch (input type is `[u8; 32]` by signature).
    /// Layout labels: `REQUIRES CIRCLE CONFIRMATION` (DEV-10) — `NO EVIDENCE OF CIRCLE
    /// APPROVAL`; `REQUIRES IMPLEMENTATION VALIDATION` (IMPL-ACCOUNTID-LAYOUT).
    #[test]
    fn tv_aid_3_address_type_and_no_fallback() {
        assert_eq!(ADDRESS_TYPE_ACCOUNT_ID, 232, "AddressType::AccountId discriminant (E-11)");
        // API-shape check: the converter accepts exactly 32 bytes (compile-time shape);
        // the absence of any keccak dependency in this crate is swept by the final gate.
        let _shape_check: fn(&[u8; 32]) -> Result<AccountId, EncodingError> =
            bytes32_to_account_id;
    }

    /// TV-AID-4 (on-chain shape): the two-felt form matches the vector's expected
    /// `[prefix, suffix]` pair and the pair recovered from the bytes32 form.
    #[test]
    fn tv_aid_4_two_felt_form() {
        let v = load();
        for vec in v.families.aid.iter().filter(|v| v.expected_variant.is_none()) {
            let b = parse_hex32(&vec.bytes32);
            let id = bytes32_to_account_id(&b)
                .unwrap_or_else(|e| panic!("vector {}: must decode, got {e}", vec.id));
            let felts = account_id_to_felts(id);
            let expected = vec.expected_felts();
            assert_eq!(felts.as_slice(), expected.as_slice(), "vector {}: felts", vec.id);
        }
    }
}
