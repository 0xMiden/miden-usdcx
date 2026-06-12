//! AccountId ↔ bytes32 family, frozen signatures per `COMPONENT-SPEC.md §6.3`
//! (INV-ACCOUNTID-ENCODING; Rust-primary — human decision D-5: no MASM leg this slice).
//! Implemented (routine R3). The byte layout is the IMPL-ACCOUNTID-LAYOUT draft: it
//! `REQUIRES CIRCLE CONFIRMATION` (DEV-10) and `REQUIRES IMPLEMENTATION VALIDATION` —
//! labels preserved, nothing resolved.

use miden_protocol::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::utils::serde::{Deserializable, Serializable};

use super::error::EncodingError;

/// `AddressType::AccountId` discriminant (EL E-11; pinned source:
/// `miden-protocol/src/address/type.rs` — 232 = 0b1110_1000).
pub const ADDRESS_TYPE_ACCOUNT_ID: u8 = 232;

/// Lossless 15-byte encoding into bytes32 (draft layout, DEV-10: bytes[0..15] = the
/// canonical 15-byte serialization — 8-byte BE prefix + 7-byte BE suffix (the suffix's
/// always-zero last byte is omitted, `v1/mod.rs:300-308`); bytes[15..32] = zero padding).
pub fn account_id_to_bytes32(id: AccountId) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..AccountId::SERIALIZED_SIZE].copy_from_slice(&id.to_bytes());
    out
}

/// Inverse; rejects bytes set outside the 15-byte region (`AccountIdOutOfRange`) and
/// non-canonical ids (`NonCanonicalAccountId`). Round-trip lossless for valid ids.
pub fn bytes32_to_account_id(b: &[u8; 32]) -> Result<AccountId, EncodingError> {
    if b[AccountId::SERIALIZED_SIZE..].iter().any(|&byte| byte != 0) {
        return Err(EncodingError::AccountIdOutOfRange);
    }
    // the protocol's deserialization validates canonicity (version/type/prefix rules,
    // `v1/mod.rs:388-394` → `AccountIdError`); the frozen unit variant cannot carry that
    // source (preserve-error-source conflict recorded in the approved plan — frozen wins)
    AccountId::read_from_bytes(&b[..AccountId::SERIALIZED_SIZE])
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
