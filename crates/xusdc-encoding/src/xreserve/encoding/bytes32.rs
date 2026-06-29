//! bytes32 → Word family, frozen signatures per `COMPONENT-SPEC.md §6.2`
//! (INV-BYTES32-HASH-TO-WORD). Implemented (routine R1).

use miden_protocol::account::StorageMapKey;
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Hasher, Word};

use super::error::EncodingError;

/// Option B (canonical for arbitrary external bytes32): infallible Poseidon2 hash-to-Word.
/// `felts = bytes_to_packed_u32_elements(b)` (8 felts); `key = Hasher::hash_elements(&felts)`.
pub fn bytes32_to_storage_map_key(b: &[u8; 32]) -> StorageMapKey {
    let felts = bytes32_to_packed_felts(b);
    StorageMapKey::new(Hasher::hash_elements(&felts))
}

/// The 8x u32-LE packing primitive (infallible, each u32 < 2^32 < p).
pub fn bytes32_to_packed_felts(b: &[u8; 32]) -> [Felt; 8] {
    bytes_to_packed_u32_elements(b)
        .try_into()
        // length is type-guaranteed (32 bytes / 4 bytes per u32 felt), not input-dependent
        .expect("32 bytes always pack to exactly 8 u32 felts")
}

/// Option A (lossless, FALLIBLE — NOT used for external map keys): native `TryFrom`.
/// Returns `Err(LimbOutOfField)` if any 8-byte LE limb >= p. Round-trip tests only.
pub fn bytes32_to_word_lossless(b: &[u8; 32]) -> Result<Word, EncodingError> {
    // the frozen `EncodingError::LimbOutOfField` is a unit variant, so the inner
    // `WordError` source cannot be carried (frozen signature takes precedence over the
    // preserve-error-source checklist; conflict recorded in the approved plan)
    Word::try_from(*b).map_err(|_| EncodingError::LimbOutOfField)
}

/// Inverse of [`bytes32_to_packed_felts`]: 8 u32-LE-packed felts → the 32-byte value
/// (additive DC-7 increment; the forward packer above is unchanged). Fail-closed — any felt
/// `> u32::MAX` is not a valid packed limb and returns [`EncodingError::LimbNotU32`] rather
/// than truncating. Round-trip: `packed_felts_to_bytes32(bytes32_to_packed_felts(b)) == b`.
/// Consumed by reference from the DC-7 burn-note decode and the off-chain withdrawal attester.
pub fn packed_felts_to_bytes32(felts: &[Felt; 8]) -> Result<[u8; 32], EncodingError> {
    let _ = felts;
    unimplemented!("P5-04 DC-7: implemented in the GREEN commit")
}

// TESTS — TV-B32-1..4 (frozen 04 TEST-AND-VERIFICATION-HARNESS §2.1)
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::vectors::{load, word_from_hex};

    /// TV-B32-1 (happy path, written first): known bytes32 → expected Poseidon2 Word.
    #[test]
    fn tv_b32_1_hash_to_word_positive() {
        let v = load();
        for vec in v.families.b32.iter().filter(|v| v.lossless_error.is_none()) {
            let key = bytes32_to_storage_map_key(&vec.bytes32());
            assert_eq!(
                Word::from(key),
                word_from_hex(&vec.expected_key),
                "vector {}: key mismatch",
                vec.id
            );
        }
    }

    /// TV-B32-2 (negative + bypass-positive): native lossless path rejects a limb >= p,
    /// while Option B succeeds on the same input.
    #[test]
    fn tv_b32_2_lossless_rejects_option_b_succeeds() {
        let v = load();
        let vec = v
            .families
            .b32
            .iter()
            .find(|v| v.lossless_error.is_some())
            .expect("artifact must carry the limb-ge-p vector");
        assert_matches!(
            bytes32_to_word_lossless(&vec.bytes32()),
            Err(EncodingError::LimbOutOfField),
            "vector {}: lossless path must reject",
            vec.id
        );
        let key = bytes32_to_storage_map_key(&vec.bytes32());
        assert_eq!(Word::from(key), word_from_hex(&vec.expected_key), "vector {}", vec.id);
    }

    /// TV-B32-3 (replay/determinism): same input → identical key twice.
    #[test]
    fn tv_b32_3_determinism() {
        let v = load();
        for vec in &v.families.b32 {
            let a = bytes32_to_storage_map_key(&vec.bytes32());
            let b = bytes32_to_storage_map_key(&vec.bytes32());
            assert_eq!(a, b, "vector {}: keying must be deterministic", vec.id);
        }
    }

    /// TV-B32-4 (boundary/width): the packing yields exactly 8 felts (2 Words — too wide
    /// for one key, which is why the hash-to-Word step exists).
    #[test]
    fn tv_b32_4_packing_is_8_felts_two_words() {
        let v = load();
        for vec in &v.families.b32 {
            let felts = bytes32_to_packed_felts(&vec.bytes32());
            assert_eq!(felts.len(), 8, "vector {}: packing width", vec.id);
            let expected: Vec<Felt> = vec.packed_felts_values();
            assert_eq!(felts.as_slice(), expected.as_slice(), "vector {}: limbs", vec.id);
        }
    }

    /// TV-B32-INV-1 (inverse round-trip): `packed_felts_to_bytes32` is the exact inverse of
    /// `bytes32_to_packed_felts` over every committed b32 vector (every limb is a valid u32).
    #[test]
    fn tv_b32_inverse_round_trip() {
        let v = load();
        for vec in &v.families.b32 {
            let b = vec.bytes32();
            let felts = bytes32_to_packed_felts(&b);
            let back = packed_felts_to_bytes32(&felts).expect("valid u32 limbs round-trip");
            assert_eq!(back, b, "vector {}: inverse round-trip", vec.id);
            assert_eq!(bytes32_to_packed_felts(&back), felts, "vector {}: forward∘inverse", vec.id);
        }
    }

    /// TV-B32-INV-2 (fail-closed): a packed felt `> u32::MAX` is rejected, never truncated.
    #[test]
    fn tv_b32_inverse_rejects_non_u32() {
        let mut felts = [Felt::from(0u32); 8];
        felts[3] = Felt::try_from((u32::MAX as u64) + 1).expect("2^32 < p");
        assert_matches!(
            packed_felts_to_bytes32(&felts),
            Err(EncodingError::LimbNotU32),
            "a 2^32 limb must be rejected, not truncated"
        );
    }
}
