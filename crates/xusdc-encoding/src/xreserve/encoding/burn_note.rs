//! Burn-note item codec — DC-7 / §6.6 (`COMPONENT-SPEC.md:363-376`): the burn-note
//! `NoteStorage.items` payload `(amount, destDomain, destRecipient, salt)`.
//!
//! 04 owns the deterministic Rust item encode/decode ONLY. The on-chain `NoteStorage.items`
//! write and TV-DUAL-4 (emit-vs-encode parity) are faucet-owned (CMP-B2), exercised through
//! the faucet MockChain/local-node harness — there is NO MASM side in this slice. Consumers:
//! the public burn note (CMP-B2, encode) and the off-chain withdrawal attester (decode).
//! `destRecipient`/`salt` consume the `bytes32` codec by reference in both directions
//! (`bytes32_to_packed_felts` / `packed_felts_to_bytes32`); no re-implementation here.

use miden_protocol::Felt;
use miden_protocol::asset::AssetAmount;

use super::error::EncodingError;

/// Felt width of the burn-note `NoteStorage.items` payload: `amount` (1) + `destDomain` (1)
/// + `destRecipient` (8 u32-LE) + `salt` (8 u32-LE) = 18 (`COMPONENT-SPEC.md:419`; ≤ 1024,
/// anti-ASG-17).
pub const BURN_NOTE_ITEMS_FELTS: usize = 18;

/// The burn-note public payload `(amount, destDomain, destRecipient, salt)` (frozen
/// signature, `COMPONENT-SPEC.md:366-371`). Destination fields live in `NoteStorage.items`,
/// never note metadata (`metadata.sender` = depositor only; anti-ASG-13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XReserveBurnItems {
    pub amount: AssetAmount,
    pub dest_domain: u32,
    pub dest_recipient: [u8; 32],
    pub salt: [u8; 32],
}

/// Encodes `(amount, destDomain, destRecipient, salt)` into the `NoteStorage.items` felt
/// layout (§7 `:419`). Infallible: `AssetAmount::MAX = 2^63 − 2^31 < p`, `destDomain` is a
/// `u32`, and both bytes32 fields pack via the existing `bytes32` codec.
pub fn encode_burn_note_items(items: &XReserveBurnItems) -> Vec<Felt> {
    let _ = items;
    unimplemented!("P5-04 DC-7: implemented in the GREEN commit")
}

/// Inverse of [`encode_burn_note_items`]. Fail-closed: a wrong length, an out-of-range
/// `amount` or `destDomain`, or a non-u32 bytes32 limb all return
/// [`EncodingError::BurnItemsMalformed`] (never a panic, never a generic error).
pub fn decode_burn_note_items(items: &[Felt]) -> Result<XReserveBurnItems, EncodingError> {
    let _ = items;
    unimplemented!("P5-04 DC-7: implemented in the GREEN commit")
}

// TESTS — TV-BN-1..4 (frozen 04 TEST-AND-VERIFICATION-HARNESS §2.5)
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::load;

    /// TV-BN-1 (round-trip + golden layout): `encode` matches the §7 golden felts and
    /// `decode(encode(x)) == x` across the accept vectors (incl. boundary values).
    #[test]
    fn tv_bn_1_round_trip() {
        let v = load();
        let accept: Vec<_> = v.families.bn.iter().filter(|x| x.kind == "accept").collect();
        assert!(!accept.is_empty(), "bn accept vectors present");
        for vec in accept {
            let x = vec.expected_struct();
            let encoded = encode_burn_note_items(&x);
            assert_eq!(encoded.len(), BURN_NOTE_ITEMS_FELTS, "{}: width", vec.id);
            assert_eq!(encoded, vec.items_values(), "{}: encode matches §7 golden layout", vec.id);
            assert_eq!(
                decode_burn_note_items(&encoded).expect("round-trip decode"),
                x,
                "{}: decode∘encode",
                vec.id
            );
            assert_eq!(
                decode_burn_note_items(&vec.items_values()).expect("golden decode"),
                x,
                "{}: decode golden felts",
                vec.id
            );
        }
    }

    /// TV-BN-2 (destination-in-items, anti-ASG-13): the destination fields land in the
    /// `NoteStorage.items` felt layout (`destDomain` at `[1]`, `destRecipient` at `[2..10]`,
    /// `salt` at `[10..18]`). `encode` has no metadata path — its only output is `Vec<Felt>`,
    /// so `metadata.sender` is structurally reserved for the depositor.
    #[test]
    fn tv_bn_2_destination_in_items() {
        let v = load();
        for vec in v.families.bn.iter().filter(|x| x.kind == "accept") {
            let items = encode_burn_note_items(&vec.expected_struct());
            let golden = vec.items_values();
            assert_eq!(items[1], golden[1], "{}: destDomain in items[1]", vec.id);
            assert_eq!(&items[2..10], &golden[2..10], "{}: destRecipient in items[2..10]", vec.id);
            assert_eq!(&items[10..18], &golden[10..18], "{}: salt in items[10..18]", vec.id);
        }
    }

    /// TV-BN-3 (note-model placement, anti-ASG-17): the payload targets `NoteStorage.items`
    /// (≤ 1024 felts), not `NoteInputs`/`aux`.
    #[test]
    fn tv_bn_3_note_storage_placement() {
        let v = load();
        for vec in v.families.bn.iter().filter(|x| x.kind == "accept") {
            let n = encode_burn_note_items(&vec.expected_struct()).len();
            assert_eq!(n, BURN_NOTE_ITEMS_FELTS, "{}: fixed width", vec.id);
            assert!(n <= 1024, "{}: within the NoteStorage.items bound", vec.id);
        }
    }

    /// TV-BN-4 (malformed → exact error): every malformed-items vector decodes to the exact
    /// `BurnItemsMalformed` (wrong length, out-of-range amount/domain, or a non-u32 limb).
    #[rstest]
    #[case("bn-rej-len-short")]
    #[case("bn-rej-len-long")]
    #[case("bn-rej-amount-over-cap")]
    #[case("bn-rej-domain-over-u32")]
    #[case("bn-rej-recipient-limb-not-u32")]
    #[case("bn-rej-salt-limb-not-u32")]
    fn tv_bn_4_malformed_burn_items(#[case] id: &str) {
        let vec = load()
            .families
            .bn
            .iter()
            .find(|x| x.id == id)
            .unwrap_or_else(|| panic!("vector {id} present"));
        assert_matches!(
            decode_burn_note_items(&vec.items_values()),
            Err(EncodingError::BurnItemsMalformed),
            "{id}",
        );
    }
}
