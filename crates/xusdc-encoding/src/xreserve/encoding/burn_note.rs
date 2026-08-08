//! Burn-note item codec: the burn-note `NoteStorage.items` payload
//! `(amount, destDomain, destRecipient, salt)`.
//!
//! This codec is Rust-only and has no MASM counterpart, because nothing on-chain ever reads the
//! payload: the faucet burns the asset, and the destination fields exist for the off-chain
//! withdrawal attester to act on. The burn note encodes and the attester decodes, so the encoding
//! has to be exactly reversible between them.
//!
//! The `destRecipient` and `salt` fields are packed and unpacked with the shared bytes32 codec in
//! both directions, so there is one definition of how 32 bytes become field elements.

use miden_protocol::asset::AssetAmount;
use miden_protocol::Felt;

use super::bytes32::{bytes32_to_packed_felts, packed_felts_to_bytes32};
use super::error::EncodingError;

/// Felt width of the burn-note `NoteStorage.items` payload: `amount` (1) then `destDomain`
/// (1) then `destRecipient` (8 u32-LE) then `salt` (8 u32-LE), totalling 18 felts
/// (≤ 1024, the note-storage bound).
pub const BURN_NOTE_ITEMS_FELTS: usize = 18;

/// The burn-note public payload `(amount, destDomain, destRecipient, salt)` — the burn note's
/// dedicated note-storage type. Destination fields live in `NoteStorage.items`, never note metadata
/// (`metadata.sender` carries the burner and nothing else). Built either as a struct literal or with
/// a `bon` builder (`XReserveBurnItems::builder().amount(..).dest_domain(..)…build()`), the standards
/// note-storage-type pattern.
#[derive(Debug, Clone, PartialEq, Eq, bon::Builder)]
pub struct XReserveBurnItems {
    pub amount: AssetAmount,
    pub dest_domain: u32,
    pub dest_recipient: [u8; 32],
    pub salt: [u8; 32],
}

impl XReserveBurnItems {
    /// Encodes the payload into its `NoteStorage.items` felt layout. The method spelling of
    /// [`encode_burn_note_items`]; byte-for-byte identical output.
    pub fn encode(&self) -> Vec<Felt> {
        encode_burn_note_items(self)
    }

    /// Decodes a `NoteStorage.items` payload back into the typed struct — the method spelling of
    /// [`decode_burn_note_items`].
    ///
    /// # Errors
    ///
    /// Returns [`EncodingError::BurnItemsMalformed`] on any wrong length, out-of-range field, or
    /// non-u32 limb (identical fail-closed behaviour to [`decode_burn_note_items`]).
    pub fn decode(items: &[Felt]) -> Result<Self, EncodingError> {
        decode_burn_note_items(items)
    }
}

/// Encodes `(amount, destDomain, destRecipient, salt)` into the `NoteStorage.items` felt
/// layout. Infallible: `AssetAmount::MAX = 2^63 − 2^31`, `destDomain` is a
/// `u32`, and both bytes32 fields pack via the existing `bytes32` codec.
pub fn encode_burn_note_items(items: &XReserveBurnItems) -> Vec<Felt> {
    let mut out = Vec::with_capacity(BURN_NOTE_ITEMS_FELTS);
    out.push(Felt::from(items.amount)); // [0]
    out.push(Felt::from(items.dest_domain)); // [1]
    out.extend_from_slice(&bytes32_to_packed_felts(&items.dest_recipient)); // [2..10]
    out.extend_from_slice(&bytes32_to_packed_felts(&items.salt)); // [10..18]
    out
}

/// Inverse of [`encode_burn_note_items`]. Fail-closed: a wrong length, an out-of-range
/// `amount` or `destDomain`, or a non-u32 bytes32 limb all return
/// [`EncodingError::BurnItemsMalformed`] (never a panic, never a generic error).
pub fn decode_burn_note_items(items: &[Felt]) -> Result<XReserveBurnItems, EncodingError> {
    if items.len() != BURN_NOTE_ITEMS_FELTS {
        return Err(EncodingError::BurnItemsMalformed);
    }
    let amount = AssetAmount::new(items[0].as_canonical_u64())
        .map_err(|_| EncodingError::BurnItemsMalformed)?;
    let dest_domain = u32::try_from(items[1].as_canonical_u64())
        .map_err(|_| EncodingError::BurnItemsMalformed)?;
    // The length was checked above, so each slice is exactly 8 felts. Unpacking goes through the
    // shared bytes32 inverse; a limb that is not a valid u32 is reported as a malformed payload
    // rather than being truncated into a plausible-looking address.
    let recipient_felts: [Felt; 8] = items[2..10]
        .try_into()
        .expect("len == 18 ⇒ items[2..10] is exactly 8 felts");
    let dest_recipient =
        packed_felts_to_bytes32(&recipient_felts).map_err(|_| EncodingError::BurnItemsMalformed)?;
    let salt_felts: [Felt; 8] = items[10..18]
        .try_into()
        .expect("len == 18 ⇒ items[10..18] is exactly 8 felts");
    let salt =
        packed_felts_to_bytes32(&salt_felts).map_err(|_| EncodingError::BurnItemsMalformed)?;
    Ok(XReserveBurnItems {
        amount,
        dest_domain,
        dest_recipient,
        salt,
    })
}

// TESTS — TV-BN-1..4
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::load;

    /// TV-BN-1 (round-trip + golden layout): `encode` matches the golden felts and
    /// `decode(encode(x)) == x` across the accept vectors (incl. boundary values).
    #[test]
    fn tv_bn_1_round_trip() {
        let v = load();
        let accept: Vec<_> = v
            .families
            .bn
            .iter()
            .filter(|x| x.kind == "accept")
            .collect();
        assert!(!accept.is_empty(), "bn accept vectors present");
        for vec in accept {
            let x = vec.expected_struct();
            let encoded = encode_burn_note_items(&x);
            assert_eq!(encoded.len(), BURN_NOTE_ITEMS_FELTS, "{}: width", vec.id);
            assert_eq!(
                encoded,
                vec.items_values(),
                "{}: encode matches the golden layout",
                vec.id
            );
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

    /// TV-BN-2 (destination-in-items): the destination fields land in the
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
            assert_eq!(
                &items[2..10],
                &golden[2..10],
                "{}: destRecipient in items[2..10]",
                vec.id
            );
            assert_eq!(
                &items[10..18],
                &golden[10..18],
                "{}: salt in items[10..18]",
                vec.id
            );
        }
    }

    /// TV-BN-3 (note-model placement): the payload targets `NoteStorage.items`
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
