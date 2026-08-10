//! Typing-slice equivalence suite.
//!
//! Locks every new typed API this typing slice introduces to the FROZEN golden vectors: the typed
//! path must produce byte-for-byte / felt-for-felt identical output to the values the encoding
//! conformance suite already pins. A wire
//! change — a reordered signature felt, a swapped account-id pair, a drifted commitment — makes these
//! RED, which is what proves the typing refactor is wire-neutral.
//!
//! It also re-locks the inlined AccountId two-felt form: the `account_id_to_felts` helper and
//! its dedicated `tv_aid_4` unit test were deleted, so this suite carries the `[prefix, suffix]`
//! golden-vector coverage that test used to provide, and pins the exact ordering a call site must
//! inline.

use assert_matches::assert_matches;
use miden_protocol::Word;
use xusdc_encoding::vectors::{load, parse_hex32};
use xusdc_encoding::xreserve::encoding::{
    account_id_to_bytes32, bytes32_to_account_id, bytes32_to_packed_felts, DepositIntent,
    DepositIntentHeader, EncodingError, EthBytes32, PublicKey, PublicKeyCommitment, Signature,
    XReserveBurnItems,
};

// Signature
// ================================================================================================

/// `Signature::new(bytes).to_felts()` is byte-identical to the golden signature felts. A
/// reordered/perturbed packing goes RED here.
#[test]
fn signature_type_matches_golden() {
    for v in &load().families.att {
        let sig = v.sig();
        let typed = Signature::new(sig);
        assert_eq!(
            typed.to_felts().as_slice(),
            v.sig_felts_values().as_slice(),
            "{}: Signature::to_felts == golden sig felts",
            v.id
        );
        assert_eq!(
            typed.as_bytes(),
            &sig,
            "{}: Signature round-trips its bytes",
            v.id
        );
    }
}

// PublicKey + stock PublicKeyCommitment reuse
// ================================================================================================

/// `PublicKey::to_affine_felts` and `PublicKey::to_commitment` match the golden affine felts and the
/// golden commitment word, and the commitment is handed out as the STOCK `PublicKeyCommitment`
/// newtype, which round-trips through `Word`.
#[test]
fn public_key_affine_and_commitment_match_golden() {
    for v in &load().families.att {
        let pk = v.pubkey();
        let typed = PublicKey::new(pk);

        let affine = typed
            .to_affine_felts()
            .expect("vector keys are valid points");
        assert_eq!(
            affine.as_slice(),
            v.packed_felts_values().as_slice(),
            "{}: PublicKey::to_affine_felts == golden pubkey felts",
            v.id
        );

        let commitment: PublicKeyCommitment = typed.to_commitment().expect("valid point");
        assert_eq!(
            Word::from(commitment),
            v.expected_commitment_word(),
            "{}: PublicKey::to_commitment word == golden commitment",
            v.id
        );
        // the stock newtype round-trips (From<Word>): the value we produced IS a PublicKeyCommitment.
        assert_eq!(
            PublicKeyCommitment::from(Word::from(commitment)),
            commitment,
            "{}: PublicKeyCommitment::from(Word) round-trips",
            v.id
        );
        assert_eq!(
            typed.as_bytes(),
            &pk,
            "{}: PublicKey round-trips its bytes",
            v.id
        );
    }
}

/// The typed pubkey conversions fail-close on an off-curve key.
#[test]
fn public_key_fail_closes_on_off_curve() {
    let mut bogus = [0xFFu8; 33];
    bogus[0] = 0x02;
    let pk = PublicKey::new(bogus);
    assert_matches!(pk.to_affine_felts(), Err(EncodingError::InvalidPubkey));
    assert_matches!(pk.to_commitment(), Err(EncodingError::InvalidPubkey));
}

// DepositIntent owns its codec
// ================================================================================================

/// `DepositIntent::new(bytes).parse_header()` / `.to_packed_felts()` and the `TryFrom<&[u8]>` header
/// decode match the golden packed preimage.
#[test]
fn deposit_intent_type_matches_golden() {
    for vec in load().families.di.iter().filter(|v| v.kind == "accept") {
        let bytes = vec.bytes();
        let intent = DepositIntent::new(&bytes);

        let typed_header = intent.parse_header().expect("accept vector parses");

        // TryFrom<&[u8]> is the same decode as parse_header.
        let via_tryfrom =
            DepositIntentHeader::try_from(bytes.as_slice()).expect("TryFrom parses accept vector");
        assert_eq!(
            via_tryfrom.nonce, typed_header.nonce,
            "{}: TryFrom<&[u8]> == parse_header",
            vec.id
        );

        let typed_felts = intent.to_packed_felts().expect("accept vector packs");
        assert_eq!(
            typed_felts,
            vec.preimage_values(),
            "{}: DepositIntent::to_packed_felts == golden preimage",
            vec.id
        );
        assert_eq!(
            intent.as_bytes(),
            bytes.as_slice(),
            "{}: as_bytes round-trips",
            vec.id
        );
    }
}

/// The typed path rejects a truncated payload.
#[test]
fn deposit_intent_type_propagates_rejects() {
    let short = [0u8; 10];
    assert_matches!(
        DepositIntent::new(&short).parse_header(),
        Err(EncodingError::TruncatedHeader)
    );
    assert_matches!(
        DepositIntentHeader::try_from(short.as_slice()),
        Err(EncodingError::TruncatedHeader)
    );
}

// XReserveBurnItems methods
// ================================================================================================

/// `XReserveBurnItems::encode` / `decode` match the golden `items` layout, and
/// round-trip.
#[test]
fn burn_items_methods_match_golden() {
    for vec in load().families.bn.iter().filter(|v| v.kind == "accept") {
        let items = vec.expected_struct();
        let encoded = items.encode();
        assert_eq!(
            encoded,
            vec.items_values(),
            "{}: XReserveBurnItems::encode == golden layout",
            vec.id
        );
        assert_eq!(
            XReserveBurnItems::decode(&encoded).expect("round-trips"),
            items,
            "{}: XReserveBurnItems::decode(encode(x)) == x",
            vec.id
        );
    }
}

/// `XReserveBurnItems::decode` fail-closes on a malformed payload.
#[test]
fn burn_items_decode_fail_closes() {
    assert_matches!(
        XReserveBurnItems::decode(&[]),
        Err(EncodingError::BurnItemsMalformed)
    );
}

// The inlined AccountId two-felt form (replacing the deleted `account_id_to_felts` + `tv_aid_4`)
// ================================================================================================

/// The inlined `(prefix, suffix)` form every call site now uses matches the vector's golden
/// `[prefix, suffix]` pair — the coverage the deleted `tv_aid_4_two_felt_form` provided, kept alive.
/// A swap to `(suffix, prefix)` at a call site is caught by comparing against this golden ordering.
#[test]
fn account_id_two_felt_form_matches_golden() {
    for vec in load()
        .families
        .aid
        .iter()
        .filter(|v| v.expected_variant.is_none())
    {
        let b = parse_hex32(&vec.bytes32);
        let id = bytes32_to_account_id(&b).expect("accept vector decodes");
        let pair = [id.prefix().as_felt(), id.suffix()];
        assert_eq!(
            pair.as_slice(),
            vec.expected_felts().as_slice(),
            "{}: inlined (prefix, suffix) == golden felts",
            vec.id
        );
    }
}

// account_id_to_bytes32 adopts the stock EthEmbeddedAccountId form (byte-identical)
// ================================================================================================

/// The forward conversion now delegates to `EthEmbeddedAccountId::to_bytes32()`, and must stay
/// byte-identical to the golden bytes32 — the adoption is not lossy.
#[test]
fn account_id_to_bytes32_adopts_stock_byte_identical() {
    for vec in load()
        .families
        .aid
        .iter()
        .filter(|v| v.expected_variant.is_none())
    {
        let b = parse_hex32(&vec.bytes32);
        let id = bytes32_to_account_id(&b).expect("accept vector decodes");
        assert_eq!(
            account_id_to_bytes32(id),
            b,
            "{}: adopted account_id_to_bytes32 stays byte-identical to the golden bytes32",
            vec.id
        );
    }
}

// EthBytes32 local newtype (32-byte; stock EthAddress is 20-byte)
// ================================================================================================

/// `EthBytes32` packs through the shared bytes32 codec, so a value packed via the newtype is
/// identical to one packed by `bytes32_to_packed_felts`, and the byte/`From`/`Into` round-trips hold.
#[test]
fn eth_bytes32_newtype_packs_like_the_shared_codec() {
    for vec in &load().families.b32 {
        let b = vec.bytes32();
        let typed = EthBytes32::new(b);
        assert_eq!(
            typed.to_packed_felts(),
            bytes32_to_packed_felts(&b),
            "{}: EthBytes32::to_packed_felts == shared codec",
            vec.id
        );
        assert_eq!(
            typed.as_bytes(),
            &b,
            "{}: EthBytes32 round-trips its bytes",
            vec.id
        );
        let via_from: EthBytes32 = b.into();
        assert_eq!(via_from, typed, "{}: From<[u8; 32]>", vec.id);
        let back: [u8; 32] = typed.into();
        assert_eq!(back, b, "{}: Into<[u8; 32]>", vec.id);
    }
}
