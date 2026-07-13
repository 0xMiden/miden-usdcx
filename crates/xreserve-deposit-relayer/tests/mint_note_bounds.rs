//! The builder's REJECTION surface: T-RLY-11's felt-count bounds, the DepositIntent structural
//! rejects, the non-public faucet, and the validated-attestation boundary.
//!
//! What ties these together is the taxonomy. The unit-04 factory wraps any codec failure in an
//! opaque `NoteError`; if the builder forwarded that, every malformed payload would collapse into
//! one indistinguishable "build failed" — and the relayer's entire retry policy turns on telling a
//! permanent fault from a transient one. So each case here asserts the FIELD-SPECIFIC variant and
//! its preserved unit-04 cause, not merely that something failed.

mod fixtures;
mod mint_support;

use assert_matches::assert_matches;
use miden_protocol::account::AccountId;
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET;
use rstest::rstest;

use xreserve_deposit_relayer::circle::schema::{AttestationObject, ValidatedAttestation};
use xreserve_deposit_relayer::error::RelayerError;
use xreserve_deposit_relayer::miden::mint_note_builder::{
    build_mint_note_with_entropy, MintNoteBuildRequest,
};
use xusdc_encoding::xreserve::encoding::{
    deposit_intent_field_offset, DepositIntentField, EncodingError, DEPOSIT_INTENT_HEADER_FELTS,
    DEPOSIT_INTENT_HEADER_LEN,
};

use fixtures::PartnerAttester;
use mint_support::{
    assert_exact_source, assert_permanent, di_by_id, producer_id, FixedEntropy, Fixture,
    BASE_VECTOR,
};

// 1 — T-RLY-11: the header is 60 felts (anti-ASG-16), never 240/8 = 30
// ================================================================================================

#[test]
fn t_rly_11_builder_packs_the_header_to_60_felts() {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(11);

    assert_eq!(
        built.preimage_felt_len(),
        DEPOSIT_INTENT_HEADER_FELTS,
        "the 240-byte header packs to 60 u32-LE felts"
    );
    assert_eq!(
        DEPOSIT_INTENT_HEADER_FELTS, 60,
        "unit-04 owns the count, and it is 60"
    );
    assert_ne!(
        built.preimage_felt_len(),
        30,
        "anti-ASG-16: NEVER 240/8 = 30 (that would be a 64-bit-per-felt packing)"
    );
    assert_eq!(
        built.note().recipient().storage().items().len(),
        DEPOSIT_INTENT_HEADER_FELTS,
        "and the note's storage carries exactly those felts"
    );
}

// 2 — T-RLY-11: the 1024-felt NoteStorage bound is INCLUSIVE
// ================================================================================================

#[test]
fn t_rly_11_builder_accepts_a_preimage_of_exactly_1024_felts() {
    // 240-byte header + 3856 hookData bytes = 4096 bytes = 60 + ceil(3856/4) = 1024 felts EXACTLY.
    // The bound is inclusive, so an accidental `>= 1024` reject cannot slip through. Only the
    // hookDataLen field is edited, at unit-04's authoritative offset.
    const HOOK_LEN: u32 = 3856;
    let mut payload = di_by_id(BASE_VECTOR).bytes();
    assert_eq!(
        payload.len(),
        DEPOSIT_INTENT_HEADER_LEN,
        "the base vector is a bare header"
    );

    let off = deposit_intent_field_offset(DepositIntentField::HookDataLen);
    payload[off..off + 4].copy_from_slice(&HOOK_LEN.to_be_bytes());
    payload.resize(DEPOSIT_INTENT_HEADER_LEN + HOOK_LEN as usize, 0u8);

    let built = Fixture::with_payload(payload)
        .build(12)
        .expect("a preimage of EXACTLY 1024 felts is within the bound and must build");

    assert_eq!(built.preimage_felt_len(), 1024, "exactly at the bound");
    assert_eq!(
        built.note().recipient().storage().items().len(),
        1024,
        "the note's storage carries all 1024 felts"
    );
}

// 3 — T-RLY-11: past the bound → PreimageTooLarge, with the exact typed cause
// ================================================================================================

#[test]
fn t_rly_11_builder_rejects_an_over_bound_preimage() {
    // The canonical overflow vector: 1025 felts, one past the 1024-felt NoteStorage bound.
    let vector = di_by_id("di-rej-hookdata-overflow");
    assert_eq!(vector.len_felts, 1025, "the canonical overflow felt count");

    let err = Fixture::with_payload(vector.bytes())
        .build(13)
        .expect_err("a preimage past the 1024-felt bound must reject");

    assert_matches!(&err, RelayerError::PreimageTooLarge(_));
    assert_exact_source(&err, &EncodingError::HookDataTooLarge);
    assert_permanent(&err);
}

// 4 — STRUCTURAL REJECTS KEEP THEIR TYPED VARIANT (not swallowed into an opaque build error)
// ================================================================================================

#[rstest]
#[case::bad_magic("di-rej-bad-magic", EncodingError::BadMagic)]
#[case::bad_version("di-rej-bad-version", EncodingError::BadVersion)]
#[case::length_mismatch("di-rej-length-mismatch", EncodingError::LengthMismatch)]
#[case::zero_amount("di-rej-zero-amount", EncodingError::ZeroField { field: DepositIntentField::Amount })]
#[case::zero_local_token("di-rej-zero-local-token", EncodingError::ZeroField { field: DepositIntentField::LocalToken })]
#[case::zero_local_depositor("di-rej-zero-local-depositor", EncodingError::ZeroField { field: DepositIntentField::LocalDepositor })]
#[case::truncated("di-rej-truncated", EncodingError::TruncatedHeader)]
fn builder_surfaces_structural_rejects_with_the_typed_variant(
    #[case] vector_id: &str,
    #[case] expected_source: EncodingError,
) {
    let err = Fixture::with_payload(di_by_id(vector_id).bytes())
        .build(14)
        .expect_err("a structurally-rejected payload must not build a note");

    assert_exact_source(&err, &expected_source);
    assert!(
        !matches!(&err, RelayerError::NoteBuild(_)),
        "a structural reject is a DepositIntent error, not an opaque note-build error"
    );
    assert_permanent(&err);
}

// 5 — A NON-PUBLIC FAUCET CANNOT BE ROUTED TO (the F5 routing attachment refuses it)
// ================================================================================================

#[test]
fn mint_note_rejects_a_non_public_faucet() {
    let fx = Fixture::new(BASE_VECTOR);
    let private_faucet =
        AccountId::try_from(ACCOUNT_ID_PRIVATE_FUNGIBLE_FAUCET).expect("a valid private faucet id");

    let req = MintNoteBuildRequest::new(producer_id(), private_faucet, &fx.attestation, fx.pubkey);
    let err = build_mint_note_with_entropy(&req, &mut FixedEntropy(15))
        .expect_err("a private faucet cannot carry a NetworkAccountTarget routing attachment");

    assert_matches!(&err, RelayerError::NoteBuild(_));
    assert_permanent(&err);
}

// 6 — THE VALIDATED-ATTESTATION BOUNDARY: unbound bytes cannot reach the builder
// ================================================================================================
//
// `MintNoteBuildRequest` takes a `ValidatedAttestation`, and the ONLY way to make one is through
// the `messageHash == keccak256(payload)` binding. That is not decoration: the on-chain D5d verify
// is over `keccak256(payload)`, so a payload/signature pair that was never bound to its digest is
// guaranteed to fail on-chain — a Miden transaction spent to prove nothing. The type system carries
// the validation order, and these cases prove the door is actually shut.

#[test]
fn an_unbound_payload_cannot_become_a_validated_attestation() {
    let attester = PartnerAttester::new();
    let signed = attester.attest(&fixtures::canonical_payload(BASE_VECTOR));
    let other = attester.attest(&fixtures::canonical_payload("di-pos-hookdata"));

    // Circle's wire object, but with a messageHash lifted from a DIFFERENT payload — the exact
    // crossed-wire an unvalidated `&[u8]` + `[u8; 65]` request would have accepted silently.
    let object: AttestationObject = serde_json::from_value(serde_json::json!({
        "payload": signed.payload_hex(),
        "messageHash": other.message_hash_hex(),
        "attestation": signed.attestation_hex(),
    }))
    .expect("the object decodes");

    let err = ValidatedAttestation::validate(object)
        .expect_err("a messageHash that does not bind the payload must not validate");

    assert_matches!(&err, RelayerError::MessageHashMismatch { .. });
    assert_permanent(&err);
}

#[test]
fn the_builder_relays_exactly_the_bytes_the_binding_covered() {
    // No re-decode, no re-derivation: the payload the note carries and the signature the attachment
    // carries are the ones the binding check already covered, straight off the validated type.
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(16);

    assert_eq!(
        fx.request().deposit_intent(),
        fx.attestation.payload(),
        "the request relays the validated payload verbatim"
    );
    assert_eq!(
        fx.request().signature(),
        fx.attestation.attestation(),
        "the request relays the validated signature verbatim"
    );
    assert_eq!(
        built.note().recipient().storage().items().len(),
        fx.attestation.payload().len().div_ceil(4),
        "and the note's storage is that same payload, u32-LE packed"
    );
}
