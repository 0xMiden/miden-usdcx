//! The mint-note builder — the FAIL-CLOSED boundary: every input the builder can be handed that
//! the shared encoding crate's factory refuses, and the operator-configured attester key.
//!
//! Why these paths are real, not hypothetical: the relayer's envelope validation
//! ([`ValidatedAttestation`]) binds `messageHash == keccak256(payload)` and shape-checks the
//! 65-byte signature — it does NOT parse the DepositIntent. So a payload Circle really signed,
//! whose digest really binds it, can still be structurally invalid (bad magic, a zero amount,
//! hookData past the 1024-felt NoteStorage bound). Those reach the builder, and the builder must
//! surface them as a typed, NON-retryable error — never as a panic, never as a malformed note, and
//! never as an infinite retry loop that wedges the relayer on one bad attestation.
//!
//! The reject payloads are the canonical golden-artifact vectors (`di-rej-*`), consumed BY
//! REFERENCE from the ONE artifact that drives the shared encoding crate's own MASM and Rust suites
//! — never a blob hand-rolled here (which would be a second, drifting definition of the
//! DepositIntent layout).
//!
//! Errors are asserted by EXACT variant AND by their preserved source chain: an operator must be
//! able to `downcast_ref` back to the shared encoding crate's `EncodingError` and read WHICH
//! structural rule the payload broke. A flattened string would have thrown that away.

mod fixtures;
mod mint_support;

use assert_matches::assert_matches;
use rstest::rstest;

use xreserve_deposit_relayer::error::HexField;
use xreserve_deposit_relayer::miden::{build_mint_note, AttesterPubkey};
use xreserve_deposit_relayer::RelayerError;
use xusdc_encoding::xreserve::encoding::{DepositIntentField, EncodingError};

use fixtures::{PartnerAttester, PARTNER_PUBKEY_HEX};
use mint_support::*;

// STRUCTURALLY-INVALID DEPOSITINTENTS (they pass the envelope; the shared encoding crate's codec
// refuses them)
// ================================================================================================

#[rstest]
#[case::bad_magic("di-rej-bad-magic", EncodingError::BadMagic)]
#[case::bad_version("di-rej-bad-version", EncodingError::BadVersion)]
#[case::zero_amount("di-rej-zero-amount", EncodingError::ZeroField { field: DepositIntentField::Amount })]
#[case::zero_local_token("di-rej-zero-local-token", EncodingError::ZeroField { field: DepositIntentField::LocalToken })]
#[case::zero_local_depositor("di-rej-zero-local-depositor", EncodingError::ZeroField { field: DepositIntentField::LocalDepositor })]
#[case::length_mismatch("di-rej-length-mismatch", EncodingError::LengthMismatch)]
#[case::truncated_header("di-rej-truncated", EncodingError::TruncatedHeader)]
#[case::hookdata_overflow("di-rej-hookdata-overflow", EncodingError::HookDataTooLarge)]
fn t_a_payload_unit04_refuses_is_a_typed_build_error(
    #[case] vector_id: &str,
    #[case] expected: EncodingError,
) {
    let attestation = validated_over_vector_id(vector_id);

    let error = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &attestation,
        &attester_pubkey(),
        &mut note_rng(1),
    )
    .expect_err("a structurally invalid deposit intent cannot become a note");

    assert_matches!(error, RelayerError::MintNoteBuild(_));
    assert_eq!(
        encoding_error_in_chain(&error).as_ref(),
        Some(&expected),
        "unit-04's exact structural verdict survives in the source chain"
    );
    assert!(
        !error.is_retryable(),
        "a malformed deposit intent never becomes well-formed — retrying it forever would wedge \
         the relayer on one bad attestation"
    );
}

/// The envelope layer really did accept these payloads — otherwise the test above would be proving
/// nothing about the BUILDER (it would be re-proving envelope validation). This is the non-vacuity
/// guard for the whole reject table.
#[rstest]
#[case("di-rej-bad-magic")]
#[case("di-rej-truncated")]
#[case("di-rej-hookdata-overflow")]
fn t_the_reject_payloads_pass_the_envelope_boundary(#[case] vector_id: &str) {
    let attestation = validated_over_vector_id(vector_id);

    assert_eq!(
        attestation.payload(),
        fixtures::canonical_payload(vector_id).as_slice(),
        "the validated boundary carries the payload verbatim — the builder's input really is this"
    );
    assert_eq!(attestation.attestation().len(), 65);
}

// THE FAUCET ARGUMENT
// ================================================================================================

/// A PRIVATE faucet id cannot carry the scheme-2 routing bind (a network transaction cannot be
/// routed at an account whose state is not public), so the shared encoding crate's factory refuses
/// it — and the relayer surfaces that refusal rather than emitting a note no network transaction
/// would ever pick up.
#[test]
fn t_a_private_faucet_id_is_refused() {
    let error = build_mint_note(
        relayer_sender_id(),
        private_faucet_id(),
        &validated_test_vector(),
        &attester_pubkey(),
        &mut note_rng(2),
    )
    .expect_err("a private faucet cannot be a network mint target");

    assert_matches!(error, RelayerError::MintNoteBuild(_));
    assert!(
        std::error::Error::source(&error).is_some(),
        "the protocol's own refusal is preserved as the source"
    );
    assert!(
        !error.is_retryable(),
        "a misconfigured faucet id is permanent"
    );
}

// THE OPERATOR-CONFIGURED ATTESTER KEY
// ================================================================================================
//
// The attester pubkey is CONFIGURATION, not a Circle response field: Circle's attestation object
// carries `payload` / `messageHash` / `attestation` and nothing else. So the 33-byte key the
// faucet's allowlist commitment is derived from reaches the relayer from its operator — and an operator's typo must be caught
// where it is typed, not on the first mint attempt six hours later.

#[test]
fn t_the_partner_key_round_trips_through_the_config_form() {
    let expected = PartnerAttester::new().pubkey();

    assert_eq!(
        AttesterPubkey::from_hex(PARTNER_PUBKEY_HEX)
            .expect("the pinned partner key parses")
            .as_bytes(),
        &expected
    );
    assert_eq!(
        AttesterPubkey::from_hex(&format!("0x{PARTNER_PUBKEY_HEX}"))
            .expect("the 0x-prefixed wire form parses too")
            .as_bytes(),
        &expected,
        "an operator may paste the key with or without the 0x prefix"
    );
}

#[test]
fn t_a_non_hex_attester_key_is_refused() {
    assert_matches!(
        AttesterPubkey::from_hex("nothexatall"),
        Err(RelayerError::MalformedHex {
            field: HexField::AttesterPubkey,
            ..
        })
    );
}

#[rstest]
#[case::empty("")]
#[case::too_short("03a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d")] // 32 bytes
#[case::uncompressed_length(
    "04a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3fa13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3f"
)] // 65 bytes — the UNCOMPRESSED SEC1 form, not the form the allowlist commitment is derived from
fn t_an_attester_key_of_the_wrong_length_is_refused(#[case] hex: &str) {
    let error = AttesterPubkey::from_hex(hex).expect_err("only a 33-byte compressed key is a key");

    assert_matches!(
        error,
        RelayerError::BadAttesterPubkeyLength { actual } if actual == hex.len() / 2
    );
}

/// 33 bytes of the right SHAPE that are not a curve point: refused at CONFIGURATION time, by the
/// shared encoding crate's own SEC1 decompression (the same primitive that packs the affine felts,
/// consumed by reference — the relayer does not re-implement point decompression). Such a key could
/// never verify on-chain, so a relayer that started with it would mint nothing and say nothing.
#[rstest]
#[case::off_curve("03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
#[case::bad_prefix("00a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3f")]
fn t_an_attester_key_that_is_not_a_curve_point_is_refused(#[case] hex: &str) {
    let error = AttesterPubkey::from_hex(hex).expect_err("not a secp256k1 point");

    assert_matches!(error, RelayerError::InvalidAttesterPubkey(_));
    assert_eq!(
        encoding_error_in_chain(&error),
        Some(EncodingError::InvalidPubkey),
        "unit-04's verdict on the key is preserved"
    );

    // …and the same 33 bytes are refused through the raw constructor, not just the hex one
    let raw: [u8; 33] = hex::decode(hex).expect("hex").try_into().expect("33 bytes");
    assert_matches!(
        AttesterPubkey::new(raw),
        Err(RelayerError::InvalidAttesterPubkey(_))
    );
}

// helpers
// ================================================================================================

/// Walks a `RelayerError`'s source chain looking for the shared encoding crate's `EncodingError` —
/// the assertion that the codec's exact verdict was PRESERVED (not flattened into a message).
fn encoding_error_in_chain(error: &RelayerError) -> Option<EncodingError> {
    let mut source = std::error::Error::source(error);
    while let Some(err) = source {
        if let Some(encoding) = err.downcast_ref::<EncodingError>() {
            return Some(encoding.clone());
        }
        source = err.source();
    }
    None
}
