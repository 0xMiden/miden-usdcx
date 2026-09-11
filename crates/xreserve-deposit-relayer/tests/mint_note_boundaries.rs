//! Checks mint-note rejection of malformed or unsupported deposit intents.
//! Uses the shared golden vectors and checks both error variants and their source errors.

mod fixtures;
mod mint_support;

use assert_matches::assert_matches;
use rstest::rstest;

use miden_protocol::crypto::utils::DeserializationError;
use xreserve_deposit_relayer::error::HexField;
use xreserve_deposit_relayer::miden::{build_mint_note, AttesterPubkey};
use xreserve_deposit_relayer::RelayerError;
use xusdc_encoding::xreserve::encoding::{DepositIntentField, EncodingError};

use fixtures::{PartnerAttester, PARTNER_PUBKEY_HEX};
use mint_support::*;
use xusdc_encoding::xreserve::encoding::DepositIntent;

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
fn t_a_payload_unit04_refuses_is_a_typed_decode_error(
    #[case] vector_id: &str,
    #[case] expected: EncodingError,
) {
    assert_decode_error(&validated_over_vector_id(vector_id), expected);
}

/// Use a correctly addressed payload so the builder reaches the hook-data limit.
#[test]
fn t_an_oversized_hookdata_is_a_typed_decode_error() {
    let attestation = validated_over(&fixtures::oversized_hook_data_payload());

    assert_decode_error(&attestation, EncodingError::HookDataTooLarge);
}

/// Malformed fields fail during decoding. A well-formed intent for another faucet fails
/// when the note builder compares its target.
#[rstest]
#[case::remote_token_mismatch("mi-rej-remote-token-mismatch", Step::Build)]
#[case::remote_token_malformed("mi-rej-remote-token-malformed", Step::Decode)]
#[case::max_fee_over_cap("mi-rej-max-fee-over-cap", Step::Decode)]
#[case::recipient_non_canonical("mi-rej-recipient-non-canonical", Step::Decode)]
fn t_an_uncarryable_intent_is_a_typed_build_error(#[case] vector_id: &str, #[case] step: Step) {
    let vector = fixtures::mi_vector(vector_id).expect("the canonical MI reject vector");
    let expected = vector
        .expected_variant
        .as_deref()
        .expect("a reject vector names the variant it must produce");
    let attestation = validated_over(&vector.payload());

    let decoded =
        DepositIntent::try_from(attestation.payload()).map_err(RelayerError::from_deposit_intent);
    let error = match step {
        Step::Decode => decoded.expect_err("the decode owns this row's rejection"),
        Step::Build => {
            let intent =
                decoded.expect("an addressing reject is still a well-formed deposit intent");
            build_mint_note(
                relayer_sender_id(),
                // the reject vectors are addressed to the artifact's own synthetic faucet, and each
                // is a reject for a reason OTHER than the faucet — so the build has to be told that
                // faucet, or it would fail on the addressing rather than on the row's subject
                vector.faucet_id(),
                vector.remote_domain,
                intent,
                attestation.attestation(),
                &attester_pubkey(),
                &mut note_rng(4),
            )
            .expect_err("an intent the mint transport cannot carry never becomes a note")
        }
    };

    if matches!(step, Step::Build) {
        assert_matches!(error, RelayerError::MintNoteBuild(_));
    }
    // the artifact names the variant, not the field it carries, so the comparison is on the name
    let verdict = format!(
        "{:?}",
        encoding_error_in_chain(&error).expect("a typed verdict")
    );
    assert_eq!(
        verdict.split_whitespace().next(),
        Some(expected),
        "unit-04's exact verdict survives in the source chain"
    );
    assert!(
        !error.is_retryable(),
        "an uncarryable intent stays uncarryable"
    );
}

/// Which step of the relayer's path owns a reject row's verdict.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// The shared codec's decode — everything that is a property of the payload alone.
    Decode,
    /// The mint-note build — the compare against the faucet the note is built for.
    Build,
}

/// The shared assertion of the structural reject table: a typed, non-retryable decode error whose
/// source chain still carries the encoding crate's own verdict.
fn assert_decode_error(
    attestation: &xreserve_deposit_relayer::circle::schema::ValidatedAttestation,
    expected: EncodingError,
) {
    let error = DepositIntent::try_from(attestation.payload())
        .map_err(RelayerError::from_deposit_intent)
        .expect_err("a structurally invalid deposit intent cannot become a note");

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
#[case("mi-rej-remote-token-mismatch")]
#[case("mi-rej-max-fee-over-cap")]
fn t_the_reject_payloads_pass_the_envelope_boundary(#[case] vector_id: &str) {
    let payload = fixtures::mi_vector(vector_id)
        .map(|vector| vector.payload())
        .unwrap_or_else(|| fixtures::canonical_payload(vector_id));
    let attestation = validated_over(&payload);

    assert_eq!(
        attestation.payload(),
        payload.as_slice(),
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
    // Match the intent target so the test reaches the private-account routing check.
    let attestation = validated_over(&fixtures::canonical_payload_addressed_to(
        fixtures::TEST_VECTOR_PAYLOAD_ID,
        private_faucet_id(),
    ));

    let intent = DepositIntent::try_from(attestation.payload())
        .map_err(RelayerError::from_deposit_intent)
        .expect("the payload is a well-formed deposit intent");
    let error = build_mint_note(
        relayer_sender_id(),
        private_faucet_id(),
        fixtures::TEST_REMOTE_DOMAIN,
        intent,
        attestation.attestation(),
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
    let expected = AttesterPubkey::new(PartnerAttester::new().pubkey())
        .expect("the partner key is a curve point");

    assert_eq!(
        AttesterPubkey::from_hex(PARTNER_PUBKEY_HEX).expect("the pinned partner key parses"),
        expected
    );
    assert_eq!(
        AttesterPubkey::from_hex(&format!("0x{PARTNER_PUBKEY_HEX}"))
            .expect("the 0x-prefixed wire form parses too"),
        expected,
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
/// protocol's own SEC1 decompression (consumed by reference — the relayer does not re-implement
/// point decompression). Such a key could never verify on-chain, so a relayer that started with it
/// would mint nothing and say nothing.
#[rstest]
#[case::off_curve("03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
#[case::bad_prefix("00a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3f")]
fn t_an_attester_key_that_is_not_a_curve_point_is_refused(#[case] hex: &str) {
    let error = AttesterPubkey::from_hex(hex).expect_err("not a secp256k1 point");

    assert_matches!(error, RelayerError::InvalidAttesterPubkey(_));
    assert_matches!(
        deserialization_error_in_chain(&error),
        Some(DeserializationError::InvalidValue(_)),
        "the protocol's verdict on the key is preserved"
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
    error_in_chain(error)
}

/// The same walk for the protocol's own decode verdict — the attester key never reaches the
/// encoding crate, so its rejection arrives as a `DeserializationError`.
fn deserialization_error_in_chain(error: &RelayerError) -> Option<DeserializationError> {
    error_in_chain(error)
}

/// Walks a `RelayerError`'s source chain looking for a preserved error of one concrete type.
fn error_in_chain<E: std::error::Error + Clone + 'static>(error: &RelayerError) -> Option<E> {
    let mut source = std::error::Error::source(error);
    while let Some(err) = source {
        if let Some(found) = err.downcast_ref::<E>() {
            return Some(found.clone());
        }
        source = err.source();
    }
    None
}
