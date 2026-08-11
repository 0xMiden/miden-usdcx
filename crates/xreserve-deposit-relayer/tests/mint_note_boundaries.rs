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
//! The reject payloads are the canonical golden-artifact vectors — the `di-rej-*` rows for the
//! structural parse and the `mi-rej-*` rows for the `DC-14` addressing and carriability checks —
//! consumed BY REFERENCE from the ONE artifact that drives the shared encoding crate's own MASM and
//! Rust suites, never a blob hand-rolled here (which would be a second, drifting definition of the
//! DepositIntent layout).
//!
//! Errors are asserted by EXACT variant AND by their preserved source chain: an operator must be
//! able to `downcast_ref` back to the shared encoding crate's `EncodingError` and read WHICH
//! structural rule the payload broke. A flattened string would have thrown that away.

mod fixtures;
mod mint_support;

use assert_matches::assert_matches;
use rstest::rstest;

use xreserve_deposit_relayer::miden::{build_mint_note, AttesterIndex};
use xreserve_deposit_relayer::RelayerError;
use xusdc_encoding::xreserve::encoding::{DepositIntentField, EncodingError};

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
fn t_a_payload_unit04_refuses_is_a_typed_build_error(
    #[case] vector_id: &str,
    #[case] expected: EncodingError,
) {
    assert_build_error(&validated_over_vector_id(vector_id), expected);
}

/// The hookData bound is the one structural reject that survives the PARSE: a payload can be a
/// well-formed, correctly-addressed DepositIntent and still carry more hookData than a
/// `NoteStorage` can hold. It therefore needs a `DC-14`-shaped payload — one that reaches the
/// bound instead of tripping an addressing check first.
#[test]
fn t_an_oversized_hookdata_is_a_typed_build_error() {
    let attestation = validated_over(&fixtures::oversized_hook_data_payload());

    assert_build_error(&attestation, EncodingError::HookDataTooLarge);
}

/// The addressing rejects `DC-14` added: an intent for another faucet, or one carrying a field
/// the mint transport cannot express, is refused HERE, with a name — never submitted to surface
/// on-chain as an unexplained bad signature.
#[rstest]
#[case::remote_token_mismatch("mi-rej-remote-token-mismatch")]
#[case::remote_token_malformed("mi-rej-remote-token-malformed")]
#[case::local_token_not_address("mi-rej-local-token-not-address")]
#[case::local_depositor_not_address("mi-rej-local-depositor-not-address")]
#[case::max_fee_over_cap("mi-rej-max-fee-over-cap")]
#[case::recipient_non_canonical("mi-rej-recipient-non-canonical")]
fn t_an_uncarryable_intent_is_a_typed_build_error(#[case] vector_id: &str) {
    let vector = fixtures::mi_vector(vector_id).expect("the canonical MI reject vector");
    let expected = vector
        .expected_variant
        .as_deref()
        .expect("a reject vector names the variant it must produce");
    let attestation = validated_over(&vector.payload());

    let error = build_mint_note(
        relayer_sender_id(),
        // the reject vectors are addressed to the artifact's own synthetic faucet, and each is a
        // reject for a reason OTHER than the faucet — so the build has to be told that faucet, or
        // it would fail on the addressing rather than on the row's subject
        vector.faucet_id(),
        &attestation,
        PARTNER_ATTESTER_INDEX,
        &mut note_rng(4),
    )
    .expect_err("an intent the mint transport cannot carry never becomes a note");

    assert_matches!(error, RelayerError::MintNoteBuild(_));
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

/// The shared assertion of the two reject tables above: a typed, non-retryable build error whose
/// source chain still carries the encoding crate's own verdict.
fn assert_build_error(
    attestation: &xreserve_deposit_relayer::circle::schema::ValidatedAttestation,
    expected: EncodingError,
) {
    let error = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        attestation,
        PARTNER_ATTESTER_INDEX,
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
#[case("mi-rej-remote-token-mismatch")]
#[case("mi-rej-max-fee-over-cap")]
fn t_the_reject_payloads_pass_the_envelope_boundary(#[case] vector_id: &str) {
    let payload = fixtures::mi_vector(vector_id)
        .map(|vector| vector.payload())
        .unwrap_or_else(|| fixtures::canonical_payload(vector_id));
    let attestation = validated_over(&payload);

    assert_eq!(
        attestation.deposit_intent().as_bytes(),
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
    // addressed to the private faucet, so the build gets past `DC-14`'s remoteToken check and
    // actually reaches the routing bind this test is about
    let attestation = validated_over(&fixtures::canonical_payload_addressed_to(
        fixtures::TEST_VECTOR_PAYLOAD_ID,
        private_faucet_id(),
    ));

    let error = build_mint_note(
        relayer_sender_id(),
        private_faucet_id(),
        &attestation,
        PARTNER_ATTESTER_INDEX,
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

// THE OPERATOR-CONFIGURED ATTESTER INDEX
// ================================================================================================
//
// The attester index is CONFIGURATION, not a Circle response field: Circle's attestation object
// carries `payload` / `messageHash` / `attestation` and nothing that says which attester signed.
// So the array position the administrator installed that attester's key at reaches the relayer
// from its operator — and an operator's typo must be caught where it is typed, not on the first
// mint attempt six hours later. Whether a key actually sits at that index is something only the
// faucet knows, so this is the whole of what the relayer can refuse.

#[rstest]
#[case::zero("0", 0)]
#[case::one("1", 1)]
#[case::max("4294967295", u32::MAX)]
fn t_the_attester_index_round_trips_through_the_config_form(
    #[case] text: &str,
    #[case] expected: u32,
) {
    assert_eq!(
        AttesterIndex::parse(text)
            .expect("a decimal u32 parses")
            .get(),
        expected
    );
}

#[rstest]
#[case::empty("")]
#[case::not_a_number("nothexatall")]
#[case::negative("-1")]
#[case::past_u32("4294967296")]
#[case::hex_form("0x01")]
fn t_an_attester_index_that_is_not_a_u32_is_refused(#[case] text: &str) {
    assert_matches!(
        AttesterIndex::parse(text),
        Err(RelayerError::MalformedAttesterIndex(_))
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
