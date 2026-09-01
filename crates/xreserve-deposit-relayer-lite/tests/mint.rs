//! Note building: valid deposits build, malformed ones are skipped — never fatal — and malformed
//! identities are refused at startup.

mod fixtures;

use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::{Felt, Word};
use rstest::rstest;

use fixtures::{
    attestation, attestation_for, intent_with, other_faucet_id, test_config,
    undecodable_attestation, TEST_REMOTE_DOMAIN,
};
use xreserve_deposit_relayer_lite::mint::{build_notes, Identities};

fn rng() -> RandomCoin {
    RandomCoin::new(Word::from([Felt::from(7u32); 4]))
}

fn identities() -> Identities {
    Identities::from_config(&test_config()).expect("the fixture config is valid")
}

/// Every valid attestation on a page becomes a note.
#[test]
fn valid_attestations_build_notes() {
    let notes = build_notes(
        &identities(),
        TEST_REMOTE_DOMAIN,
        &[attestation(1), attestation(2)],
        &mut rng(),
    );
    assert_eq!(notes.len(), 2);
}

/// A malformed attestation is skipped while the valid attestations in the page still build.
#[test]
fn a_malformed_attestation_is_skipped_not_fatal() {
    let notes = build_notes(
        &identities(),
        TEST_REMOTE_DOMAIN,
        &[attestation(1), undecodable_attestation(), attestation(3)],
        &mut rng(),
    );
    assert_eq!(notes.len(), 2, "the two good deposits still build");
}

/// A deposit addressed to another faucet is skipped while the rest of the page still builds.
#[test]
fn a_deposit_for_another_faucet_is_skipped() {
    let elsewhere = attestation_for(&intent_with([9; 32], other_faucet_id()));
    let notes = build_notes(
        &identities(),
        TEST_REMOTE_DOMAIN,
        &[elsewhere, attestation(2)],
        &mut rng(),
    );
    assert_eq!(notes.len(), 1);
}

/// Rebuilding the same deposit twice yields distinct notes because each receives a new serial
/// number from the random number generator.
#[test]
fn a_rebuilt_deposit_is_a_distinct_note() {
    let identities = identities();
    let mut rng = rng();
    let first = build_notes(&identities, TEST_REMOTE_DOMAIN, &[attestation(1)], &mut rng);
    let second = build_notes(&identities, TEST_REMOTE_DOMAIN, &[attestation(1)], &mut rng);
    assert_ne!(first[0].id(), second[0].id());
}

/// A malformed attester key is rejected during startup.
#[rstest]
#[case::not_hex("nothex")]
#[case::wrong_length("0xdeadbeef")]
#[case::not_a_point("03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
fn a_malformed_attester_key_is_refused_at_startup(#[case] value: &str) {
    let mut config = test_config();
    config.attester_public_key = value.to_string();

    let error = format!("{:#}", Identities::from_config(&config).unwrap_err());
    assert!(
        error.contains("attester public key"),
        "unexpected error: {error}"
    );
}
