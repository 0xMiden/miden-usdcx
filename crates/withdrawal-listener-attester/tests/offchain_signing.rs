//! Off-chain `k256` signing (`attester::sign`).
//!
//! **Opaque-and-sign; the digest's derivation stays OPEN with Circle.** The burn path signs
//! OFF-CHAIN: a single attester `k256`-ECDSA-signs Circle's `messageHashToSign`, which is consumed
//! as an OPAQUE 32-byte digest — no local re-hashing, no EIP-712 re-derivation. There is NO
//! on-chain Miden typed-data hashing on the burn path.
//!
//! The gating check is that the produced signature VERIFIES against the supplied attester pubkey —
//! not merely that it is 65 bytes long. Every negative is exact-variant (`assert_matches!`), never
//! `is_err()`.
//!
//! Single-key signing is a non-gating local primitive / unit-test only — NEVER submitted to Circle;
//! the assembly gate  is what a `/v1/withdraw` submission must clear.

use assert_matches::assert_matches;
use k256::ecdsa::{RecoveryId, Signature as K256Signature};
use rstest::rstest;

use withdrawal_listener_attester::attester::{
    evm_v_from_recovery_id, sign, Signature65, EVM_V_OFFSET, SIGNATURE_LEN,
};
use withdrawal_listener_attester::error::{SignError, SignatureError};

#[path = "attester_vectors/mod.rs"]
mod attester_vectors;
use attester_vectors::{attesters, recover, verify, MESSAGE_HASH_TO_SIGN, OTHER_MESSAGE_HASH};

/// A signature over Circle's opaque digest is exactly 65 bytes `r‖s‖v`, and VERIFIES against the
/// signer's pubkey — the non-vacuity oracle: the bytes actually cover the digest, they are not
/// just the right length.
#[test]
fn sign_produces_65_bytes_that_verify_against_the_pubkey() {
    let attester = &attesters()[0];
    let sig = sign(&MESSAGE_HASH_TO_SIGN, attester.secret()).expect("sign a 32-byte digest");

    assert_eq!(sig.as_bytes().len(), SIGNATURE_LEN, "65-byte r‖s‖v");
    assert!(
        verify(&attester.pubkey_compressed(), &MESSAGE_HASH_TO_SIGN, &sig),
        "the produced signature must VERIFY against the supplied pubkey"
    );
}

/// The signature covers the EXACT opaque digest, signed as-is: recovering the pubkey from the
/// digest and `r‖s‖v` yields the signer's own pubkey. This forecloses any local re-hashing of the
/// input (a signature over `keccak(digest)`, or an EIP-712 re-derivation, would recover a different
/// signer or fail to recover), and proves `v` is the true EVM recovery byte.
#[test]
fn sign_signs_the_digest_opaquely_recoverable_to_the_signer() {
    let attester = &attesters()[0];
    let sig = sign(&MESSAGE_HASH_TO_SIGN, attester.secret()).expect("sign");

    assert_eq!(
        recover(&MESSAGE_HASH_TO_SIGN, &sig),
        Some(attester.pubkey_compressed()),
        "the signature must recover to the signer over the opaque digest as-is"
    );
}

/// A signature over one digest does NOT verify against a DIFFERENT digest — the wrong-hash
/// negative: the listener must not treat a signature over the wrong message as valid.
#[test]
fn signature_over_one_hash_does_not_verify_against_another() {
    let attester = &attesters()[0];
    let sig = sign(&MESSAGE_HASH_TO_SIGN, attester.secret()).expect("sign");

    assert!(
        !verify(&attester.pubkey_compressed(), &OTHER_MESSAGE_HASH, &sig),
        "a signature over MESSAGE_HASH_TO_SIGN must fail verification against OTHER_MESSAGE_HASH"
    );
}

/// A signature does NOT verify under a DIFFERENT signer's pubkey — pins that `sign` used the secret
/// it was handed (guards a fixture that reports the wrong pubkey).
#[test]
fn signature_does_not_verify_under_a_foreign_pubkey() {
    let all = attesters();
    let sig = sign(&MESSAGE_HASH_TO_SIGN, all[0].secret()).expect("sign");

    assert!(
        !verify(&all[1].pubkey_compressed(), &MESSAGE_HASH_TO_SIGN, &sig),
        "signer 0's signature must not verify under signer 1's pubkey"
    );
}

/// A digest that is not exactly 32 bytes → `Err(SignError::DigestLength { actual })`, exact
/// variant. `sign` treats the digest opaquely and refuses to hash/pad/truncate it into shape.
#[rstest]
#[case::empty(0)]
#[case::one_short(31)]
#[case::one_long(33)]
#[case::double(64)]
fn non_32_byte_digest_is_rejected(#[case] len: usize) {
    let attester = &attesters()[0];
    let digest = vec![0x42u8; len];

    assert_matches!(
        sign(&digest, attester.secret()),
        Err(SignError::DigestLength { actual }) if actual == len
    );
}

/// secp256k1 signing here is RFC 6979 deterministic: signing the same digest with the same key
/// twice yields byte-identical signatures (deterministic test vectors, Circle's documentation).
#[test]
fn signing_is_deterministic() {
    let attester = &attesters()[0];
    let a = sign(&MESSAGE_HASH_TO_SIGN, attester.secret()).expect("sign");
    let b = sign(&MESSAGE_HASH_TO_SIGN, attester.secret()).expect("sign");

    assert_eq!(a, b, "RFC-6979 deterministic signing");
    assert!(verify(
        &attester.pubkey_compressed(),
        &MESSAGE_HASH_TO_SIGN,
        &a
    ));
}

/// Distinct signers produce distinct signatures over the same digest (a signature binds the key).
#[test]
fn distinct_signers_produce_distinct_signatures() {
    let all = attesters();
    let s0 = sign(&MESSAGE_HASH_TO_SIGN, all[0].secret()).expect("sign");
    let s1 = sign(&MESSAGE_HASH_TO_SIGN, all[1].secret()).expect("sign");

    assert_ne!(s0, s1);
}

/// `v` is the **EVM** recovery byte `27`/`28` (`EVM_V_OFFSET + recid`), NOT k256's raw `0`/`1` —
/// what OpenZeppelin-style `ECDSA.recover` on Circle's source chain requires
/// (`CIRCLE-DATA-SCHEMAS.md:46`,`:196`). A raw `0`/`1` would be rejected at the fund-release
/// boundary even though the local k256 oracle accepts it.
#[test]
fn signature_v_is_evm_27_or_28() {
    assert_eq!(EVM_V_OFFSET, 27);
    for attester in &attesters() {
        let sig = sign(&MESSAGE_HASH_TO_SIGN, attester.secret()).expect("sign");
        assert!(
            sig.v() == 27 || sig.v() == 28,
            "EVM v must be 27 or 28, got {}",
            sig.v()
        );
    }
}

/// The recovery-id → EVM `v` mapping (the single source of truth [`sign`] uses): the non-x-reduced
/// ids `0`/`1` map to `27`/`28`, and the **x-reduced ids `2`/`3` map to `None`** — so `sign`
/// refuses to emit a `v = 29`/`30` the source-chain verifier would reject. This tests the sign-side
/// guard's logic directly (an x-reduced recovery id cannot be produced deterministically from a
/// real signing call, ~2^-128, so the mapping is the testable boundary).
#[rstest]
#[case(0, Some(27))]
#[case(1, Some(28))]
#[case(2, None)]
#[case(3, None)]
fn evm_v_mapping_rejects_x_reduced_recovery_ids(
    #[case] recid_byte: u8,
    #[case] expected: Option<u8>,
) {
    let recovery_id = RecoveryId::from_byte(recid_byte).expect("0..=3 is a valid recovery id");
    assert_eq!(evm_v_from_recovery_id(recovery_id), expected);
}

/// The signature is low-`s`-normalized — the malleability form the same OpenZeppelin
/// `ECDSA.recover` verifier requires (it rejects an `s` in the upper half of the curve order). k256
/// normalizes on signing; this pins that a produced signature would not be rejected as malleable.
#[test]
fn signature_is_low_s_normalized() {
    for attester in &attesters() {
        let sig = sign(&MESSAGE_HASH_TO_SIGN, attester.secret()).expect("sign");
        let parsed = K256Signature::from_slice(&sig.as_bytes()[..64]).expect("valid r‖s");
        assert!(
            parsed.normalize_s().is_none(),
            "signature must already be low-s (EVM malleability guard)"
        );
    }
}

/// The 65-byte wire form decomposes as `r‖s‖v` and renders as the OpenAPI `^0x[a-fA-F0-9]*$` hex.
#[test]
fn signature_wire_form_is_r_s_v_hex() {
    let attester = &attesters()[0];
    let sig = sign(&MESSAGE_HASH_TO_SIGN, attester.secret()).expect("sign");

    let bytes = sig.as_bytes();
    assert_eq!(&sig.r()[..], &bytes[..32]);
    assert_eq!(&sig.s()[..], &bytes[32..64]);
    assert_eq!(sig.v(), bytes[64]);

    let hex = sig.to_hex();
    assert_eq!(hex.len(), 2 + 2 * SIGNATURE_LEN, "0x + 130 hex digits");
    let body = hex.strip_prefix("0x").expect("0x prefix");
    assert!(body.chars().all(|c| c.is_ascii_hexdigit()));
}

/// `Signature65::from_bytes` accepts exactly 65 bytes and round-trips them; a
/// DER/64-byte/other-length blob is refused with the exact `SignatureError::Length` variant (the
/// "non-65-byte / DER form" foreclosure).
#[rstest]
#[case::empty(0)]
#[case::r_s_only(64)]
#[case::der_ish(70)]
#[case::one_long(66)]
fn signature65_rejects_non_65_byte_forms(#[case] len: usize) {
    let bytes = vec![0x11u8; len];
    assert_matches!(
        Signature65::from_bytes(&bytes),
        Err(SignatureError::Length { actual }) if actual == len
    );
}

#[test]
fn signature65_from_bytes_round_trips_exactly_65() {
    let raw = [0x7fu8; SIGNATURE_LEN];
    let sig = Signature65::from_bytes(&raw).expect("exactly 65 bytes");
    assert_eq!(sig.as_bytes(), &raw);
}
