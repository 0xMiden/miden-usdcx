//! Quorum assembly (`attester::assemble_quorum`).
//!
//! The `burnSignatures[]` bundle Circle verifies on the source chain must be **exactly-threshold
//! count (`MIN_SIGNATURE_THRESHOLD = 2`), every signature verifying to its claimed signer,
//! ascending signer-address order, no duplicates** (`CIRCLE-DATA-SCHEMAS.md:196`; the
//! recover-then-authorize step at `:46`). This assembler enforces that contract off-chain, BEFORE
//! submit.
//!
//! These tests drive the assembler with REAL signatures (produced by `attester::sign`) paired with
//! the addresses they actually recover to — never synthetic address/signature bytes — so the
//! verify-against-claimed-signer rule is exercised for real. Every negative is exact-variant
//! (`assert_matches!`). Ordering and uniqueness are over the 20-byte signer ADDRESS.
//!
//! Single-key signing is a non-gating local primitive / unit-test only and is NEVER submitted; the
//! below-threshold negative is exactly the `/v1/withdraw` gate refusing a single-key set.

use assert_matches::assert_matches;
use rstest::rstest;

use withdrawal_listener_attester::attester::{
    assemble_quorum, recover_address, Address, Signature65, MIN_SIGNATURE_THRESHOLD,
};
use withdrawal_listener_attester::error::QuorumError;

#[path = "attester_vectors/mod.rs"]
mod attester_vectors;
use attester_vectors::{attesters, verify, x_reduced_pair, TestAttester, MESSAGE_HASH_TO_SIGN};

/// The `n` canonical attesters, sorted ascending by their (recovered) signer address — the order a
/// caller must present to Circle. Distinct keys give distinct addresses.
fn attesters_by_address(n: usize) -> Vec<TestAttester> {
    let mut all = attesters();
    all.sort_by_key(|a| *a.address().as_bytes());
    all.truncate(n);
    all
}

/// `n` valid `(claimed address, signature)` pairs over the digest, in ascending address order.
fn ascending_pairs(n: usize) -> Vec<(Address, Signature65)> {
    attesters_by_address(n)
        .iter()
        .map(|a| a.signed_pair(&MESSAGE_HASH_TO_SIGN))
        .collect()
}

// POSITIVE
// ================================================================================================

/// Exactly the threshold (2), ascending distinct addresses, each signature verifying to its claimed
/// signer → `Ok`, order and content preserved, and each returned signature still VERIFIES.
#[test]
fn assembles_exactly_two_ascending_verifying_signatures() {
    let signers = attesters_by_address(2);
    assert!(
        signers[0].address() < signers[1].address(),
        "distinct ascending addresses"
    );
    let pairs = vec![
        signers[0].signed_pair(&MESSAGE_HASH_TO_SIGN),
        signers[1].signed_pair(&MESSAGE_HASH_TO_SIGN),
    ];
    let expected: Vec<Signature65> = pairs.iter().map(|(_, s)| *s).collect();

    let bundle = assemble_quorum(&MESSAGE_HASH_TO_SIGN, pairs).expect("a valid 2-of-n quorum");

    assert_eq!(
        bundle.signatures(),
        expected.as_slice(),
        "signatures carried in address order"
    );
    assert_eq!(bundle.len(), MIN_SIGNATURE_THRESHOLD);
    assert!(!bundle.is_empty());
    assert!(verify(
        &signers[0].pubkey_compressed(),
        &MESSAGE_HASH_TO_SIGN,
        &bundle.signatures()[0]
    ));
    assert!(verify(
        &signers[1].pubkey_compressed(),
        &MESSAGE_HASH_TO_SIGN,
        &bundle.signatures()[1]
    ));
    for s in bundle.signatures() {
        assert!(s
            .to_hex()
            .strip_prefix("0x")
            .unwrap()
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }
}

/// Assembling the same signer set twice yields the same ordered bundle (deterministic).
#[test]
fn assembly_is_deterministic() {
    assert_eq!(
        assemble_quorum(&MESSAGE_HASH_TO_SIGN, ascending_pairs(2)),
        assemble_quorum(&MESSAGE_HASH_TO_SIGN, ascending_pairs(2))
    );
}

// NEGATIVE — exact variants
// ================================================================================================

/// Below threshold: a single-key set → `Err(BelowThreshold)`. Forecloses "threshold treated as ≥1".
#[test]
fn one_signature_is_below_threshold() {
    assert_matches!(
        assemble_quorum(&MESSAGE_HASH_TO_SIGN, ascending_pairs(1)),
        Err(QuorumError::BelowThreshold { have: 1, need: 2 })
    );
}

#[test]
fn zero_signatures_is_below_threshold() {
    assert_matches!(
        assemble_quorum(&MESSAGE_HASH_TO_SIGN, vec![]),
        Err(QuorumError::BelowThreshold { have: 0, need: 2 })
    );
}

/// Above threshold: three valid signatures → `Err(AboveThreshold)`. Circle's verifier is
/// exactly-threshold, so an over-threshold bundle is refused here rather than at the fund-release
/// boundary — this assembler does NOT silently truncate to two.
#[test]
fn three_signatures_are_above_threshold() {
    assert_matches!(
        assemble_quorum(&MESSAGE_HASH_TO_SIGN, ascending_pairs(3)),
        Err(QuorumError::AboveThreshold { have: 3, need: 2 })
    );
}

/// Descending address order (two VALID pairs fed high→low) → `Err(NotAscending)` at the dip. Both
/// signatures verify, so the ordering check is genuinely reached.
#[test]
fn descending_addresses_are_rejected() {
    let signers = attesters_by_address(2);
    let pairs = vec![
        signers[1].signed_pair(&MESSAGE_HASH_TO_SIGN),
        signers[0].signed_pair(&MESSAGE_HASH_TO_SIGN),
    ];
    assert_matches!(
        assemble_quorum(&MESSAGE_HASH_TO_SIGN, pairs),
        Err(QuorumError::NotAscending { at: 1 })
    );
}

/// A duplicate signer (the same attester twice, hence the same address and — signing being
/// deterministic — the same signature) → `Err(DuplicateSigner)`, NOT a silent dedupe. Both entries
/// verify, so the duplicate check is genuinely reached.
#[test]
fn duplicate_signer_is_rejected() {
    let a = &attesters_by_address(1)[0];
    let pairs = vec![
        a.signed_pair(&MESSAGE_HASH_TO_SIGN),
        a.signed_pair(&MESSAGE_HASH_TO_SIGN),
    ];
    assert_matches!(
        assemble_quorum(&MESSAGE_HASH_TO_SIGN, pairs),
        Err(QuorumError::DuplicateSigner { address }) if address == a.address()
    );
}

// VERIFY-AGAINST-CLAIMED-SIGNER — the fund-safety core
// ================================================================================================

/// A signature paired with the WRONG signer address (signer B's signature attributed to signer A's
/// address) is excluded with `Err(SignatureDoesNotVerify)` — the `ECDSA.recover`-then-authorize
/// rule (`TEST-AND-VERIFICATION-HARNESS.md:157`). The check runs before ordering/duplicate, so the
/// exact index is reported.
#[test]
fn signature_not_from_claimed_signer_is_rejected() {
    let all = attesters();
    // Index 0: signer A's address, but signer B's signature — a forged attribution.
    let forged = (
        all[0].address(),
        all[1].signed_pair(&MESSAGE_HASH_TO_SIGN).1,
    );
    let valid = all[2].signed_pair(&MESSAGE_HASH_TO_SIGN);

    assert_matches!(
        assemble_quorum(&MESSAGE_HASH_TO_SIGN, vec![forged, valid]),
        Err(QuorumError::SignatureDoesNotVerify { at: 0 })
    );
}

/// A signature carrying any non-EVM recovery byte (a real signature with `v` retagged to a value
/// outside `27`/`28`) does not verify against its claimed signer → `Err(SignatureDoesNotVerify)`.
/// Covers the raw k256 ids `0`/`1`, the x-reduced wire values `29`/`30`, and out-of-band bytes.
/// This ties the `v` range to the quorum gate: a signature Circle would reject is refused
/// off-chain.
#[rstest]
#[case::raw_zero(0)]
#[case::raw_one(1)]
#[case::just_below(26)]
#[case::x_reduced_29(29)]
#[case::x_reduced_30(30)]
#[case::just_above(31)]
#[case::max(255)]
fn signature_with_non_evm_v_does_not_verify(#[case] bad_v: u8) {
    let a = &attesters()[0];
    let (addr, good) = a.signed_pair(&MESSAGE_HASH_TO_SIGN);
    let mut bytes = *good.as_bytes();
    bytes[64] = bad_v;
    let tampered = Signature65::from_bytes(&bytes).expect("65 bytes");
    let valid = attesters()[1].signed_pair(&MESSAGE_HASH_TO_SIGN);

    assert_matches!(
        assemble_quorum(&MESSAGE_HASH_TO_SIGN, vec![(addr, tampered), valid]),
        Err(QuorumError::SignatureDoesNotVerify { at: 0 })
    );
}

/// The discriminating v=29/30 case: a crafted signature whose x-reduced recovery id (`2`/`3`, wire
/// `v = 29`/`30`) a RANGE-UNCHECKED recovery WOULD accept — paired with the very address that
/// recovery yields. A correct `recover_address` rejects it on the `v` range alone (never
/// recovering), so it is refused; the pre-fix `v - 27 → RecoveryId::from_byte` path would have
/// blessed it. This is the exact gap the auditor's scratch probe exercised (`accepted v=29/30,
/// assembled 2 non-EVM signatures`).
#[rstest]
#[case::v29(2)]
#[case::v30(3)]
fn recover_address_rejects_x_reduced_v(#[case] recid_byte: u8) {
    let (claimed, sig) = x_reduced_pair(&MESSAGE_HASH_TO_SIGN, recid_byte);
    assert_eq!(sig.v(), 27 + recid_byte, "the crafted wire v is 29/30");

    // Directly: the fix rejects on the v range; the buggy path would recover `claimed`.
    assert_eq!(
        recover_address(&MESSAGE_HASH_TO_SIGN, &sig),
        None,
        "v=29/30 must not recover, even though k256 could recover the x-reduced point"
    );

    // Through the quorum gate: refused as SignatureDoesNotVerify at its index.
    let valid = attesters()[0].signed_pair(&MESSAGE_HASH_TO_SIGN);
    assert_matches!(
        assemble_quorum(&MESSAGE_HASH_TO_SIGN, vec![(claimed, sig), valid]),
        Err(QuorumError::SignatureDoesNotVerify { at: 0 })
    );
}

/// A real (EVM `v` `27`/`28`) signature DOES recover to its signer — the positive counterpart to
/// the boundary rejections, so `recover_address` is not vacuously returning `None`.
#[test]
fn recover_address_accepts_a_real_evm_signature() {
    let a = &attesters()[0];
    let (addr, sig) = a.signed_pair(&MESSAGE_HASH_TO_SIGN);
    assert!(sig.v() == 27 || sig.v() == 28);
    assert_eq!(recover_address(&MESSAGE_HASH_TO_SIGN, &sig), Some(addr));
}

/// A signature that verifies over a DIFFERENT digest is refused when assembled against the real
/// digest — the recovered address no longer matches the claimed signer (recovery is digest-bound).
#[test]
fn signature_over_a_different_digest_does_not_verify() {
    let a = &attesters()[0];
    let other_digest = [0x99u8; 32];
    let sig_over_other = a.signed_pair(&other_digest).1;
    let valid = attesters()[1].signed_pair(&MESSAGE_HASH_TO_SIGN);

    assert_matches!(
        // claimed = A's real address, but the signature covers `other_digest`, not MESSAGE_HASH_TO_SIGN
        assemble_quorum(
            &MESSAGE_HASH_TO_SIGN,
            vec![(a.address(), sig_over_other), valid]
        ),
        Err(QuorumError::SignatureDoesNotVerify { at: 0 })
    );
}
