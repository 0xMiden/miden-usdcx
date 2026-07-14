//! Recipient AccountId helper suite: every behavior test drives the
//! faucet-owned `xreserve::xreserve_mint::extract_recipient_account_id` helper through MockChain
//! `execute().await` via a CALL-entered driver component (account context). The helper reads the
//! eight u32-LE-packed `remoteRecipient` limbs at `intent_ptr + REMOTE_RECIPIENT_FELT_OFF` (= 19,
//! the "R-B" right-aligned layout: 16-byte zero pad, then big-endian `prefix`/`suffix` u64s),
//! rebuilds each felt through a no-reduction `build_felt` (proving it did not reduce mod the field —
//! Agglayer `eth_address.masm` precedent / Rust `Felt::try_from`), and delegates canonical AccountId
//! validation to the pinned-protocol `account_id::validate` (`use miden::protocol::account_id`).
//! Returns `[recipient_id_suffix, recipient_id_prefix]` for `apply_mint_effects` (note: Rust
//! `account_id_to_felts` is `[prefix, suffix]`; the MASM stack order is the reverse).
//!
//! Canonical `aid-*` / `di-*` vectors are loaded BY REFERENCE; the field-modulus / suffix-MSB
//! / bad-version / malformed-limb cases are constructed in-test from a valid `aid-rt-1` recipient
//! (the `d5b_fee_advice_malformed_limb` precedent for constructed adversarial inputs).
//!
//! RED-SUITE (executing-red): `xreserve_mint.masm` currently holds only the NAMED placeholder trap
//! ("red-suite placeholder: extract_recipient_account_id is not implemented"). Each behavior case
//! below asserts its FINAL (green) expectation and is therefore RED here — the placeholder trap
//! (reached via real execution after the preimage is staged) reverts the tx with the wrong error /
//! prevents the happy output — until it is implemented. `probe_recipient_extract_exports`
//! is a declared green scaffold (the placeholder makes the proc path resolve).

mod support;

use anyhow::Result;
use miden_processor::operation::OperationError;
use miden_processor::ExecutionError;
use miden_protocol::errors::MasmError;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use rstest::rstest;
use support::*;
use xusdc_encoding::vectors::{load, parse_hex32, AidVector, DiVector};

/// The Miden field (Goldilocks) modulus `p = 2^64 - 2^32 + 1`. A reconstructed `prefix`/`suffix`
/// u64 equal to (or above) `p` must be rejected as out-of-field, mirroring Rust `Felt::try_from`.
const FIELD_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

/// Looks up a canonical AccountId↔bytes32 vector by id (by-reference loading).
fn aid(id: &str) -> &'static AidVector {
    load()
        .families
        .aid
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing aid vector {id}"))
}

/// Looks up a canonical DepositIntent vector by id (by-reference loading).
fn di(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

/// The base accept preimage spliced in every case (the helper only reads felts 19..27; the rest of
/// the envelope is irrelevant to it, so any structurally-valid accept preimage serves).
fn base_preimage() -> Vec<Felt> {
    di("di-pos-empty-hookdata").preimage_values()
}

/// A canonical valid recipient bytes32 (the round-tripped `aid-rt-1` worked vector) — the base for
/// the in-test constructed adversarial cases (corrupt exactly one aspect).
fn valid_recipient() -> [u8; 32] {
    parse_hex32(&aid("aid-rt-1").bytes32)
}

/// Binds the harness account. The extractor reads NO config slots, so the bound domain/identifier
/// words are arbitrary (any value works); `setup_shell_account` still binds them + `usedNonces`.
fn harness(driver_src: &str) -> Result<ShellHarness> {
    let domain = Word::from([TEST_DOMAIN, 0, 0, 0]);
    let identifier = Word::from([11u32, 12, 13, 14]);
    // effects-public variant: after the F1 demotion `extract_recipient_account_id` is private in the
    // shipped library, so this isolation harness installs the test-only assembly where the demoted
    // proc is reachable (identical MAST root; a test-only account, never the production component).
    setup_shell_account_effects_public(domain, identifier, driver_src, SHELL_DRIVER_PATH)
}

// The former `probe_recipient_extract_exports` (asserting `extract_recipient_account_id` IS a
// library export) is retired by the demotion: it is now a same-module `exec`-only internal.
// The production callable-root set is pinned by
// `mint_root_surface::production_supply_raising_root_set_is_exactly_mint`.

// HAPPY PATH FIRST — the worked vectors extract to their canonical [suffix, prefix]
// ================================================================================================

#[rstest]
#[case::aid_rt_1("aid-rt-1")]
#[case::aid_rt_2("aid-rt-2")]
#[case::aid_rt_3("aid-rt-3")]
#[tokio::test]
async fn aid_rt_extracts_account_id(#[case] aid_id: &str) -> Result<()> {
    let v = aid(aid_id);
    // `expected_felts()` is the Rust order [prefix, suffix]; the MASM helper returns [suffix, prefix]
    let [prefix, suffix] = v.expected_felts();
    let preimage = splice_recipient(&base_preimage(), parse_hex32(&v.bytes32));
    let driver_src = recipient_driver_src(&preimage, Some((suffix, prefix)));
    let h = harness(&driver_src)?;
    // the driver pins [suffix, prefix] internally; a clean run proves the extracted felts match
    run_call_driver(&h, "drive").await.unwrap_or_else(|e| {
        panic!(
            "vector {aid_id}: the extractor must return the canonical [suffix, prefix] felts: {e}"
        )
    });
    Ok(())
}

// REJECTS — each pins the EXACT expected error (no `is_err()`)
// ================================================================================================
// Local layout/field-range rejects (faucet-owned `ERR_XRESERVE_RECIPIENT_*`); suffix-shape and
// unknown-version rejects surface the PROTOCOL `account_id::validate` `ERR_ACCOUNT_ID_*` constants.

/// `aid-rej-out-of-range`: a non-zero byte in the 16-byte leading pad (here `bytes[0] = 0x01`) must
/// reject locally before any felt is built (mirrors Rust `AccountIdOutOfRange`).
#[tokio::test]
async fn aid_rej_out_of_range_traps() -> Result<()> {
    let preimage = splice_recipient(
        &base_preimage(),
        parse_hex32(&aid("aid-rej-out-of-range").bytes32),
    );
    let h = harness(&recipient_driver_src(&preimage, None))?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_RECIPIENT_OUT_OF_RANGE")
    );
    Ok(())
}

/// `aid-rej-non-canonical` (`prefix = suffix = 7`): the felts build cleanly (both < p), then
/// `account_id::validate` rejects it. Mirrors Rust `NonCanonicalAccountId`; in MASM it surfaces a
/// specific protocol constant — at v0.16 the version gate runs FIRST (`validate` = version check
/// then `validate_structure`, protocol #3188/#3216; account_id.masm:141-152), so this frozen
/// Circle vector (whose prefix carries version bits ≠ 1) trips the exact
/// `ERR_ACCOUNT_ID_UNKNOWN_VERSION`. The low-byte leg it hit at v0.15 stays covered by
/// [`aid_low_byte_traps_protocol_low_byte`] below (a crafted, valid-version recipient), so this
/// upstream re-ordering costs no coverage.
#[tokio::test]
async fn aid_rej_non_canonical_traps_protocol_version() -> Result<()> {
    let preimage = splice_recipient(
        &base_preimage(),
        parse_hex32(&aid("aid-rej-non-canonical").bytes32),
    );
    let h = harness(&recipient_driver_src(&preimage, None))?;
    let result = run_call_driver(&h, "drive").await;
    let expected = MasmError::from_static_str("unknown version in account ID");
    assert_transaction_executor_error!(result, &expected);
    Ok(())
}

/// The protocol low-byte leg, isolated: a VALID recipient (canonical version) whose suffix low
/// byte is flipped non-zero passes the version gate and trips the exact protocol low-byte
/// constant — the assertion `aid_rej_non_canonical_traps_protocol_version` covered at v0.15
/// before the upstream check re-ordering.
#[tokio::test]
async fn aid_low_byte_traps_protocol_low_byte() -> Result<()> {
    let mut recipient = valid_recipient();
    // R-B layout: bytes[24..32] are the suffix (u64 BE) — its LAST byte is the low byte.
    recipient[31] = 0x07;
    let preimage = splice_recipient(&base_preimage(), recipient);
    let h = harness(&recipient_driver_src(&preimage, None))?;
    let result = run_call_driver(&h, "drive").await;
    let expected =
        MasmError::from_static_str("least significant byte of the account ID suffix must be zero");
    assert_transaction_executor_error!(result, &expected);
    Ok(())
}

/// A `prefix` u64 equal to the field modulus reduces to a different felt — the no-reduction
/// `build_felt` round-trip must catch it (mirrors `Felt::try_from(prefix)` failing).
#[tokio::test]
async fn prefix_eq_modulus_traps_noncanonical() -> Result<()> {
    let mut recipient = valid_recipient();
    recipient[16..24].copy_from_slice(&FIELD_MODULUS.to_be_bytes());
    let preimage = splice_recipient(&base_preimage(), recipient);
    let h = harness(&recipient_driver_src(&preimage, None))?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_RECIPIENT_NONCANONICAL")
    );
    Ok(())
}

/// A `suffix` u64 equal to the field modulus must be caught by the SAME no-reduction `build_felt`
/// round-trip (not deferred to / subsumed by protocol validation) — both felts get the check.
#[tokio::test]
async fn suffix_eq_modulus_traps_noncanonical() -> Result<()> {
    let mut recipient = valid_recipient();
    recipient[24..32].copy_from_slice(&FIELD_MODULUS.to_be_bytes());
    let preimage = splice_recipient(&base_preimage(), recipient);
    let h = harness(&recipient_driver_src(&preimage, None))?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_RECIPIENT_NONCANONICAL")
    );
    Ok(())
}

/// A `suffix` with its most-significant bit set but still < p (here `2^63`, low byte zero) builds
/// cleanly, then `account_id::validate` rejects via the protocol suffix-MSB constant.
#[tokio::test]
async fn suffix_msb_in_field_traps_protocol_msb() -> Result<()> {
    let mut recipient = valid_recipient();
    recipient[24..32].copy_from_slice(&0x8000_0000_0000_0000u64.to_be_bytes());
    let preimage = splice_recipient(&base_preimage(), recipient);
    let h = harness(&recipient_driver_src(&preimage, None))?;
    let result = run_call_driver(&h, "drive").await;
    let expected =
        MasmError::from_static_str("most significant bit of the account ID suffix must be zero");
    assert_transaction_executor_error!(result, &expected);
    Ok(())
}

/// An otherwise-valid prefix whose version nibble (low nibble of the prefix's low u32) is changed
/// from `1` to `2` must reject via the protocol unknown-version constant — version is 1, not 0.
#[tokio::test]
async fn bad_version_nibble_traps_protocol_unknown_version() -> Result<()> {
    let mut recipient = valid_recipient();
    // byte 23 is the prefix LSB (bytes[16..24] is the big-endian prefix u64); flip its low nibble
    recipient[23] = (recipient[23] & 0xf0) | 0x02;
    let preimage = splice_recipient(&base_preimage(), recipient);
    let h = harness(&recipient_driver_src(&preimage, None))?;
    let result = run_call_driver(&h, "drive").await;
    let expected = MasmError::from_static_str("unknown version in account ID");
    assert_transaction_executor_error!(result, &expected);
    Ok(())
}

/// A staged `remoteRecipient` limb that is a valid field element but NOT a valid u32 (here `2^32`,
/// in the first prefix limb at felt 23) must trap the `build_felt` `u32assert2` guard. `u32assert*`
/// surfaces as `OperationError::U32AssertionFailed` (not `FailedAssertion`), so the named error is
/// pinned on that variant's code AND message — same strength as the D5b malformed-limb row.
#[tokio::test]
async fn malformed_limb_traps_bad_limb() -> Result<()> {
    let mut preimage = splice_recipient(&base_preimage(), valid_recipient());
    preimage[REMOTE_RECIPIENT_FELT_OFF + 4] =
        Felt::try_from(1u64 << 32).expect("2^32 is within the field");
    let h = harness(&recipient_driver_src(&preimage, None))?;
    let result = run_call_driver(&h, "drive").await;
    let expected = shell_error_by_name("ERR_XRESERVE_RECIPIENT_BAD_LIMB");
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { ref err_code, ref err_msg, .. },
            ..
        } if *err_code == expected.code() && err_msg.as_deref() == Some(expected.message())
    );
    Ok(())
}

// READ-ONLY (no-effects) — the extractor mutates no account state
// ================================================================================================

/// On a valid recipient the extractor is side-effect-free: the only account mutation is the auth
/// nonce increment (no storage delta, no note, no supply change). The driver pins the extracted
/// felts, so a clean run also re-proves correctness.
#[tokio::test]
async fn extract_is_read_only() -> Result<()> {
    let v = aid("aid-rt-1");
    let [prefix, suffix] = v.expected_felts();
    let preimage = splice_recipient(&base_preimage(), valid_recipient());
    let driver_src = recipient_driver_src(&preimage, Some((suffix, prefix)));
    let h = harness(&driver_src)?;
    let executed = run_call_driver(&h, "drive").await.unwrap_or_else(|e| {
        panic!("the extractor must be read-only and succeed on a valid recipient: {e}")
    });
    assert_eq!(
        (executed.final_account().nonce() - executed.initial_account().nonce()),
        miden_protocol::ONE,
        "auth must increment the nonce exactly once"
    );
    assert!(
        executed.account_patch().storage().is_empty(),
        "the recipient extractor must not write account storage"
    );
    assert_eq!(
        executed.output_notes().num_notes(),
        0,
        "the recipient extractor must not create output notes"
    );
    Ok(())
}
