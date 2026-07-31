//! Faucet mint-precondition suite: every behavior test executes the faucet-owned
//! `xreserve::deposit_intent_parser::assert_deposit_intent` on a MockChain, entered by `call`
//! from a small driver component. The `call` matters: `assert_deposit_intent` reads the
//! faucet's own domain/identifier configuration with `active_account::get_item`, which the
//! kernel only honors when the caller runs in account context.
//!
//! The DepositIntent payloads come from the canonical golden-vector artifact shared with the
//! Rust codec, so an accept here and an accept in the Rust parser are driven by the same bytes.
//!
//! The reject rows split into two groups by who owns the check. Five of them — bad magic, bad
//! version, and a zero `amount` / `localToken` / `localDepositor` — are enforced by the shared
//! encoding parser and surface as its `ERR_DI_*` errors travelling back out through the call.
//! The other two are the faucet's own compares against its configured slots: the intent's
//! `remoteDomain` must equal the configured domain, and its `remoteToken`, hashed to a storage
//! key, must equal the configured identifier.
//!
//! The file is organized by the stages the mint pipeline runs in, and the section headers and
//! test names use the short stage labels the faucet's own comments use. The sequence, defined
//! here so nothing outside this file has to be consulted:
//!
//! - `d5a` — parse the DepositIntent and assert its fields against the faucet configuration
//!   (the first two sections below).
//! - `d5b` — reduce `amount` / `maxFee` / `feeAmount` from uint256 to asset amounts and assert
//!   the relations between them.
//! - `d5c` — assert the intent's nonce has not been spent (read-only; the marker write is a
//!   later stage).
//! - `d5d` — verify the depositor's ECDSA attestation against the attester allowlist.
//! - `d5e` — the state-changing tail (mint, write the nonce marker); driven end to end in
//!   `mint_policy_e2e.rs`, not here.

mod support;

use anyhow::Result;
use miden_processor::operation::OperationError;
use miden_processor::ExecutionError;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use rstest::rstest;
use support::*;
use xusdc_encoding::vectors::{load, parse_hex32, AmtVector, DiVector};
use xusdc_encoding::xreserve::encoding::{bytes32_to_storage_map_key, uint256_to_asset_amount};

/// Looks up a canonical DepositIntent vector by id (by-reference loading).
fn di(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

/// Builds the two faucet configuration words a vector should be accepted against.
///
/// The domain slot holds the remote domain id in its first element and zeros elsewhere; the
/// identifier slot holds the storage-map key the faucet compares `remoteToken` to, derived from
/// the vector's own remoteToken bytes with the Rust side of the shared codec
/// (`bytes32_to_storage_map_key`) so the expected value is never hand-written here.
///
/// Set `flip_identifier_byte` to corrupt the first remoteToken byte before hashing: the result
/// is a well-formed but wrong identifier key, which is what the wrong-identifier reject needs.
fn config_for(vector_id: &str, domain: u32, flip_identifier_byte: bool) -> (Word, Word) {
    let f = di(vector_id)
        .fields
        .as_ref()
        .expect("config vector carries fields");
    let domain_word = Word::new([
        Felt::from(domain),
        miden_protocol::ZERO,
        miden_protocol::ZERO,
        miden_protocol::ZERO,
    ]);
    let mut identifier_bytes = parse_hex32(&f.remote_token_hex);
    if flip_identifier_byte {
        identifier_bytes[0] ^= 0xff;
    }
    let identifier_word = Word::from(bytes32_to_storage_map_key(&identifier_bytes));
    (domain_word, identifier_word)
}

// HAPPY PATH FIRST — matching config x both canonical accept vectors
// ================================================================================================

#[rstest]
#[case::hookdata("di-pos-hookdata")]
#[case::empty_hookdata("di-pos-empty-hookdata")]
#[tokio::test]
async fn happy_path_mint_preconditions(#[case] vector_id: &str) -> Result<()> {
    let v = di(vector_id);
    let f = v.fields.as_ref().expect("accept vector carries fields");
    let (domain, identifier) = config_for(vector_id, TEST_DOMAIN, false);
    let driver_src = shell_driver_src(&v.preimage_values(), v.len_felts, Some(f.hook_data_len));
    let h = setup_shell_account(domain, identifier, &driver_src, SHELL_DRIVER_PATH)?;
    let executed = run_call_driver(&h, "drive").await.unwrap_or_else(|e| {
        panic!("vector {vector_id}: the shell must accept a matching DepositIntent: {e}")
    });
    // the shell is read-only: the only account mutation is the auth nonce increment
    assert_eq!(
        (executed.final_account().nonce() - executed.initial_account().nonce()),
        miden_protocol::ONE,
        "auth must increment the nonce exactly once"
    );
    assert!(
        executed.account_patch().storage().is_empty(),
        "the shell must not write account storage"
    );
    Ok(())
}

// DEPOSIT-INTENT REJECTS (parametrized; every case pins the EXACT expected error)
// ================================================================================================
// The first five rows feed a reject vector against MATCHING configuration, so the shared
// encoding parser's own trap is the only thing that can fire and the case proves which
// `ERR_DI_*` reaches the caller. The last two rows do the opposite: they feed an ACCEPT vector
// against deliberately wrong configuration, so the only remaining candidate is the faucet's own
// compare. They are kept apart on purpose — the wrong-domain row keeps the identifier matching
// and the wrong-identifier row keeps the domain matching, so neither assert can mask the other.

#[rstest]
#[case::r_mint_1_bad_magic("di-rej-bad-magic", TEST_DOMAIN, false, "ERR_DI_BAD_MAGIC")]
#[case::r_mint_2_bad_version("di-rej-bad-version", TEST_DOMAIN, false, "ERR_DI_BAD_VERSION")]
#[case::r_mint_3_zero_amount("di-rej-zero-amount", TEST_DOMAIN, false, "ERR_DI_ZERO_FIELD")]
#[case::r_mint_4_zero_local_token(
    "di-rej-zero-local-token",
    TEST_DOMAIN,
    false,
    "ERR_DI_ZERO_FIELD"
)]
#[case::r_mint_5_zero_local_depositor(
    "di-rej-zero-local-depositor",
    TEST_DOMAIN,
    false,
    "ERR_DI_ZERO_FIELD"
)]
#[case::r_mint_6_wrong_domain(
    "di-pos-hookdata",
    TEST_WRONG_DOMAIN,
    false,
    "ERR_XRESERVE_WRONG_DOMAIN"
)]
#[case::r_mint_7_wrong_identifier(
    "di-pos-hookdata",
    TEST_DOMAIN,
    true,
    "ERR_XRESERVE_WRONG_IDENTIFIER"
)]
#[tokio::test]
async fn r_mint_rejects(
    #[case] vector_id: &str,
    #[case] domain: u32,
    #[case] flip_identifier_byte: bool,
    #[case] expected_err: &str,
) -> Result<()> {
    // config always derives from the accept vector (reject vectors carry no fields
    // block; for rows 1-5 the config is irrelevant — the parser traps first)
    let (domain_word, identifier_word) =
        config_for("di-pos-hookdata", domain, flip_identifier_byte);
    let v = di(vector_id);
    let len_felts = v.staging_len_felts.unwrap_or(v.len_felts);
    let driver_src = shell_driver_src(&v.preimage_values(), len_felts, None);
    let h = setup_shell_account(domain_word, identifier_word, &driver_src, SHELL_DRIVER_PATH)?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(result, shell_error_by_name(expected_err));
    Ok(())
}

// PROBES — harness mechanics, not faucet behavior
// ================================================================================================
// These tests do not exercise the mint preconditions at all. They pin the assumptions the
// behavior tests are built on: that the library exports each proc under the fully-qualified path
// the drivers call it by, and that named storage slots read back what they were seeded with.
// Keeping them separate means an assembler or naming regression fails as itself rather than
// masquerading as a mint-policy reject.

/// The assembled library exports `assert_deposit_intent` under its fully-qualified path.
///
/// The drivers in this file invoke it by that exact path, and so does the faucet component, so a
/// module move or rename would silently break both. Comparing against the assembler's own export
/// list is what catches it.
#[test]
fn probe_shell_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::deposit_intent_parser::assert_deposit_intent";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical shell proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

/// Pins the plumbing the other tests depend on: that a named storage slot really resolves to the
/// word it was seeded with.
///
/// A minimal probe component reads both named value slots by name and compares them against the
/// fixture words. It deliberately does not touch the deposit-intent code, so if the slot naming
/// or the call-context read path ever breaks on a toolchain bump, this fails on its own instead
/// of showing up as a confusing wrong-domain or wrong-identifier reject elsewhere in the file.
#[tokio::test]
async fn probe_slot_binding() -> Result<()> {
    let domain = Word::from([7u32, 0, 0, 0]);
    let identifier = Word::from([11u32, 12, 13, 14]);
    let probe_src = slot_probe_src(domain, identifier);
    let h = setup_shell_account(domain, identifier, &probe_src, SLOT_PROBE_PATH)?;
    run_call_driver(&h, "read_slots")
        .await
        .unwrap_or_else(|e| panic!("slot-binding probe must execute green: {e}"));
    Ok(())
}

// D5B — AMOUNT / MAXFEE / FEEAMOUNT PRECONDITIONS
// ================================================================================================
// Executes the faucet-owned `xreserve::deposit_intent_parser::assert_mint_amounts` on a
// MockChain. Each case splices a chosen `amount` and `maxFee` into an otherwise-valid
// DepositIntent preimage, taking the uint256 limb patterns from the shared `amt-*` golden
// vectors so the conversion behavior under test is the same one the Rust mirror is pinned to;
// the driver passes the mirror-computed amount witness. `feeAmount` does not travel in the
// intent: the caller stages its limbs in memory and passes the pointer.

/// Decimal exponent the amount reducer divides by, handed to the proc as a parameter rather
/// than read from a faucet constant.
///
/// Six matches the scale the `amt-*` vectors were generated at. Passing it in keeps this suite
/// from asserting anything about the production scale factor, which Circle has not yet fixed —
/// the shipped value lives with the faucet's configuration, deliberately not here.
const D5B_SCALE_EXP: u32 = 6;

/// Looks up a canonical amount vector by id (by-reference loading).
fn amt(id: &str) -> &'static AmtVector {
    load()
        .families
        .amt
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing amt vector {id}"))
}

/// Builds a D5b harness over a base accept preimage with `amount`/`maxFee` spliced from the
/// given limbs. The shell does not read config slots, but the component still binds them;
/// the matching `di-pos-empty-hookdata` config is reused for tidiness.
///
/// The driver's amount witness is the Rust mirror's quotient (the value the mint-note factory
/// would carry); an unreducible amount pushes a zero witness — the verifier traps on the x
/// bound before consuming y.
fn d5b_harness(
    amount_limbs: [u32; 8],
    maxfee_limbs: [u32; 8],
    fee_amount: &[Felt],
) -> Result<ShellHarness> {
    let base = di("di-pos-empty-hookdata").preimage_values();
    let preimage = splice_amounts(&base, amount_limbs, maxfee_limbs);
    let (domain, identifier) = config_for("di-pos-empty-hookdata", TEST_DOMAIN, false);
    let amount_y = uint256_to_asset_amount(amount_limbs, D5B_SCALE_EXP)
        .map(u64::from)
        .unwrap_or(0);
    let driver_src = mint_amounts_driver_src(&preimage, fee_amount, D5B_SCALE_EXP, amount_y);
    setup_shell_account(domain, identifier, &driver_src, SHELL_DRIVER_PATH)
}

// HAPPY PATH FIRST
// ------------------------------------------------------------------------------------------------

#[rstest]
// feeAmount == 0 (MVP default) accepted; amount (amt-ge-gt.a) > maxFee (amt-ge-gt.b)
#[case::fee_zero(amt("amt-ge-gt").le_limbs(), amt("amt-ge-gt").b_le_limbs(), fee_amount_felts([0u32; 8]))]
// boundary: amount exactly equal to maxFee is accepted — the reject fires below maxFee, not at it
#[case::amount_eq_maxfee(amt("amt-ge-eq").le_limbs(), amt("amt-ge-eq").b_le_limbs(), fee_amount_felts([0u32; 8]))]
// value at AssetAmount::MAX accepted at the cap; amount (cap) >= maxFee (amt-pos-1)
#[case::cap_value(amt("amt-cap-accept").le_limbs(), amt("amt-pos-1").le_limbs(), fee_amount_felts([0u32; 8]))]
#[tokio::test]
async fn d5b_happy_amount_fee(
    #[case] amount_limbs: [u32; 8],
    #[case] maxfee_limbs: [u32; 8],
    #[case] fee_amount: Vec<Felt>,
) -> Result<()> {
    let h = d5b_harness(amount_limbs, maxfee_limbs, &fee_amount)?;
    let executed = run_call_driver(&h, "drive")
        .await
        .unwrap_or_else(|e| panic!("D5b must accept these reduced amount/fee values: {e}"));
    // the shell is read-only: the only account mutation is the auth nonce increment
    assert_eq!(
        (executed.final_account().nonce() - executed.initial_account().nonce()),
        miden_protocol::ONE,
        "auth must increment the nonce exactly once"
    );
    assert!(
        executed.account_patch().storage().is_empty(),
        "the D5b shell must not write account storage"
    );
    Ok(())
}

// REJECTS — every case pins the EXACT error symbol, never a bare `is_err()`
// ------------------------------------------------------------------------------------------------
// Two distinct failure kinds are covered here. A value too large to convert traps its staging
// guard (the amount inside the standards verifier, maxFee/fee in the parser's own staging); a
// value that converts fine but breaks a relation the faucet requires traps with one of the
// faucet's own `ERR_XRESERVE_*` symbols. Both arrive as MASM assertion failures, so one
// `assert_transaction_executor_error!` shape covers the family.

#[rstest]
// too large: the AMOUNT exceeds 2^128; the amount goes through the standards verifier, so
// the trap is its own x bound (distinct from the shell's maxFee/fee ERR_X_TOO_LARGE below)
#[case::r_mint_9_amount_overflow(amt("amt-rej-limb-overflow").le_limbs(), amt("amt-pos-1").le_limbs(), fee_amount_felts([0u32; 8]), "STD_ERR_X_TOO_LARGE")]
// same overflow on MAXFEE — ordered so the amount reduces cleanly first and the trap is maxFee's
#[case::r_mint_9_maxfee_overflow(amt("amt-pos-2").le_limbs(), amt("amt-rej-limb-overflow").le_limbs(), fee_amount_felts([0u32; 8]), "ERR_X_TOO_LARGE")]
// same overflow on the separately staged FEEAMOUNT — the third reduction is guarded too
#[case::r_mint_9_fee_overflow(amt("amt-pos-2").le_limbs(), amt("amt-pos-1").le_limbs(), fee_amount_felts(amt("amt-rej-limb-overflow").le_limbs()), "ERR_X_TOO_LARGE")]
// relation broken: the reduced amount is strictly below maxFee, so the mint could not cover its fee
#[case::r_mint_10_amount_below_fee(amt("amt-ge-lt").le_limbs(), amt("amt-ge-lt").b_le_limbs(), fee_amount_felts([0u32; 8]), "ERR_XRESERVE_AMOUNT_BELOW_FEE")]
// amount >= maxFee passes, then a NONZERO feeAmount is rejected: the faucet pays no relayer fee,
// so any nonzero fee is refused regardless of how it compares to maxFee
#[case::r_mint_11_fee_over_maxfee(amt("amt-pos-2").le_limbs(), amt("amt-ge-lt").le_limbs(), fee_amount_felts(amt("amt-ge-lt").b_le_limbs()), "ERR_XRESERVE_FEE_NONZERO")]
// the same refusal at the tightest point: a feeAmount that exactly equals maxFee is still nonzero,
// so it is still rejected — the gate is "zero", not "within maxFee"
#[case::fee_eq_maxfee(amt("amt-pos-2").le_limbs(), amt("amt-ge-eq").le_limbs(), fee_amount_felts(amt("amt-ge-eq").le_limbs()), "ERR_XRESERVE_FEE_NONZERO")]
#[tokio::test]
async fn d5b_amount_fee_rejects(
    #[case] amount_limbs: [u32; 8],
    #[case] maxfee_limbs: [u32; 8],
    #[case] fee_amount: Vec<Felt>,
    #[case] expected_err: &str,
) -> Result<()> {
    let h = d5b_harness(amount_limbs, maxfee_limbs, &fee_amount)?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(result, shell_error_by_name(expected_err));
    Ok(())
}

// REJECTS — a malformed staged feeAmount limb
// ------------------------------------------------------------------------------------------------

/// A malformed (non-u32) `feeAmount` limb must ERROR: the reducer's `u32assertw` guard
/// traps `ERR_FELT_OUT_OF_FIELD`. `u32assert*` surfaces as `OperationError::U32AssertionFailed`
/// (not `FailedAssertion`), so the named error is pinned on that variant's code AND message
/// — same strength as `masm_dual.rs`'s `amt-guard-limb-not-u32` row.
#[tokio::test]
async fn d5b_fee_amount_malformed_limb() -> Result<()> {
    // a felt at 2^32 is a valid field element but NOT a valid u32 limb
    let malformed = vec![Felt::try_from(1u64 << 32).expect("2^32 is within the field"); 8];
    let h = d5b_harness(
        amt("amt-ge-gt").le_limbs(),
        amt("amt-ge-gt").b_le_limbs(),
        &malformed,
    )?;
    let result = run_call_driver(&h, "drive").await;
    let expected = shell_error_by_name("ERR_FELT_OUT_OF_FIELD");
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { ref err_code, ref err_msg, .. },
            ..
        } if *err_code == expected.code() && err_msg.as_deref() == Some(expected.message())
    );
    Ok(())
}

// PROBE (export check for the new proc)
// ------------------------------------------------------------------------------------------------

/// The assembled library exports `assert_mint_amounts` under its fully-qualified path — the same
/// rename guard as `probe_shell_exports`, for the amount/fee stage.
#[test]
fn probe_mint_amounts_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::deposit_intent_parser::assert_mint_amounts";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical D5b proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// D5C — NONCE REPLAY GUARD
// ================================================================================================
// Executes the faucet-owned `xreserve::deposit_intent_parser::assert_nonce_unused` on a
// MockChain. The guard hashes the intent's 32-byte nonce (felts 51..58 of the parsed preimage)
// into a storage-map key with the shared `bytes32_to_key`, reads `usedNonces[key]` from account
// storage, and requires it to still be the empty Word; anything else means this deposit has
// already been minted and it traps. The guard only READS — writing the spent marker belongs to
// the mint tail, so the tests here also assert that no storage was written.

/// A stand-in "this nonce is spent" marker used to seed `usedNonces`. Any non-empty Word does:
/// the guard's whole test is empty vs non-empty, and the value the mint tail actually writes is
/// not what this section exercises.
const NONCE_MARKER: [u32; 4] = [1, 0, 0, 0];

/// Computes the `usedNonces` map key a vector's nonce should land on.
///
/// It runs the Rust half of the shared bytes32→Word codec, so the expected key is derived the
/// same way the MASM guard derives it rather than being pinned by hand; the cross-language
/// parity test in `masm_dual.rs` is what guarantees the two halves agree.
fn nonce_key(vector_id: &str) -> Word {
    let f = di(vector_id)
        .fields
        .as_ref()
        .expect("accept vector carries fields");
    Word::from(bytes32_to_storage_map_key(&f.bytes32("nonce")))
}

// HAPPY PATH FIRST — an unused nonce (empty map) passes the guard
// ------------------------------------------------------------------------------------------------

#[rstest]
#[case::hookdata("di-pos-hookdata")]
#[case::empty_hookdata("di-pos-empty-hookdata")]
#[tokio::test]
async fn d5c_happy_nonce_unused(#[case] vector_id: &str) -> Result<()> {
    let v = di(vector_id);
    let (domain, identifier) = config_for(vector_id, TEST_DOMAIN, false);
    let driver_src = nonce_driver_src(&v.preimage_values());
    // empty usedNonces map -> usedNonces[key] reads EMPTY_WORD (unused) -> passes
    let h = setup_shell_account(domain, identifier, &driver_src, SHELL_DRIVER_PATH)?;
    let executed = run_call_driver(&h, "drive").await.unwrap_or_else(|e| {
        panic!("vector {vector_id}: an unused nonce must pass the D5c guard: {e}")
    });
    assert_eq!(
        (executed.final_account().nonce() - executed.initial_account().nonce()),
        miden_protocol::ONE,
        "auth must increment the nonce exactly once"
    );
    assert!(
        executed.account_patch().storage().is_empty(),
        "D5c is assert-zero only: it must not write account storage (no nonce SET)"
    );
    Ok(())
}

// REPLAY REJECT — a nonce already recorded as spent traps with the exact replay error
// ------------------------------------------------------------------------------------------------

#[rstest]
#[case::hookdata("di-pos-hookdata")]
#[case::empty_hookdata("di-pos-empty-hookdata")]
#[tokio::test]
async fn d5c_replay_rejects(#[case] vector_id: &str) -> Result<()> {
    let v = di(vector_id);
    let (domain, identifier) = config_for(vector_id, TEST_DOMAIN, false);
    let driver_src = nonce_driver_src(&v.preimage_values());
    // mark this vector's nonce as already spent, so the guard's map read returns a non-empty
    // Word and the "must still be empty" assert fires — this is the same-deposit-twice case
    let seed = (nonce_key(vector_id), Word::from(NONCE_MARKER));
    let h = setup_shell_account_with_nonce_seed(
        domain,
        identifier,
        Some(seed),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_NONCE_REPLAY"));
    Ok(())
}

// KEY-SCOPING (strengthening) — a non-empty map must not reject an UNRELATED nonce
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn d5c_unrelated_seeded_nonce_passes() -> Result<()> {
    // seeding a DIFFERENT nonce's key must NOT reject this nonce — the read is key-scoped
    // (re-proven at the faucet level). The "other" key is THIS nonce with one
    // byte flipped (the `config_for` identifier-flip idiom), so it is guaranteed distinct
    // (the two canonical accept vectors happen to share a nonce, so cross-vector keys would
    // collide).
    let run_id = "di-pos-hookdata";
    let f = di(run_id)
        .fields
        .as_ref()
        .expect("accept vector carries fields");
    let mut other_nonce = f.bytes32("nonce");
    other_nonce[0] ^= 0xff;
    let other_key = Word::from(bytes32_to_storage_map_key(&other_nonce));
    assert_ne!(
        other_key,
        nonce_key(run_id),
        "the flipped-byte nonce key must differ"
    );

    let v = di(run_id);
    let (domain, identifier) = config_for(run_id, TEST_DOMAIN, false);
    let driver_src = nonce_driver_src(&v.preimage_values());
    let seed = (other_key, Word::from(NONCE_MARKER));
    let h = setup_shell_account_with_nonce_seed(
        domain,
        identifier,
        Some(seed),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let executed = run_call_driver(&h, "drive")
        .await
        .unwrap_or_else(|e| panic!("a seeded-but-unrelated nonce must not reject {run_id}: {e}"));
    assert_eq!(
        (executed.final_account().nonce() - executed.initial_account().nonce()),
        miden_protocol::ONE
    );
    assert!(
        executed.account_patch().storage().is_empty(),
        "D5c is assert-zero only: it must not write account storage (no nonce SET)"
    );
    Ok(())
}

// PROBE (export check for the new proc)
// ------------------------------------------------------------------------------------------------

/// The assembled library exports `assert_nonce_unused` under its fully-qualified path — the same
/// rename guard as the other export probes, for the replay stage.
#[test]
fn probe_nonce_unused_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::deposit_intent_parser::assert_nonce_unused";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical D5c proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// D5D — ATTESTATION VERIFY
// ================================================================================================
// Executes the faucet-owned `xreserve::attestation_verify::verify_attestation` on a MockChain.
// The proc does three things in order: keccak256 the DepositIntent payload, check that the
// candidate public key is an enabled attester (its Poseidon2 commitment must have a non-empty
// entry in the `xReserveAttesters` map), and ECDSA-verify the supplied signature against that
// digest and key. Only a deposit Circle actually signed can pass.
//
// The security property these cases exist for: the pubkey is read from the advice stack ONCE,
// into one local memory region, and that same region feeds both the allowlist lookup and the
// signature check. If the two steps could read different keys, an attacker could present an
// allowlisted attester's key for the lookup and their own signature for the verification.
//
// Keypairs and signatures are generated inside the test (k256 + sha3 + miden-crypto) rather than
// baked into the shared vector artifact, because the tests need two attesters signing the SAME
// payload: key A and key B, with distinct commitments, so a signature by one can be offered
// under the identity of the other.
//
// Every case runs the real proc — real keccak, real Poseidon2 commitment, real map read, real
// `verify_prehash` — and pins the exact outcome: an accepted attestation stops at the
// supply-write boundary having written nothing; a rejected one traps with the specific error for
// the check that failed; and an attestation with nothing staged on the advice stack fails closed
// rather than proceeding with garbage.

/// The DepositIntent whose bytes the attestation cases hash and sign: the 240-byte accept vector
/// with no hookData, so the payload is exactly the fixed header.
const ATTESTATION_VECTOR: &str = "di-pos-empty-hookdata";

/// The value stored under an attester's commitment to mark it enabled. Any non-empty Word does —
/// the allowlist check is presence, and an absent key reads back as the empty Word.
const ATTESTER_MARKER: [u32; 4] = [1, 0, 0, 0];

/// Returns the attestation payload three ways: as the felts staged into the driver, as the raw
/// bytes the attester signs, and as its byte length.
///
/// The bytes and the felts must describe the same payload — the felts are the u32-little-endian
/// packing of those bytes — because the signature is made over the bytes while the on-chain
/// keccak runs over what the felts reconstruct. If they diverged, every case would fail closed.
fn attestation_payload() -> (Vec<Felt>, Vec<u8>, u64) {
    let v = di(ATTESTATION_VECTOR);
    let bytes = v.bytes();
    let len_bytes = bytes.len() as u64;
    (v.preimage_values(), bytes, len_bytes)
}

/// Generates the two attesters the reject cases need: key A, which the tests allowlist, and key
/// B, the foreign key. Both sign keccak256 of the same payload, and the assertion pins that their
/// commitments differ — otherwise "allowlist A, present B" would not actually be a mismatch.
fn seam_keys(payload: &[u8]) -> (AttesterVector, AttesterVector) {
    let a = gen_attester(1, payload);
    let b = gen_attester(2, payload);
    assert_ne!(
        a.commitment, b.commitment,
        "seam keys A and B must have distinct commitments"
    );
    (a, b)
}

/// Builds a driver that stages one attester's public key together with a different attester's
/// signature — the mix-and-match input an attacker would try.
fn paired_driver_src(
    preimage: &[Felt],
    len_bytes: u64,
    pubkey_of: &AttesterVector,
    sig_of: &AttesterVector,
) -> String {
    attestation_driver_src(
        preimage,
        len_bytes,
        &pubkey_of.pubkey_felts,
        &sig_of.sig_felts,
    )
}

// HAPPY PATH FIRST — an allowlisted attester with its own valid signature
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn d5d_happy_attestation() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, _b) = seam_keys(&bytes);
    let driver_src = paired_driver_src(&preimage, len_bytes, &a, &a);
    // seed the allowlist with A's commitment -> A is an enabled attester
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let executed = run_call_driver(&h, "drive")
        .await
        .unwrap_or_else(|e| panic!("an allowlisted attester + valid signature must pass D5d: {e}"));
    // the verify shell is read-only: the only account mutation is the auth nonce increment
    assert_eq!(
        (executed.final_account().nonce() - executed.initial_account().nonce()),
        miden_protocol::ONE,
        "auth must increment the nonce exactly once"
    );
    assert!(
        executed.account_patch().storage().is_empty(),
        "the D5d verify shell must not write account storage"
    );
    Ok(())
}

// REJECTS — each pins the EXACT expected error (no is_err())
// ------------------------------------------------------------------------------------------------

/// A signature that does not belong to the presented key is rejected.
///
/// The driver stages allowlisted key A together with B's signature. B's signature is
/// perfectly well-formed — this is a genuine ECDSA verification failure, not a decode abort on
/// junk bytes — so the case proves the signature check itself, not input validation.
#[tokio::test]
async fn d5d_forged_sig_rejects() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, b) = seam_keys(&bytes);
    let driver_src = paired_driver_src(&preimage, len_bytes, &a, &b);
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_SIG_INVALID"));
    Ok(())
}

/// A key the faucet does not know is rejected even with a perfectly valid signature.
///
/// Key B signs the payload correctly, but only A's commitment was seeded into the allowlist, so
/// the map lookup on B's commitment reads back the empty Word and the proc traps before it ever
/// gets to the signature. A valid signature by a stranger is not an attestation.
#[tokio::test]
async fn d5d_non_allowlisted_rejects() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, b) = seam_keys(&bytes);
    let driver_src = paired_driver_src(&preimage, len_bytes, &b, &b);
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT")
    );
    Ok(())
}

// THE SEAM (the catastrophic case) — BOTH attacker arrangements must reject
// ------------------------------------------------------------------------------------------------

/// Neither way of splitting "who is allowlisted" from "who signed" gets through.
///
/// An attacker holding a valid signature by an unknown key B has two moves, and this test runs
/// both for real: the allowlisted key A presented with B's signature (the allowlist check passes,
/// the ECDSA verify then fails) and B's own key presented with it (the ECDSA verify would pass,
/// but the allowlist check comes first and refuses). There is no third arrangement, because the
/// proc reads the candidate key exactly once and both checks consume that one copy.
#[tokio::test]
async fn d5d_seam_both_arrangements_reject() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, b) = seam_keys(&bytes);
    let allowlist_a = Some((a.commitment, Word::from(ATTESTER_MARKER)));

    // arrangement 1: allowlisted key A carries the allowlist check, B's signature fails the verify
    let mixed_src = paired_driver_src(&preimage, len_bytes, &a, &b);
    let h1 = setup_attestation_account(allowlist_a, &mixed_src, SHELL_DRIVER_PATH)?;
    let r1 = run_call_driver(&h1, "drive").await;
    assert_transaction_executor_error!(r1, shell_error_by_name("ERR_XRESERVE_SIG_INVALID"));

    // arrangement 2: B's key and B's own valid signature, but B was never allowlisted
    let b_only_src = paired_driver_src(&preimage, len_bytes, &b, &b);
    let h2 = setup_attestation_account(allowlist_a, &b_only_src, SHELL_DRIVER_PATH)?;
    let r2 = run_call_driver(&h2, "drive").await;
    assert_transaction_executor_error!(r2, shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT"));
    Ok(())
}

// UNSTAGED OPERANDS — an all-zero pubkey region must fail closed
// ------------------------------------------------------------------------------------------------

/// A caller that stages no key and no signature must be rejected, not waved through.
///
/// Miden memory reads back as zero, so "nothing staged" is not a read error here — it is sixteen
/// zero felts that could be mistaken for a key. The allowlist gate is what refuses it: the zero
/// pubkey's commitment was never enabled, so the lookup reads the empty Word and the proc traps
/// before the signature check.
#[tokio::test]
async fn d5d_unstaged_pubkey_rejects() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, _b) = seam_keys(&bytes);
    let driver_src = attestation_driver_src(&preimage, len_bytes, &[], &[]);
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT")
    );
    Ok(())
}

// PROBE (export check for the new proc)
// ------------------------------------------------------------------------------------------------

/// The assembled library exports `verify_attestation` under its fully-qualified path — the same
/// rename guard as the other export probes, for the attestation stage.
#[test]
fn probe_attestation_verify_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::attestation_verify::verify_attestation";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical D5d proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}
