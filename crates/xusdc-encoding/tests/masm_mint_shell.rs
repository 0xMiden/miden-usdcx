//! 01 faucet mint-precondition shell suite (P5-01 slice): every behavior test drives
//! the FAUCET(01)-owned `xreserve::deposit_intent_parser::assert_deposit_intent` shell
//! through MockChain `execute().await` via a CALL-entered driver component (account
//! context — the kernel authenticates `active_account::get_item` as account-origin).
//! Canonical 04 vectors are loaded by reference; the R-MINT-1..5 rows assert the
//! ratified seam mapping (`ERR_DI_*` through the shell call path); R-MINT-6/7 assert
//! the two NEW faucet-owned errors against mismatched config slots.
//!
//! RED-SUITE: the shell module holds only the named placeholder trap
//! ("red-suite placeholder: assert_deposit_intent is not implemented") — all nine
//! behavior cases below are RED on that trap, via real execution, until the staged
//! implementation commits land. The two probes are declared green scaffolds.

mod support;

use anyhow::Result;
use miden_processor::ExecutionError;
use miden_processor::operation::OperationError;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use rstest::rstest;
use support::*;
use xusdc_encoding::vectors::{AmtVector, DiVector, load, parse_hex32};
use xusdc_encoding::xreserve::encoding::bytes32_to_storage_map_key;

/// Looks up a canonical 04 DepositIntent vector by id (by-reference loading; G1).
fn di(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

/// Derives the TEST-ONLY config words from an accept vector: domain word
/// `[remote_domain, 0, 0, 0]` and the identifier slot value = the canonical key-Word
/// of the vector's remoteToken bytes (ratified D-C representation), computed via the
/// 04-owned Rust routine `bytes32_to_storage_map_key` (NS-1 name; by reference).
fn config_for(vector_id: &str, domain: u32, flip_identifier_byte: bool) -> (Word, Word) {
    let f = di(vector_id).fields.as_ref().expect("config vector carries fields");
    let domain_word =
        Word::new([Felt::from(domain), miden_protocol::ZERO, miden_protocol::ZERO, miden_protocol::ZERO]);
    let mut identifier_bytes = parse_hex32(&f.remote_token_hex);
    if flip_identifier_byte {
        identifier_bytes[0] ^= 0xff;
    }
    let identifier_word = Word::from(bytes32_to_storage_map_key(&identifier_bytes));
    (domain_word, identifier_word)
}

// HAPPY PATH FIRST (G4) — matching config x both canonical accept vectors
// ================================================================================================

#[rstest]
#[case::hookdata("di-pos-hookdata")]
#[case::empty_hookdata("di-pos-empty-hookdata")]
#[tokio::test]
async fn happy_path_mint_preconditions(#[case] vector_id: &str) -> Result<()> {
    let v = di(vector_id);
    let f = v.fields.as_ref().expect("accept vector carries fields");
    let (domain, identifier) = config_for(vector_id, TEST_DOMAIN, false);
    let driver_src =
        shell_driver_src(&v.preimage_values(), v.len_felts, Some(f.hook_data_len));
    let h = setup_shell_account(domain, identifier, &driver_src, SHELL_DRIVER_PATH)?;
    let executed = run_call_driver(&h, "drive").await.unwrap_or_else(|e| {
        panic!("vector {vector_id}: the shell must accept a matching DepositIntent: {e}")
    });
    // the shell is read-only: the only account mutation is the auth nonce increment
    assert_eq!(
        executed.account_delta().nonce_delta(),
        miden_protocol::ONE,
        "auth must increment the nonce exactly once"
    );
    assert!(
        executed.account_delta().storage().is_empty(),
        "the shell must not write account storage"
    );
    Ok(())
}

// R-MINT REJECTS (parametrized; every case pins the EXACT expected error)
// ================================================================================================
// Rows 1-5: the ratified seam mapping — canonical reject vectors trap inside the
// 04-owned parser, propagated through the shell call path (matching config so the
// parser trap is the only candidate). Rows 6-7: NEW faucet-owned compares against
// deliberately mismatched config over an accept vector (6 mismatches the domain with a
// MATCHING identifier; 7 mismatches only the identifier — isolating each assert).

#[rstest]
#[case::r_mint_1_bad_magic("di-rej-bad-magic", TEST_DOMAIN, false, "ERR_DI_BAD_MAGIC")]
#[case::r_mint_2_bad_version("di-rej-bad-version", TEST_DOMAIN, false, "ERR_DI_BAD_VERSION")]
#[case::r_mint_3_zero_amount("di-rej-zero-amount", TEST_DOMAIN, false, "ERR_DI_ZERO_FIELD")]
#[case::r_mint_4_zero_local_token("di-rej-zero-local-token", TEST_DOMAIN, false, "ERR_DI_ZERO_FIELD")]
#[case::r_mint_5_zero_local_depositor(
    "di-rej-zero-local-depositor",
    TEST_DOMAIN,
    false,
    "ERR_DI_ZERO_FIELD"
)]
#[case::r_mint_6_wrong_domain("di-pos-hookdata", TEST_WRONG_DOMAIN, false, "ERR_XRESERVE_WRONG_DOMAIN")]
#[case::r_mint_7_wrong_identifier("di-pos-hookdata", TEST_DOMAIN, true, "ERR_XRESERVE_WRONG_IDENTIFIER")]
#[tokio::test]
async fn r_mint_rejects(
    #[case] vector_id: &str,
    #[case] domain: u32,
    #[case] flip_identifier_byte: bool,
    #[case] expected_err: &str,
) -> Result<()> {
    // config always derives from the accept vector (reject vectors carry no fields
    // block; for rows 1-5 the config is irrelevant — the parser traps first)
    let (domain_word, identifier_word) = config_for("di-pos-hookdata", domain, flip_identifier_byte);
    let v = di(vector_id);
    let len_felts = v.staging_len_felts.unwrap_or(v.len_felts);
    let driver_src = shell_driver_src(&v.preimage_values(), len_felts, None);
    let h = setup_shell_account(domain_word, identifier_word, &driver_src, SHELL_DRIVER_PATH)?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(result, shell_error_by_name(expected_err));
    Ok(())
}

// PROBES (declared green scaffolds — harness mechanics, not shell behavior)
// ================================================================================================

/// P1 (D-1A / D-A ratified check): the assembled library exports the canonical NESTED
/// shell path (mirrors 04's `probe_p1_exports`; exports render absolute at 0.23.3).
#[test]
fn probe_shell_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::deposit_intent_parser::assert_deposit_intent";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical shell proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

/// P2 (the 0.23.3 canary — run FIRST via its own `--exact` invocation, §8 of the plan):
/// a probe component reads BOTH named value slots via `word(\"label\")[0..2]` +
/// `active_account::get_item` from a CALL-entered proc and pins the fixture words —
/// the spike's Q4/Q5/Q6 pipeline re-proven on the pinned 0.23.3 stack, independent of
/// the shell implementation.
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

// D5B AMOUNT/FEE PRECONDITIONS (P5-01 slice 2) — RED-SUITE
// ================================================================================================
// Drives the NEW faucet-owned `xreserve::deposit_intent_parser::assert_mint_amounts` shell
// through MockChain `execute().await`. `amount`/`maxFee` are spliced into a base accept
// preimage from the canonical 04 `amt-*` vectors (by reference, G1); `feeAmount` is staged
// on the advice stack (§4 Option C). RED-SUITE: the shell holds only the placeholder trap
// (`ERR_UNIMPLEMENTED_MINT_AMOUNTS`), so every behavior case below is RED on that trap via
// real execution until the green commits land. `probe_mint_amounts_exports` is a declared
// green scaffold.

/// The D5b scale exponent, passed as a proc parameter (NOT a faucet constant): it matches
/// the scale-6 `amt-*` vectors and keeps DEV-5 / Q-CRY-6 (scale factor) cleanly OPEN — the
/// production source is deferred to the xreserve_mint/config slice (plan §10, decision 2).
const D5B_SCALE_EXP: u32 = 6;

/// Looks up a canonical 04 amount vector by id (by-reference loading; G1).
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
fn d5b_harness(amount_limbs: [u32; 8], maxfee_limbs: [u32; 8]) -> Result<ShellHarness> {
    let base = di("di-pos-empty-hookdata").preimage_values();
    let preimage = splice_amounts(&base, amount_limbs, maxfee_limbs);
    let (domain, identifier) = config_for("di-pos-empty-hookdata", TEST_DOMAIN, false);
    let driver_src = mint_amounts_driver_src(&preimage, D5B_SCALE_EXP);
    setup_shell_account(domain, identifier, &driver_src, SHELL_DRIVER_PATH)
}

// HAPPY PATH FIRST (G4)
// ------------------------------------------------------------------------------------------------

#[rstest]
// feeAmount == 0 (MVP default) accepted; amount (amt-ge-gt.a) > maxFee (amt-ge-gt.b)
#[case::fee_zero(amt("amt-ge-gt").le_limbs(), amt("amt-ge-gt").b_le_limbs(), fee_advice_felts([0u32; 8]))]
// boundary amount == maxFee accepted (R-MINT-10 is `<`, not `<=`)
#[case::amount_eq_maxfee(amt("amt-ge-eq").le_limbs(), amt("amt-ge-eq").b_le_limbs(), fee_advice_felts([0u32; 8]))]
// boundary feeAmount == maxFee accepted (R-MINT-11 is `>`, not `>=`)
#[case::fee_eq_maxfee(amt("amt-pos-2").le_limbs(), amt("amt-ge-eq").le_limbs(), fee_advice_felts(amt("amt-ge-eq").le_limbs()))]
// value at AssetAmount::MAX accepted at the cap; amount (cap) >= maxFee (amt-pos-1)
#[case::cap_value(amt("amt-cap-accept").le_limbs(), amt("amt-pos-1").le_limbs(), fee_advice_felts([0u32; 8]))]
#[tokio::test]
async fn d5b_happy_amount_fee(
    #[case] amount_limbs: [u32; 8],
    #[case] maxfee_limbs: [u32; 8],
    #[case] fee_advice: Vec<Felt>,
) -> Result<()> {
    let h = d5b_harness(amount_limbs, maxfee_limbs)?;
    let executed = run_call_driver_with_advice(&h, "drive", Some(fee_advice))
        .await
        .unwrap_or_else(|e| panic!("D5b must accept these reduced amount/fee values: {e}"));
    // the shell is read-only: the only account mutation is the auth nonce increment
    assert_eq!(
        executed.account_delta().nonce_delta(),
        miden_protocol::ONE,
        "auth must increment the nonce exactly once"
    );
    assert!(
        executed.account_delta().storage().is_empty(),
        "the D5b shell must not write account storage"
    );
    Ok(())
}

// REJECTS — plain `assert` traps (R-MINT-9 ERR_X_TOO_LARGE; R-MINT-10/11 faucet errors)
// ------------------------------------------------------------------------------------------------
// Each case pins the EXACT expected error (no `is_err()`); the family is parametrized
// (parametrize-related-tests). ERR_X_TOO_LARGE propagates from the 04 reducer's
// `assert.err=` (a FailedAssertion), so the plain `assert_transaction_executor_error!`
// (MasmError) form applies — same as `masm_dual.rs` reject vectors.

#[rstest]
// R-MINT-9: high-4 limbs nonzero on the AMOUNT reduction
#[case::r_mint_9_amount_overflow(amt("amt-rej-limb-overflow").le_limbs(), amt("amt-pos-1").le_limbs(), fee_advice_felts([0u32; 8]), "ERR_X_TOO_LARGE")]
// R-MINT-9: high-4 limbs nonzero on the MAXFEE reduction (amount reduces OK first)
#[case::r_mint_9_maxfee_overflow(amt("amt-pos-2").le_limbs(), amt("amt-rej-limb-overflow").le_limbs(), fee_advice_felts([0u32; 8]), "ERR_X_TOO_LARGE")]
// R-MINT-9: high-4 limbs nonzero on the FEEAMOUNT (advice) reduction
#[case::r_mint_9_fee_overflow(amt("amt-pos-2").le_limbs(), amt("amt-pos-1").le_limbs(), fee_advice_felts(amt("amt-rej-limb-overflow").le_limbs()), "ERR_X_TOO_LARGE")]
// R-MINT-10: reduced amount (amt-ge-lt.a) < maxFee (amt-ge-lt.b)
#[case::r_mint_10_amount_below_fee(amt("amt-ge-lt").le_limbs(), amt("amt-ge-lt").b_le_limbs(), fee_advice_felts([0u32; 8]), "ERR_XRESERVE_AMOUNT_BELOW_FEE")]
// R-MINT-11: amount >= maxFee passes, then reduced feeAmount (amt-ge-lt.b) > maxFee (amt-ge-lt.a)
#[case::r_mint_11_fee_over_maxfee(amt("amt-pos-2").le_limbs(), amt("amt-ge-lt").le_limbs(), fee_advice_felts(amt("amt-ge-lt").b_le_limbs()), "ERR_XRESERVE_FEE_OVER_MAX")]
#[tokio::test]
async fn d5b_amount_fee_rejects(
    #[case] amount_limbs: [u32; 8],
    #[case] maxfee_limbs: [u32; 8],
    #[case] fee_advice: Vec<Felt>,
    #[case] expected_err: &str,
) -> Result<()> {
    let h = d5b_harness(amount_limbs, maxfee_limbs)?;
    let result = run_call_driver_with_advice(&h, "drive", Some(fee_advice)).await;
    assert_transaction_executor_error!(result, shell_error_by_name(expected_err));
    Ok(())
}

// REJECTS — advice-provider hygiene (§4 Option C, rule 3): missing + malformed advice
// ------------------------------------------------------------------------------------------------

/// Missing `feeAmount` advice must ERROR (never default): the advice-stack read traps with
/// `AdviceError::StackReadFailed` ("advice stack read failed"). Pinned on the exact
/// `ExecutionError::AdviceError` variant + message (not `is_err()`).
#[tokio::test]
async fn d5b_fee_advice_missing() -> Result<()> {
    // amount (amt-ge-gt.a) >= maxFee (amt-ge-gt.b) so execution reaches the feeAmount read
    let h = d5b_harness(amt("amt-ge-gt").le_limbs(), amt("amt-ge-gt").b_le_limbs())?;
    let result = run_call_driver_with_advice(&h, "drive", None).await;
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::AdviceError { ref err, .. }
            if format!("{err}").contains("advice stack read failed")
    );
    Ok(())
}

/// A malformed (non-u32) `feeAmount` limb must ERROR: the reducer's `u32assertw` guard
/// traps `ERR_FELT_OUT_OF_FIELD`. `u32assert*` surfaces as `OperationError::U32AssertionFailed`
/// (not `FailedAssertion`), so the named error is pinned on that variant's code AND message
/// — same strength as `masm_dual.rs`'s `amt-guard-limb-not-u32` row.
#[tokio::test]
async fn d5b_fee_advice_malformed_limb() -> Result<()> {
    let h = d5b_harness(amt("amt-ge-gt").le_limbs(), amt("amt-ge-gt").b_le_limbs())?;
    // a felt at 2^32 is a valid field element but NOT a valid u32 limb
    let malformed = vec![Felt::try_from(1u64 << 32).expect("2^32 is within the field"); 8];
    let result = run_call_driver_with_advice(&h, "drive", Some(malformed)).await;
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

// PROBE (declared green scaffold — D-1A export check for the new proc)
// ------------------------------------------------------------------------------------------------

/// The assembled library exports the canonical NESTED D5b proc path (mirrors
/// `probe_shell_exports`; exports render absolute at 0.23.3).
#[test]
fn probe_mint_amounts_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::deposit_intent_parser::assert_mint_amounts";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical D5b proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// D5C NONCE REPLAY GUARD (P5-01 slice 3) — RED-SUITE
// ================================================================================================
// Drives the NEW faucet-owned `xreserve::deposit_intent_parser::assert_nonce_unused` shell
// through MockChain `execute().await`. The guard derives `key = bytes32_to_key(nonce felt[51..58])`
// (consumed BY REFERENCE, G1), reads `usedNonces[key]` via the canary-proven
// `active_account::get_map_item`, and asserts `== EMPTY_WORD` else traps R-MINT-12. D5c is
// assert-zero ONLY — the nonce SET is deferred to D5e. RED-SUITE: the shell holds only the
// placeholder trap ("red-suite placeholder: assert_nonce_unused is not implemented"), so every
// behavior case below is RED via REAL execution until the green commit lands.
// `probe_nonce_unused_exports` is a declared green scaffold.

/// Any non-empty marker Word for seeding `usedNonces` (distinct from `EMPTY_WORD`). The real
/// D5e marker value is out of scope for D5c (assert-zero only); the guard only distinguishes
/// empty vs non-empty.
const NONCE_MARKER: [u32; 4] = [1, 0, 0, 0];

/// Derives the canonical `usedNonces` map key for a vector's nonce via the 04-owned Rust
/// routine (`bytes32_to_storage_map_key`, by reference, G1) — guaranteed to match the MASM
/// `bytes32_to_key(nonce felt[51..58])` by TV-DUAL-1.
fn nonce_key(vector_id: &str) -> Word {
    let f = di(vector_id).fields.as_ref().expect("accept vector carries fields");
    Word::from(bytes32_to_storage_map_key(&f.bytes32("nonce")))
}

// HAPPY PATH FIRST (G4) — an unused nonce (empty map) passes the guard
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
        executed.account_delta().nonce_delta(),
        miden_protocol::ONE,
        "auth must increment the nonce exactly once"
    );
    assert!(
        executed.account_delta().storage().is_empty(),
        "D5c is assert-zero only: it must not write account storage (no nonce SET)"
    );
    Ok(())
}

// REPLAY REJECT (R-MINT-12) — a seeded (used) nonce traps with the EXACT error
// ------------------------------------------------------------------------------------------------

#[rstest]
#[case::hookdata("di-pos-hookdata")]
#[case::empty_hookdata("di-pos-empty-hookdata")]
#[tokio::test]
async fn d5c_replay_rejects(#[case] vector_id: &str) -> Result<()> {
    let v = di(vector_id);
    let (domain, identifier) = config_for(vector_id, TEST_DOMAIN, false);
    let driver_src = nonce_driver_src(&v.preimage_values());
    // seed usedNonces[key(nonce)] = marker so the guard's REAL get_map_item read returns
    // non-empty and the assert-zero traps R-MINT-12
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
    // (canary Q4, re-proven at the faucet level). The "other" key is THIS nonce with one
    // byte flipped (the `config_for` identifier-flip idiom), so it is guaranteed distinct
    // (the two canonical accept vectors happen to share a nonce, so cross-vector keys would
    // collide).
    let run_id = "di-pos-hookdata";
    let f = di(run_id).fields.as_ref().expect("accept vector carries fields");
    let mut other_nonce = f.bytes32("nonce");
    other_nonce[0] ^= 0xff;
    let other_key = Word::from(bytes32_to_storage_map_key(&other_nonce));
    assert_ne!(other_key, nonce_key(run_id), "the flipped-byte nonce key must differ");

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
    let executed = run_call_driver(&h, "drive").await.unwrap_or_else(|e| {
        panic!("a seeded-but-unrelated nonce must not reject {run_id}: {e}")
    });
    assert_eq!(executed.account_delta().nonce_delta(), miden_protocol::ONE);
    assert!(
        executed.account_delta().storage().is_empty(),
        "D5c is assert-zero only: it must not write account storage (no nonce SET)"
    );
    Ok(())
}

// PROBE (declared green scaffold — D-1A export check for the new proc)
// ------------------------------------------------------------------------------------------------

/// The assembled library exports the canonical NESTED D5c proc path (mirrors
/// `probe_shell_exports`/`probe_mint_amounts_exports`; exports render absolute at 0.23.3).
#[test]
fn probe_nonce_unused_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::deposit_intent_parser::assert_nonce_unused";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical D5c proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// D5D ATTESTATION VERIFY (P5-01 slice 4) — RED-SUITE
// ================================================================================================
// Drives the NEW faucet-owned `xreserve::attestation_verify::verify_attestation` shell through
// MockChain execute().await: keccak the DepositIntent payload (hash_bytes), gate the candidate
// pubkey against xReserveAttesters (get_map_item over Poseidon2(pubkey) -> R-MINT-13), and
// ECDSA-verify the signature (verify_prehash -> R-MINT-14). The candidate pubkey is read ONCE into
// one local region that feeds BOTH the commitment lookup and verify_prehash (the seam).
//
// Attester keypairs/signatures are generated IN-TEST (k256 + sha3 + miden-crypto), zero touch to
// the 04 canonical artifact; key A (seed 1) and key B (seed 2) sign the SAME payload, so the seam
// test can pair an allowlisted commitment with a foreign valid signature.
//
// RED-SUITE: the shell is the executing-red placeholder — it runs hash_bytes + pubkey_commitment +
// get_map_item + verify_prehash then traps ERR_XRESERVE_D5D_RED_PLACEHOLDER, so the four behavior
// cases are RED via REAL primitive execution until the implementation commit wires the gate. The
// advice-hygiene case + the export probe are declared green scaffolds.

/// The canonical payload the D5d cases keccak + sign over: the 240-byte (60-felt, no-hookData)
/// accept DepositIntent, consumed BY REFERENCE (G1).
const ATTESTATION_VECTOR: &str = "di-pos-empty-hookdata";

/// Any non-empty enabled-marker Word for the allowlist value (absent/EMPTY_WORD = not allowlisted).
const ATTESTER_MARKER: [u32; 4] = [1, 0, 0, 0];

/// (preimage felts, payload bytes, len_bytes) for the attestation payload — the bytes the attester
/// signs MUST equal the bytes the on-chain keccak hashes (the staged felts reconstruct them u32-LE).
fn attestation_payload() -> (Vec<Felt>, Vec<u8>, u64) {
    let v = di(ATTESTATION_VECTOR);
    let bytes = v.bytes();
    let len_bytes = bytes.len() as u64;
    (v.preimage_values(), bytes, len_bytes)
}

/// The seam pair: key A (allowlisted in the happy/forged cases) and key B (the foreign key), both
/// signing keccak256(the SAME payload). Distinct commitments.
fn seam_keys(payload: &[u8]) -> (AttesterVector, AttesterVector) {
    let a = gen_attester(1, payload);
    let b = gen_attester(2, payload);
    assert_ne!(a.commitment, b.commitment, "seam keys A and B must have distinct commitments");
    (a, b)
}

/// Advice stack pairing one attester's pubkey with another's signature (the seam attack input):
/// `[pubkey(9), sig(17)]`.
fn paired_advice(pubkey_of: &AttesterVector, sig_of: &AttesterVector) -> Vec<Felt> {
    pubkey_of.pubkey_felts.iter().chain(sig_of.sig_felts.iter()).copied().collect()
}

// HAPPY PATH FIRST (G4)
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn d5d_happy_attestation() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, _b) = seam_keys(&bytes);
    let driver_src = attestation_driver_src(&preimage, len_bytes);
    // seed the allowlist with A's commitment -> A is an enabled attester
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let executed = run_call_driver_with_advice(&h, "drive", Some(a.advice()))
        .await
        .unwrap_or_else(|e| panic!("an allowlisted attester + valid signature must pass D5d: {e}"));
    // the verify shell is read-only: the only account mutation is the auth nonce increment
    assert_eq!(
        executed.account_delta().nonce_delta(),
        miden_protocol::ONE,
        "auth must increment the nonce exactly once"
    );
    assert!(
        executed.account_delta().storage().is_empty(),
        "the D5d verify shell must not write account storage"
    );
    Ok(())
}

// REJECTS — each pins the EXACT expected error (no is_err())
// ------------------------------------------------------------------------------------------------

/// §4.D forged-sig (R-MINT-14): an allowlisted pubkey A with a WELL-FORMED tampered signature
/// (B's valid-for-B signature, not a malformed-bytes abort) -> verify_prehash returns 0.
#[tokio::test]
async fn d5d_forged_sig_rejects() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, b) = seam_keys(&bytes);
    let driver_src = attestation_driver_src(&preimage, len_bytes);
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver_with_advice(&h, "drive", Some(paired_advice(&a, &b))).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_SIG_INVALID"));
    Ok(())
}

/// §4.E non-allowlisted (R-MINT-13): pubkey B with B's valid signature, but only A is allowlisted
/// -> xReserveAttesters[Poseidon2(B)] is EMPTY_WORD.
#[tokio::test]
async fn d5d_non_allowlisted_rejects() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, b) = seam_keys(&bytes);
    let driver_src = attestation_driver_src(&preimage, len_bytes);
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver_with_advice(&h, "drive", Some(b.advice())).await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT")
    );
    Ok(())
}

// THE SEAM (the catastrophic case) — BOTH attacker arrangements must reject
// ------------------------------------------------------------------------------------------------

/// An allowlisted commitment must NOT be pairable with a foreign valid signature. Drives BOTH
/// arrangements through real execution: (1) A's pubkey (allowlisted) + B's signature -> R-MINT-14;
/// (2) B's pubkey + B's signature, B not allowlisted -> R-MINT-13. The single pubkey local region
/// makes it impossible to check one pubkey against the allowlist and verify against another.
#[tokio::test]
async fn d5d_seam_both_arrangements_reject() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, b) = seam_keys(&bytes);
    let driver_src = attestation_driver_src(&preimage, len_bytes);
    let allowlist_a = Some((a.commitment, Word::from(ATTESTER_MARKER)));

    // arrangement 1: allowlisted pubkey A + B's (foreign, valid-for-B) signature -> R-MINT-14
    let h1 = setup_attestation_account(allowlist_a, &driver_src, SHELL_DRIVER_PATH)?;
    let r1 = run_call_driver_with_advice(&h1, "drive", Some(paired_advice(&a, &b))).await;
    assert_transaction_executor_error!(r1, shell_error_by_name("ERR_XRESERVE_SIG_INVALID"));

    // arrangement 2: B's pubkey + B's valid signature, but B is NOT allowlisted -> R-MINT-13
    let h2 = setup_attestation_account(allowlist_a, &driver_src, SHELL_DRIVER_PATH)?;
    let r2 = run_call_driver_with_advice(&h2, "drive", Some(b.advice())).await;
    assert_transaction_executor_error!(r2, shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT"));
    Ok(())
}

// ADVICE-PROVIDER HYGIENE (declared green scaffold) — missing advice must fail closed
// ------------------------------------------------------------------------------------------------

/// Missing pubkey/signature advice must ERROR (never default): the materialization `adv_push*`
/// traps with `AdviceError::StackReadFailed` ("advice stack read failed"). Green on arrival (the
/// fail-closed materialization is structural), like the export probe.
#[tokio::test]
async fn d5d_missing_advice_traps() -> Result<()> {
    let (preimage, bytes, len_bytes) = attestation_payload();
    let (a, _b) = seam_keys(&bytes);
    let driver_src = attestation_driver_src(&preimage, len_bytes);
    let h = setup_attestation_account(
        Some((a.commitment, Word::from(ATTESTER_MARKER))),
        &driver_src,
        SHELL_DRIVER_PATH,
    )?;
    let result = run_call_driver_with_advice(&h, "drive", None).await;
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::AdviceError { ref err, .. }
            if format!("{err}").contains("advice stack read failed")
    );
    Ok(())
}

// PROBE (declared green scaffold — D-1A export check for the new proc)
// ------------------------------------------------------------------------------------------------

/// The assembled library exports the canonical NESTED D5d proc path (mirrors the other export
/// probes; exports render absolute at 0.23.3).
#[test]
fn probe_attestation_verify_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::attestation_verify::verify_attestation";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical D5d proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}
