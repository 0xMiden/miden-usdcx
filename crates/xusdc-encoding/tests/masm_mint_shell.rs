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
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use rstest::rstest;
use support::*;
use xusdc_encoding::vectors::{DiVector, load, parse_hex32};
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
