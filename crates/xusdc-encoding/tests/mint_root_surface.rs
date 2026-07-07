//! P5-01 Slice 1 (F1/F3) — procedure-root sole-supply-surface suite. The charter's #1 invariant
//! (CIR-DEPLOY-2: mintable ONLY with a valid Circle Deposit Attestation) must hold at the
//! account-code-commitment / procedure-root level: the ONLY callable account-procedure root that
//! raises `token_supply` is `mint` (the full verify-once -> write-once path). `apply_mint_effects`
//! (the write stage) and `extract_recipient_account_id` (L1) must be reachable ONLY via same-module
//! `exec` from `mint`, never as callable account roots.
//!
//! Two tests, both EXECUTING-RED at the `pub proc` HEAD and GREEN after the demotion:
//! - `apply_mint_effects_root_is_not_a_callable_account_surface`: an external note whose script
//!   `call`s the `apply_mint_effects` MAST root against the PRODUCTION-built faucet. Pre-fix the
//!   root is a member of the account code, so the call executes and mints UNBACKED USDCx (no
//!   attestation / nonce / parse / pause / fee gate) — the failure surfaces the real supply delta.
//!   Post-fix the root is not a member, so the kernel's membership check rejects it (surfaced as the
//!   host `UnknownAccountProcedure` event error, the runtime face of
//!   `ERR_ACCOUNT_PROC_NOT_PART_OF_ACCOUNT_CODE`).
//! - `production_supply_raising_root_set_is_exactly_mint`: enumerates the production component's
//!   callable procedure roots (`AccountComponent::procedures()`) and asserts `apply_mint_effects` /
//!   `extract_recipient_account_id` are absent, `mint` present, and the exported-proc set equals the
//!   frozen sanctioned set (a tripwire: any new export is a potential new supply door). This is the
//!   correct-level replacement for the former file-grep `no_other_supply_surface_static_sweep`.
//!
//! The `apply_mint_effects` MAST root is obtained from a TEST-ONLY assembly of the same source with
//! the proc forced `pub` (`assemble_xreserve_lib_effects_public`): visibility does not change a
//! procedure's MAST, so this is the exact root the production faucet no longer exposes post-fix.

mod support;

use anyhow::Result;
use miden_protocol::account::component::AccountComponentCode;
use miden_protocol::account::{AccountId, StorageSlotDelta, StorageSlotName};
use miden_protocol::note::{Note, NoteType};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_processor::crypto::random::RandomCoin;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::TransactionExecutorError;
use support::*;

/// The frozen sanctioned callable-root set of the shipped `xreserve` library after the F1 demotion:
/// the 15 do-not-demote procs plus `mint` = 16. `apply_mint_effects` and
/// `extract_recipient_account_id` are ABSENT (demoted to same-module `exec`-only). Any drift (a new
/// export, i.e. a new supply door) trips `production_supply_raising_root_set_is_exactly_mint`.
/// Paths render absolute (leading `::`) at assembler 0.23.3.
const FROZEN_CALLABLE_ROOTS: [&str; 16] = [
    "::xreserve::attestation_verify::verify_attestation",
    "::xreserve::attester_admin::set_attester",
    "::xreserve::burn_policy::check_policy",
    "::xreserve::deposit_intent_parser::assert_deposit_intent",
    "::xreserve::deposit_intent_parser::assert_mint_amounts",
    "::xreserve::deposit_intent_parser::assert_nonce_unused",
    "::xreserve::domain_config::domain_init",
    "::xreserve::encoding::bytes32_to_key",
    "::xreserve::encoding::parse_deposit_intent",
    "::xreserve::encoding::pubkey_commitment",
    "::xreserve::encoding::uint256_to_asset_amount",
    "::xreserve::min_burn_admin::set_min_burn_size",
    "::xreserve::mint_deny_guard::check_policy",
    "::xreserve::pause_admin::pause",
    "::xreserve::pause_admin::unpause",
    "::xreserve::xreserve_mint::mint",
];

const APPLY_MINT_EFFECTS_PATH: &str = "xreserve::xreserve_mint::apply_mint_effects";
const EXTRACT_RECIPIENT_PATH: &str = "xreserve::xreserve_mint::extract_recipient_account_id";
const MINT_PATH: &str = "xreserve::xreserve_mint::mint";

/// The MAST root of a proc in the effects-public xreserve library (the demoted procs are `pub`
/// there, so addressable by path; their roots are identical to the shipped private ones).
fn effects_public_root(path: &str) -> Result<Word> {
    let code = AccountComponentCode::from(assemble_xreserve_lib_effects_public()?);
    Ok(Word::from(code.get_procedure_root_by_path(path).unwrap_or_else(|| {
        panic!("the effects-public xreserve library must export {path}")
    })))
}

/// A no-op driver so the assembled-faucet harness has its required (unused) driver; the root-surface
/// test fires a STANDALONE exploit note, not this driver.
fn noop_driver_src() -> String {
    "#! A no-op driver — the root-surface test fires a standalone exploit note, not this driver; the\n\
     #! assembled-faucet harness merely requires at least one driver component.\n\
     #!\n\
     #! Inputs:  [pad(16)]\n\
     #! Outputs: [pad(16)]\n\
     #!\n\
     #! Invocation: call\n\
     pub proc drive\n\
     \x20\x20\x20\x20push.0 drop\n\
     end\n"
        .to_string()
}

/// Builds an external note whose script `call`s the `apply_mint_effects` MAST root directly, staging
/// the 16 in-window operands (`[amount, feeAmount, KEY, recip_suffix, recip_prefix, SERIAL_NUM,
/// P2ID_SCRIPT_ROOT]`; the out-of-window `tag`/`note_type` auto-pad to 0, and `note_type = 0` is a
/// valid `NoteType::Private`, so `output_note::create` does not trap). Attacker-chosen recipient,
/// amount, nonce KEY, and serial — no attestation. Pre-fix this mints; post-fix the call is rejected.
fn apply_mint_effects_exploit_note(
    sender: AccountId,
    recipient: AccountId,
    amount: u64,
    apply_root_hex: &str,
    seed: u64,
) -> Result<Note> {
    let script_root: Word = P2idNote::script_root().into();
    // bottom-first push order (deepest first) so the proc sees `amount` on top; the two out-of-window
    // inputs (tag, note_type) are omitted — they auto-pad to 0 at the `call` boundary.
    let src = format!(
        "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20push.{script_root}\n\
         \x20\x20\x20\x20push.[9,9,9,9]\n\
         \x20\x20\x20\x20push.{prefix}\n\
         \x20\x20\x20\x20push.{suffix}\n\
         \x20\x20\x20\x20push.[1,2,3,4]\n\
         \x20\x20\x20\x20push.0\n\
         \x20\x20\x20\x20push.{amount}\n\
         \x20\x20\x20\x20call.{apply_root_hex}\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
        script_root = script_root,
        prefix = recipient.prefix().as_felt(),
        suffix = recipient.suffix(),
        amount = amount,
        apply_root_hex = apply_root_hex,
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("exploit note script failed to compile: {e}\n--- script ---\n{src}"))?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng).note_type(NoteType::Private).script(script).build()?)
}

/// Executes `note` (unauthenticated input note) against the assembled faucet account.
async fn fire_note(
    af: &AssembledFaucet,
    note: Note,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let account = faucet_account(&af.harness);
    af.harness
        .mock_chain
        .build_tx_context(account, &[], core::slice::from_ref(&note))
        .expect("building the exploit tx context")
        .build()
        .expect("building the exploit transaction")
        .execute()
        .await
}

/// The committed `token_supply` delta (token_config word element 0) of an executed tx, if any.
fn token_supply_delta(executed: &ExecutedTransaction) -> Option<Felt> {
    let slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL).expect("token_config slot label");
    match executed.account_delta().storage().get(&slot) {
        Some(StorageSlotDelta::Value(w)) => Some(w[0]),
        _ => None,
    }
}

// EXECUTING-RED -> GREEN — the external `call` of the apply_mint_effects root
// ================================================================================================

#[tokio::test]
async fn apply_mint_effects_root_is_not_a_callable_account_surface() -> Result<()> {
    const MAX_SUPPLY: u64 = 1_000_000;
    const AMOUNT: u64 = 1_000;

    let af = setup_assembled_faucet(MAX_SUPPLY, 0, |_recipient| (vec![noop_driver_src()], vec![]))?;
    let apply_root = effects_public_root(APPLY_MINT_EFFECTS_PATH)?;
    let note = apply_mint_effects_exploit_note(
        test_account_id(99),
        af.recipient_id,
        AMOUNT,
        &apply_root.to_hex(),
        7,
    )?;

    match fire_note(&af, note).await {
        // GREEN (post-fix): the root is not a member of the account code -> kernel membership reject
        // (host UnknownAccountProcedure, the runtime face of ERR_ACCOUNT_PROC_NOT_PART_OF_ACCOUNT_CODE).
        Err(err) => assert_unknown_account_procedure(&err),
        // RED (pre-fix): the root IS a callable account root -> the exploit executed and minted.
        Ok(executed) => panic!(
            "SECURITY: the apply_mint_effects MAST root is a callable account-procedure root — an \
             external note minted UNBACKED USDCx on the production faucet (token_supply delta = \
             {:?}, {} recipient note(s)) with no attestation/nonce/parse/pause/fee gate; the ungated \
             second supply surface executed",
            token_supply_delta(&executed),
            executed.output_notes().num_notes(),
        ),
    }
    Ok(())
}

// PROCEDURE-ROOT SOLE-SURFACE ENUMERATION (replaces the file-grep sole-surface proxy)
// ================================================================================================

#[test]
fn production_supply_raising_root_set_is_exactly_mint() -> Result<()> {
    let components = production_component_set(1_000_000, 0)?;

    // the xreserve component is the one that exports the mint composition entry.
    let xreserve = components
        .iter()
        .find(|c| c.get_procedure_root_by_path(MINT_PATH).is_some())
        .expect("a production component must export xreserve::xreserve_mint::mint");

    // the account's callable procedure roots (the code-commitment membership set).
    let callable: std::collections::BTreeSet<Word> =
        xreserve.procedures().map(|(root, _is_auth)| Word::from(root)).collect();

    let mint_root = Word::from(
        xreserve.get_procedure_root_by_path(MINT_PATH).expect("mint root resolves"),
    );
    let apply_root = effects_public_root(APPLY_MINT_EFFECTS_PATH)?;
    let extract_root = effects_public_root(EXTRACT_RECIPIENT_PATH)?;

    assert!(callable.contains(&mint_root), "mint must be a callable supply-raising root");
    assert!(
        !callable.contains(&apply_root),
        "apply_mint_effects must NOT be a callable account root — it is the ungated second supply \
         surface (F1); only mint may raise supply"
    );
    assert!(
        !callable.contains(&extract_root),
        "extract_recipient_account_id must NOT be a callable account root (L1)"
    );

    // Frozen tripwire: the exported-proc set is EXACTLY the 16 sanctioned roots.
    let lib: &miden_protocol::assembly::Library = xreserve.component_code().as_ref();
    let mut paths: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    paths.sort();
    let mut expected: Vec<String> = FROZEN_CALLABLE_ROOTS.iter().map(|s| (*s).to_string()).collect();
    expected.sort();
    assert_eq!(
        paths, expected,
        "the xreserve callable-root set drifted from the frozen sanctioned set (a new export is a \
         potential new supply door)"
    );
    Ok(())
}
