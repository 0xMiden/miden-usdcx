//! Shared test-support for the 01 faucet mint-precondition shell suite (P5-01 slice).
//!
//! OWNERSHIP NOTE: the `ERR_XRESERVE_*` constants and the config-slot labels below are
//! FAUCET(01)-owned TEST-SIDE mirrors — the 04 library crate owns none of them (NS-2:
//! 01 owns only mint-specific assertions). They are the single Rust source for both the
//! fixture slot bindings and the generated-driver interpolation; once the shell module
//! declares its production `word("…")` slot consts (staged C5 commits), the
//! constant-parity suite pins the production labels against these.
//!
//! Harness mechanics mirror `tests/masm_dual.rs` (assemble → bind → MockChain →
//! execute) extended per the approved plan: the shell reads config slots via
//! `active_account::get_item`, which the kernel authenticates as account-origin, so the
//! driver is a CALL-entered account component proc that stages the preimage in its own
//! (account-context) memory and `exec`s the shell — exactly the production
//! `xreserve_mint` calling shape.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result};
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountId, StorageSlot, StorageSlotName};
use miden_protocol::assembly::Library;
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::{ExecutedTransaction, TransactionKernel};
use miden_protocol::{Felt, Word};
use miden_processor::advice::AdviceInputs;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::TransactionExecutorError;
use xusdc_encoding::xreserve::encoding::masm_error_by_name;

// TEST-ONLY FAUCET CONFIG (Q-DOM-1 / DEV-10 OPEN)
// ================================================================================================
// Q-DOM-1: the real Miden domain id is Circle-assigned and OPEN — `TEST_DOMAIN` exists
// solely to match the canonical 04 accept vectors' `remote_domain` (= 7) and must never
// be presented as the real value. DEV-10: the AccountId↔bytes32 identifier encoding is
// Circle-OPEN; the test identifier is the accept vector's remoteToken bytes, nothing
// more.

/// Matches `di-pos-hookdata` / `di-pos-empty-hookdata` `fields.remote_domain`.
pub const TEST_DOMAIN: u32 = 7;
/// Any value != the vectors' remote_domain, for the R-MINT-6 reject.
pub const TEST_WRONG_DOMAIN: u32 = 8;

/// Slot labels (frozen CMP-A6 `XReserveDomainConfig` field names under the product
/// namespace). The MASM shell module must declare `word("…")` consts with byte-identical
/// labels (parity-enforced from the C5 commits on).
pub const DOMAIN_CONFIG_SLOT_LABEL: &str = "xusdc::xreserve::domain_config::domain";
pub const IDENTIFIER_CONFIG_SLOT_LABEL: &str = "xusdc::xreserve::domain_config::identifier";

// FAUCET(01) ERROR MIRRORS (frozen names: 01 TEST-AND-VERIFICATION-HARNESS.md:72-73)
// ================================================================================================

/// Name → constant table for the faucet-owned shell errors (D-2 string `MasmError`
/// pattern). The implementation must declare byte-identical strings in MASM. The two
/// D5b amount/fee errors (R-MINT-10/11) are PROPOSED names pending human approval
/// (plan §7); the D5b green commit declares the matching MASM consts + adds them to
/// `SHELL_ERRORS_DECLARED` for parity. The red-suite carries them here so the D5b
/// behavior tests can name their EXACT expected error.
pub static SHELL_ERR_TABLE: [(&str, MasmError); 4] = [
    (
        "ERR_XRESERVE_WRONG_DOMAIN",
        MasmError::from_static_str("deposit intent remote domain does not match the faucet domain"),
    ),
    (
        "ERR_XRESERVE_WRONG_IDENTIFIER",
        MasmError::from_static_str(
            "deposit intent remote token does not match the faucet identifier",
        ),
    ),
    (
        "ERR_XRESERVE_AMOUNT_BELOW_FEE",
        MasmError::from_static_str("deposit intent amount is below the max fee"),
    ),
    (
        "ERR_XRESERVE_FEE_OVER_MAX",
        MasmError::from_static_str("operator fee amount exceeds the deposit intent max fee"),
    ),
];

/// Looks up an expected MASM error: faucet-owned shell errors first, then the 04
/// library's table (`ERR_DI_*` rows of the ratified seam mapping).
pub fn shell_error_by_name(name: &str) -> &'static MasmError {
    SHELL_ERR_TABLE
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, e)| e)
        .or_else(|| masm_error_by_name(name))
        .unwrap_or_else(|| panic!("test names unknown MASM error constant {name}"))
}

// HARNESS (assemble → bind components+slots → MockChain account)
// ================================================================================================

/// Memory base for preimages staged by the driver proc in ITS OWN call context
/// (word-aligned; same base convention as `masm_dual.rs`). Test-fixture-only global
/// staging: the driver owns the entire fresh call context, so the
/// `masm-locals-over-globals` scratch rule is deliberately not applied here (recorded
/// deviation; the shell itself uses no memory at all).
pub const INTENT_PTR: u64 = 1024;

/// Module path of the generated per-case shell driver component.
pub const SHELL_DRIVER_PATH: &str = "xusdc::test_fixtures::shell_driver";
/// Module path of the slot-binding probe component (P2 canary).
pub const SLOT_PROBE_PATH: &str = "xusdc::test_fixtures::slot_probe";

/// Assembles the `asm/standards/xreserve` tree into one library under namespace
/// `xreserve` — lifted from `masm_dual.rs:41-47` (test scaffolding, not an owned
/// routine; kept byte-equivalent).
pub fn assemble_xreserve_lib() -> Result<Library> {
    let assembler = TransactionKernel::assembler().with_warnings_as_errors(true);
    let lib = assembler
        .assemble_library_from_dir(xusdc_encoding::xreserve_asm_dir(), "xreserve")
        .map_err(|e| anyhow::anyhow!("xreserve library failed to assemble: {e}"))?;
    Ok(Arc::unwrap_or_clone(lib))
}

pub struct ShellHarness {
    pub mock_chain: MockChain,
    pub account_id: AccountId,
    pub driver_code: AccountComponentCode,
    pub driver_path: &'static str,
}

/// Builds the MockChain account carrying [the xreserve component WITH the two named
/// value config slots] + [the generated driver component], per the spike-proven Q4/Q5
/// binding (`StorageSlotName::new(label)` ↔ MASM `word("label")`).
pub fn setup_shell_account(
    domain: Word,
    identifier: Word,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
    let library = assemble_xreserve_lib()?;

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![
            StorageSlot::with_value(
                StorageSlotName::new(DOMAIN_CONFIG_SLOT_LABEL).context("domain slot label")?,
                domain,
            ),
            StorageSlot::with_value(
                StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)
                    .context("identifier slot label")?,
                identifier,
            ),
        ],
        AccountComponentMetadata::new("xusdc-mint-shell-harness"),
    )
    .context("binding the xreserve library + config slots as a component")?;

    let driver_code = CodeBuilder::new()
        .with_dynamically_linked_library(&library)
        .context("linking the xreserve library into the driver component")?
        .compile_component_code(driver_path, driver_src)
        .with_context(|| format!("driver component failed to compile\n--- driver ---\n{driver_src}"))?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-shell-driver"),
    )
    .context("binding the driver component")?;

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [xreserve_component, driver_component])
        .context("adding the shell harness account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(ShellHarness { mock_chain, account_id: account.id(), driver_code, driver_path })
}

/// Executes `call.driver::<proc>` from a trivial tx script (spike alias-import pattern)
/// — the call enters the driver component proc in the ACCOUNT context.
pub async fn run_call_driver(
    h: &ShellHarness,
    proc_name: &str,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src = format!("use {path}->driver\nbegin\n    call.driver::{proc_name}\nend\n", path = h.driver_path);
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_library(&h.driver_code)
        .expect("linking the driver component into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| panic!("driver call script failed to compile: {e}\n--- script ---\n{src}"));
    h.mock_chain
        .build_tx_context(h.account_id, &[], &[])
        .expect("building the tx context")
        .tx_script(tx_script)
        .build()
        .expect("building the transaction")
        .execute()
        .await
}

// GENERATED DRIVER SOURCES
// ================================================================================================

fn word_of(felts: &[Felt]) -> Word {
    Word::new([felts[0], felts[1], felts[2], felts[3]])
}

/// Emits the `push.[..] mem_storew_le.{addr} dropw` staging sequence for a felt slice
/// (zero-padding the trailing word), starting at `INTENT_PTR` — the `masm_dual.rs`
/// staging convention inside the driver proc's own call context.
fn stage_preimage(src: &mut String, felts: &[Felt]) {
    for (i, chunk) in felts.chunks(4).enumerate() {
        let mut w = [miden_protocol::ZERO; 4];
        w[..chunk.len()].copy_from_slice(chunk);
        let addr = INTENT_PTR + 4 * i as u64;
        writeln!(src, "    push.{} mem_storew_le.{addr} dropw", word_of(&w)).unwrap();
    }
}

/// Generates the per-case shell-driver component source: a CALL-entered account proc
/// that stages the case's preimage, pushes `[intent_ptr, len_felts]`, `exec`s the
/// shell, and (happy path) asserts the returned `hook_data_len`.
pub fn shell_driver_src(
    preimage: &[Felt],
    len_felts: u64,
    expected_hook_data_len: Option<u32>,
) -> String {
    let mut src = String::from(
        "use xreserve::deposit_intent_parser\n\n\
         #! Test driver: stages a DepositIntent preimage in the account context and\n\
         #! execs the faucet assertion shell.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    writeln!(src, "    push.{len_felts}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.deposit_intent_parser::assert_deposit_intent\n");
    match expected_hook_data_len {
        // happy path: pin the shell's output, restoring the 16-depth call boundary
        Some(expected) => {
            writeln!(src, "    push.{expected} assert_eq.err=\"driver: hook_data_len mismatch\"")
                .unwrap();
        },
        // reject path: balance the would-be output so an unexpected non-trapping run
        // returns cleanly and the test's exact-error assertion reports the mismatch
        None => src.push_str("    drop\n"),
    }
    src.push_str("end\n");
    src
}

/// Generates the P2 slot-binding probe component: reads BOTH config slots via
/// `word("label")[0..2]` + `active_account::get_item` and pins the fixture words —
/// proving the `StorageSlotName` ↔ `word("…")` linkage and the call-context `get_item`
/// pipeline on the pinned 0.23.3 stack, independent of the shell implementation.
pub fn slot_probe_src(domain: Word, identifier: Word) -> String {
    format!(
        "use miden::protocol::active_account\n\n\
         # slot ids derive from the SAME labels the Rust fixture binds (single source:\n\
         # the tests/support label consts)\n\
         const PROBE_DOMAIN_SLOT = word(\"{domain_label}\")\n\
         const PROBE_IDENTIFIER_SLOT = word(\"{identifier_label}\")\n\n\
         #! Probe: asserts both config slots hold the fixture words.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc read_slots\n\
             push.PROBE_DOMAIN_SLOT[0..2]\n\
             exec.active_account::get_item\n\
             push.{domain}\n\
             assert_eqw.err=\"probe: domain slot mismatch\"\n\
             push.PROBE_IDENTIFIER_SLOT[0..2]\n\
             exec.active_account::get_item\n\
             push.{identifier}\n\
             assert_eqw.err=\"probe: identifier slot mismatch\"\n\
         end\n",
        domain_label = DOMAIN_CONFIG_SLOT_LABEL,
        identifier_label = IDENTIFIER_CONFIG_SLOT_LABEL,
    )
}

// D5B AMOUNT/FEE HELPERS (P5-01 slice 2)
// ================================================================================================

/// Felt offsets of the `amount` (felt[2..9]) and `maxFee` (felt[43..50]) uint256 fields
/// within the staged preimage (DC-1 byte offset / 4 — equal to the MASM
/// `AMOUNT_FELT_OFF` / `MAX_FEE_FELT_OFF` layout consts, parity-checked at the MASM layer
/// by `constant_parity.rs`).
pub const AMOUNT_FELT_OFF: usize = 2;
pub const MAX_FEE_FELT_OFF: usize = 43;

/// Clones a base accept preimage and overwrites the `amount` and `maxFee` fields with the
/// 8 u32-LE limbs of the chosen canonical `amt-*` vectors (consumed BY REFERENCE — no
/// copied vector tables, G1). The rest of the DepositIntent envelope (magic / version /
/// nonzero fields / length) is unchanged, so the 04 structural parse stays valid and
/// execution reaches the D5b reduce+compare.
pub fn splice_amounts(base: &[Felt], amount_limbs: [u32; 8], maxfee_limbs: [u32; 8]) -> Vec<Felt> {
    let mut preimage = base.to_vec();
    for (i, limb) in amount_limbs.iter().enumerate() {
        preimage[AMOUNT_FELT_OFF + i] = Felt::from(*limb);
    }
    for (i, limb) in maxfee_limbs.iter().enumerate() {
        preimage[MAX_FEE_FELT_OFF + i] = Felt::from(*limb);
    }
    preimage
}

/// The 8 u32-LE `feeAmount` limbs as advice-stack felts (`Felt::from(u32)`, infallible —
/// `felt-construction`). `feeAmount == 0` is the operator EXPLICITLY supplying eight zero
/// limbs — distinct from missing advice (which errors, §4 Option C / rule 3).
pub fn fee_advice_felts(limbs: [u32; 8]) -> Vec<Felt> {
    limbs.iter().map(|l| Felt::from(*l)).collect()
}

/// Generates the per-case D5b driver: stages the (spliced) preimage in the account
/// context, pushes `[intent_ptr, scale_exp]`, and `exec`s the faucet `assert_mint_amounts`
/// shell (which reads `feeAmount` from the advice stack). The proc returns `[]`, so the
/// staged-then-consumed stack restores the 16-depth `call` boundary.
pub fn mint_amounts_driver_src(preimage: &[Felt], scale_exp: u32) -> String {
    let mut src = String::from(
        "use xreserve::deposit_intent_parser\n\n\
         #! Test driver: stages a DepositIntent preimage in the account context and execs\n\
         #! the D5b amount/fee precondition shell (feeAmount from the advice stack).\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    writeln!(src, "    push.{scale_exp}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.deposit_intent_parser::assert_mint_amounts\n");
    src.push_str("end\n");
    src
}

/// Like `run_call_driver`, but stages an optional `feeAmount` advice stack into the tx
/// context (`extend_advice_inputs`). `None` ⇒ no advice staged (the missing-advice case,
/// which must error — §4 Option C, rule 3). `AdviceInputs::with_stack` preserves order:
/// the first felt is the first one `adv_push` returns.
pub async fn run_call_driver_with_advice(
    h: &ShellHarness,
    proc_name: &str,
    advice_stack: Option<Vec<Felt>>,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src =
        format!("use {path}->driver\nbegin\n    call.driver::{proc_name}\nend\n", path = h.driver_path);
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_library(&h.driver_code)
        .expect("linking the driver component into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| panic!("driver call script failed to compile: {e}\n--- script ---\n{src}"));
    let mut ctx = h
        .mock_chain
        .build_tx_context(h.account_id, &[], &[])
        .expect("building the tx context")
        .tx_script(tx_script);
    if let Some(stack) = advice_stack {
        ctx = ctx.extend_advice_inputs(AdviceInputs::default().with_stack(stack));
    }
    ctx.build().expect("building the transaction").execute().await
}
