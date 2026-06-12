//! MASM execution harness: TV-DUAL-1..3 cross-language conformance tests plus the
//! harness probes/meta-tests. Protocol-derived mechanics (approved plan §4):
//! `TransactionKernel::assembler().with_warnings_as_errors(true)` +
//! `assemble_library_from_dir` (miden-standards/build.rs:45,:77), dynamic library
//! linking into tx scripts (code_builder/mod.rs:224; test_array.rs:127-129), MockChain
//! account + `build_tx_context(...).tx_script(...).execute()` (test_account.rs:158-162,
//! :460-474; the grounding spike), exact-error assertion via
//! `assert_transaction_executor_error!` (miden-testing/src/utils.rs).
//!
//! Every conformance assertion here is on the RESULT OF `execute().await` — there is no
//! assemble-only assertion path, and the Rust mirror is never consulted: expected values
//! come from the canonical artifact, actual values from the VM.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountId};
use miden_protocol::assembly::Library;
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::{ExecutedTransaction, TransactionKernel};
use miden_processor::ExecutionError;
use miden_processor::operation::OperationError;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::TransactionExecutorError;
use xusdc_encoding::vectors::{felt_from_hex, load, word_from_hex};
use xusdc_encoding::xreserve::encoding::masm_error_by_name;

/// Memory base for staged DepositIntent preimages in driver scripts (word-aligned,
/// inside global program memory, clear of anything the kernel stages).
const INTENT_PTR: u64 = 1024;

// HARNESS (assemble → bind → MockChain account)
// ================================================================================================

/// Assembles the `asm/standards/xreserve` tree into one library under namespace
/// `xreserve` — mirrors `miden-standards/build.rs:45,:77` verbatim.
fn assemble_xreserve_lib() -> Result<Library> {
    let assembler = TransactionKernel::assembler().with_warnings_as_errors(true);
    let lib = assembler
        .assemble_library_from_dir(xusdc_encoding::xreserve_asm_dir(), "xreserve")
        .map_err(|e| anyhow::anyhow!("xreserve library failed to assemble: {e}"))?;
    Ok(Arc::unwrap_or_clone(lib))
}

struct Harness {
    mock_chain: MockChain,
    account_id: AccountId,
    library: Library,
}

/// Builds the MockChain account that carries the encoding library (registering its MAST
/// forest with the executor — the spike-proven availability mechanism).
fn setup() -> Result<Harness> {
    let library = assemble_xreserve_lib()?;
    let component = AccountComponent::new(
        library.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-encoding-harness"),
    )
    .context("binding the encoding library as a harness component")?;
    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [component])
        .context("adding the harness account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(Harness { mock_chain, account_id: account.id(), library })
}

/// Compiles a generated driver script with the encoding library dynamically linked and
/// executes it as a transaction (test_array.rs:127-135 pattern).
async fn run_driver(
    h: &Harness,
    src: &str,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_library(&h.library)
        .expect("linking the encoding library into the driver script")
        .compile_tx_script(src)
        .unwrap_or_else(|e| panic!("driver script failed to compile: {e}\n--- driver ---\n{src}"));
    h.mock_chain
        .build_tx_context(h.account_id, &[], &[])
        .expect("building the tx context")
        .tx_script(tx_script)
        .build()
        .expect("building the transaction")
        .execute()
        .await
}

fn word_of(felts: &[Felt]) -> Word {
    Word::new([felts[0], felts[1], felts[2], felts[3]])
}

fn expected_err(name: &str) -> &'static MasmError {
    masm_error_by_name(name)
        .unwrap_or_else(|| panic!("vector names unknown MASM error constant {name}"))
}

/// Emits the `push.[..] mem_storew.{addr} dropw` staging sequence for a felt slice
/// (zero-padding the trailing word), starting at `INTENT_PTR`.
fn stage_preimage(src: &mut String, felts: &[Felt]) {
    for (i, chunk) in felts.chunks(4).enumerate() {
        let mut w = [miden_protocol::ZERO; 4];
        w[..chunk.len()].copy_from_slice(chunk);
        let addr = INTENT_PTR + 4 * i as u64;
        writeln!(src, "    push.{} mem_storew_le.{addr} dropw", word_of(&w)).unwrap();
    }
}

// TV-DUAL-1 — bytes32_to_key (every b32 vector, executed)
// ================================================================================================

#[tokio::test]
async fn tv_dual_1_bytes32_to_key() -> Result<()> {
    let h = setup()?;
    for vec in &load().families.b32 {
        let limbs = vec.packed_felts_values();
        let (b0, b1) = (word_of(&limbs[0..4]), word_of(&limbs[4..8]));
        let expected = word_from_hex(&vec.expected_key);
        let src = format!(
            r#"use xreserve::encoding

begin
    push.{b0}
    push.{b1}
    exec.encoding::bytes32_to_key
    push.{expected}
    assert_eqw.err="vector {id}: key mismatch"
end
"#,
            id = vec.id,
        );
        run_driver(&h, &src).await.unwrap_or_else(|e| {
            panic!("vector {}: MASM bytes32_to_key must produce the canonical key: {e}", vec.id)
        });
    }
    Ok(())
}

// TV-DUAL-2 — uint256_to_asset_amount (every reducer vector: accepts, rejects, guard)
// ================================================================================================

#[tokio::test]
async fn tv_dual_2_uint256_reducer() -> Result<()> {
    let h = setup()?;
    for vec in &load().families.amt {
        match vec.kind.as_str() {
            "accept" => {
                let limbs: Vec<Felt> =
                    vec.le_limbs().iter().map(|l| Felt::from(*l)).collect();
                let (u0, u1) = (word_of(&limbs[0..4]), word_of(&limbs[4..8]));
                let y: u64 = vec.expected_y.as_deref().unwrap().parse().unwrap();
                let src = format!(
                    r#"use xreserve::encoding

begin
    push.{scale}
    push.{u0}
    push.{u1}
    exec.encoding::uint256_to_asset_amount
    push.{y}
    assert_eq.err="vector {id}: amount mismatch"
end
"#,
                    scale = vec.scale_exp,
                    id = vec.id,
                );
                run_driver(&h, &src).await.unwrap_or_else(|e| {
                    panic!("vector {}: MASM reducer must accept and match: {e}", vec.id)
                });
            },
            "reject" | "guard" => {
                let masm_err = vec
                    .masm_err
                    .as_deref()
                    .unwrap_or_else(|| panic!("vector {}: reject without masm_err", vec.id));
                let limbs: Vec<Felt> = match (&vec.staging_felts, &vec.le_limbs) {
                    (Some(staged), _) => staged.iter().map(|s| felt_from_hex(s)).collect(),
                    (None, Some(le)) => le.iter().map(|l| Felt::from(*l)).collect(),
                    (None, None) => panic!("vector {}: no reducer input", vec.id),
                };
                let (u0, u1) = (word_of(&limbs[0..4]), word_of(&limbs[4..8]));
                let src = format!(
                    r#"use xreserve::encoding

begin
    push.{scale}
    push.{u0}
    push.{u1}
    exec.encoding::uint256_to_asset_amount
    drop
end
"#,
                    scale = vec.scale_exp,
                );
                let result = run_driver(&h, &src).await;
                if vec.kind == "guard" {
                    // `u32assert*` traps surface as `OperationError::U32AssertionFailed`
                    // (not `FailedAssertion`), so the named error is pinned on that
                    // variant's code AND message — same strength, correct trap class
                    let expected = expected_err(masm_err);
                    assert_transaction_executor_error!(
                        result,
                        matches ExecutionError::OperationError {
                            err: OperationError::U32AssertionFailed {
                                ref err_code, ref err_msg, ..
                            },
                            ..
                        } if *err_code == expected.code()
                            && err_msg.as_deref() == Some(expected.message())
                    );
                } else {
                    assert_transaction_executor_error!(result, expected_err(masm_err));
                }
            },
            "ge" | "dust" => {}, // Rust-fn-only rows (frozen harness §1; plan §5)
            other => panic!("vector {}: unknown kind {other}", vec.id),
        }
    }
    Ok(())
}

// TV-DUAL-3 — parse_deposit_intent (every di vector; D-4A output contract + layout
// memory assertions via the `layout` constants)
// ================================================================================================

#[tokio::test]
async fn tv_dual_3_parse_deposit_intent() -> Result<()> {
    let h = setup()?;
    for vec in &load().families.di {
        // The hookData-overflow reject is Rust-only (the 1024-felt bound lives in the
        // Rust packer, 04:344) — no MASM leg by design (plan §5).
        if vec.kind == "reject" && vec.masm_err.is_none() {
            continue;
        }
        let preimage = vec.preimage_values();
        let len_felts = vec.staging_len_felts.unwrap_or(vec.len_felts);

        // constants are imported individually (`push.` takes only unqualified constant
        // identifiers — the protocol's own single-const import style, report §2.3)
        let mut src = String::from("use xreserve::encoding\n");
        for c in [
            "MAGIC_FELT_OFF",
            "VERSION_FELT_OFF",
            "AMOUNT_FELT_OFF",
            "REMOTE_DOMAIN_FELT_OFF",
            "REMOTE_TOKEN_FELT_OFF",
            "REMOTE_RECIPIENT_FELT_OFF",
            "LOCAL_TOKEN_FELT_OFF",
            "LOCAL_DEPOSITOR_FELT_OFF",
            "MAX_FEE_FELT_OFF",
            "NONCE_FELT_OFF",
            "HOOK_DATA_LEN_FELT_OFF",
            "HOOK_DATA_FELT_OFF",
        ] {
            writeln!(src, "use xreserve::encoding::layout::{c}").unwrap();
        }
        src.push_str("\nbegin\n");
        stage_preimage(&mut src, &preimage);
        writeln!(src, "    push.{len_felts}").unwrap();
        writeln!(src, "    push.{INTENT_PTR}").unwrap();
        writeln!(src, "    exec.encoding::parse_deposit_intent").unwrap();

        match vec.kind.as_str() {
            "accept" => {
                let f = vec.fields.as_ref().expect("accept vector carries fields");
                let rt: Vec<Felt> =
                    f.remote_token_felts.iter().map(|s| felt_from_hex(s)).collect();
                let (rt0, rt1) = (word_of(&rt[0..4]), word_of(&rt[4..8]));
                // D-4A stack outputs: [remote_domain, REMOTE_TOKEN_1, REMOTE_TOKEN_0, hook_data_len].
                writeln!(
                    src,
                    "    push.{} assert_eq.err=\"vector {}: remote_domain\"",
                    f.remote_domain, vec.id
                )
                .unwrap();
                writeln!(src, "    push.{rt1} assert_eqw.err=\"vector {}: remote_token_1\"", vec.id)
                    .unwrap();
                writeln!(src, "    push.{rt0} assert_eqw.err=\"vector {}: remote_token_0\"", vec.id)
                    .unwrap();
                writeln!(
                    src,
                    "    push.{} assert_eq.err=\"vector {}: hook_data_len\"",
                    f.hook_data_len, vec.id
                )
                .unwrap();
                // Layout-constant memory assertions: every DC-1 field read back from the
                // staged preimage via `layout::*` offsets (run AFTER exec — also proves
                // the parser did not mutate the staged memory).
                for pf in &f.packed {
                    let const_name = match pf.name.as_str() {
                        "magic" => "MAGIC_FELT_OFF",
                        "version" => "VERSION_FELT_OFF",
                        "amount" => "AMOUNT_FELT_OFF",
                        "remote_domain" => "REMOTE_DOMAIN_FELT_OFF",
                        "remote_token" => "REMOTE_TOKEN_FELT_OFF",
                        "remote_recipient" => "REMOTE_RECIPIENT_FELT_OFF",
                        "local_token" => "LOCAL_TOKEN_FELT_OFF",
                        "local_depositor" => "LOCAL_DEPOSITOR_FELT_OFF",
                        "max_fee" => "MAX_FEE_FELT_OFF",
                        "nonce" => "NONCE_FELT_OFF",
                        "hook_data_len" => "HOOK_DATA_LEN_FELT_OFF",
                        "hook_data" => "HOOK_DATA_FELT_OFF",
                        other => panic!("unknown packed field {other}"),
                    };
                    let felts: Vec<Felt> = pf.felts.iter().map(|s| felt_from_hex(s)).collect();
                    // single-felt loads throughout: the DC-1 felt offsets are not
                    // word-aligned, and word memory ops trap on unaligned addresses
                    // (processor `UnalignedWordAccess`, errors.rs:228-232)
                    for (i, felt) in felts.iter().enumerate() {
                        writeln!(
                            src,
                            "    push.{const_name} push.{INTENT_PTR} add push.{i} add \
                             mem_load push.{} assert_eq.err=\"vector {}: layout {} felt {i}\"",
                            felt.as_canonical_u64(),
                            vec.id,
                            pf.name
                        )
                        .unwrap();
                    }
                }
                src.push_str("end\n");
                run_driver(&h, &src).await.unwrap_or_else(|e| {
                    panic!(
                        "vector {}: MASM parser must accept, return the compare fields, and \
                         satisfy the layout assertions: {e}",
                        vec.id
                    )
                });
            },
            "reject" => {
                // Clean up the would-be outputs so a non-trapping run completes cleanly
                // and the error assertion below reports "unexpectedly successful".
                src.push_str("    drop dropw dropw drop\nend\n");
                let masm_err = vec.masm_err.as_deref().unwrap();
                let result = run_driver(&h, &src).await;
                assert_transaction_executor_error!(result, expected_err(masm_err));
            },
            other => panic!("vector {}: unknown kind {other}", vec.id),
        }
    }
    Ok(())
}

// HARNESS META-TEST + PROBES (scaffold surfaces — allowed green in the red-suite)
// ================================================================================================

/// Meta-test: a deliberately-wrong expected value (constructed here, never in the
/// artifact) must FAIL execution — proves a vector mismatch fails the run.
#[tokio::test]
async fn harness_detects_wrong_vector() -> Result<()> {
    let h = setup()?;
    let vec = &load().families.b32[0];
    let limbs = vec.packed_felts_values();
    let (b0, b1) = (word_of(&limbs[0..4]), word_of(&limbs[4..8]));
    let mut wrong = word_from_hex(&vec.expected_key);
    wrong[0] += miden_protocol::ONE;
    let src = format!(
        r#"use xreserve::encoding

begin
    push.{b0}
    push.{b1}
    exec.encoding::bytes32_to_key
    push.{wrong}
    assert_eqw.err="meta-test: deliberately wrong expected value"
end
"#
    );
    let result = run_driver(&h, &src).await;
    assert!(
        result.is_err(),
        "a wrong expected value MUST fail execution — the harness cannot pass on a bad vector"
    );
    Ok(())
}

/// P1 (D-1A check): the assembled library exports exactly the canonical flat proc paths.
#[test]
fn probe_p1_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    // exports render as ABSOLUTE paths (leading `::`) at this assembler version
    for canonical in [
        "::xreserve::encoding::bytes32_to_key",
        "::xreserve::encoding::uint256_to_asset_amount",
        "::xreserve::encoding::parse_deposit_intent",
    ] {
        assert!(
            exports.iter().any(|e| e == canonical),
            "canonical proc path {canonical} missing; exports: {exports:?}"
        );
    }
    Ok(())
}

/// P2: a trivial driver executes through the MockChain path (script wiring sanity).
#[tokio::test]
async fn probe_p2_script_executes() -> Result<()> {
    let h = setup()?;
    run_driver(&h, "begin push.1 drop end").await.expect("trivial driver must execute");
    Ok(())
}

// probe_p3_placeholder_trap_surfaces was DELETED in R4 (pre-flagged in the R2 report and
// the probe's own doc): it existed to prove trap plumbing against red-suite placeholders,
// and R4 removed the last placeholder. The exact-error plumbing it proved is now
// exercised continuously by every reject vector in tv_dual_2/tv_dual_3.

/// P4: the packing primitive is reachable via the miden-protocol re-export.
#[test]
fn probe_p4_packing_util() {
    let felts = miden_protocol::utils::bytes_to_packed_u32_elements(&[1u8, 2, 3, 4]);
    assert_eq!(felts.len(), 1);
}
