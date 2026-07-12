//! MASM execution harness: the TV-DUAL-1..3 cross-language conformance tests plus the
//! harness probes/meta-tests. Protocol-derived mechanics:
//! `TransactionKernel::assembler().with_warnings_as_errors(true)` +
//! `assemble_library_from_dir` (miden-standards/build.rs), dynamic library
//! linking into tx scripts (code_builder/mod.rs; test_array.rs), MockChain
//! account + `build_tx_context(...).tx_script(...).execute()` (test_account.rs),
//! exact-error assertion via `assert_transaction_executor_error!`
//! (miden-testing/src/utils.rs).
//!
//! Every conformance assertion here is on the RESULT OF `execute().await` — there is no
//! assemble-only assertion path, and the Rust mirror is never consulted: expected values
//! come from the canonical artifact, actual values from the VM.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result};
use miden_processor::operation::OperationError;
use miden_processor::ExecutionError;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountId};
use miden_protocol::assembly::Library;
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::{ExecutedTransaction, TransactionKernel};
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::StandardsLib;
use miden_testing::{assert_transaction_executor_error, Auth, MockChain};
use miden_tx::TransactionExecutorError;
use serde::Deserialize;
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
    // Link StandardsLib (mirrors support::assemble_xreserve_lib): attester_admin::set_attester calls
    // the stock authority/pausable procs, which live in StandardsLib.
    let assembler = TransactionKernel::assembler()
        .with_dynamic_library(StandardsLib::default())
        .map_err(|e| {
            anyhow::anyhow!("linking the standards library into the xreserve assembler: {e}")
        })?
        .with_warnings_as_errors(true);
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
/// forest with the executor, which is what makes its procedures available to run).
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
    Ok(Harness {
        mock_chain,
        account_id: account.id(),
        library,
    })
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
            panic!(
                "vector {}: MASM bytes32_to_key must produce the canonical key: {e}",
                vec.id
            )
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
                let limbs: Vec<Felt> = vec.le_limbs().iter().map(|l| Felt::from(*l)).collect();
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
            }
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
            }
            "ge" | "dust" => {} // Rust-fn-only rows (no MASM leg by design)
            other => panic!("vector {}: unknown kind {other}", vec.id),
        }
    }
    Ok(())
}

// TV-DUAL-3 — parse_deposit_intent (every di vector; the parser stack-output contract +
// layout memory assertions via the `layout` constants)
// ================================================================================================

/// Builds the shared `parse_deposit_intent` driver prefix: the layout-const imports,
/// preimage staging, and the `exec` call — leaving the parser's stack outputs
/// `[remote_domain, REMOTE_TOKEN_1, REMOTE_TOKEN_0, hook_data_len]` on the stack. Shared by
/// the canonical TV-DUAL-3 path and the Circle differential so both stage + exec via ONE
/// code path. (Constants are imported individually — `push.` takes only unqualified
/// constant identifiers, the protocol's single-const import style.)
fn build_parser_driver_prefix(preimage: &[Felt], len_felts: u64) -> String {
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
    stage_preimage(&mut src, preimage);
    writeln!(src, "    push.{len_felts}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    writeln!(src, "    exec.encoding::parse_deposit_intent").unwrap();
    src
}

/// Maps a DC-1 field name to its `layout::*` felt-offset constant.
fn layout_const_for(field: &str) -> &'static str {
    match field {
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
    }
}

/// Builds + runs an accept-path driver: stages the preimage, execs the parser, asserts the
/// parser's stack outputs, then asserts every DC-1 field reads back at its `layout::*` offset
/// post-exec (⇒ staged memory unmutated). `packed` is `(field name, expected packed felts at
/// that field's offset)`. Single-felt loads throughout: the DC-1 felt offsets are not
/// word-aligned and word memory ops trap on unaligned addresses (processor
/// `UnalignedWordAccess`). Shared by TV-DUAL-3 accepts and the Circle differential.
async fn run_accept_driver(
    h: &Harness,
    label: &str,
    preimage: &[Felt],
    len_felts: u64,
    remote_domain: u64,
    rt0: Word,
    rt1: Word,
    hook_data_len: u64,
    packed: &[(&str, Vec<Felt>)],
) {
    let mut src = build_parser_driver_prefix(preimage, len_felts);
    // parser stack outputs: [remote_domain, REMOTE_TOKEN_1, REMOTE_TOKEN_0, hook_data_len].
    writeln!(
        src,
        "    push.{remote_domain} assert_eq.err=\"{label}: remote_domain\""
    )
    .unwrap();
    writeln!(
        src,
        "    push.{rt1} assert_eqw.err=\"{label}: remote_token_1\""
    )
    .unwrap();
    writeln!(
        src,
        "    push.{rt0} assert_eqw.err=\"{label}: remote_token_0\""
    )
    .unwrap();
    writeln!(
        src,
        "    push.{hook_data_len} assert_eq.err=\"{label}: hook_data_len\""
    )
    .unwrap();
    for (name, felts) in packed {
        let const_name = layout_const_for(name);
        for (i, felt) in felts.iter().enumerate() {
            writeln!(
                src,
                "    push.{const_name} push.{INTENT_PTR} add push.{i} add mem_load \
                 push.{} assert_eq.err=\"{label}: layout {name} felt {i}\"",
                felt.as_canonical_u64()
            )
            .unwrap();
        }
    }
    src.push_str("end\n");
    run_driver(h, &src).await.unwrap_or_else(|e| {
        panic!(
            "{label}: MASM parser must accept, return the compare fields, and satisfy the \
             layout assertions: {e}"
        )
    });
}

#[tokio::test]
async fn tv_dual_3_parse_deposit_intent() -> Result<()> {
    let h = setup()?;
    for vec in &load().families.di {
        // The hookData-overflow reject is Rust-only (the 1024-felt bound lives in the
        // Rust packer) — no MASM leg by design.
        if vec.kind == "reject" && vec.masm_err.is_none() {
            continue;
        }
        let preimage = vec.preimage_values();
        let len_felts = vec.staging_len_felts.unwrap_or(vec.len_felts);

        match vec.kind.as_str() {
            "accept" => {
                let f = vec.fields.as_ref().expect("accept vector carries fields");
                let rt: Vec<Felt> = f
                    .remote_token_felts
                    .iter()
                    .map(|s| felt_from_hex(s))
                    .collect();
                let (rt0, rt1) = (word_of(&rt[0..4]), word_of(&rt[4..8]));
                let packed: Vec<(&str, Vec<Felt>)> = f
                    .packed
                    .iter()
                    .map(|pf| {
                        (
                            pf.name.as_str(),
                            pf.felts.iter().map(|s| felt_from_hex(s)).collect(),
                        )
                    })
                    .collect();
                run_accept_driver(
                    &h,
                    &vec.id,
                    &preimage,
                    len_felts,
                    f.remote_domain as u64,
                    rt0,
                    rt1,
                    f.hook_data_len as u64,
                    &packed,
                )
                .await;
            }
            "reject" => {
                let mut src = build_parser_driver_prefix(&preimage, len_felts);
                // Clean up the would-be outputs so a non-trapping run completes cleanly
                // and the error assertion below reports "unexpectedly successful".
                src.push_str("    drop dropw dropw drop\nend\n");
                let masm_err = vec.masm_err.as_deref().unwrap();
                let result = run_driver(&h, &src).await;
                assert_transaction_executor_error!(result, expected_err(masm_err));
            }
            other => panic!("vector {}: unknown kind {other}", vec.id),
        }
    }
    Ok(())
}

// TV-DUAL-5 — pubkey_commitment (every att vector, executed): the MASM commitment Word
// equals BOTH the canonical artifact's `expected_commitment` (miden-crypto
// `PublicKey::to_commitment`) AND — asserted alongside — the Rust mirror `pubkey_commitment`.
// Anti-drift across MASM ↔ Rust ↔ miden-crypto.
// ================================================================================================

#[tokio::test]
async fn tv_dual_5_pubkey_commitment() -> Result<()> {
    let h = setup()?;
    for vec in &load().families.att {
        let limbs = vec.packed_felts_values(); // 9 felts f0..f8 (to_elements order)
        let (pkw0, pkw1) = (word_of(&limbs[0..4]), word_of(&limbs[4..8]));
        let pk8 = limbs[8].as_canonical_u64();
        let expected = vec.expected_commitment_word();

        // Rust mirror == the vector oracle (miden-crypto to_commitment): the third anti-drift
        // leg, asserted in-process so a mirror regression fails here too, not only in TV-ATT-2.
        assert_eq!(
            xusdc_encoding::xreserve::encoding::pubkey_commitment(&vec.pubkey()),
            expected,
            "vector {}: Rust pubkey_commitment must equal miden-crypto to_commitment",
            vec.id
        );

        // MASM proc executed under MockChain: push [PK_W0, PK_W1, pk8] (PK_W0 on top, consumed
        // first by loc_storew_le.0), exec, assert the returned Word equals the canonical oracle.
        let src = format!(
            r#"use xreserve::encoding

begin
    push.{pk8}
    push.{pkw1}
    push.{pkw0}
    exec.encoding::pubkey_commitment
    push.{expected}
    assert_eqw.err="vector {id}: pubkey_commitment mismatch"
end
"#,
            id = vec.id,
        );
        run_driver(&h, &src).await.unwrap_or_else(|e| {
            panic!(
                "vector {}: MASM pubkey_commitment must equal miden-crypto to_commitment: {e}",
                vec.id
            )
        });
    }
    Ok(())
}

// HARNESS META-TEST + PROBES (scaffold surfaces)
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

/// P1: the assembled library exports exactly the canonical flat proc paths.
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
        "::xreserve::encoding::pubkey_commitment",
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
    run_driver(&h, "begin push.1 drop end")
        .await
        .expect("trivial driver must execute");
    Ok(())
}

// probe_p3_placeholder_trap_surfaces was removed: it existed to prove trap plumbing against
// placeholder traps, and the last placeholder is now gone. The exact-error plumbing it proved
// is now exercised continuously by every reject vector in tv_dual_2/tv_dual_3.

/// P4: the packing primitive is reachable via the miden-protocol re-export.
#[test]
fn probe_p4_packing_util() {
    let felts = miden_protocol::utils::bytes_to_packed_u32_elements(&[1u8, 2, 3, 4]);
    assert_eq!(felts.len(), 1);
}

// TV-CIRCLE-DIFF — Circle-encoder-produced DepositIntent bytes through our parser
// ================================================================================================
// Differential ("spec → Circle") test. The fixture
// `tests/vectors/circle-depositintent-groundtruth.json` was LOCALLY GENERATED/RECONSTRUCTED from
// Circle source (evm-xreserve-contracts @ a571cbe12fa7cede3dfd48bc4fedb74739c04377) by an
// agent-authored Foundry extraction script (reproduced under `tests/vectors/circle-extraction/`)
// that invokes Circle's OWN `DepositIntentLib.encodeDepositIntent` (abi.encodePacked) over
// hardcoded field values. It is NOT copied from Circle's repo; Circle's tracked tree at that
// commit ships no golden-hex blob and no extraction script. EXPECTED field values here are
// fixture/raw-byte-derived and source-verified against Circle's DC-1 layout (DepositIntent.sol
// offsets) — this test does NOT run Circle's decoder. INPUTS are the Circle-encoder-produced
// bytes; only the u32-LE staging packing and our parser are "ours". Validates the
// shared-encoding PARSER ENVELOPE (offsets, sizes, endianness, magic/version, length rule). It does NOT exercise the
// faucet R-MINT-7 identifier compare against a real Miden identifier — Circle treats remoteToken /
// remoteRecipient as opaque bytes32, so DEV-10 / Q-CRY-3/4 stay OPEN and out of scope here.

const CIRCLE_FIXTURE: &str = include_str!("vectors/circle-depositintent-groundtruth.json");

#[derive(Deserialize)]
struct CircleFile {
    vectors: Vec<CircleVec>,
}

#[derive(Deserialize)]
struct CircleVec {
    id: String,
    bytes_hex: String,
    length: u64,
    fields: CircleFields,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CircleFields {
    magic: String,
    version: u64,
    amount: u128,
    remote_domain: u64,
    remote_token: String,
    remote_recipient: String,
    local_token: String,
    local_depositor: String,
    max_fee: u128,
    nonce: String,
    hook_data_length: u64,
    hook_data: String,
}

/// Decodes a `0x`-prefixed hex string to bytes.
fn circle_hexdec(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// `0x`-prefixed lowercase hex of a byte slice.
fn circle_hex(s: &[u8]) -> String {
    let mut out = String::from("0x");
    for b in s {
        write!(out, "{b:02x}").unwrap();
    }
    out
}

/// A uint256 value (here always within u128) as its 32-byte big-endian wire encoding.
fn be32_of_u128(v: u128) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[16..32].copy_from_slice(&v.to_be_bytes());
    b
}

#[tokio::test]
async fn tv_circle_differential_real_bytes() -> Result<()> {
    let h = setup()?;
    let pack = miden_protocol::utils::bytes_to_packed_u32_elements;
    let file: CircleFile =
        serde_json::from_str(CIRCLE_FIXTURE).expect("circle ground-truth fixture parses");
    assert!(
        !file.vectors.is_empty(),
        "circle fixture must carry vectors"
    );

    for v in &file.vectors {
        let raw = circle_hexdec(&v.bytes_hex);
        let f = &v.fields;

        // (1) INDEPENDENT cross-check — our DC-1 offset model vs the fixture's stated field
        // values (themselves source-verified against Circle's layout by the extraction
        // script's offset self-asserts). Raw bytes sliced at the DC-1 offsets (big-endian)
        // must equal the fixture's stated fields. Catches any offset / size / endianness
        // error in our spec model, using only the fixture bytes + its stated fields (no
        // parser involved).
        assert_eq!(raw.len() as u64, v.length, "{}: declared length", v.id);
        assert_eq!(
            raw.len() as u64,
            240 + f.hook_data_length,
            "{}: length == 240 + hookDataLength",
            v.id
        );
        assert_eq!(circle_hex(&raw[0..4]), f.magic, "{}: magic @0", v.id);
        assert_eq!(
            u32::from_be_bytes(raw[4..8].try_into().unwrap()) as u64,
            f.version,
            "{}: version @4",
            v.id
        );
        assert_eq!(
            &raw[8..40],
            &be32_of_u128(f.amount)[..],
            "{}: amount @8",
            v.id
        );
        assert_eq!(
            u32::from_be_bytes(raw[40..44].try_into().unwrap()) as u64,
            f.remote_domain,
            "{}: remoteDomain @40",
            v.id
        );
        assert_eq!(
            circle_hex(&raw[44..76]),
            f.remote_token,
            "{}: remoteToken @44",
            v.id
        );
        assert_eq!(
            circle_hex(&raw[76..108]),
            f.remote_recipient,
            "{}: remoteRecipient @76",
            v.id
        );
        assert_eq!(
            circle_hex(&raw[108..140]),
            f.local_token,
            "{}: localToken @108",
            v.id
        );
        assert_eq!(
            circle_hex(&raw[140..172]),
            f.local_depositor,
            "{}: localDepositor @140",
            v.id
        );
        assert_eq!(
            &raw[172..204],
            &be32_of_u128(f.max_fee)[..],
            "{}: maxFee @172",
            v.id
        );
        assert_eq!(circle_hex(&raw[204..236]), f.nonce, "{}: nonce @204", v.id);
        assert_eq!(
            u32::from_be_bytes(raw[236..240].try_into().unwrap()) as u64,
            f.hook_data_length,
            "{}: hookDataLength @236",
            v.id
        );
        let hd = if raw.len() > 240 {
            circle_hex(&raw[240..])
        } else {
            String::from("0x")
        };
        assert_eq!(hd, f.hook_data, "{}: hookData @240", v.id);

        // (2) MASM parser run — the Circle-encoder-produced bytes → u32-LE staging → our
        // parser. The expected parser outputs are derived from the RAW bytes (big-endian), NOT
        // by mirroring the parser's own LE-pack-then-byte-swap path, so a parser endianness or
        // offset bug surfaces as a mismatch rather than a silent pass.
        let preimage = pack(&raw);
        let len_felts = preimage.len() as u64;
        let remote_domain = u32::from_be_bytes(raw[40..44].try_into().unwrap()) as u64;
        let hook_data_len = u32::from_be_bytes(raw[236..240].try_into().unwrap()) as u64;
        let rt = pack(&raw[44..76]);
        assert_eq!(rt.len(), 8, "{}: remoteToken packs to 8 limbs", v.id);
        let (rt0, rt1) = (word_of(&rt[0..4]), word_of(&rt[4..8]));
        // Every DC-1 field's packed felts at its offset. All offsets/sizes are 4-byte
        // aligned (only trailing hookData is variable), so per-field packing equals the
        // matching slice of the whole-preimage packing.
        let spans: [(&str, usize, usize); 12] = [
            ("magic", 0, 4),
            ("version", 4, 4),
            ("amount", 8, 32),
            ("remote_domain", 40, 4),
            ("remote_token", 44, 32),
            ("remote_recipient", 76, 32),
            ("local_token", 108, 32),
            ("local_depositor", 140, 32),
            ("max_fee", 172, 32),
            ("nonce", 204, 32),
            ("hook_data_len", 236, 4),
            ("hook_data", 240, f.hook_data_length as usize),
        ];
        let packed: Vec<(&str, Vec<Felt>)> = spans
            .iter()
            .map(|(name, off, size)| (*name, pack(&raw[*off..*off + *size])))
            .collect();

        run_accept_driver(
            &h,
            &v.id,
            &preimage,
            len_felts,
            remote_domain,
            rt0,
            rt1,
            hook_data_len,
            &packed,
        )
        .await;
    }

    // (3) NEGATIVE CONTROLS — prove the differential actually rejects corrupted input,
    // so a green positive run cannot be a false pass. Corrupt one Circle-encoder-produced
    // blob and confirm our parser traps the EXACT structural error through the same call path.
    let base = circle_hexdec(&file.vectors[0].bytes_hex);
    let reject_src = |raw: &[u8]| {
        let preimage = pack(raw);
        let mut src = build_parser_driver_prefix(&preimage, preimage.len() as u64);
        src.push_str("    drop dropw dropw drop\nend\n");
        src
    };

    // corrupted magic → ERR_DI_BAD_MAGIC
    {
        let mut bad = base.clone();
        bad[0] ^= 0xff;
        let result = run_driver(&h, &reject_src(&bad)).await;
        assert_transaction_executor_error!(result, expected_err("ERR_DI_BAD_MAGIC"));
    }
    // zeroed amount → ERR_DI_ZERO_FIELD
    {
        let mut bad = base.clone();
        for b in &mut bad[8..40] {
            *b = 0;
        }
        let result = run_driver(&h, &reject_src(&bad)).await;
        assert_transaction_executor_error!(result, expected_err("ERR_DI_ZERO_FIELD"));
    }

    Ok(())
}
