//! Cross-language conformance: the MASM codecs must agree with their Rust twins on every
//! canonical vector.
//!
//! Four routines are shared between the on-chain faucet and the off-chain services, and each is
//! written twice — once in MASM, once in Rust. If the two ever disagree, the off-chain side
//! signs or relays something the chain will reject, or worse, accepts something the chain would
//! have rejected. The tests here run each MASM routine over the same golden vectors the Rust
//! unit tests use and require identical results, accept and reject alike: the bytes32 → storage
//! key hash, the uint256 → asset amount reduction, the DepositIntent parser, and the attester
//! pubkey commitment.
//!
//! How the assertions are made matters as much as what they assert. Every conformance claim is
//! made on the result of actually EXECUTING the MASM in a transaction — never on assembly
//! succeeding — and the expected values are read from the canonical vector artifact rather than
//! recomputed by calling the Rust routine. Comparing the Rust implementation against itself
//! would pass no matter how far the MASM had drifted.
//!
//! The harness itself is assembled the way the protocol assembles its own standard libraries
//! (warnings as errors, a library built from the source directory, linked dynamically into a
//! transaction script) so the code under test is exercised through the real pipeline. A handful
//! of probe tests at the end pin those harness mechanics, so that a toolchain change breaks them
//! rather than silently changing what the conformance tests mean.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result};
use miden_processor::operation::OperationError;
use miden_processor::ExecutionError;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountId};
use miden_protocol::assembly::{Linkage, Package, Path as MasmPath};
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
fn assemble_xreserve_lib() -> Result<Package> {
    // Link StandardsLib (mirrors support::assemble_xreserve_lib): attester_admin::set_attester calls
    // the stock authority/pausable procs, which live in StandardsLib.
    let assembler = TransactionKernel::assembler()
        .with_package(Arc::new(StandardsLib::default().into()), Linkage::Dynamic)
        .map_err(|e| {
            anyhow::anyhow!("linking the standards library into the xreserve assembler: {e}")
        })?
        .with_warnings_as_errors(true);
    let lib = assembler
        .assemble_library_from_root(
            xusdc_encoding::xreserve_asm_dir().join("mod.masm"),
            Some(MasmPath::new("xreserve")),
        )
        .map_err(|e| anyhow::anyhow!("xreserve library failed to assemble: {e}"))?;
    Ok(*lib)
}

struct Harness {
    mock_chain: MockChain,
    account_id: AccountId,
    library: Package,
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
        .with_dynamically_linked_package(&h.library)
        .expect("linking the encoding library into the driver script")
        .compile_tx_script(src)
        .unwrap_or_else(|e| panic!("driver script failed to compile: {e}\n--- driver ---\n{src}"));
    h.mock_chain
        .build_transaction(h.account_id)
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

// PARITY 1 — bytes32 → storage-map key: every b32 vector, executed on the VM
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

@transaction_script
pub proc main
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

// PARITY 2 — uint256 → asset amount: every reducer vector, accepts and rejects alike
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

@transaction_script
pub proc main
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

@transaction_script
pub proc main
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

// PARITY 3 — DepositIntent parsing: every intent vector, its stack outputs, and the memory
// layout every field is expected to sit at
// ================================================================================================

/// Emits the common prologue for a `parse_deposit_intent` driver: import the layout offset
/// constants, stage the intent preimage into memory, and call the parser, leaving its outputs
/// `[remote_domain, REMOTE_TOKEN_UPPER, REMOTE_TOKEN_LOWER, hook_data_len]` on the stack.
///
/// The two suites that parse intents — the vector-driven conformance run and the differential
/// against Circle's own encoder — share this one prologue, so neither can accidentally test a
/// different staging path than the other.
///
/// The layout constants are imported one by one because `push.` only accepts an unqualified
/// constant identifier, which is also how the protocol's own MASM imports constants.
fn build_parser_driver_prefix(preimage: &[Felt], len_felts: u64) -> String {
    let mut src = String::from("use xreserve::encoding\n");
    // v0.25 braced item-import form (bare `use module::CONST` no longer resolves constants).
    writeln!(
        src,
        "use {{MAGIC_FELT_OFF, VERSION_FELT_OFF, AMOUNT_FELT_OFF, REMOTE_DOMAIN_FELT_OFF, \
         REMOTE_TOKEN_FELT_OFF, REMOTE_RECIPIENT_FELT_OFF, LOCAL_TOKEN_FELT_OFF, \
         LOCAL_DEPOSITOR_FELT_OFF, MAX_FEE_FELT_OFF, NONCE_FELT_OFF, HOOK_DATA_LEN_FELT_OFF, \
         HOOK_DATA_FELT_OFF}} from xreserve::encoding::layout"
    )
    .unwrap();
    src.push_str("\n@transaction_script\npub proc main\n");
    stage_preimage(&mut src, preimage);
    writeln!(src, "    push.{len_felts}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    writeln!(src, "    exec.encoding::parse_deposit_intent").unwrap();
    src
}

/// Maps a DepositIntent field name to the `layout::*` constant holding its felt offset in the
/// parsed preimage.
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

/// Runs one accepted DepositIntent end to end and checks both halves of the parser's contract.
///
/// First the values it hands back on the stack, then — for each field named in `packed` — that
/// reading the parsed region at that field's declared offset still returns the expected felts.
/// The second half is what proves the parser left the caller's staged intent unmodified: it
/// reports fields by offset into memory the caller supplied, so a parser that overwrote its input
/// would still return plausible stack values while corrupting everything downstream.
///
/// Reads are single-felt rather than word-sized on purpose: field offsets are not word-aligned,
/// and a word-sized memory op on an unaligned address traps in the processor.
///
/// Both the vector-driven run and the differential against Circle's encoder use this, so an
/// accept means the same thing in both.
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
    // parser stack outputs: [remote_domain, REMOTE_TOKEN_UPPER, REMOTE_TOKEN_LOWER, hook_data_len].
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

// PARITY 4 — attester pubkey commitment: the Word the allowlist is keyed by
// ================================================================================================
// Each attestation vector is run through the MASM commitment routine and the result is checked
// against two independent references at once: the value pinned in the canonical artifact (which
// miden-crypto's own `PublicKey::to_commitment` produced) and the Rust mirror used off-chain.
// All three must agree, because the faucet decides whether an attester is allowlisted by looking
// up exactly this Word — if the off-chain side computed a different commitment for the same key,
// a legitimate attester would be seeded under a key the chain never looks at.
// ================================================================================================

#[tokio::test]
async fn tv_dual_5_pubkey_commitment() -> Result<()> {
    let h = setup()?;
    for vec in &load().families.att {
        // the public key as 16 field elements, in the affine-coordinate order miden-crypto emits
        let limbs = vec.packed_felts_values();
        let (pkw0, pkw1, pkw2, pkw3) = (
            word_of(&limbs[0..4]),
            word_of(&limbs[4..8]),
            word_of(&limbs[8..12]),
            word_of(&limbs[12..16]),
        );
        let expected = vec.expected_commitment_word();

        // Rust mirror == the vector oracle (miden-crypto to_commitment): the third anti-drift
        // leg, asserted in-process so a mirror regression fails here too, not only in TV-ATT-2.
        assert_eq!(
            xusdc_encoding::xreserve::encoding::pubkey_commitment(&vec.pubkey())
                .expect("vector pubkeys are valid curve points"),
            expected,
            "vector {}: Rust pubkey_commitment must equal miden-crypto to_commitment",
            vec.id
        );

        // MASM proc executed under MockChain: push [PK_W0, PK_W1, PK_W2, PK_W3] (PK_W0 on top,
        // consumed first by loc_storew_le.0), exec, assert the returned Word equals the oracle.
        let src = format!(
            r#"use xreserve::encoding

@transaction_script
pub proc main
    push.{pkw3}
    push.{pkw2}
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

@transaction_script
pub proc main
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
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
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
    run_driver(
        &h,
        "@transaction_script\npub proc main\n    push.1 drop\nend\n",
    )
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

// DIFFERENTIAL — bytes produced by Circle's own encoder, parsed by ours
// ================================================================================================
// Everything else in this file compares our MASM against our Rust over vectors we generated. That
// cannot catch a shared misreading of Circle's wire format: if both halves place a field at the
// wrong offset, both agree and both are wrong. This test closes that gap by parsing bytes that
// Circle's encoder produced.
//
// Provenance of the fixture, stated precisely because it bounds what the test proves. It was
// generated locally from Circle's contract source (evm-xreserve-contracts @ a571cbe12fa7cede)
// by a Foundry script — kept alongside it under `tests/vectors/circle-extraction/` — that calls
// Circle's own `DepositIntentLib.encodeDepositIntent` over fixed field values. It is not a blob
// copied from Circle: their tracked tree at that commit ships neither golden hex nor an
// extraction script. So the INPUT bytes are genuinely Circle's encoding; the expected field
// values are derived from those raw bytes and checked against the field offsets declared in
// Circle's `DepositIntent.sol`. Circle's decoder is never run here.
//
// What this establishes is that the shared parser's envelope — field offsets, field sizes,
// endianness, the magic and version constants, and the total-length rule — matches Circle's
// encoder. What it deliberately does not touch is the faucet's identifier compare: Circle treats
// remoteToken and remoteRecipient as opaque bytes32 and has not fixed how a Miden account id is
// carried in them, so there is no ground truth to test that against yet.

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

        // (1) Check our understanding of the layout without involving the parser at all: slice
        // the raw bytes at the offsets and widths we believe Circle uses, read them big-endian,
        // and require them to equal the field values the fixture states (which the extraction
        // script asserted against Circle's own offset constants). If our offset model is wrong,
        // this fails here, before any of our code has had a chance to be consistently wrong.
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

        // (2) Now run the real parser over those same bytes, staged the way the chain stages
        // them. The expected outputs are computed from the raw big-endian bytes directly, not by
        // replaying the parser's own pack-then-swap steps — reusing its logic to predict its
        // result would turn an endianness or offset bug into a silent pass.
        let preimage = pack(&raw);
        let len_felts = preimage.len() as u64;
        let remote_domain = u32::from_be_bytes(raw[40..44].try_into().unwrap()) as u64;
        let hook_data_len = u32::from_be_bytes(raw[236..240].try_into().unwrap()) as u64;
        let rt = pack(&raw[44..76]);
        assert_eq!(rt.len(), 8, "{}: remoteToken packs to 8 limbs", v.id);
        let (rt0, rt1) = (word_of(&rt[0..4]), word_of(&rt[4..8]));
        // The expected felts for every field, at that field's offset. Each field's offset and
        // width is a multiple of four bytes (only the trailing hookData varies in length), so
        // packing a field on its own gives the same felts as the corresponding slice of the
        // whole packed preimage — which is what lets the fields be checked independently.
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
