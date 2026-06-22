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
use miden_protocol::account::{
    AccountComponent, AccountId, StorageMap, StorageMapKey, StorageSlot, StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::assembly::Library;
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::{ExecutedTransaction, TransactionKernel};
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Word};
use miden_processor::advice::AdviceInputs;
use miden_standards::account::access::PausableManager;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{MintPolicyConfig, PolicyRegistration, TokenPolicyManager};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_testing::{Auth, MockChain};
use miden_tx::TransactionExecutorError;
use xusdc_encoding::xreserve::encoding::masm_error_by_name;

// D5d attestation vectors — IN-TEST deterministic secp256k1 generation (zero touch to the 04
// canonical artifact), mirroring the precompile canary + gen_vectors att_* helpers: k256 the
// keypair+signature, sha3 the keccak digest, miden-crypto `PublicKey::to_commitment` the
// allowlist-key oracle, miden_protocol `bytes_to_packed_u32_elements` the advice felt packing.
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey};
use miden_crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_crypto::utils::Deserializable;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha3::{Digest, Keccak256};

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

/// D5c `usedNonces` map-slot label (frozen §5.6 nonce registry). The MASM shell declares a
/// `word("…")` const with the byte-identical label at the D5c green commit (parity-enforced
/// from that commit). Bound here as the single Rust source for the fixture slot binding.
pub const USED_NONCES_SLOT_LABEL: &str = "xusdc::xreserve::nonce_registry::used_nonces";

/// D5e faucet `token_config` value-slot label — the slot the standard `FungibleFaucet` component
/// installs (`[token_supply, max_supply, decimals, token_symbol]`), read/written by
/// `xreserve_mint.masm`. Bound here as the single Rust source for the constant-parity row.
pub const TOKEN_CONFIG_SLOT_LABEL: &str = "miden::standards::faucets::fungible::token_config";

/// D5d `xReserveAttesters` map-slot label (frozen §5.5 XReserveAttesterAdmin). The MASM
/// `attestation_verify.masm` declares a `word("…")` const with the byte-identical label
/// (parity-enforced); the later `set_attester` admin slice co-owns the SAME slot. Bound here as
/// the single Rust source for the allowlist fixture slot binding.
pub const XRESERVE_ATTESTERS_SLOT_LABEL: &str = "xusdc::xreserve::attester_admin::xreserve_attesters";

// FAUCET(01) ERROR MIRRORS (frozen names: 01 TEST-AND-VERIFICATION-HARNESS.md:72-73)
// ================================================================================================

/// Name → constant table for the faucet-owned shell errors (D-2 string `MasmError`
/// pattern). The implementation must declare byte-identical strings in MASM. The two
/// D5b amount/fee errors (R-MINT-10/11) are PROPOSED names pending human approval
/// (plan §7); the D5b green commit declares the matching MASM consts + adds them to
/// `SHELL_ERRORS_DECLARED` for parity. The red-suite carries them here so the D5b
/// behavior tests can name their EXACT expected error.
pub static SHELL_ERR_TABLE: [(&str, MasmError); 12] = [
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
    // D5c R-MINT-12 nonce replay. Frozen name (spec R-MINT-12); the red-suite carries it
    // here so the replay test can name its EXACT expected error. The D5c green commit
    // declares the matching MASM const + adds it to `SHELL_ERRORS_DECLARED` for parity.
    (
        "ERR_XRESERVE_NONCE_REPLAY",
        MasmError::from_static_str("deposit intent nonce has already been used"),
    ),
    // D5d R-MINT-13 / R-MINT-14 (attestation_verify.masm). Wording proposed in the plan and
    // user-selected; parity-pinned against the MASM consts.
    (
        "ERR_XRESERVE_BAD_PK_COMMITMENT",
        MasmError::from_static_str("deposit attester pubkey commitment is not allowlisted"),
    ),
    (
        "ERR_XRESERVE_SIG_INVALID",
        MasmError::from_static_str("deposit attestation signature verification failed"),
    ),
    // D5e R-MINT-15 supply cap (xreserve_mint.masm). Proposed wording; parity-pinned.
    (
        "ERR_XRESERVE_SUPPLY_CAP",
        MasmError::from_static_str("mint amount exceeds the faucet supply cap"),
    ),
    // Slice-1 recipient AccountId helper (extract_recipient_account_id, xreserve_mint.masm). These
    // are the LOCAL layout / field-range errors; the suffix-shape and unknown-version rejects
    // surface the PROTOCOL `account_id::validate` `ERR_ACCOUNT_ID_*` constants directly (asserted
    // inline in the recipient test). The red-suite carries these mirrors so the behavior tests can
    // name their EXACT expected error; the green commit declares the matching MASM consts and adds
    // them to `SHELL_ERRORS_DECLARED` for parity.
    (
        "ERR_XRESERVE_RECIPIENT_OUT_OF_RANGE",
        MasmError::from_static_str("deposit intent remote recipient address pad is not zero"),
    ),
    (
        "ERR_XRESERVE_RECIPIENT_BAD_LIMB",
        MasmError::from_static_str("deposit intent remote recipient limb is not a valid u32"),
    ),
    (
        "ERR_XRESERVE_RECIPIENT_NONCANONICAL",
        MasmError::from_static_str("deposit intent remote recipient value does not fit in the field"),
    ),
    // R-MINT-16 mint-deny guard (mint_deny_guard.masm). The stock inherited `mint_and_send` is
    // denied so `xreserve_mint` is the sole supply-increasing surface (INV-MINT-SECURITY, §5.2);
    // parity-pinned against the MASM const declared in mint_deny_guard.masm.
    (
        "ERR_XRESERVE_MINT_DENIED",
        MasmError::from_static_str("stock mint_and_send is denied; only xreserve_mint may raise supply"),
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

/// Builds the MockChain account carrying [the xreserve component WITH the two named value
/// config slots + the `usedNonces` map slot] + [the generated driver component], per the
/// spike-proven Q4/Q5 binding (`StorageSlotName::new(label)` ↔ MASM `word("label")`) and the
/// canary-proven `StorageSlot::with_map` map-slot path. The `usedNonces` map starts EMPTY
/// (unused nonces read `EMPTY_WORD`); use `setup_shell_account_with_nonce_seed` to
/// pre-populate it for the D5c replay path.
pub fn setup_shell_account(
    domain: Word,
    identifier: Word,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
    setup_shell_account_with_nonce_seed(domain, identifier, None, driver_src, driver_path)
}

/// Like `setup_shell_account`, but optionally seeds the `usedNonces` map with a single
/// `key -> marker` entry (the D5c replay fixture): `Some((key, marker))` pre-populates the
/// map so a real `active_account::get_map_item` read returns the non-empty marker; `None`
/// leaves it empty. D5c is assert-zero ONLY — this seeding is a TEST fixture, not the
/// on-chain nonce SET (deferred to D5e).
pub fn setup_shell_account_with_nonce_seed(
    domain: Word,
    identifier: Word,
    nonce_seed: Option<(Word, Word)>,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
    let library = assemble_xreserve_lib()?;

    let nonce_map = match nonce_seed {
        Some((key, marker)) => StorageMap::with_entries([(StorageMapKey::new(key), marker)])
            .map_err(|e| anyhow::anyhow!("seeding the usedNonces map fixture: {e}"))?,
        None => StorageMap::new(),
    };

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
            StorageSlot::with_map(
                StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
                nonce_map,
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

// D5C NONCE REPLAY HELPERS (P5-01 slice 3)
// ================================================================================================

/// Generates the per-case D5c driver: stages the preimage in the account context, pushes
/// `[intent_ptr]`, and `exec`s the faucet `assert_nonce_unused` shell. The shell returns `[]`
/// (D5c is read-only — assert-zero, no nonce SET), so the staged-then-consumed stack restores
/// the 16-depth `call` boundary.
pub fn nonce_driver_src(preimage: &[Felt]) -> String {
    let mut src = String::from(
        "use xreserve::deposit_intent_parser\n\n\
         #! Test driver: stages a DepositIntent preimage in the account context and execs the\n\
         #! D5c nonce replay-guard shell.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.deposit_intent_parser::assert_nonce_unused\n");
    src.push_str("end\n");
    src
}

// D5D ATTESTATION VERIFY HELPERS (P5-01 slice 4)
// ================================================================================================

/// A deterministically-generated attester: its 9-felt compressed pubkey + 17-felt signature (as
/// advice felts) over a payload's keccak digest, and its `xReserveAttesters` allowlist commitment
/// (the miden-crypto `PublicKey::to_commitment` oracle == the on-chain MASM `pubkey_commitment`).
pub struct AttesterVector {
    /// 9-felt u32-LE-packed compressed SEC1 pubkey (the candidate-pubkey advice felts).
    pub pubkey_felts: Vec<Felt>,
    /// 17-felt u32-LE-packed r||s||v signature over keccak256(payload) (the signature advice felts).
    pub sig_felts: Vec<Felt>,
    /// Poseidon2 commitment Word = the `xReserveAttesters` allowlist key for this pubkey.
    pub commitment: Word,
}

impl AttesterVector {
    /// The advice stack `verify_attestation` reads: pubkey (9) then signature (17), in seed order.
    pub fn advice(&self) -> Vec<Felt> {
        self.pubkey_felts.iter().chain(self.sig_felts.iter()).copied().collect()
    }
}

/// Deterministically generates an attester keypair (k256 + seeded StdRng) and signs
/// `keccak256(payload)` (sha3) with it — the SAME independent path the precompile canary and
/// gen_vectors use. Two distinct seeds over the SAME payload give the seam's key A / key B.
pub fn gen_attester(seed: u64, payload: &[u8]) -> AttesterVector {
    let sk = SigningKey::random(&mut StdRng::seed_from_u64(seed));
    let pk33: [u8; 33] = sk
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 pubkey is 33 bytes");

    let mut hasher = Keccak256::new();
    hasher.update(payload);
    let digest: [u8; 32] = hasher.finalize().into();

    let (sig, recid): (K256Signature, RecoveryId) =
        sk.sign_prehash_recoverable(&digest).expect("k256 prehash sign");
    let mut sig65 = [0u8; 65];
    sig65[..64].copy_from_slice(sig.to_bytes().as_slice());
    sig65[64] = recid.to_byte();

    let commitment = PublicKey::read_from_bytes(&pk33)
        .expect("valid compressed secp256k1 pubkey")
        .to_commitment();

    AttesterVector {
        pubkey_felts: bytes_to_packed_u32_elements(&pk33),
        sig_felts: bytes_to_packed_u32_elements(&sig65),
        commitment,
    }
}

/// Builds the MockChain account carrying [the xreserve component WITH the `xReserveAttesters` map
/// slot] + [the generated driver]. `attesters_seed = Some((commitment, marker))` pre-populates the
/// allowlist (an enabled attester); `None` leaves it empty (no attester allowlisted). The seeding
/// is a TEST fixture — the real `set_attester` admin setter is a separate (out-of-scope) slice.
pub fn setup_attestation_account(
    attesters_seed: Option<(Word, Word)>,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
    let library = assemble_xreserve_lib()?;

    let attesters_map = match attesters_seed {
        Some((key, marker)) => StorageMap::with_entries([(StorageMapKey::new(key), marker)])
            .map_err(|e| anyhow::anyhow!("seeding the xReserveAttesters map fixture: {e}"))?,
        None => StorageMap::new(),
    };

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![StorageSlot::with_map(
            StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
                .context("xReserveAttesters slot label")?,
            attesters_map,
        )],
        AccountComponentMetadata::new("xusdc-attestation-harness"),
    )
    .context("binding the xreserve library + attester allowlist slot as a component")?;

    let driver_code = CodeBuilder::new()
        .with_dynamically_linked_library(&library)
        .context("linking the xreserve library into the driver component")?
        .compile_component_code(driver_path, driver_src)
        .with_context(|| {
            format!("driver component failed to compile\n--- driver ---\n{driver_src}")
        })?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-attestation-driver"),
    )
    .context("binding the driver component")?;

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [xreserve_component, driver_component])
        .context("adding the attestation harness account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(ShellHarness { mock_chain, account_id: account.id(), driver_code, driver_path })
}

/// Generates the per-case D5d driver: stages the DepositIntent payload preimage in the account
/// context, pushes `[intent_ptr, len_bytes]`, and `exec`s the faucet `verify_attestation` shell
/// (which reads the candidate pubkey + signature from the advice stack). The shell returns `[]`
/// (assert-only gate), so the staged-then-consumed stack restores the 16-depth `call` boundary.
pub fn attestation_driver_src(preimage: &[Felt], len_bytes: u64) -> String {
    let mut src = String::from(
        "use xreserve::attestation_verify\n\n\
         #! Test driver: stages a DepositIntent payload in the account context and execs the D5d\n\
         #! attestation verify shell (pubkey + signature from the advice stack).\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    writeln!(src, "    push.{len_bytes}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.attestation_verify::verify_attestation\n");
    src.push_str("end\n");
    src
}

// D5E MINT WRITE-PHASE HELPERS (P5-01 slice 5)
// ================================================================================================

/// Module path of the generated D5e mint-effects driver component.
pub const MINT_DRIVER_PATH: &str = "xusdc::test_fixtures::mint_driver";
/// Module path of the generated D5e no-effects readback probe component.
pub const MINT_PROBE_PATH: &str = "xusdc::test_fixtures::mint_probe";

/// A faucet harness for the D5e mint write-phase: a `FungibleFaucet` account carrying the mint
/// driver (`drive`) AND a no-effects readback probe (`check`), so the over-cap reject can be
/// proven to leave token_config / usedNonces unchanged on the SAME account (finding #3b).
pub struct MintHarness {
    pub mock_chain: MockChain,
    pub account_id: AccountId,
    /// The P2ID recipient account id (for asserting the emitted note targets it).
    pub recipient_id: AccountId,
    pub mint_driver_code: AccountComponentCode,
    pub probe_driver_code: AccountComponentCode,
}

/// The verified-intent outputs `apply_mint_effects` consumes (explicit-stack inputs). For the
/// standalone write-phase shell these are seeded directly (the composition wires them from the
/// parsed/verified DepositIntent). `key` stands in for `bytes32_to_key(nonce)` (consumed by
/// reference); `note_type` 1 = public.
pub struct MintInputs {
    pub amount: u64,
    pub fee_amount: u64,
    pub key: [u32; 4],
    pub serial: [u32; 4],
    pub tag: u32,
    pub note_type: u8,
}

/// Builds a MockChain `FungibleFaucet` account (token_config = [token_supply, max_supply, 6,
/// "XUSDC"]) carrying the xreserve component (the `apply_mint_effects` proc + the `usedNonces` map
/// slot), the generated mint driver, AND a no-effects readback probe, plus a recipient wallet for
/// the P2ID note. Mirrors the canary-proven construction
/// (`add_existing_account_from_components([faucet.into(), …])`).
pub fn setup_mint_faucet_account(
    max_supply: u64,
    token_supply: u64,
    inputs: &MintInputs,
) -> Result<MintHarness> {
    let library = assemble_xreserve_lib()?;

    let mut builder = MockChain::builder();
    let recipient = builder.add_existing_wallet(Auth::IncrNonce).context("adding recipient")?;
    let driver_src = mint_effects_driver_src(inputs, recipient.id());
    let probe_src = mint_noeffect_probe_src(token_supply, inputs.key);

    let link = |path: &'static str, src: &str, what: &str| -> Result<AccountComponentCode> {
        CodeBuilder::new()
            .with_dynamically_linked_library(&library)
            .with_context(|| format!("linking the xreserve library into the {what}"))?
            .compile_component_code(path, src)
            .with_context(|| format!("{what} failed to compile\n--- src ---\n{src}"))
    };
    let mint_driver_code = link(MINT_DRIVER_PATH, &driver_src, "mint driver")?;
    let probe_driver_code = link(MINT_PROBE_PATH, &probe_src, "no-effects probe")?;
    let mint_driver_component = AccountComponent::new(
        mint_driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-mint-effects-driver"),
    )
    .context("binding the mint driver component")?;
    let probe_driver_component = AccountComponent::new(
        probe_driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-mint-noeffect-probe"),
    )
    .context("binding the no-effects probe component")?;

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![StorageSlot::with_map(
            StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
            StorageMap::new(),
        )],
        AccountComponentMetadata::new("xusdc-mint-effects-harness"),
    )
    .context("binding the xreserve library + usedNonces slot as a component")?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("XUSDC")?)
        .symbol(TokenSymbol::new("XUSDC")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .build()
        .context("failed to build FungibleFaucet")?;

    let account = builder
        .add_existing_account_from_components(
            Auth::IncrNonce,
            [faucet.into(), xreserve_component, mint_driver_component, probe_driver_component],
        )
        .context("adding the mint faucet account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(MintHarness {
        mock_chain,
        account_id: account.id(),
        recipient_id: recipient.id(),
        mint_driver_code,
        probe_driver_code,
    })
}

/// Runs `call.<driver>::<proc>` from a trivial tx script against the faucet account.
async fn run_mint_driver(
    h: &MintHarness,
    driver_code: &AccountComponentCode,
    driver_path: &str,
    proc: &str,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src = format!("use {driver_path}->driver\nbegin\n    call.driver::{proc}\nend\n");
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_library(driver_code)
        .expect("linking the driver into the tx script")
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

/// Drives `apply_mint_effects` (the mint write-phase) against the faucet account.
pub async fn run_mint(
    h: &MintHarness,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    run_mint_driver(h, &h.mint_driver_code, MINT_DRIVER_PATH, "drive").await
}

/// Runs the no-effects readback probe (asserts token_config / usedNonces unchanged). Used after a
/// rejected over-cap mint on the SAME account (which traps and commits nothing) to concretely
/// prove no nonce / supply effect landed (finding #3b).
pub async fn run_noeffect_probe(
    h: &MintHarness,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    run_mint_driver(h, &h.probe_driver_code, MINT_PROBE_PATH, "check").await
}

/// Generates the per-case D5e driver: a CALL-entered account proc that stages the mint inputs and
/// `exec`s `apply_mint_effects`. Push order is bottom-first so the proc sees `[amount, feeAmount,
/// KEY, recipient_suffix, recipient_prefix, SERIAL_NUM, P2ID_SCRIPT_ROOT, tag, note_type]`. The
/// P2ID script root is the canonical `P2idNote::script_root()` (the recipient note is P2ID).
pub fn mint_effects_driver_src(inputs: &MintInputs, recipient: AccountId) -> String {
    let wlit = |w: [u32; 4]| format!("[{},{},{},{}]", w[0], w[1], w[2], w[3]);
    let script_root: Word = P2idNote::script_root().into();
    let mut src = String::from(
        "use xreserve::xreserve_mint\n\n\
         #! Test driver: stages the D5e mint-effects inputs in the account context and execs the\n\
         #! faucet write-phase shell apply_mint_effects.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc drive\n",
    );
    writeln!(src, "    push.{}", inputs.note_type).unwrap();
    writeln!(src, "    push.{}", inputs.tag).unwrap();
    writeln!(src, "    push.{script_root}").unwrap();
    writeln!(src, "    push.{}", wlit(inputs.serial)).unwrap();
    writeln!(src, "    push.{}", recipient.prefix().as_felt()).unwrap();
    writeln!(src, "    push.{}", recipient.suffix()).unwrap();
    writeln!(src, "    push.{}", wlit(inputs.key)).unwrap();
    writeln!(src, "    push.{}", inputs.fee_amount).unwrap();
    writeln!(src, "    push.{}", inputs.amount).unwrap();
    src.push_str("    exec.xreserve_mint::apply_mint_effects\n");
    src.push_str("end\n");
    src
}

/// Generates the no-effects readback probe component: `check` asserts the faucet token_config
/// `token_supply` still equals `expected_token_supply` and `usedNonces[key]` is still EMPTY_WORD —
/// run on the SAME account after a rejected over-cap mint to prove no supply/nonce effect committed
/// (the rejected tx traps and commits nothing; this concretely observes the unchanged genesis
/// state). Uses the proven `active_account::{get_item, get_map_item}` reads.
pub fn mint_noeffect_probe_src(expected_token_supply: u64, key: [u32; 4]) -> String {
    format!(
        "use miden::protocol::active_account\n\n\
         const PROBE_TOKEN_CONFIG_SLOT = word(\"{cfg}\")\n\
         const PROBE_USED_NONCES_SLOT = word(\"{used}\")\n\n\
         #! No-effects readback: token_config.token_supply == expected and usedNonces[KEY] EMPTY.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc check\n\
         \x20\x20\x20\x20push.PROBE_TOKEN_CONFIG_SLOT[0..2] exec.active_account::get_item\n\
         \x20\x20\x20\x20push.{expected} assert_eq.err=\"no-effect: token_supply changed\"\n\
         \x20\x20\x20\x20dropw\n\
         \x20\x20\x20\x20push.{key} push.PROBE_USED_NONCES_SLOT[0..2] exec.active_account::get_map_item\n\
         \x20\x20\x20\x20padw assert_eqw.err=\"no-effect: usedNonces key was set\"\n\
         end\n",
        cfg = TOKEN_CONFIG_SLOT_LABEL,
        used = USED_NONCES_SLOT_LABEL,
        expected = expected_token_supply,
        key = format!("[{},{},{},{}]", key[0], key[1], key[2], key[3]),
    )
}

// RECIPIENT ACCOUNTID HELPER (P5-01 Slice 1) — extract_recipient_account_id
// ================================================================================================

/// Felt offset of the `remoteRecipient` bytes32 field within the staged preimage (DC-1 byte offset
/// 76 / 4 == the MASM `REMOTE_RECIPIENT_FELT_OFF` layout const, parity-checked at the MASM layer by
/// `constant_parity.rs`). The eight u32-LE limbs occupy felts `[19..27)`.
pub const REMOTE_RECIPIENT_FELT_OFF: usize = 19;

/// Clones a base accept preimage and overwrites the 8-felt `remoteRecipient` field with the u32-LE
/// packing of `recipient` (the protocol `bytes_to_packed_u32_elements` — the SAME packing the
/// canonical preimage uses, so the helper's byte-swap recovers the big-endian AccountId). Consumed
/// BY REFERENCE — no copied vector tables (G1).
pub fn splice_recipient(base: &[Felt], recipient: [u8; 32]) -> Vec<Felt> {
    let mut preimage = base.to_vec();
    for (i, limb) in bytes_to_packed_u32_elements(&recipient).iter().enumerate() {
        preimage[REMOTE_RECIPIENT_FELT_OFF + i] = *limb;
    }
    preimage
}

/// Generates the per-case Slice-1 driver: a CALL-entered account proc that stages the (spliced)
/// preimage in the account context, pushes `[intent_ptr]`, and `exec`s
/// `xreserve_mint::extract_recipient_account_id`. The extractor returns `[suffix, prefix]`:
/// `Some((suffix, prefix))` pins both (happy path, restoring the 16-depth `call` boundary); `None`
/// drops them (reject path — the extractor traps, but a non-trapping run returns cleanly so the
/// test's exact-error assertion reports the mismatch).
pub fn recipient_driver_src(preimage: &[Felt], expected: Option<(Felt, Felt)>) -> String {
    let mut src = String::from(
        "use xreserve::xreserve_mint\n\n\
         #! Test driver: stages a DepositIntent preimage in the account context and execs the\n\
         #! Slice-1 recipient AccountId extractor.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.xreserve_mint::extract_recipient_account_id\n");
    match expected {
        // happy: the extractor returns [suffix, prefix]; pin both, restoring the call boundary
        Some((suffix, prefix)) => {
            writeln!(src, "    push.{suffix} assert_eq.err=\"driver: recipient suffix mismatch\"")
                .unwrap();
            writeln!(src, "    push.{prefix} assert_eq.err=\"driver: recipient prefix mismatch\"")
                .unwrap();
        },
        // reject: the extractor traps; balance the would-be [suffix, prefix] for a non-trapping run
        None => src.push_str("    drop drop\n"),
    }
    src.push_str("end\n");
    src
}

// MINT COMPOSITION (P5-01 Slice 2) — xreserve_mint::mint
// ================================================================================================

/// Module path of the generated mint-composition driver component.
pub const MINT_COMPOSITION_DRIVER_PATH: &str = "xusdc::test_fixtures::mint_composition_driver";

/// Byte offsets (DC-1 felt offset x 4) of the fields a composition fixture splices in BYTES — so the
/// keccak'd attestation payload stays consistent with the staged felts. Each uint256 / bytes32 field
/// is 32 bytes.
pub const AMOUNT_BYTE_OFF: usize = AMOUNT_FELT_OFF * 4;
pub const MAX_FEE_BYTE_OFF: usize = MAX_FEE_FELT_OFF * 4;
pub const REMOTE_RECIPIENT_BYTE_OFF: usize = REMOTE_RECIPIENT_FELT_OFF * 4;

/// A `uint256` big-endian 32-byte encoding of a u64 value (24 zero bytes + 8-byte BE) — for splicing
/// `amount` / `maxFee` into a payload's byte image.
pub fn uint256_be(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}

/// The composition's combined advice stack, in the order the chain consumes it: `feeAmount` (8
/// limbs, read by D5b) then the attester's pubkey (9) + signature (17) (read by D5d).
pub fn composition_advice(fee_amount_limbs: [u32; 8], attester: &AttesterVector) -> Vec<Felt> {
    fee_advice_felts(fee_amount_limbs).into_iter().chain(attester.advice()).collect()
}

pub struct CompositionHarness {
    pub mock_chain: MockChain,
    pub account_id: AccountId,
    pub driver_code: AccountComponentCode,
    pub probe_code: AccountComponentCode,
}

/// Builds a `FungibleFaucet` account carrying the xreserve component bound with ALL composition
/// slots (domain_config + identifier_config value slots, usedNonces + xReserveAttesters map slots),
/// the mint-composition driver, AND a no-effects readback probe — the union of the D5a-D5e harnesses
/// on ONE account (the production composition shape). `nonce_seed` / `attesters_seed` pre-populate
/// the respective maps (the D5c replay fixture / the D5d allowlist).
pub fn setup_mint_composition_account(
    max_supply: u64,
    token_supply: u64,
    domain: Word,
    identifier: Word,
    nonce_seed: Option<(Word, Word)>,
    attesters_seed: Option<(Word, Word)>,
    driver_src: &str,
    probe_src: &str,
) -> Result<CompositionHarness> {
    let library = assemble_xreserve_lib()?;

    let map_of = |seed: Option<(Word, Word)>, what: &str| -> Result<StorageMap> {
        match seed {
            Some((key, marker)) => StorageMap::with_entries([(StorageMapKey::new(key), marker)])
                .map_err(|e| anyhow::anyhow!("seeding the {what} map fixture: {e}")),
            None => Ok(StorageMap::new()),
        }
    };

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![
            StorageSlot::with_value(
                StorageSlotName::new(DOMAIN_CONFIG_SLOT_LABEL).context("domain slot label")?,
                domain,
            ),
            StorageSlot::with_value(
                StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL).context("identifier slot label")?,
                identifier,
            ),
            StorageSlot::with_map(
                StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
                map_of(nonce_seed, "usedNonces")?,
            ),
            StorageSlot::with_map(
                StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
                    .context("xReserveAttesters slot label")?,
                map_of(attesters_seed, "xReserveAttesters")?,
            ),
        ],
        AccountComponentMetadata::new("xusdc-mint-composition-harness"),
    )
    .context("binding the xreserve library + all composition slots as a component")?;

    let link = |path: &'static str, src: &str, what: &str| -> Result<AccountComponentCode> {
        CodeBuilder::new()
            .with_dynamically_linked_library(&library)
            .with_context(|| format!("linking the xreserve library into the {what}"))?
            .compile_component_code(path, src)
            .with_context(|| format!("{what} failed to compile\n--- src ---\n{src}"))
    };
    let driver_code = link(MINT_COMPOSITION_DRIVER_PATH, driver_src, "mint composition driver")?;
    let probe_code = link(MINT_PROBE_PATH, probe_src, "no-effects probe")?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-mint-composition-driver"),
    )
    .context("binding the mint composition driver component")?;
    let probe_component = AccountComponent::new(
        probe_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-mint-composition-probe"),
    )
    .context("binding the no-effects probe component")?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("XUSDC")?)
        .symbol(TokenSymbol::new("XUSDC")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .build()
        .context("failed to build FungibleFaucet")?;

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(
            Auth::IncrNonce,
            [faucet.into(), xreserve_component, driver_component, probe_component],
        )
        .context("adding the mint composition account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(CompositionHarness { mock_chain, account_id: account.id(), driver_code, probe_code })
}

/// Generates the per-case composition driver: a CALL-entered account proc that stages the preimage,
/// pushes `[intent_ptr, len_felts, scale_exp]`, and `exec`s `xreserve_mint::mint` (which reads
/// feeAmount + pubkey + signature from the advice stack). `mint` returns `[pad(16)]`, restoring the
/// 16-depth `call` boundary.
pub fn mint_composition_driver_src(preimage: &[Felt], len_felts: u64, scale_exp: u32) -> String {
    let mut src = String::from(
        "use xreserve::xreserve_mint\n\n\
         #! Test driver: stages a DepositIntent preimage in the account context and execs the\n\
         #! xreserve_mint composition entry (feeAmount + attestation pubkey/sig from advice).\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    writeln!(src, "    push.{scale_exp}").unwrap();
    writeln!(src, "    push.{len_felts}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.xreserve_mint::mint\n");
    src.push_str("end\n");
    src
}

/// No-effects readback probe for the composition: asserts `token_config.token_supply ==
/// expected_token_supply` and `usedNonces[nonce_key]` is EMPTY. Distinct from
/// `mint_noeffect_probe_src` because the composition's nonce key is a Poseidon2 `Word` (not a
/// synthetic `[u32; 4]`).
pub fn composition_noeffect_probe_src(expected_token_supply: u64, nonce_key: Word) -> String {
    format!(
        "use miden::protocol::active_account\n\n\
         const PROBE_TOKEN_CONFIG_SLOT = word(\"{cfg}\")\n\
         const PROBE_USED_NONCES_SLOT = word(\"{used}\")\n\n\
         #! No-effects readback: token_config.token_supply == expected and usedNonces[KEY] EMPTY.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc check\n\
         \x20\x20\x20\x20push.PROBE_TOKEN_CONFIG_SLOT[0..2] exec.active_account::get_item\n\
         \x20\x20\x20\x20push.{expected} assert_eq.err=\"no-effect: token_supply changed\"\n\
         \x20\x20\x20\x20dropw\n\
         \x20\x20\x20\x20push.{key} push.PROBE_USED_NONCES_SLOT[0..2] exec.active_account::get_map_item\n\
         \x20\x20\x20\x20padw assert_eqw.err=\"no-effect: usedNonces key was set\"\n\
         end\n",
        cfg = TOKEN_CONFIG_SLOT_LABEL,
        used = USED_NONCES_SLOT_LABEL,
        expected = expected_token_supply,
        key = nonce_key,
    )
}

/// Supply-only no-effects readback probe: asserts `token_config.token_supply ==
/// expected_token_supply`. Used by the replay reject, where `usedNonces[KEY]` is non-empty BY
/// FIXTURE (the seed) — so only the supply invariant is a meaningful no-effect check there.
pub fn composition_supply_probe_src(expected_token_supply: u64) -> String {
    format!(
        "use miden::protocol::active_account\n\n\
         const PROBE_TOKEN_CONFIG_SLOT = word(\"{cfg}\")\n\n\
         #! No-effects readback: token_config.token_supply == expected.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc check\n\
         \x20\x20\x20\x20push.PROBE_TOKEN_CONFIG_SLOT[0..2] exec.active_account::get_item\n\
         \x20\x20\x20\x20push.{expected} assert_eq.err=\"no-effect: token_supply changed\"\n\
         \x20\x20\x20\x20dropw\n\
         end\n",
        cfg = TOKEN_CONFIG_SLOT_LABEL,
        expected = expected_token_supply,
    )
}

async fn run_composition_driver(
    h: &CompositionHarness,
    driver_code: &AccountComponentCode,
    driver_path: &str,
    proc: &str,
    advice: Option<Vec<Felt>>,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src = format!("use {driver_path}->driver\nbegin\n    call.driver::{proc}\nend\n");
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_library(driver_code)
        .expect("linking the driver into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| panic!("driver call script failed to compile: {e}\n--- script ---\n{src}"));
    let mut ctx = h
        .mock_chain
        .build_tx_context(h.account_id, &[], &[])
        .expect("building the tx context")
        .tx_script(tx_script);
    if let Some(stack) = advice {
        ctx = ctx.extend_advice_inputs(AdviceInputs::default().with_stack(stack));
    }
    ctx.build().expect("building the transaction").execute().await
}

/// Drives the `xreserve_mint::mint` composition with the combined advice stack.
pub async fn run_mint_composition(
    h: &CompositionHarness,
    advice: Vec<Felt>,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    run_composition_driver(h, &h.driver_code, MINT_COMPOSITION_DRIVER_PATH, "drive", Some(advice)).await
}

/// Runs the no-effects readback probe on the SAME account after a rejected mint (the trapped tx
/// committed nothing), proving token_config / usedNonces unchanged.
pub async fn run_composition_probe(
    h: &CompositionHarness,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    run_composition_driver(h, &h.probe_code, MINT_PROBE_PATH, "check", None).await
}

// R-MINT-16 MINT-DENY GUARD (P5-01) — guarded faucet composition + stock mint_and_send invocation
// ================================================================================================

/// Which mint policy the guarded faucet fixture installs.
pub enum GuardSelection {
    /// PRODUCTION `XReserveStablecoinBuilder::build_components` (deny ONLY, no reserved allow-all).
    ProductionDeny,
    /// TEST-ONLY oracle (test-harness [`oracle_components`]): deny ACTIVE, allow-all RESERVED.
    OracleDeny,
    /// TEST-ONLY oracle (test-harness [`oracle_components`]): allow-all ACTIVE, deny RESERVED.
    OracleAllowAll,
}

/// A guarded mint harness: the composition account WITH the `TokenPolicyManager` (mint-deny guard
/// active or allow-all per the [`GuardSelection`]) + `PausableManager`, plus the resolved deny-guard
/// proc root. The production deny path is composed by `XReserveStablecoinBuilder::build_components`;
/// the allow-all/deny oracle pair is composed by the test-only [`oracle_components`] helper.
pub struct GuardedMint {
    pub harness: CompositionHarness,
    pub deny_root: Word,
}

/// Like [`setup_mint_composition_account`] but ALSO installs the `TokenPolicyManager` (mint-deny
/// guard active or allow-all per `selection`) + `PausableManager` via [`XReserveStablecoinBuilder`].
/// The deny guard rides the same `xreserve` library component (its `check_policy` proc). Used by the
/// R-MINT-16 deny suite to drive the inherited stock `mint_and_send` against a policy-managed faucet.
pub fn setup_guarded_mint_account(
    selection: GuardSelection,
    max_supply: u64,
    token_supply: u64,
    domain: Word,
    identifier: Word,
    nonce_seed: Option<(Word, Word)>,
    attesters_seed: Option<(Word, Word)>,
    driver_src: &str,
    probe_src: &str,
) -> Result<GuardedMint> {
    let library = assemble_xreserve_lib()?;

    let map_of = |seed: Option<(Word, Word)>, what: &str| -> Result<StorageMap> {
        match seed {
            Some((key, marker)) => StorageMap::with_entries([(StorageMapKey::new(key), marker)])
                .map_err(|e| anyhow::anyhow!("seeding the {what} map fixture: {e}")),
            None => Ok(StorageMap::new()),
        }
    };

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![
            StorageSlot::with_value(
                StorageSlotName::new(DOMAIN_CONFIG_SLOT_LABEL).context("domain slot label")?,
                domain,
            ),
            StorageSlot::with_value(
                StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL).context("identifier slot label")?,
                identifier,
            ),
            StorageSlot::with_map(
                StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
                map_of(nonce_seed, "usedNonces")?,
            ),
            StorageSlot::with_map(
                StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
                    .context("xReserveAttesters slot label")?,
                map_of(attesters_seed, "xReserveAttesters")?,
            ),
        ],
        AccountComponentMetadata::new("xusdc-mint-composition-harness"),
    )
    .context("binding the xreserve library + all composition slots as a component")?;

    let link = |path: &'static str, src: &str, what: &str| -> Result<AccountComponentCode> {
        CodeBuilder::new()
            .with_dynamically_linked_library(&library)
            .with_context(|| format!("linking the xreserve library into the {what}"))?
            .compile_component_code(path, src)
            .with_context(|| format!("{what} failed to compile\n--- src ---\n{src}"))
    };
    let driver_code = link(MINT_COMPOSITION_DRIVER_PATH, driver_src, "mint composition driver")?;
    let probe_code = link(MINT_PROBE_PATH, probe_src, "no-effects probe")?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-mint-composition-driver"),
    )
    .context("binding the mint composition driver component")?;
    let probe_component = AccountComponent::new(
        probe_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-mint-composition-probe"),
    )
    .context("binding the no-effects probe component")?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("XUSDC")?)
        .symbol(TokenSymbol::new("XUSDC")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .build()
        .context("failed to build FungibleFaucet")?;

    // Resolve the deny-guard root from the assembled component (a benign read-only proc-root lookup;
    // the same value the production builder registers as the active mint policy).
    let deny_root: Word = xreserve_component
        .get_procedure_root_by_path(xusdc_encoding::account::xreserve::MINT_DENY_GUARD_PROC_PATH)
        .map(Word::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "xreserve component does not export the mint-deny guard procedure '{}'",
                xusdc_encoding::account::xreserve::MINT_DENY_GUARD_PROC_PATH
            )
        })?;
    let mut components = match selection {
        // PRODUCTION path: the real builder, deny ONLY (no reserved allow-all).
        GuardSelection::ProductionDeny => {
            xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::new(
                faucet,
                xreserve_component,
            )
            .build_components()
            .map_err(|e| anyhow::anyhow!("composing the production deny faucet: {e}"))?
        },
        // TEST-ONLY oracle (non-vacuity pair): both policies registered, deny ACTIVE.
        GuardSelection::OracleDeny => oracle_components(faucet, xreserve_component, deny_root, true)
            .context("composing the oracle deny faucet")?,
        // TEST-ONLY oracle (non-vacuity pair): both policies registered, allow-all ACTIVE.
        GuardSelection::OracleAllowAll => {
            oracle_components(faucet, xreserve_component, deny_root, false)
                .context("composing the oracle allow-all faucet")?
        },
    };
    components.push(driver_component);
    components.push(probe_component);

    let mut mc = MockChain::builder();
    let account = mc
        .add_existing_account_from_components(Auth::IncrNonce, components)
        .context("adding guarded faucet")?;
    let mock_chain = mc.build().context("building MockChain")?;
    Ok(GuardedMint {
        harness: CompositionHarness {
            mock_chain,
            account_id: account.id(),
            driver_code,
            probe_code,
        },
        deny_root,
    })
}

/// TEST-ONLY oracle composition for the R-MINT-16 non-vacuity pair. Registers BOTH the mint-deny
/// guard (`Custom(deny_root)`) and the stock allow-all in the `TokenPolicyManager`, one `Active` and
/// the other `Reserved`, so the allow-all and deny accounts are CODE-IDENTICAL (same components —
/// faucet + xreserve + policy-manager + `MintAllowAll` + `PausableManager` — and the same allowed
/// mint-policy set) and differ ONLY in `active_mint_policy_proc_root`. That identity is what makes the
/// allow-vs-deny pair a sound non-vacuity oracle: a deny trap is attributable to the active policy,
/// not to any fixture difference.
///
/// This lives in the TEST harness — NOT the production `XReserveStablecoinBuilder` — precisely so no
/// shipped API can construct an allow-all-active (stock-`mint_and_send`-reopening) faucet. The only
/// production composition path, [`xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::build_components`],
/// is deny-ONLY and rejects any non-deny active mint policy.
fn oracle_components(
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
    deny_root: Word,
    deny_active: bool,
) -> Result<Vec<AccountComponent>> {
    let deny = MintPolicyConfig::Custom(deny_root);
    let (active, reserved) = if deny_active {
        (deny, MintPolicyConfig::AllowAll)
    } else {
        (MintPolicyConfig::AllowAll, deny)
    };
    let manager = TokenPolicyManager::new()
        .with_mint_policy(active, PolicyRegistration::Active)
        .map_err(|e| anyhow::anyhow!("oracle manager active mint policy: {e}"))?
        .with_mint_policy(reserved, PolicyRegistration::Reserved)
        .map_err(|e| anyhow::anyhow!("oracle manager reserved mint policy: {e}"))?;
    // PausableManager is mandatory (the stock execute_mint_policy runs assert_not_paused before
    // dispatching). Component order/contents mirror XReserveStablecoinBuilder::assemble_components.
    let mut components = vec![faucet.into(), xreserve_component];
    components.extend(manager); // [policy-manager component, MintAllowAll]
    components.push(PausableManager.into());
    Ok(components)
}

/// Invokes the stock `mint_and_send` faucet entrypoint via a tx script (NOT a driver proc):
/// `create_fungible_asset` then `call.::miden::standards::faucets::fungible::mint_and_send`. The
/// push order feeds `create_fungible_asset` then `mint_and_send`, mirroring the protocol's own
/// faucet `create_mint_script_code` (miden-testing scripts/faucet.rs). `mint_and_send` routes
/// through `policy_manager::execute_mint_policy`, so the active mint policy (deny guard or allow-all)
/// gates it — the R-MINT-16 deny surface.
pub async fn run_mint_and_send(
    h: &CompositionHarness,
    recipient: Word,
    note_type: u8,
    tag: u32,
    amount: u64,
    enable_callbacks: u8,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src = format!(
        "
            begin
                push.{recipient}
                push.{note_type}
                push.{tag}
                push.{amount}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                push.{enable_callbacks}
                exec.::miden::protocol::asset::create_fungible_asset
                call.::miden::standards::faucets::fungible::mint_and_send
                dropw dropw dropw dropw
            end
            ",
        faucet_id_prefix = h.account_id.prefix().as_felt(),
        faucet_id_suffix = h.account_id.suffix(),
    );
    let tx_script = CodeBuilder::new().compile_tx_script(&src).unwrap_or_else(|e| {
        panic!("mint_and_send script failed to compile: {e}\n--- script ---\n{src}")
    });
    h.mock_chain
        .build_tx_context(h.account_id, &[], &[])
        .expect("building the tx context")
        .tx_script(tx_script)
        .build()
        .expect("building the transaction")
        .execute()
        .await
}
