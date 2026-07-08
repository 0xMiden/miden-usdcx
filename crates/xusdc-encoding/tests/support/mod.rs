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
    Account, AccountComponent, AccountId, AccountIdVersion, AccountType, RoleSymbol, StorageMap,
    StorageMapKey, StorageSlot, StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, FungibleAsset, TokenSymbol};
use miden_protocol::note::{Note, NoteType};
use miden_standards::testing::note::NoteBuilder;
use miden_protocol::assembly::Library;
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote, TransactionKernel};
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Word};
use miden_processor::advice::AdviceInputs;
use miden_processor::crypto::random::RandomCoin;
use miden_standards::account::access::{Authority, Ownable2Step, RoleBasedAccessControl};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicyConfig, MintPolicyConfig, PolicyRegistration, TokenPolicyManager,
};
use miden_standards::StandardsLib;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{BurnNote, P2idNote};
use miden_testing::{Auth, MockChain};
use miden_tx::TransactionExecutorError;
use xusdc_encoding::account::xreserve::{
    BURN_POLICY_PROC_PATH, DOM_MANAGER_ROLE, DOM_PAUSER_ROLE, MINT_DENY_GUARD_PROC_PATH,
};
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
// RE-EXPORTED from the production crate (the MIN_BURN_SIZE_SLOT_LABEL precedent, single Rust
// source: the builder's §5.13 slot-presence guard and these test bindings can never drift). The
// MASM modules declare byte-identical `word("…")` consts (parity-enforced). The two
// `xreserve_contract` slots carry the D-A6-XRC raw 8×u32-LE realization (hi = packed felts[0..4]
// / wire bytes 0..16, lo = felts[4..8]); `identifier` stays the D5a-consumer-forced hash-Word;
// `source_domain`/`xreserve_contract` are written ONLY by `domain_init` (off-chain identity,
// `GetAccount`-readable).
pub use xusdc_encoding::account::xreserve::{
    DOMAIN_CONFIG_SLOT_LABEL, IDENTIFIER_CONFIG_SLOT_LABEL, SOURCE_DOMAIN_CONFIG_SLOT_LABEL,
    XRESERVE_CONTRACT_HI_SLOT_LABEL, XRESERVE_CONTRACT_LO_SLOT_LABEL,
};

/// D5c `usedNonces` map-slot label (frozen §5.6 nonce registry). The MASM shell declares a
/// `word("…")` const with the byte-identical label at the D5c green commit (parity-enforced
/// from that commit). Re-exported from the production crate (single Rust source with the
/// builder's §5.13 slot-presence guard).
pub use xusdc_encoding::account::xreserve::USED_NONCES_SLOT_LABEL;

/// D5e faucet `token_config` value-slot label — the slot the standard `FungibleFaucet` component
/// installs (`[token_supply, max_supply, decimals, token_symbol]`), read/written by
/// `xreserve_mint.masm`. Bound here as the single Rust source for the constant-parity row.
pub const TOKEN_CONFIG_SLOT_LABEL: &str = "miden::standards::faucets::fungible::token_config";

/// D5d `xReserveAttesters` map-slot label (frozen §5.5 XReserveAttesterAdmin). The MASM
/// `attestation_verify.masm` declares a `word("…")` const with the byte-identical label
/// (parity-enforced); the later `set_attester` admin slice co-owns the SAME slot. Re-exported
/// from the production crate (single Rust source with the builder's §5.13 slot-presence guard).
pub use xusdc_encoding::account::xreserve::XRESERVE_ATTESTERS_SLOT_LABEL;

/// CMP-A10 `minBurnSize` value-slot label (§5.5 XReserveAttesterAdmin home, SPEC-OWNER RATIFIED).
/// Re-exported from the production crate so the builder (which SEEDS the slot) and the tests share a
/// SINGLE Rust source; `burn_policy.masm` declares a byte-identical `word("…")` const (parity-enforced)
/// and the future CMP-F2 `set_min_burn_size` setter co-owns the SAME slot (twin of
/// [`XRESERVE_ATTESTERS_SLOT_LABEL`]).
pub use xusdc_encoding::account::xreserve::MIN_BURN_SIZE_SLOT_LABEL;

// FAUCET(01) ERROR MIRRORS (frozen names: 01 TEST-AND-VERIFICATION-HARNESS.md:72-73)
// ================================================================================================

/// Name → constant table for the faucet-owned shell errors (D-2 string `MasmError`
/// pattern). The implementation must declare byte-identical strings in MASM. The two
/// D5b amount/fee errors (R-MINT-10/11) are PROPOSED names pending human approval
/// (plan §7); the D5b green commit declares the matching MASM consts + adds them to
/// `SHELL_ERRORS_DECLARED` for parity. The red-suite carries them here so the D5b
/// behavior tests can name their EXACT expected error.
pub static SHELL_ERR_TABLE: [(&str, MasmError); 25] = [
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
    // D5e F2 fee guard (xreserve_mint.masm). apply_mint_effects rejects a non-zero feeAmount (MVP
    // requires 0); parity-pinned against the MASM const.
    (
        "ERR_XRESERVE_FEE_NONZERO",
        MasmError::from_static_str("mint fee amount must be zero"),
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
    // R-ADMIN-4 domain-config init-once setter (domain_config.masm). The second write traps this; the
    // red-suite carries it here so the reinit test can name its EXACT expected error. The GREEN commit
    // declares the matching MASM const + adds it to `SHELL_ERRORS_DECLARED` for parity.
    (
        "ERR_XRESERVE_DOMAIN_REINIT",
        MasmError::from_static_str("domain config has already been initialized"),
    ),
    // CMP-A10 R-BURN-1: a burn must move a strictly positive amount (burn_policy.masm). The red-suite
    // carries it here so the zero-amount reject test can name its EXACT expected error; the GREEN
    // commit references the matching MASM const (declared now for parity).
    (
        "ERR_XRESERVE_BURN_ZERO",
        MasmError::from_static_str("burn amount must be greater than zero"),
    ),
    // CMP-A10 R-BURN-2: a burn must be at least the configured minimum burn size (burn_policy.masm).
    (
        "ERR_XRESERVE_BURN_BELOW_MIN",
        MasmError::from_static_str("burn amount is below the minimum burn size"),
    ),
    // CMP-B1 mint-note-entry transport-shape guards (xreserve_mint_note_entry.masm): the
    // note-storage header-length floor, the scheme-1 attestation + scheme-2 routing-target presence,
    // the exactly-two-attachment count (F5 fix-slice A), and the 9-word size assert on the
    // hash-verified attestation attachment.
    (
        "ERR_XRESERVE_MINT_NOTE_STORAGE_TOO_SHORT",
        MasmError::from_static_str("mint note storage is shorter than the deposit intent header"),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_ATTACHMENT_MISSING",
        MasmError::from_static_str("mint note attestation attachment is missing"),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_ATTACHMENT_COUNT",
        MasmError::from_static_str("mint note must carry exactly two attachments"),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_ATTACHMENT_NUM_WORDS",
        MasmError::from_static_str("mint note attachment word count is invalid"),
    ),
    // F5 fix-slice A: the 2-attachment reconciliation requires the scheme-2 NetworkAccountTarget
    // routing attachment to be present (routing-only). The red-suite carries the error here so the
    // scheme-aware negatives can name their EXACT expected error; the GREEN commit declares the
    // matching MASM const in xreserve_mint_note_entry.masm + adds it to the constant_parity covered
    // list. (The ATTACHMENT_COUNT string is reworded "exactly one"→"exactly two" in the GREEN commit,
    // MASM + this table together, so parity stays consistent.)
    (
        "ERR_XRESERVE_MINT_NOTE_TARGET_MISSING",
        MasmError::from_static_str("mint note routing target attachment is missing"),
    ),
    // §5.9 scalar-u32 exactness (full-assembly slice, Round-P change 1): domain_init guards BOTH
    // scalar fields as valid u32 values BEFORE any write (the spec types them u32,
    // COMPONENT-SPEC.md:331). The red-suite carries the three guard errors here so the
    // malformed-scalar/limb tests can name their EXACT expected error; the GREEN commit declares the
    // matching MASM consts in domain_config.masm + adds them to SHELL_ERRORS_DECLARED for parity.
    (
        "ERR_XRESERVE_DOMAIN_NOT_U32",
        MasmError::from_static_str("domain is not a valid u32"),
    ),
    (
        "ERR_XRESERVE_SOURCE_DOMAIN_NOT_U32",
        MasmError::from_static_str("source domain is not a valid u32"),
    ),
    // D-A6-XRC guard 2: every xreserve_contract limb must be a valid u32 before the two packed
    // words are stored (the fail-closed on-chain mirror of `packed_felts_to_bytes32`).
    (
        "ERR_XRESERVE_XRC_LIMB_NOT_U32",
        MasmError::from_static_str("xreserve contract limb is not a valid u32"),
    ),
    // R-ADMIN-4 hardening (P5-01 hardening Item 4): the identifier IS the init-once sentinel; an
    // EMPTY identifier would never arm it, leaving the "immutable" config silently
    // re-initializable. The red-suite carries the error here so the empty-identifier test can name
    // its EXACT expected error; the GREEN commit declares the matching MASM const in
    // domain_config.masm + adds it to SHELL_ERRORS_DECLARED for parity.
    (
        "ERR_XRESERVE_IDENTIFIER_EMPTY",
        MasmError::from_static_str("identifier must be non-empty"),
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
/// A deterministic dummy `AccountId` for the builder's `owner` / DOM role-holder inputs and for the
/// role-holder / non-holder note senders in the `set_attester` suite. Mirrors
/// `miden-testing/tests/scripts/rbac.rs:49-51`.
pub fn test_account_id(seed: u8) -> AccountId {
    AccountId::dummy([seed; 15], AccountIdVersion::Version1, AccountType::Private)
}

/// A deterministic PUBLIC dummy account id — usable as a faucet target for the F5 scheme-2
/// `NetworkAccountTarget` routing attachment (mint/burn/admin notes require a PUBLIC faucet id) and
/// as a fungible-asset issuer in note-construction unit tests.
pub fn test_faucet_id(seed: u8) -> AccountId {
    AccountId::dummy([seed; 15], AccountIdVersion::Version1, AccountType::Public)
}

pub fn assemble_xreserve_lib() -> Result<Library> {
    // Link the standards library (mirrors CodeBuilder's own `with_dynamic_library(StandardsLib)`):
    // attester_admin::set_attester calls the stock `authority::assert_authorized` /
    // `pausable::assert_not_paused`, which live in StandardsLib. The other xreserve modules stay
    // core+protocol-only; linking standards only adds resolvable symbols (it does not change their
    // MAST roots).
    let assembler = TransactionKernel::assembler()
        .with_dynamic_library(StandardsLib::default())
        .map_err(|e| anyhow::anyhow!("linking the standards library into the xreserve assembler: {e}"))?
        .with_warnings_as_errors(true);
    let lib = assembler
        .assemble_library_from_dir(xusdc_encoding::xreserve_asm_dir(), "xreserve")
        .map_err(|e| anyhow::anyhow!("xreserve library failed to assemble: {e}"))?;
    Ok(Arc::unwrap_or_clone(lib))
}

/// Assembles a TEST-ONLY variant of the `xreserve` library in which `apply_mint_effects` and
/// `extract_recipient_account_id` are forced `pub` (callable + addressable by path/root), whatever
/// their visibility in the shipped source. It copies the shipped `asm/standards/xreserve` tree to a
/// temp dir, idempotently forces the two procs `pub` (a no-op when they are already `pub`), and
/// assembles the copy with the SAME assembler as [`assemble_xreserve_lib`].
///
/// Visibility does not change a procedure's MAST, so this library's `apply_mint_effects` /
/// `extract_recipient_account_id` carry the IDENTICAL MAST root to the shipped (post-fix: private)
/// ones. That is what lets the isolation tests reach the demoted procs via cross-module `exec`, and
/// lets the procedure-root security test target the exact root the production faucet no longer
/// exposes. This is NOT the shipped `xreserve` component — it is used only to drive the demoted
/// procs in isolation.
pub fn assemble_xreserve_lib_effects_public() -> Result<Library> {
    let src_dir = xusdc_encoding::xreserve_asm_dir();
    let tmp_dir = unique_temp_dir("xusdc_xreserve_effects_public");
    copy_dir_recursive(&src_dir, &tmp_dir).context("copying the xreserve asm tree to a temp dir")?;

    // force the two demoted procs `pub` in the temp copy (idempotent: no-op when already `pub`).
    let mint_masm = tmp_dir.join("xreserve_mint.masm");
    let mut src = std::fs::read_to_string(&mint_masm)
        .with_context(|| format!("reading {}", mint_masm.display()))?;
    src = force_proc_public(&src, "apply_mint_effects");
    src = force_proc_public(&src, "extract_recipient_account_id");
    std::fs::write(&mint_masm, src).context("writing the effects-public xreserve_mint.masm")?;

    let assembler = TransactionKernel::assembler()
        .with_dynamic_library(StandardsLib::default())
        .map_err(|e| {
            anyhow::anyhow!("linking the standards library into the effects-public assembler: {e}")
        })?
        .with_warnings_as_errors(true);
    let lib = assembler
        .assemble_library_from_dir(&tmp_dir, "xreserve")
        .map_err(|e| anyhow::anyhow!("effects-public xreserve library failed to assemble: {e}"))?;
    Ok(Arc::unwrap_or_clone(lib))
}

/// Inserts `pub ` before the line-anchored `proc {name}` declaration iff it is not already
/// `pub proc {name}` — idempotent whether the shipped source has the proc `pub` or private.
fn force_proc_public(src: &str, name: &str) -> String {
    let pub_decl = format!("\npub proc {name}");
    if src.contains(&pub_decl) {
        return src.to_string();
    }
    src.replacen(&format!("\nproc {name}"), &pub_decl, 1)
}

/// Recursively copies every file and subdirectory under `from` into `to` (creating `to`).
fn copy_dir_recursive(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if src.is_dir() {
            copy_dir_recursive(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// A collision-free temp-dir path (process id + a monotonic counter — no RNG/timestamp needed, so
/// parallel test threads never clash).
fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}_{}_{n}", std::process::id()))
}

/// Composes the PRODUCTION component set exactly as the on-chain faucet is built — via
/// `XReserveStablecoinBuilder::build_components()`, installing the shipped `xreserve` library
/// (from [`assemble_xreserve_lib`]) with the full seven-slot production storage set. Returns the
/// composed `AccountComponent`s (the union whose exported procedure roots become the account's
/// callable interface). Used by the procedure-root sole-surface test — NOT a bespoke harness.
pub fn production_component_set(max_supply: u64, token_supply: u64) -> Result<Vec<AccountComponent>> {
    let library = assemble_xreserve_lib()?;
    let empty = || Word::from([0u32, 0, 0, 0]);
    let xreserve_component = AccountComponent::new(
        library,
        vec![
            StorageSlot::with_value(
                StorageSlotName::new(DOMAIN_CONFIG_SLOT_LABEL).context("domain slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)
                    .context("identifier slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(SOURCE_DOMAIN_CONFIG_SLOT_LABEL)
                    .context("source_domain slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_HI_SLOT_LABEL)
                    .context("xreserve_contract_hi slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_LO_SLOT_LABEL)
                    .context("xreserve_contract_lo slot label")?,
                empty(),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
                StorageMap::new(),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
                    .context("xReserveAttesters slot label")?,
                StorageMap::new(),
            ),
        ],
        AccountComponentMetadata::new("xusdc-production-surface"),
    )
    .context("binding the xreserve library + all seven slots as a component")?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .is_max_supply_mutable(true)
        .build()
        .context("failed to build FungibleFaucet")?;

    xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .map_err(|e| anyhow::anyhow!("composing the production faucet components: {e}"))
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
    setup_shell_account_with_lib(
        assemble_xreserve_lib()?,
        domain,
        identifier,
        nonce_seed,
        driver_src,
        driver_path,
    )
}

/// Like [`setup_shell_account`], but installs the effects-public `xreserve` variant so a driver's
/// cross-module `exec.xreserve_mint::extract_recipient_account_id` resolves and the demoted proc is
/// a member of this TEST-ONLY account. The recipient-extractor isolation tests use this after the
/// F1 demotion makes the proc private in the shipped component.
pub fn setup_shell_account_effects_public(
    domain: Word,
    identifier: Word,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
    setup_shell_account_with_lib(
        assemble_xreserve_lib_effects_public()?,
        domain,
        identifier,
        None,
        driver_src,
        driver_path,
    )
}

fn setup_shell_account_with_lib(
    library: Library,
    domain: Word,
    identifier: Word,
    nonce_seed: Option<(Word, Word)>,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
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
    /// Raw 33-byte compressed SEC1 pubkey (what the relayer hands `XReserveMintNote::create`).
    pub pubkey_bytes: [u8; 33],
    /// Raw 65-byte `r||s||v` signature (what the relayer hands `XReserveMintNote::create`).
    pub sig_bytes: [u8; 65],
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
        pubkey_bytes: pk33,
        sig_bytes: sig65,
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
/// "USDCX"]) carrying the xreserve component (the `apply_mint_effects` proc + the `usedNonces` map
/// slot), the generated mint driver, AND a no-effects readback probe, plus a recipient wallet for
/// the P2ID note. Mirrors the canary-proven construction
/// (`add_existing_account_from_components([faucet.into(), …])`).
pub fn setup_mint_faucet_account(
    max_supply: u64,
    token_supply: u64,
    inputs: &MintInputs,
) -> Result<MintHarness> {
    // effects-public variant: after the F1 demotion `apply_mint_effects` is private in the shipped
    // library, so the isolation driver's cross-module `exec.xreserve_mint::apply_mint_effects` only
    // resolves against this test-only assembly (identical MAST root; a test-only account, never the
    // production component).
    let library = assemble_xreserve_lib_effects_public()?;

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
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
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
            // §5.9 4-field closure: the two new scalar/bytes32 config slots, EMPTY at assembly
            // (domain_init is the sole writer; per-slice fixtures never read them).
            StorageSlot::with_value(
                StorageSlotName::new(SOURCE_DOMAIN_CONFIG_SLOT_LABEL)
                    .context("source_domain slot label")?,
                Word::from([0u32, 0, 0, 0]),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_HI_SLOT_LABEL)
                    .context("xreserve_contract_hi slot label")?,
                Word::from([0u32, 0, 0, 0]),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_LO_SLOT_LABEL)
                    .context("xreserve_contract_lo slot label")?,
                Word::from([0u32, 0, 0, 0]),
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
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
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

/// Assembles a MINIMAL, faucet-ONLY account with an IMMUTABLE `max_supply` — a builder-BYPASS fixture
/// (`add_existing_account_from_components`, NOT `XReserveStablecoinBuilder`, so the build-time mutability
/// guard does not apply). The immutable control [`set_max_supply_immutable_traps`] uses it to prove the
/// stock RUNTIME mutability gate fires: stock `set_max_supply` checks mutability FIRST (before
/// auth / pause / below-supply), so a bare faucet (no RBAC) traps `ERR_MAX_SUPPLY_NOT_MUTABLE`
/// identically to a full production account. `driver_code` / `probe_code` are unused on this path
/// (set_max_supply runs via a note, not the mint driver), so the faucet's own code stands in as a
/// harmless placeholder for those [`CompositionHarness`] fields.
pub fn setup_bare_immutable_faucet(token_supply: u64, max_supply: u64) -> Result<CompositionHarness> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        // is_max_supply_mutable defaults to false (immutable) — the control fixture.
        .build()
        .context("failed to build the bare immutable FungibleFaucet")?;
    let placeholder = FungibleFaucet::code().clone();

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [faucet.into()])
        .context("adding the bare immutable faucet account")?;
    let mock_chain = builder.build().context("building the bare-faucet MockChain")?;
    Ok(CompositionHarness {
        mock_chain,
        account_id: account.id(),
        driver_code: placeholder.clone(),
        probe_code: placeholder,
    })
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

// set_attester — role-holder note invocation + the set->verify seam
// ================================================================================================

/// Builds an unauthenticated note SENT BY `sender` whose script `call`s
/// `xreserve::attester_admin::set_attester(PK_COMMITMENT, enabled)`. The RBAC gate reads the note
/// sender (`active_note::get_sender`), so the sender is what the owner check tests. `enabled`
/// is 1 (allowlist) or 0 (remove). The note script is compiled with the `xreserve` library linked so
/// the `call` resolves to the same proc installed on the faucet account.
pub fn set_attester_note(sender: AccountId, commitment: Word, enabled: u8, seed: u64) -> Result<Note> {
    let lib = assemble_xreserve_lib()?;
    // Stack contract: [PK_COMMITMENT, enabled, pad(11)] (PK_COMMITMENT element-0 on top). Push the
    // 11 pad felts (deepest), then enabled, then the commitment so c0 ends on top: 11 + 1 + 4 = 16.
    let src = format!(
        "use xreserve::attester_admin\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.11 push.0 end\n\
         \x20\x20\x20\x20push.{enabled}\n\
         \x20\x20\x20\x20push.{c3}.{c2}.{c1}.{c0}\n\
         \x20\x20\x20\x20call.attester_admin::set_attester\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
        c0 = commitment[0],
        c1 = commitment[1],
        c2 = commitment[2],
        c3 = commitment[3],
    );
    let script = CodeBuilder::new()
        .with_dynamically_linked_library(&lib)
        .context("linking xreserve into the set_attester note script")?
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("set_attester note script failed to compile: {e}\n{src}"))?;
    // Deterministic note rng (RandomCoin satisfies NoteBuilder's `Rng` bound; StdRng's `rand`
    // version does not). The seed only affects the note serial, never the gate.
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(1u32),
        Felt::from(2u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a `set_attester` note (sent by `sender`) against the faucet `account`, returning the raw
/// execution result so callers can assert success or the exact trap. Note building (assemble/compile)
/// is a test-setup invariant (panics on failure); only the on-chain execution is returned.
pub async fn run_set_attester_tx(
    h: &CompositionHarness,
    account: &Account,
    sender: AccountId,
    commitment: Word,
    enabled: u8,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = set_attester_note(sender, commitment, enabled, seed)
        .expect("building the set_attester note (test-setup invariant)");
    h.mock_chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the set_attester tx context")
        .build()
        .expect("building the set_attester transaction")
        .execute()
        .await
}

/// The faucet account's CURRENT committed state — the starting point for the seam's first tx.
pub fn faucet_account(h: &CompositionHarness) -> Account {
    h.mock_chain
        .committed_account(h.account_id)
        .expect("faucet account is committed in the mock chain")
        .clone()
}

/// Builds a note SENT BY `sender` whose script calls the stock `PausableManager::pause`. Under
/// Option 1 (Domain-Pauser-only) the composition does NOT install `PausableManager`, so this note is
/// the NEGATIVE PROBE for `owner_has_no_pause_path`: it assembles (StandardsLib is pre-linked) but
/// executing it traps `UnknownAccountProcedure` (the root is not in the account code). No xreserve
/// link is needed.
pub fn pause_note(sender: AccountId, seed: u64) -> Result<Note> {
    let src = "use miden::standards::access::pausable::manager\n\
               @note_script\n\
               pub proc main\n\
               \x20\x20\x20\x20repeat.16 push.0 end\n\
               \x20\x20\x20\x20call.manager::pause\n\
               \x20\x20\x20\x20dropw dropw dropw dropw\n\
               end\n";
    let script = CodeBuilder::new()
        .compile_note_script(src)
        .map_err(|e| anyhow::anyhow!("pause note script failed to compile: {e}"))?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a stock `PausableManager::pause` note (sent by `sender`) against the faucet `account` —
/// the CompositionHarness-shaped twin of [`run_pause_against`]. Under Option 1 this is a negative
/// probe: the stock proc is not installed, so execution traps `UnknownAccountProcedure`.
pub async fn run_pause_tx(
    h: &CompositionHarness,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = pause_note(sender, seed).expect("building the pause note (test-setup invariant)");
    h.mock_chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the pause tx context")
        .build()
        .expect("building the pause transaction")
        .execute()
        .await
}

// domain_init — owner-gated init-once domain-config setter note (P5-01 R-ADMIN-4 slice)
// ================================================================================================

/// The exact stock error `ownable2step::assert_sender_is_owner` traps (ownable2step.masm:38
/// ERR_SENDER_NOT_OWNER). Constructed inline (a stock protocol error, not an xusdc shell error, so it
/// is not in `SHELL_ERR_TABLE`). Under the reconciled owner-gated model (DECISION-ADMIN-ROLE-MODEL)
/// this is the SHARED trap for a non-owner sender across every setter (`set_attester` /
/// `set_min_burn_size` / `set_max_supply` / `domain_init`).
pub fn err_sender_not_owner() -> MasmError {
    MasmError::from_static_str("note sender is not the owner")
}

/// Builds an unauthenticated note SENT BY `sender` whose script `call`s the FOUR-FIELD
/// `xreserve::domain_config::domain_init(IDENTIFIER, XRC_HI, XRC_LO, source_domain, domain)` (§5.9
/// closure). The Ownable2Step gate reads the note sender (`active_note::get_sender`), so the sender
/// is what the owner check tests. `domain`/`source_domain` are the u32 scalar fields (each stored as
/// element 0 of its config word, u32-guarded on-chain before any write); `xreserve_contract` is the
/// raw bytes32 packed via the 04 codec BY REFERENCE (`bytes32_to_packed_felts` — D-A6-XRC guard 1;
/// hi = felts[0..4], lo = felts[4..8]); `identifier` is the pre-hashed `bytes32_to_key` Word stored
/// verbatim (unchanged). The note script links the `xreserve` library so the `call` resolves to the
/// same proc installed on the faucet account.
pub fn domain_init_note(
    sender: AccountId,
    domain: u32,
    source_domain: u32,
    xreserve_contract: &[u8; 32],
    identifier: Word,
    seed: u64,
) -> Result<Note> {
    let xrc = xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts(xreserve_contract);
    let mut xrc_u64 = [0u64; 8];
    for (dst, felt) in xrc_u64.iter_mut().zip(xrc.iter()) {
        *dst = felt.as_canonical_u64();
    }
    domain_init_note_raw(sender, u64::from(domain), u64::from(source_domain), &xrc_u64, identifier, seed)
}

/// RAW-FELT variant of [`domain_init_note`]: stages `domain` / `source_domain` / the 8
/// `xreserve_contract` limbs as raw u64 felt literals, BYPASSING the u32-typed builder above — the
/// only way to stage the malformed (> `u32::MAX`) values the on-chain scalar/limb guards must trap
/// (`ERR_XRESERVE_DOMAIN_NOT_U32` / `ERR_XRESERVE_SOURCE_DOMAIN_NOT_U32` /
/// `ERR_XRESERVE_XRC_LIMB_NOT_U32`; §5.9 scalar-u32 exactness, Round-P change 1).
pub fn domain_init_note_raw(
    sender: AccountId,
    domain: u64,
    source_domain: u64,
    xrc_limbs: &[u64; 8],
    identifier: Word,
    seed: u64,
) -> Result<Note> {
    let lib = assemble_xreserve_lib()?;
    // Stack contract: [IDENTIFIER, XRC_HI, XRC_LO, source_domain, domain, pad(2)] (IDENTIFIER
    // element-0 on top; 4+4+4+1+1 = 14 meaningful + pad(2) = 16, the full call-boundary window —
    // ZERO margin; any future field forces the advice path). Push order: 2 pads (deepest), domain,
    // source_domain, XRC_LO word, XRC_HI word, IDENTIFIER word (each word pushed e3..e0 so element 0
    // ends on top).
    let src = format!(
        "use xreserve::domain_config\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.2 push.0 end\n\
         \x20\x20\x20\x20push.{domain}\n\
         \x20\x20\x20\x20push.{source_domain}\n\
         \x20\x20\x20\x20push.{xl3}.{xl2}.{xl1}.{xl0}\n\
         \x20\x20\x20\x20push.{xh3}.{xh2}.{xh1}.{xh0}\n\
         \x20\x20\x20\x20push.{i3}.{i2}.{i1}.{i0}\n\
         \x20\x20\x20\x20call.domain_config::domain_init\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
        xh0 = xrc_limbs[0],
        xh1 = xrc_limbs[1],
        xh2 = xrc_limbs[2],
        xh3 = xrc_limbs[3],
        xl0 = xrc_limbs[4],
        xl1 = xrc_limbs[5],
        xl2 = xrc_limbs[6],
        xl3 = xrc_limbs[7],
        i0 = identifier[0],
        i1 = identifier[1],
        i2 = identifier[2],
        i3 = identifier[3],
    );
    let script = CodeBuilder::new()
        .with_dynamically_linked_library(&lib)
        .context("linking xreserve into the domain_init note script")?
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("domain_init note script failed to compile: {e}\n{src}"))?;
    // Deterministic note rng (serial only; never affects the gate). Distinct tail [9,10] keeps serials
    // disjoint from set_attester [1,2] / pause [3,4] / set_max_supply [5,6].
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(9u32),
        Felt::from(10u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a FOUR-FIELD `domain_init` note (sent by `sender`) against the faucet `account`,
/// returning the raw execution result so callers can assert success or the exact trap. Mirrors
/// `run_set_attester_tx`.
pub async fn run_domain_init_tx(
    h: &CompositionHarness,
    account: &Account,
    sender: AccountId,
    domain: u32,
    source_domain: u32,
    xreserve_contract: &[u8; 32],
    identifier: Word,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = domain_init_note(sender, domain, source_domain, xreserve_contract, identifier, seed)
        .expect("building the domain_init note (test-setup invariant)");
    h.mock_chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the domain_init tx context")
        .build()
        .expect("building the domain_init transaction")
        .execute()
        .await
}

/// The raw-felt twin of [`run_domain_init_tx`] (malformed-scalar/limb staging).
pub async fn run_domain_init_tx_raw(
    h: &CompositionHarness,
    account: &Account,
    sender: AccountId,
    domain: u64,
    source_domain: u64,
    xrc_limbs: &[u64; 8],
    identifier: Word,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = domain_init_note_raw(sender, domain, source_domain, xrc_limbs, identifier, seed)
        .expect("building the raw domain_init note (test-setup invariant)");
    h.mock_chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the domain_init tx context")
        .build()
        .expect("building the domain_init transaction")
        .execute()
        .await
}

/// Reads the FIVE domain-config words `[domain, source_domain, xrc_hi, xrc_lo, identifier]` from a
/// committed/evolved account — the §5.9 4-field read-back (+ the no-write assert of the guard
/// tests). Missing-slot reads propagate as errors (the slots are always declared on the fixtures).
pub fn read_domain_config_words(account: &Account) -> Result<[Word; 5]> {
    let read = |label: &str| -> Result<Word> {
        account
            .storage()
            .get_item(&StorageSlotName::new(label).with_context(|| format!("slot label {label}"))?)
            .map_err(|e| anyhow::anyhow!("reading domain-config slot {label}: {e}"))
    };
    Ok([
        read(DOMAIN_CONFIG_SLOT_LABEL)?,
        read(SOURCE_DOMAIN_CONFIG_SLOT_LABEL)?,
        read(XRESERVE_CONTRACT_HI_SLOT_LABEL)?,
        read(XRESERVE_CONTRACT_LO_SLOT_LABEL)?,
        read(IDENTIFIER_CONFIG_SLOT_LABEL)?,
    ])
}

// set_min_burn_size — owner-gated minBurnSize setter note + slot read-back (P5-01 CMP-F2 slice)
// ================================================================================================

/// Builds an unauthenticated note SENT BY `sender` whose script `call`s
/// `xreserve::min_burn_admin::set_min_burn_size(new_min)`. Like `set_attester`/`domain_init`, the gate
/// reads the note sender (`active_note::get_sender`), so the sender is what the owner check tests.
/// `new_min` is the single felt written as element 0 of the `MIN_BURN_SIZE_SLOT` value word. The note
/// script links the `xreserve` library so the `call` resolves to the same proc installed on the faucet.
pub fn set_min_burn_size_note(sender: AccountId, new_min: u64, seed: u64) -> Result<Note> {
    let lib = assemble_xreserve_lib()?;
    // Stack contract: [new_min, pad(15)] (new_min on top). Push 15 pad felts (deepest) then new_min so
    // it ends on top: 15 + 1 = 16.
    let src = format!(
        "use xreserve::min_burn_admin\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.15 push.0 end\n\
         \x20\x20\x20\x20push.{new_min}\n\
         \x20\x20\x20\x20call.min_burn_admin::set_min_burn_size\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .with_dynamically_linked_library(&lib)
        .context("linking xreserve into the set_min_burn_size note script")?
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("set_min_burn_size note script failed to compile: {e}\n{src}"))?;
    // Deterministic note rng (serial only; never affects the gate). Distinct tail [7,8] keeps serials
    // disjoint from set_attester [1,2] / pause [3,4] / set_max_supply [5,6] / domain_init [9,10].
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(8u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a `set_min_burn_size` note (sent by `sender`) against the faucet `account` on a bare
/// `&MockChain` (the burn-policy harness is a `BurnPolicyHarness`, not a `CompositionHarness`). Returns
/// the raw execution result so callers assert success or the exact trap. Mirrors [`run_pause_against`].
pub async fn run_set_min_burn_size_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    new_min: u64,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = set_min_burn_size_note(sender, new_min, seed)
        .expect("building the set_min_burn_size note (test-setup invariant)");
    chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the set_min_burn_size tx context")
        .build()
        .expect("building the set_min_burn_size transaction")
        .execute()
        .await
}

/// Reads the faucet `MIN_BURN_SIZE_SLOT` value word `[min_burn_size, 0, 0, 0]` from a committed/evolved
/// account — the full-word read-back the CMP-F2 write-integrity + no-state-change tests use (the slot
/// CMP-A10's `burn_policy::check_policy` reads for R-BURN-2). Mirrors [`read_token_config`].
pub fn read_min_burn_size(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(
            &StorageSlotName::new(MIN_BURN_SIZE_SLOT_LABEL).context("min_burn_size slot label")?,
        )
        .map_err(|e| anyhow::anyhow!("reading the min_burn_size value slot: {e}"))
}

// set_max_supply — stock admin setter note + token_config read-back (P5-01 set_max_supply slice)
// ================================================================================================

/// The exact stock error `set_max_supply` traps when the faucet's max_supply is immutable
/// (`fungible.masm:40` ERR_MAX_SUPPLY_NOT_MUTABLE). Constructed inline (a stock protocol error, not an
/// xusdc shell error, so it is not in `SHELL_ERR_TABLE`).
pub fn err_max_supply_not_mutable() -> MasmError {
    MasmError::from_static_str("max supply is not mutable")
}

/// The exact stock error `set_max_supply` traps when `new_max_supply < token_supply`
/// (`fungible.masm:41` ERR_NEW_MAX_SUPPLY_BELOW_TOKEN_SUPPLY).
pub fn err_new_max_supply_below_token_supply() -> MasmError {
    MasmError::from_static_str("new max supply is less than current token supply")
}

/// Builds a note SENT BY `sender` whose script `call`s the stock `set_max_supply(new_max_supply)` —
/// gated on the SAME owner Authority + `assert_not_paused` + the build-time mutability flag,
/// fired mutability -> auth -> pause -> below-supply. Stock `set_max_supply` consumes
/// `[new_max_supply, pad(15)]` and returns `[pad(16)]`. Like `pause_note`, `set_max_supply` is a pure
/// standards proc (CodeBuilder pre-links StandardsLib), so no xreserve link is needed; the
/// absolute-path `call` resolves to the same stock proc the faucet account exposes (the path
/// `run_mint_and_send` reaches `mint_and_send` through).
pub fn set_max_supply_note(sender: AccountId, new_max_supply: u64, seed: u64) -> Result<Note> {
    // Stack contract: [new_max_supply, pad(15)] (new_max_supply on top). Push 15 pad felts (deepest)
    // then new_max_supply so it ends on top: 15 + 1 = 16.
    let src = format!(
        "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.15 push.0 end\n\
         \x20\x20\x20\x20push.{new_max_supply}\n\
         \x20\x20\x20\x20call.::miden::standards::faucets::fungible::set_max_supply\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("set_max_supply note script failed to compile: {e}\n{src}"))?;
    // Deterministic note rng (serial only; never affects the gate). Distinct tail [5,6] keeps serials
    // disjoint from set_attester [1,2] and pause [3,4].
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(5u32),
        Felt::from(6u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a `set_max_supply` note (sent by `sender`) against the faucet `account`, returning the raw
/// execution result so callers can assert success or the exact trap. Mirrors `run_set_attester_tx`.
pub async fn run_set_max_supply_tx(
    h: &CompositionHarness,
    account: &Account,
    sender: AccountId,
    new_max_supply: u64,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = set_max_supply_note(sender, new_max_supply, seed)
        .expect("building the set_max_supply note (test-setup invariant)");
    h.mock_chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the set_max_supply tx context")
        .build()
        .expect("building the set_max_supply transaction")
        .execute()
        .await
}

/// Reads the faucet `token_config` value word `[token_supply, max_supply, decimals, token_symbol]`
/// from a committed/evolved account — the full-word read-back the set_max_supply write-integrity test
/// uses to prove `set_max_supply` changed ONLY word[1] (max_supply).
pub fn read_token_config(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(&StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL).context("token_config slot label")?)
        .map_err(|e| anyhow::anyhow!("reading the token_config value slot: {e}"))
}

/// Runs the mint composition driver against an explicit (possibly evolved) `account` — the seam's
/// tx2, after a real `set_attester` tx evolved the faucet. Mirrors [`run_mint_composition`] but
/// threads the account instead of `h.account_id`, so tx1's storage delta is visible to the read path.
pub async fn run_mint_against(
    h: &CompositionHarness,
    account: &Account,
    advice: Vec<Felt>,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src =
        format!("use {MINT_COMPOSITION_DRIVER_PATH}->driver\nbegin\n    call.driver::drive\nend\n");
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_library(&h.driver_code)
        .expect("linking the driver into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| panic!("driver call script failed to compile: {e}\n--- script ---\n{src}"));
    h.mock_chain
        .build_tx_context(account.clone(), &[], &[])
        .expect("building the tx context")
        .tx_script(tx_script)
        .extend_advice_inputs(AdviceInputs::default().with_stack(advice))
        .build()
        .expect("building the transaction")
        .execute()
        .await
}

/// A rotation harness: the owner-gated production faucet (owner = id(1)) with an EMPTY
/// allowlist + ONE mint driver per distinct-nonce payload, so the rotation can run several successful
/// mints (each consumes its own nonce) on ONE evolving account. Reuses [`CompositionHarness`] for
/// `mock_chain` / `account_id`; the rotation runs drivers explicitly via [`run_rotation_mint`].
pub struct RotationHarness {
    pub harness: CompositionHarness,
    pub drivers: Vec<(String, AccountComponentCode)>,
}

/// Builds the rotation account: the production builder (RBAC seeded) + one driver component per
/// `driver_srcs` entry, each at a distinct module path (`xusdc::test_fixtures::rotation_driver_{i}`).
pub fn setup_rotation_account(
    domain: Word,
    identifier: Word,
    driver_srcs: &[&str],
) -> Result<RotationHarness> {
    let library = assemble_xreserve_lib()?;
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
            // §5.9 4-field closure: the two new scalar/bytes32 config slots, EMPTY at assembly
            // (domain_init is the sole writer).
            StorageSlot::with_value(
                StorageSlotName::new(SOURCE_DOMAIN_CONFIG_SLOT_LABEL)
                    .context("source_domain slot label")?,
                Word::from([0u32, 0, 0, 0]),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_HI_SLOT_LABEL)
                    .context("xreserve_contract_hi slot label")?,
                Word::from([0u32, 0, 0, 0]),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_LO_SLOT_LABEL)
                    .context("xreserve_contract_lo slot label")?,
                Word::from([0u32, 0, 0, 0]),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
                StorageMap::new(),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
                    .context("xReserveAttesters slot label")?,
                StorageMap::new(),
            ),
        ],
        AccountComponentMetadata::new("xusdc-rotation-harness"),
    )
    .context("binding the rotation xreserve component")?;

    let mut drivers = Vec::new();
    let mut driver_components = Vec::new();
    for (i, src) in driver_srcs.iter().enumerate() {
        let path = format!("xusdc::test_fixtures::rotation_driver_{i}");
        let code = CodeBuilder::new()
            .with_dynamically_linked_library(&library)
            .with_context(|| format!("linking xreserve into rotation driver {i}"))?
            .compile_component_code(&path, *src)
            .with_context(|| format!("rotation driver {i} failed to compile"))?;
        driver_components.push(
            AccountComponent::new(
                code.clone(),
                vec![],
                AccountComponentMetadata::new(format!("xusdc-rotation-driver-{i}")),
            )
            .with_context(|| format!("binding rotation driver {i}"))?,
        );
        drivers.push((path, code));
    }

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(1_000_000).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(0).context("invalid token_supply")?)
        // Mutable: the production builder now rejects an immutable max_supply (build-time guard).
        .is_max_supply_mutable(true)
        .build()
        .context("failed to build FungibleFaucet")?;

    let mut components = xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .map_err(|e| anyhow::anyhow!("composing the rotation faucet: {e}"))?;
    components.extend(driver_components);

    let mut mc = MockChain::builder();
    let account = mc
        .add_existing_account_from_components(Auth::IncrNonce, components)
        .context("adding the rotation account")?;
    let mock_chain = mc.build().context("building the rotation MockChain")?;
    let first = drivers[0].1.clone();
    Ok(RotationHarness {
        harness: CompositionHarness {
            mock_chain,
            account_id: account.id(),
            driver_code: first.clone(),
            probe_code: first,
        },
        drivers,
    })
}

/// Runs rotation `driver` (path + code) against an explicit (evolving) `account` with `advice` — the
/// per-payload analog of [`run_mint_against`].
pub async fn run_rotation_mint(
    h: &CompositionHarness,
    driver: &(String, AccountComponentCode),
    account: &Account,
    advice: Vec<Felt>,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let (path, code) = driver;
    let src = format!("use {path}->driver\nbegin\n    call.driver::drive\nend\n");
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_library(code)
        .expect("linking the rotation driver into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| panic!("rotation driver script failed to compile: {e}\n{src}"));
    h.mock_chain
        .build_tx_context(account.clone(), &[], &[])
        .expect("building the rotation tx context")
        .tx_script(tx_script)
        .extend_advice_inputs(AdviceInputs::default().with_stack(advice))
        .build()
        .expect("building the rotation transaction")
        .execute()
        .await
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
/// active or allow-all per the [`GuardSelection`]), plus the resolved deny-guard proc root. The
/// production deny path is composed by `XReserveStablecoinBuilder::build_components`; the
/// allow-all/deny oracle pair is composed by the test-only [`oracle_components`] helper. No stock
/// `PausableManager` anywhere (Option 1, Domain-Pauser-only): the `is_paused` slot is
/// FungibleFaucet-installed and pause is exclusively `xreserve::pause_admin`.
pub struct GuardedMint {
    pub harness: CompositionHarness,
    pub deny_root: Word,
}

/// Like [`setup_mint_composition_account`] but ALSO installs the `TokenPolicyManager` (mint-deny
/// guard active or allow-all per `selection`) via [`XReserveStablecoinBuilder`].
/// The deny guard rides the same `xreserve` library component (its `check_policy` proc). Used by the
/// R-MINT-16 deny suite to drive the inherited stock `mint_and_send` against a policy-managed faucet.
///
/// `is_max_supply_mutable` configures the built faucet's stock max-supply mutability flag (threaded
/// into the `FungibleFaucet::builder()` chain). The production builder (`GuardSelection::ProductionDeny`)
/// REJECTS an immutable max_supply at build time, so every `ProductionDeny` caller must pass `true`; the
/// `OracleDeny` / `OracleAllowAll` paths bypass the builder and are unaffected. The immutable control
/// (`set_max_supply_immutable_traps`) builds its immutable fixture via the builder-bypassing
/// [`setup_bare_immutable_faucet`] instead of this helper.
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
    is_max_supply_mutable: bool,
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
            // §5.9 4-field closure: the two new scalar/bytes32 config slots, EMPTY at assembly
            // (domain_init is the sole writer; per-slice fixtures never read them).
            StorageSlot::with_value(
                StorageSlotName::new(SOURCE_DOMAIN_CONFIG_SLOT_LABEL)
                    .context("source_domain slot label")?,
                Word::from([0u32, 0, 0, 0]),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_HI_SLOT_LABEL)
                    .context("xreserve_contract_hi slot label")?,
                Word::from([0u32, 0, 0, 0]),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_LO_SLOT_LABEL)
                    .context("xreserve_contract_lo slot label")?,
                Word::from([0u32, 0, 0, 0]),
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
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .is_max_supply_mutable(is_max_supply_mutable)
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
                test_account_id(1),
                test_account_id(2),
                test_account_id(3),
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
/// faucet + xreserve + policy-manager + `MintAllowAll` — and the same allowed mint-policy set) and
/// differ ONLY in `active_mint_policy_proc_root`. That identity is what makes the allow-vs-deny pair
/// a sound non-vacuity oracle: a deny trap is attributable to the active policy, not to any fixture
/// difference.
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
    // No PausableManager (Option 1, Domain-Pauser-only): the is_paused slot execute_mint_policy's
    // assert_not_paused reads is FungibleFaucet-installed (fungible/mod.rs:397, pinned v0.15.3).
    // Component order/contents mirror XReserveStablecoinBuilder::assemble_components.
    let mut components = vec![faucet.into(), xreserve_component];
    components.extend(manager); // [policy-manager component, MintAllowAll]
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

// CMP-A10 BURN POLICY (P5-01 R-BURN-1/2) — real-MockChain 2-block burn-consume oracle + direct driver
// ================================================================================================

/// Which burn policy the burn-oracle faucet fixture installs ACTIVE. Both selections compose a
/// CODE-IDENTICAL account (faucet + xreserve + policy-manager + BurnAllowAll + RBAC,
/// with the mint-deny guard ACTIVE and BOTH burn policies registered) differing ONLY in
/// `active_burn_policy_proc_root` — the non-vacuity oracle the R-BURN-2 reject leans on.
/// Test-side u64 -> `Felt` for burn magnitudes (`min_burn_size` / `amount`), which are `AssetAmount`s
/// `< 2^63` and therefore always field-safe. `Felt::new` is fallible (it validates `< p`); this wraps
/// the infallible-for-our-range case.
fn felt_from_u64(value: u64) -> Felt {
    Felt::new(value).expect("a burn magnitude (< 2^63) is a valid field element")
}

pub enum BurnGuardSelection {
    /// TEST-ONLY oracle: the real `burn_policy::check_policy` (`Custom(burn_root)`) ACTIVE, allow-all
    /// RESERVED. The arm the R-BURN-1/2 rejects + the valid-burn positive run against.
    OracleBurnReal,
    /// TEST-ONLY oracle: stock `BurnAllowAll` ACTIVE, the real burn policy RESERVED. The non-vacuity
    /// control: the SAME below-min burn succeeds + decrements here, proving the real arm's trap is
    /// policy-caused.
    OracleBurnAllowAll,
}

/// A burn-policy harness: a built [`MockChain`] holding the composed faucet (real burn policy active or
/// allow-all per [`BurnGuardSelection`]) + a user wallet seeded with the burn asset + the canonical
/// asset-bearing [`BurnNote`] the tests reproduce in-block and consume via the canary 2-block
/// lifecycle.
pub struct BurnPolicyHarness {
    pub chain: MockChain,
    pub faucet_id: AccountId,
    pub user_id: AccountId,
    /// The canonical burn note (random serial) the user emits in-block, then the faucet consumes.
    pub burn_note: Note,
    /// The single fungible burn asset (`FungibleAsset::new(faucet_id, burn_amount)`).
    pub asset: FungibleAsset,
    pub burn_root: Word,
    pub min_burn_size: u64,
    pub burn_amount: u64,
}

/// Hand-builds the seeded `RoleBasedAccessControl` `AccountComponent` for the burn oracle — a faithful
/// replica of the production builder's private `seeded_dom_roles_rbac` (Option A: both stock RBAC maps
/// direct-seeded with the two Circle Domain role members `DOM_PAUSER`→`pauser_holder` and
/// `DOM_MANAGER`→`manager_holder`; `DOM_PAUSER` administration delegated to `DOM_MANAGER` — the CMP-F5
/// seed `role_config[DOM_PAUSER] = [1, DOM_MANAGER, 0, 0]`). The burn oracle needs the RBAC foundation
/// so the DOM_PAUSER-sent custom `xreserve::pause_admin::pause` clears its role gate (the pause gate
/// `burn_paused_rejects` exercises). Reuses the stock RBAC code + slot names + metadata verbatim.
/// Replica fidelity to the production seed is pinned by
/// `set_min_burn.rs::support_replica_carries_delegation_seed` (the production twin is
/// `role_admin.rs::shipped_delegation_reads_back`).
fn seeded_dom_roles_rbac_component(
    pauser_holder: AccountId,
    manager_holder: AccountId,
) -> AccountComponent {
    let pauser = RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol");
    let manager = RoleSymbol::new(DOM_MANAGER_ROLE).expect("DOM_MANAGER is a fixed valid role symbol");
    let member_word = Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    // [1, DOM_MANAGER, 0, 0]: member_count = 1 with administration delegated to DOM_MANAGER (CMP-F5).
    let delegated_config_word =
        Word::from([Felt::from(1u32), Felt::from(&manager), Felt::ZERO, Felt::ZERO]);

    let role_config = StorageMap::with_entries([
        (
            StorageMapKey::new(Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(&pauser)])),
            delegated_config_word,
        ),
        (
            StorageMapKey::new(Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(&manager)])),
            member_word,
        ),
    ])
    .expect("the two-role role_config seed is valid");

    let role_membership = StorageMap::with_entries([
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&pauser),
                pauser_holder.suffix(),
                pauser_holder.prefix().as_felt(),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&manager),
                manager_holder.suffix(),
                manager_holder.prefix().as_felt(),
            ])),
            member_word,
        ),
    ])
    .expect("the two-role role_membership seed is valid");

    AccountComponent::new(
        RoleBasedAccessControl::code().clone(),
        vec![
            StorageSlot::with_map(RoleBasedAccessControl::role_config_slot().clone(), role_config),
            StorageSlot::with_map(
                RoleBasedAccessControl::role_membership_slot().clone(),
                role_membership,
            ),
        ],
        RoleBasedAccessControl::component_metadata(),
    )
    .expect("the seeded RBAC component mirrors the stock From impl and is valid")
}

/// TEST-ONLY burn-oracle composition: registers the mint-deny guard ACTIVE (the production mint slot)
/// AND BOTH burn policies (the real `Custom(burn_root)` + stock `BurnAllowAll`), one `Active` and one
/// `Reserved` per `burn_real_active`, so the real-vs-allow-all pair is CODE-IDENTICAL and differs ONLY
/// in `active_burn_policy_proc_root`. Mirrors `oracle_components` (mint) + the production
/// `XReserveStablecoinBuilder::{assemble_components, build_components}` RBAC foundation, but is the
/// TEST harness — production composition (`build_components`) installs the real burn policy ONLY (no
/// reserved allow-all), so no shipped API can construct an allow-all-active burn faucet.
fn oracle_burn_components(
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
    mint_deny_root: Word,
    burn_root: Word,
    burn_real_active: bool,
    owner: AccountId,
    pauser_holder: AccountId,
    manager_holder: AccountId,
) -> Result<Vec<AccountComponent>> {
    let real_burn = BurnPolicyConfig::Custom(burn_root);
    let (active_burn, reserved_burn) = if burn_real_active {
        (real_burn, BurnPolicyConfig::AllowAll)
    } else {
        (BurnPolicyConfig::AllowAll, real_burn)
    };
    let manager = TokenPolicyManager::new()
        .with_mint_policy(MintPolicyConfig::Custom(mint_deny_root), PolicyRegistration::Active)
        .map_err(|e| anyhow::anyhow!("oracle manager active mint policy: {e}"))?
        .with_burn_policy(active_burn, PolicyRegistration::Active)
        .map_err(|e| anyhow::anyhow!("oracle manager active burn policy: {e}"))?
        .with_burn_policy(reserved_burn, PolicyRegistration::Reserved)
        .map_err(|e| anyhow::anyhow!("oracle manager reserved burn policy: {e}"))?;

    // Component order/contents mirror XReserveStablecoinBuilder::{assemble_components, build_components}:
    // faucet + xreserve + [policy-manager, BurnAllowAll] + the owner-gating foundation
    // (Ownable2Step + seeded DOM-roles RBAC + Authority::OwnerControlled). No PausableManager
    // (Option 1, Domain-Pauser-only): the is_paused slot is FungibleFaucet-installed and pause is
    // exclusively the DOM_PAUSER custom xreserve::pause_admin procs.
    let mut components = vec![faucet.into(), xreserve_component];
    components.extend(manager);
    components.push(Ownable2Step::new(owner).into());
    components.push(seeded_dom_roles_rbac_component(pauser_holder, manager_holder));
    components.push(Authority::OwnerControlled.into());
    Ok(components)
}

/// Builds the burn-policy harness: assembles the `xreserve` component with the full production slot set
/// (domain/identifier value slots, usedNonces/xReserveAttesters map slots, AND the NET-NEW minBurnSize
/// value slot seeded `[min_burn_size, 0, 0, 0]`), composes the faucet via [`oracle_burn_components`]
/// (`owner` = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3)), adds a user wallet seeded with the single burn asset, and
/// creates the canonical [`BurnNote`]. The faucet is built with `is_max_supply_mutable(true)` + decimals
/// 6, mirroring the mint composition fixtures.
pub fn setup_burn_policy_account(
    selection: BurnGuardSelection,
    max_supply: u64,
    token_supply: u64,
    min_burn_size: u64,
    burn_amount: u64,
) -> Result<BurnPolicyHarness> {
    let library = assemble_xreserve_lib()?;

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![
            StorageSlot::with_value(
                StorageSlotName::new(DOMAIN_CONFIG_SLOT_LABEL).context("domain slot label")?,
                Word::from([TEST_DOMAIN, 0, 0, 0]),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL).context("identifier slot label")?,
                Word::from([11u32, 12, 13, 14]),
            ),
            // §5.9 4-field closure: the two new scalar/bytes32 config slots, EMPTY at assembly
            // (domain_init is the sole writer; the burn fixtures never read them).
            StorageSlot::with_value(
                StorageSlotName::new(SOURCE_DOMAIN_CONFIG_SLOT_LABEL)
                    .context("source_domain slot label")?,
                Word::from([0u32, 0, 0, 0]),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_HI_SLOT_LABEL)
                    .context("xreserve_contract_hi slot label")?,
                Word::from([0u32, 0, 0, 0]),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_LO_SLOT_LABEL)
                    .context("xreserve_contract_lo slot label")?,
                Word::from([0u32, 0, 0, 0]),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
                StorageMap::new(),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
                    .context("xReserveAttesters slot label")?,
                StorageMap::new(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(MIN_BURN_SIZE_SLOT_LABEL).context("min_burn_size slot label")?,
                Word::from([felt_from_u64(min_burn_size), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            ),
        ],
        AccountComponentMetadata::new("xusdc-burn-policy-harness"),
    )
    .context("binding the xreserve library + all composition slots + minBurnSize as a component")?;

    let resolve = |path: &str| -> Result<Word> {
        xreserve_component
            .get_procedure_root_by_path(path)
            .map(Word::from)
            .ok_or_else(|| anyhow::anyhow!("xreserve component does not export '{path}'"))
    };
    let mint_deny_root = resolve(MINT_DENY_GUARD_PROC_PATH)?;
    let burn_root = resolve(BURN_POLICY_PROC_PATH)?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .is_max_supply_mutable(true)
        .build()
        .context("failed to build FungibleFaucet")?;

    let burn_real_active = matches!(selection, BurnGuardSelection::OracleBurnReal);
    let components = oracle_burn_components(
        faucet,
        xreserve_component,
        mint_deny_root,
        burn_root,
        burn_real_active,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )?;

    let mut builder = MockChain::builder();
    let faucet_account = builder
        .add_existing_account_from_components(Auth::IncrNonce, components)
        .context("adding the burn-policy faucet account")?;
    let faucet_id = faucet_account.id();

    // The user wallet seeded with exactly the burn asset (faucet_id known only now).
    let asset = FungibleAsset::new(faucet_id, burn_amount).context("invalid burn asset")?;
    let user = builder
        .add_existing_wallet_with_assets(Auth::IncrNonce, [asset.into()])
        .context("adding the burn user wallet")?;
    let user_id = user.id();

    // The canonical burn note (random serial) — created while the builder rng is live (canary C1).
    let burn_note = BurnNote::create(
        user_id,
        faucet_id,
        asset.into(),
        Default::default(),
        builder.rng_mut(),
    )
    .context("creating the canonical burn note")?;

    let chain = builder.build().context("building the burn-policy MockChain")?;
    Ok(BurnPolicyHarness {
        chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        burn_root,
        min_burn_size,
        burn_amount,
    })
}

/// The user send tx-script that emits `burn_note` exactly (ported from the burn canary
/// `burn_canary.rs:57-91`): pushes `burn_note`'s recipient digest + the note's OWN metadata
/// (`note_type` + `tag`, read from `burn_note.metadata()`) into `output_note::create`, then `call`s
/// the BasicWallet `move_asset_to_note` to draw `fungible_asset` from the executing user's vault into
/// that note. Reading the note's own metadata keeps the emitted note's id == `burn_note.id()` for BOTH
/// the stock `BurnNote` (Public + `with_account_target`) and the `XReserveBurnNote` (Public + the fixed
/// xUSDC burn tag) — NoteId commits to metadata, so a recomputed tag would break id parity.
pub fn send_burn_note_script(
    burn_note: &Note,
    fungible_asset: &FungibleAsset,
    _faucet_id: AccountId,
) -> String {
    let recipient = burn_note.recipient().digest();
    let note_type = Felt::from(burn_note.metadata().note_type());
    let tag = Felt::from(burn_note.metadata().tag());
    let asset_key = fungible_asset.to_key_word();
    let asset_value = fungible_asset.to_value_word();
    // F5: reproduce the note's attachments (e.g. the scheme-2 NetworkAccountTarget) so the emitted
    // note's id == burn_note.id() (NoteId commits to attachments). The content is supplied via the
    // advice map keyed by its commitment (see `attachment_advice`, extended in `try_emit_burn_note`).
    let mut attachments_src = String::new();
    for attachment in burn_note.attachments().iter() {
        let scheme = attachment.attachment_scheme().as_u16();
        let commitment = attachment.content().to_commitment();
        attachments_src.push_str(&format!(
            "    dup\n    push.{commitment}\n    push.{scheme}\n    exec.output_note::add_attachment\n"
        ));
    }
    format!(
        r#"
use miden::protocol::output_note
use miden::standards::wallets::basic->wallet

begin
    # create the burn note (empty) carrying burn_note's recipient + metadata.
    push.{recipient}
    push.{note_type}
    push.{tag}
    exec.output_note::create
    # => [note_idx]

    # reproduce the note's attachments (routing target).
{attachments_src}
    # move the user's single fungible asset from the vault into the note.
    push.{asset_value}
    push.{asset_key}
    # => [ASSET_KEY, ASSET_VALUE, note_idx]
    call.wallet::move_asset_to_note
    # => [pad(16)]

    exec.::miden::core::sys::truncate_stack
end
"#
    )
}

/// The advice-map inputs carrying each of `note`'s attachment contents keyed by its commitment — the
/// witness the `output_note::add_attachment` emit path resolves (F5: the scheme-2 routing target).
pub fn attachment_advice(note: &Note) -> AdviceInputs {
    let mut advice = AdviceInputs::default();
    for attachment in note.attachments().iter() {
        advice = advice
            .with_map([(attachment.content().to_commitment(), attachment.content().to_elements())]);
    }
    advice
}

/// Reads the faucet's committed `token_supply` from its `token_config` slot post-block (ported from
/// the burn canary `burn_canary.rs:94-97`).
pub fn committed_token_supply(chain: &MockChain, faucet_id: AccountId) -> Result<AssetAmount> {
    let storage = chain.committed_account(faucet_id)?.storage();
    Ok(FungibleFaucet::try_from(storage)?.token_supply())
}

/// CMP-B3 N1B — reads the ACTIVE burn-policy procedure root committed in the faucet account's
/// `TokenPolicyManager` storage slot (the burn-slot twin of the mint deny-root). Asserting this stored
/// root equals the CMP-A10 `burn_policy_root()` is the storage-COMMITMENT proof that the sole
/// supply-decrement path (stock `receive_and_burn`) is CMP-A10-gated — stronger than resolving the
/// merely-EXPORTED proc root via `get_procedure_root_by_path`.
pub fn read_active_burn_policy_root(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(TokenPolicyManager::active_burn_policy_slot())
        .map_err(|e| anyhow::anyhow!("reading the active burn policy root slot: {e}"))
}

/// CMP-B3 N1D — returns the names of the procedures in a vendored pinned-standards MASM source that
/// call `exec.faucet::burn` (the inherited supply-decrement primitive). A call's enclosing proc is the
/// most recent `(pub )?proc <name>` declaration above it (MASM procs are top-level; inner block `end`s
/// are irrelevant to which proc a line belongs to). Used to prove the sole inherited decrement surface
/// is `receive_and_burn`.
pub fn faucet_burn_caller_procs(src: &str) -> Vec<String> {
    let mut current: Option<String> = None;
    let mut callers = Vec::new();
    for line in src.lines() {
        let trimmed = line.trim();
        // A call's enclosing proc is the most recent `(pub )?proc <name>` above it; MASM procs are
        // top-level, so inner block `end`s never change which proc a line belongs to.
        if let Some(rest) = trimmed
            .strip_prefix("pub proc ")
            .or_else(|| trimmed.strip_prefix("proc "))
        {
            current = Some(rest.split_whitespace().next().unwrap_or(rest).to_string());
        } else if trimmed.contains("exec.faucet::burn") {
            callers.push(current.clone().unwrap_or_else(|| "<top-level>".to_string()));
        }
    }
    callers
}

/// CMP-B3 N1D — returns the names of the procedures in a vendored pinned-standards MASM source that
/// perform a supply-DECREMENT write to `TOKEN_CONFIG_SLOT` (a `set_item` write whose written value is
/// produced by a `sub`). For each `TOKEN_CONFIG_SLOT` `set_item` write it finds the nearest preceding
/// arithmetic op (`add`/`sub`) within the enclosing proc and classifies the write `sub` => decrement,
/// `add` => raise. The standards' `mint_and_send` write is `add`-fed (raise) and `set_max_supply`
/// preserves supply, so the only decrement write is `receive_and_burn`'s. Used to prove the sole
/// inherited supply-LOWERING surface is `receive_and_burn` (the burn-write twin of `faucet_burn_caller_procs`).
pub fn faucet_supply_decrement_write_procs(src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut current: Option<String> = None;
    let mut proc_start = 0usize;
    let mut procs = Vec::new();
    for (idx, raw) in lines.iter().enumerate() {
        let trimmed = raw.trim();
        if let Some(rest) = trimmed
            .strip_prefix("pub proc ")
            .or_else(|| trimmed.strip_prefix("proc "))
        {
            current = Some(rest.split_whitespace().next().unwrap_or(rest).to_string());
            proc_start = idx;
        } else if trimmed.contains("set_item") && trimmed.contains("TOKEN_CONFIG_SLOT") {
            // Nearest preceding arithmetic op within the enclosing proc decides the write's DIRECTION
            // (robust to stack ops/comments between the arithmetic and the write-back).
            let arith = lines[proc_start..idx]
                .iter()
                .rev()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .find_map(|l| {
                    let toks: Vec<&str> = l.split_whitespace().collect();
                    if toks.iter().any(|&t| t == "sub") {
                        Some("sub")
                    } else if toks.iter().any(|&t| t == "add") {
                        Some("add")
                    } else {
                        None
                    }
                });
            if arith == Some("sub") {
                procs.push(current.clone().unwrap_or_else(|| "<top-level>".to_string()));
            }
        }
    }
    procs
}

/// tx0 ONLY (non-panicking): the user emits `burn_note` in-block (a send tx-script that draws the asset
/// from the user vault into the note). Returns the raw execution result so callers can observe an
/// upstream rejection (the zero-amount reachability probe) without the strict-path panic. Used as the
/// first half of [`run_burn_consume`].
pub async fn try_emit_burn_note(
    chain: &MockChain,
    burn_note: &Note,
    asset: &FungibleAsset,
    faucet_id: AccountId,
    user_id: AccountId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let tx_script = CodeBuilder::new()
        .compile_tx_script(send_burn_note_script(burn_note, asset, faucet_id))
        .expect("the user send-burn-note script compiles");
    chain
        .build_tx_context(user_id, &[], &[])
        .expect("building the user emit tx context")
        .tx_script(tx_script)
        // F5: the attachment contents (routing target) keyed by commitment for `add_attachment`.
        .extend_advice_inputs(attachment_advice(burn_note))
        // Register the full note details so the kernel's `before_created` event can resolve the PUBLIC
        // note's details when tx0 creates it (canary C1).
        .extend_expected_output_notes(vec![RawOutputNote::Full(burn_note.clone())])
        .build()
        .expect("building the user emit tx")
        .execute()
        .await
}

/// Runs the canary 2-block burn lifecycle against `chain`: the user emits `burn_note` at block N (tx0,
/// a test-setup invariant — panics on failure), the block is proven, then the FAUCET consumes the
/// now-committed note at block N+1 via stock `receive_and_burn`. Returns the faucet-consume RESULT so
/// the caller asserts the policy trap (`assert_transaction_executor_error!`) or the success+decrement
/// (`committed_token_supply` after committing the returned tx).
pub async fn run_burn_consume(
    chain: &mut MockChain,
    burn_note: &Note,
    asset: &FungibleAsset,
    faucet_id: AccountId,
    user_id: AccountId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let tx0 = try_emit_burn_note(chain, burn_note, asset, faucet_id, user_id)
        .await
        .expect("the user emit tx0 succeeds (test-setup invariant)");
    chain
        .add_pending_executed_transaction(&tx0)
        .expect("queuing tx0 into block N");
    chain.prove_next_block().expect("proving block N");

    // tx1: the faucet consumes the committed burn note (runs receive_and_burn -> execute_burn_policy ->
    // the active burn policy).
    chain
        .build_tx_context(faucet_id, &[burn_note.id()], &[])
        .expect("building the faucet consume tx context")
        .build()
        .expect("building the faucet consume tx")
        .execute()
        .await
}

/// Executes a stock `PausableManager::pause` note SENT BY `sender` against the faucet `account` on a
/// bare `&MockChain` (the note is provided unauthenticated). Under Option 1 (Domain-Pauser-only) the
/// stock proc is NOT installed — this is the NEGATIVE PROBE `owner_has_no_pause_path` drives: the tx
/// must trap `UnknownAccountProcedure` and never flip `is_paused`. To actually pause, use
/// [`run_dom_pauser_pause`] (the DOM_PAUSER custom proc — the only pause surface).
pub async fn run_pause_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = pause_note(sender, seed).expect("building the pause note (test-setup invariant)");
    chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the pause tx context")
        .build()
        .expect("building the pause transaction")
        .execute()
        .await
}

/// Builds a note SENT BY `sender` whose script calls the stock `PausableManager::unpause` — the
/// unpause twin of [`pause_note`]. Serial tail [25, 26] keeps note serials disjoint from the other
/// admin-note families.
pub fn stock_unpause_note(sender: AccountId, seed: u64) -> Result<Note> {
    let src = "use miden::standards::access::pausable::manager\n\
               @note_script\n\
               pub proc main\n\
               \x20\x20\x20\x20repeat.16 push.0 end\n\
               \x20\x20\x20\x20call.manager::unpause\n\
               \x20\x20\x20\x20dropw dropw dropw dropw\n\
               end\n";
    let script = CodeBuilder::new()
        .compile_note_script(src)
        .map_err(|e| anyhow::anyhow!("stock unpause note script failed to compile: {e}"))?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(25u32),
        Felt::from(26u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a stock `PausableManager::unpause` note (sent by `sender`) against the faucet `account`
/// on a bare `&MockChain` — the unpause twin of [`run_pause_against`].
pub async fn run_stock_unpause_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = stock_unpause_note(sender, seed)
        .expect("building the stock unpause note (test-setup invariant)");
    chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the stock unpause tx context")
        .build()
        .expect("building the stock unpause transaction")
        .execute()
        .await
}

/// Asserts an executor error carries the EXACT `UnknownAccountProcedure` failure — the pinned
/// surface when a note `call`s a procedure whose MAST root is NOT in the account code: the kernel's
/// `authenticate_and_track_procedure` first emits `ACCOUNT_PUSH_PROCEDURE_INDEX_EVENT`, whose host
/// handler fails with `TransactionKernelError::UnknownAccountProcedure` ("account procedure with
/// procedure root .. is not in the account procedure index map"), surfacing as
/// `ExecutionError::EventError` — a HOST event error, NOT a MASM assert (so `MasmError` matching
/// can never see it). Walks the full error chain and asserts the exact static message
/// (assert-specific-error-in-tests; no bare `is_err()`).
pub fn assert_unknown_account_procedure(err: &TransactionExecutorError) {
    let mut messages = vec![err.to_string()];
    let mut source: Option<&dyn std::error::Error> = std::error::Error::source(err);
    while let Some(inner) = source {
        messages.push(inner.to_string());
        source = inner.source();
    }
    assert!(
        messages.iter().any(|m| m.contains("is not in the account procedure index map")),
        "expected the exact UnknownAccountProcedure failure (the called proc root is not part of \
         the account code); actual error chain: {messages:?}"
    );
}

// CMP-F3 DOM_PAUSER CUSTOM PAUSE — notes + runners for the xreserve::pause_admin procs
// ================================================================================================

/// Builds a note SENT BY `sender` whose script `call`s the CUSTOM `xreserve::pause_admin::{proc}`
/// (DOM_PAUSER-gated, CMP-F3) — under Option 1 the ONLY installed pause surface. Unlike
/// [`pause_note`] (the stock negative probe, a pre-linked StandardsLib proc), this links the
/// `xreserve` library so the `xreserve::pause_admin::*` path resolves. `pause`/`unpause` take
/// `[pad(16)]` and return `[pad(16)]`, so the note pushes 16 pad felts, `call`s, and clears the
/// returned frame — the [`pause_note`] shape.
fn dom_pauser_pause_admin_note(
    sender: AccountId,
    seed: u64,
    proc: &str,
    tail0: u32,
    tail1: u32,
) -> Result<Note> {
    let lib = assemble_xreserve_lib()?;
    let src = format!(
        "use xreserve::pause_admin\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.16 push.0 end\n\
         \x20\x20\x20\x20call.pause_admin::{proc}\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .with_dynamically_linked_library(&lib)
        .context("linking xreserve into the dom_pauser pause_admin note script")?
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("dom_pauser {proc} note script failed to compile: {e}\n{src}"))?;
    // Deterministic note rng (serial only; never affects the gate). Distinct tails ([21,22] pause /
    // [23,24] unpause) keep serials disjoint from set_attester [1,2] / pause [3,4] / set_max_supply
    // [5,6] / set_min_burn [7,8] / domain_init [9,10].
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(tail0),
        Felt::from(tail1),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// A DOM_PAUSER `pause_admin::pause` note sent by `sender`.
pub fn dom_pauser_pause_note(sender: AccountId, seed: u64) -> Result<Note> {
    dom_pauser_pause_admin_note(sender, seed, "pause", 21, 22)
}

/// A DOM_PAUSER `pause_admin::unpause` note sent by `sender`.
pub fn dom_pauser_unpause_note(sender: AccountId, seed: u64) -> Result<Note> {
    dom_pauser_pause_admin_note(sender, seed, "unpause", 23, 24)
}

/// Executes a DOM_PAUSER `pause_admin::pause` note (sent by `sender`) against the faucet `account` on a
/// bare `&MockChain`. Mirrors [`run_pause_against`] (stock owner pause) but drives the CUSTOM CMP-F3
/// proc; the caller applies the returned delta (the unauthenticated note is not block-proven).
pub async fn run_dom_pauser_pause(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = dom_pauser_pause_note(sender, seed)
        .expect("building the dom_pauser pause note (test-setup invariant)");
    chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the dom_pauser pause tx context")
        .build()
        .expect("building the dom_pauser pause transaction")
        .execute()
        .await
}

/// The `unpause` twin of [`run_dom_pauser_pause`].
pub async fn run_dom_pauser_unpause(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = dom_pauser_unpause_note(sender, seed)
        .expect("building the dom_pauser unpause note (test-setup invariant)");
    chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the dom_pauser unpause tx context")
        .build()
        .expect("building the dom_pauser unpause transaction")
        .execute()
        .await
}

/// Reads the FungibleFaucet-installed `is_paused` value slot (`[0,0,0,0]` unpaused, `[1,0,0,0]` paused)
/// from a committed/evolved account — the CIR-ADMIN-4 `GetAccount` observability read. Mirrors
/// [`read_min_burn_size`] / [`read_token_config`]; the slot is installed by FungibleFaucet, so it is
/// present on every production faucet (never a missing-slot artifact).
pub fn read_is_paused(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(
            &StorageSlotName::new("miden::standards::access::pausable::is_paused")
                .context("is_paused slot label")?,
        )
        .map_err(|e| anyhow::anyhow!("reading the is_paused value slot: {e}"))
}

// CMP-F5 RBAC ROLE ADMINISTRATION — grant/revoke/set_role_admin notes + runners + role read-backs
// ================================================================================================

/// Builds a note SENT BY `sender` whose script `call`s a stock rbac member-administration proc
/// (`grant_role` / `revoke_role`, rbac.masm:197/:228) for (`role`, `member`). Stack contract:
/// `[role_symbol, account_suffix, account_prefix, pad(13)]` (role on top). Like `set_max_supply_note`,
/// the stock rbac procs are pure standards procs (CodeBuilder pre-links StandardsLib), so the
/// absolute-path `call` resolves to the SAME proc root the production account exposes via the RBAC
/// component re-exports (`account_components/access/rbac.masm`) — no xreserve link is needed. The
/// role/member felts are injected from the Rust-side `RoleSymbol`/`AccountId` (single source; no new
/// MASM constants, no new parity surface).
fn rbac_member_note(
    sender: AccountId,
    proc_name: &str,
    role: &RoleSymbol,
    member: AccountId,
    seed: u64,
    tail0: u32,
    tail1: u32,
) -> Result<Note> {
    // Push 13 pads (deepest), then prefix, suffix, role so the triple ends role-on-top: 13 + 3 = 16.
    let role_felt = Felt::from(role).as_canonical_u64();
    let member_suffix = member.suffix().as_canonical_u64();
    let member_prefix = member.prefix().as_felt().as_canonical_u64();
    let src = format!(
        "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.13 push.0 end\n\
         \x20\x20\x20\x20push.{member_prefix}\n\
         \x20\x20\x20\x20push.{member_suffix}\n\
         \x20\x20\x20\x20push.{role_felt}\n\
         \x20\x20\x20\x20call.::miden::standards::access::rbac::{proc_name}\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("rbac {proc_name} note script failed to compile: {e}\n{src}"))?;
    // Deterministic note rng (serial only; never affects the gate). Distinct tails ([11,12] grant /
    // [13,14] revoke / [15,16] set_role_admin) keep serials disjoint from set_attester [1,2] / pause
    // [3,4] / set_max_supply [5,6] / set_min_burn [7,8] / domain_init [9,10] / dom pause [21,22] /
    // dom unpause [23,24].
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(tail0),
        Felt::from(tail1),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// A `grant_role(role, member)` note sent by `sender` (stock gate: owner-or-role-admin, rbac.masm:411).
pub fn grant_role_note(sender: AccountId, role: &RoleSymbol, member: AccountId, seed: u64) -> Result<Note> {
    rbac_member_note(sender, "grant_role", role, member, seed, 11, 12)
}

/// A `revoke_role(role, member)` note sent by `sender` (same owner-or-role-admin gate).
pub fn revoke_role_note(sender: AccountId, role: &RoleSymbol, member: AccountId, seed: u64) -> Result<Note> {
    rbac_member_note(sender, "revoke_role", role, member, seed, 13, 14)
}

/// A `set_role_admin(role, admin_role)` note sent by `sender` (stock gate: OWNER-ONLY, rbac.masm:163).
/// `admin_role = None` pushes 0 — the stock "clear the delegation" sentinel (rbac.masm:147-148).
/// Stack contract: `[role_symbol, admin_role_symbol, pad(14)]` (role on top).
pub fn set_role_admin_note(
    sender: AccountId,
    role: &RoleSymbol,
    admin_role: Option<&RoleSymbol>,
    seed: u64,
) -> Result<Note> {
    let role_felt = Felt::from(role).as_canonical_u64();
    let admin_felt = admin_role.map(|r| Felt::from(r).as_canonical_u64()).unwrap_or(0);
    let src = format!(
        "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.14 push.0 end\n\
         \x20\x20\x20\x20push.{admin_felt}\n\
         \x20\x20\x20\x20push.{role_felt}\n\
         \x20\x20\x20\x20call.::miden::standards::access::rbac::set_role_admin\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("set_role_admin note script failed to compile: {e}\n{src}"))?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(15u32),
        Felt::from(16u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a role-administration `note` against the faucet `account` on a bare `&MockChain` —
/// the shared body of the grant/revoke/set_role_admin runners. Mirrors [`run_dom_pauser_pause`];
/// the caller applies the returned delta (the unauthenticated note is not block-proven).
async fn run_rbac_note_against(
    chain: &MockChain,
    account: &Account,
    note: Note,
    what: &str,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .unwrap_or_else(|e| panic!("building the {what} tx context: {e}"))
        .build()
        .unwrap_or_else(|e| panic!("building the {what} transaction: {e}"))
        .execute()
        .await
}

/// Executes a `grant_role` note (sent by `sender`) against the faucet `account`.
pub async fn run_grant_role_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    role: &RoleSymbol,
    member: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = grant_role_note(sender, role, member, seed)
        .expect("building the grant_role note (test-setup invariant)");
    run_rbac_note_against(chain, account, note, "grant_role").await
}

/// Executes a `revoke_role` note (sent by `sender`) against the faucet `account`.
pub async fn run_revoke_role_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    role: &RoleSymbol,
    member: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = revoke_role_note(sender, role, member, seed)
        .expect("building the revoke_role note (test-setup invariant)");
    run_rbac_note_against(chain, account, note, "revoke_role").await
}

/// Executes a `set_role_admin` note (sent by `sender`) against the faucet `account`.
pub async fn run_set_role_admin_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    role: &RoleSymbol,
    admin_role: Option<&RoleSymbol>,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = set_role_admin_note(sender, role, admin_role, seed)
        .expect("building the set_role_admin note (test-setup invariant)");
    run_rbac_note_against(chain, account, note, "set_role_admin").await
}

/// A `renounce_role(role)` note sent by `sender` (stock gate: SELF-only by construction —
/// `rbac::renounce_role` reads the note sender and revokes that account's own membership;
/// re-exported on the account interface, `account_components/access/rbac.masm:12`). Stack
/// contract: `[role_symbol, pad(15)]`.
pub fn renounce_role_note(sender: AccountId, role: &RoleSymbol, seed: u64) -> Result<Note> {
    let role_felt = Felt::from(role).as_canonical_u64();
    let src = format!(
        "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.15 push.0 end\n\
         \x20\x20\x20\x20push.{role_felt}\n\
         \x20\x20\x20\x20call.::miden::standards::access::rbac::renounce_role\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("renounce_role note script failed to compile: {e}\n{src}"))?;
    // Fresh serial tail [31,32] — disjoint from every other admin-note family.
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(31u32),
        Felt::from(32u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a `renounce_role` note (sent by `sender`, self-targeting) against the faucet `account`.
pub async fn run_renounce_role_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    role: &RoleSymbol,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = renounce_role_note(sender, role, seed)
        .expect("building the renounce_role note (test-setup invariant)");
    run_rbac_note_against(chain, account, note, "renounce_role").await
}

// ITEM-6 OWNABLE2STEP TWO-STEP OWNER TRANSFER — notes + runners + owner-config read-back
// ================================================================================================

/// A `transfer_ownership(new_owner)` note sent by `sender` (stock gate: OWNER-only,
/// `standards/access/ownable2step.masm:248`; the pending nominee has no authority until accept).
/// Stack contract: `[new_owner_suffix, new_owner_prefix, pad(14)]` (suffix on top). Like the rbac
/// notes, the stock proc is a pure standards proc, so the absolute-path `call` resolves to the
/// SAME proc root the production account exposes via the Ownable2Step component re-exports
/// (`account_components/access/ownable2step.masm`).
pub fn transfer_ownership_note(sender: AccountId, new_owner: AccountId, seed: u64) -> Result<Note> {
    let new_suffix = new_owner.suffix().as_canonical_u64();
    let new_prefix = new_owner.prefix().as_felt().as_canonical_u64();
    let src = format!(
        "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.14 push.0 end\n\
         \x20\x20\x20\x20push.{new_prefix}\n\
         \x20\x20\x20\x20push.{new_suffix}\n\
         \x20\x20\x20\x20call.::miden::standards::access::ownable2step::transfer_ownership\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| {
            anyhow::anyhow!("transfer_ownership note script failed to compile: {e}\n{src}")
        })?;
    // Fresh serial tail [27,28] — disjoint from every other admin-note family.
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(27u32),
        Felt::from(28u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// An `accept_ownership` note sent by `sender` (stock gate: NOMINATED-owner-only,
/// `standards/access/ownable2step.masm:292-324`). Stack contract: `[pad(16)]`.
pub fn accept_ownership_note(sender: AccountId, seed: u64) -> Result<Note> {
    let src = "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.16 push.0 end\n\
         \x20\x20\x20\x20call.::miden::standards::access::ownable2step::accept_ownership\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n"
        .to_string();
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| {
            anyhow::anyhow!("accept_ownership note script failed to compile: {e}\n{src}")
        })?;
    // Fresh serial tail [29,30] — disjoint from every other admin-note family.
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(29u32),
        Felt::from(30u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a `transfer_ownership` note (sent by `sender`) against the faucet `account`.
pub async fn run_transfer_ownership_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    new_owner: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = transfer_ownership_note(sender, new_owner, seed)
        .expect("building the transfer_ownership note (test-setup invariant)");
    run_rbac_note_against(chain, account, note, "transfer_ownership").await
}

/// Executes an `accept_ownership` note (sent by `sender`) against the faucet `account`.
pub async fn run_accept_ownership_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = accept_ownership_note(sender, seed)
        .expect("building the accept_ownership note (test-setup invariant)");
    run_rbac_note_against(chain, account, note, "accept_ownership").await
}

/// Reads the Ownable2Step `owner_config` value slot:
/// `[owner_suffix, owner_prefix, nominated_owner_suffix, nominated_owner_prefix]`
/// (pinned `ownable2step.rs:25,40-42`); the nominated pair is `(0, 0)` when no transfer pends.
pub fn read_owner_config(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(
            &StorageSlotName::new("miden::standards::access::ownable2step::owner_config")
                .context("owner_config slot label")?,
        )
        .map_err(|e| anyhow::anyhow!("reading the owner_config value slot: {e}"))
}

/// Reads a role's `role_config` word `[member_count, admin_role_symbol, 0, 0]` from a
/// committed/evolved account (stock key encoding `[0,0,0,role_symbol]`, rbac.masm:12).
pub fn read_role_config(account: &Account, role: &RoleSymbol) -> Result<Word> {
    let key = Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(role)]);
    account
        .storage()
        .get_map_item(RoleBasedAccessControl::role_config_slot(), key)
        .map_err(|e| anyhow::anyhow!("reading the role_config entry: {e}"))
}

/// Reads a member's `role_membership` word `[is_member, 0, 0, 0]` from a committed/evolved account
/// (stock key encoding `[0, role_symbol, account_suffix, account_prefix]`, rbac.masm:15).
pub fn read_role_membership(account: &Account, role: &RoleSymbol, member: AccountId) -> Result<Word> {
    let key = Word::from([
        Felt::ZERO,
        Felt::from(role),
        member.suffix(),
        member.prefix().as_felt(),
    ]);
    account
        .storage()
        .get_map_item(RoleBasedAccessControl::role_membership_slot(), key)
        .map_err(|e| anyhow::anyhow!("reading the role_membership entry: {e}"))
}

// CMP-A10 R-BURN-1 DIRECT-POLICY DRIVER — exec check_policy with a crafted [ASSET_KEY, ASSET_VALUE]
// ================================================================================================

/// Module path of the generated direct burn-policy driver component.
pub const BURN_POLICY_DRIVER_PATH: &str = "xusdc::test_fixtures::burn_policy_driver";

/// Generates a direct-policy driver: a CALL-entered account proc that pushes a crafted
/// `[ASSET_KEY, ASSET_VALUE]` burn-policy stack (`ASSET_VALUE = [amount, 0, 0, 0]`) and `exec`s
/// `burn_policy::check_policy`. The policy consumes the 8 cells and returns `[]`, restoring the
/// 16-depth `call` boundary. Drives the R-BURN-1 zero-amount proof DIRECTLY as a SUPPLEMENTARY,
/// belt-and-suspenders proof. Zero-amount note reachability is now PROVEN: `burn_zero_amount_rejects`
/// constructs and consumes a REAL 0-amount burn note that reaches `check_policy` (the vault no-ops a
/// 0-amount asset without failing; see `zero_amount_burn_note_reachability`), so R-BURN-1 has BOTH a
/// note-reachable reject AND this direct-driver proof. This driver exercises `check_policy` in
/// isolation (not because note reachability is unproven).
pub fn burn_policy_direct_driver_src(asset_key: Word, amount: u64) -> String {
    let asset_value = Word::from([felt_from_u64(amount), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    format!(
        "use xreserve::burn_policy\n\n\
         #! Test driver: pushes [ASSET_KEY, ASSET_VALUE] and execs the burn policy directly.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         pub proc drive\n\
         \x20\x20\x20\x20push.{asset_value}\n\
         \x20\x20\x20\x20push.{asset_key}\n\
         \x20\x20\x20\x20exec.burn_policy::check_policy\n\
         end\n",
    )
}

/// Builds a MockChain account carrying [the xreserve component WITH the seeded minBurnSize value slot]
/// + [the generated direct burn-policy driver], reusing [`ShellHarness`] + [`run_call_driver`]. Used by
/// the R-BURN-1 zero-amount direct proof: only the minBurnSize slot is bound (the direct
/// `check_policy` reads only `amount` + that slot; a zero amount traps before the slot is read).
pub fn setup_burn_policy_direct_account(min_burn_size: u64, driver_src: &str) -> Result<ShellHarness> {
    let library = assemble_xreserve_lib()?;

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![StorageSlot::with_value(
            StorageSlotName::new(MIN_BURN_SIZE_SLOT_LABEL).context("min_burn_size slot label")?,
            Word::from([felt_from_u64(min_burn_size), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        )],
        AccountComponentMetadata::new("xusdc-burn-policy-direct-harness"),
    )
    .context("binding the xreserve library + minBurnSize slot as a component")?;

    let driver_code = CodeBuilder::new()
        .with_dynamically_linked_library(&library)
        .context("linking the xreserve library into the direct driver component")?
        .compile_component_code(BURN_POLICY_DRIVER_PATH, driver_src)
        .with_context(|| format!("direct driver failed to compile\n--- driver ---\n{driver_src}"))?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-burn-policy-direct-driver"),
    )
    .context("binding the direct driver component")?;

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [xreserve_component, driver_component])
        .context("adding the direct burn-policy account")?;
    let mock_chain = builder.build().context("building the direct-policy MockChain")?;
    Ok(ShellHarness {
        mock_chain,
        account_id: account.id(),
        driver_code,
        driver_path: BURN_POLICY_DRIVER_PATH,
    })
}

// FULL-ASSEMBLY E2E HARNESS (P5-01 final on-chain slice) — the production-assembled faucet with
// EMPTY domain config + a real recipient wallet, run sequentially through the whole lifecycle.
// ================================================================================================

/// The full-assembly E2E harness: ONE production-composed faucet (`XReserveStablecoinBuilder`,
/// owner = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3)) whose FIVE domain-config slots start
/// EMPTY (the E2E's `domain_init` tx is the writer — the production bring-up path, not a fixture
/// seed), an EMPTY attester allowlist (the E2E's `set_attester` tx populates it), one mint driver
/// per distinct-nonce payload (the rotation-harness pattern), and a REAL recipient wallet that
/// consumes the minted P2ID note and emits the burn notes (D-E2E-ARC: the burn consumes the
/// actually-minted funds).
pub struct AssembledFaucet {
    pub harness: CompositionHarness,
    pub drivers: Vec<(String, AccountComponentCode)>,
    pub recipient_id: AccountId,
    /// The admin notes seeded ON-CHAIN at build (in the caller's order): admin steps consume them
    /// BY ID as authenticated inputs, so every admin tx is block-provable (an unauthenticated note
    /// cannot be committed — "no inclusion proof" — which would break the commit-each-step E2E).
    pub seeded_notes: Vec<Note>,
}

/// Builds the assembled-faucet E2E fixture. `driver_srcs_for` receives the recipient wallet's
/// `AccountId` FIRST (the DepositIntent payloads embed `remoteRecipient =
/// account_id_to_bytes32(recipient)`, and the driver sources embed the payloads), then the faucet +
/// drivers are composed via the PRODUCTION `XReserveStablecoinBuilder::build_components` path.
/// `max_supply`/`token_supply` configure the faucet build (mutable max_supply, decimals 6, XUSDC).
pub fn setup_assembled_faucet(
    max_supply: u64,
    token_supply: u64,
    driver_srcs_for: impl FnOnce(AccountId) -> (Vec<String>, Vec<Note>),
) -> Result<AssembledFaucet> {
    let (assembled, _ids) =
        setup_assembled_faucet_inner(max_supply, token_supply, 1, |ids| driver_srcs_for(ids[0]))?;
    Ok(assembled)
}

/// The TWO-recipient variant (Item 11 `second_mint_to_distinct_recipient`): identical composition,
/// but with a SECOND independent recipient wallet so a second attested mint can route funds to a
/// DIFFERENT wallet (full-path recipient routing). Returns the fixture (whose `recipient_id` is
/// the FIRST wallet) plus the second wallet's id; the closure receives both ids in order.
pub fn setup_assembled_faucet_two_recipients(
    max_supply: u64,
    token_supply: u64,
    driver_srcs_for: impl FnOnce(AccountId, AccountId) -> (Vec<String>, Vec<Note>),
) -> Result<(AssembledFaucet, AccountId)> {
    let (assembled, ids) = setup_assembled_faucet_inner(max_supply, token_supply, 2, |ids| {
        driver_srcs_for(ids[0], ids[1])
    })?;
    Ok((assembled, ids[1]))
}

/// Shared body of the assembled-faucet fixtures, parameterized by recipient-wallet count.
fn setup_assembled_faucet_inner(
    max_supply: u64,
    token_supply: u64,
    n_recipients: usize,
    driver_srcs_for: impl FnOnce(&[AccountId]) -> (Vec<String>, Vec<Note>),
) -> Result<(AssembledFaucet, Vec<AccountId>)> {
    let mut mc = MockChain::builder();
    // The recipient wallet(s) FIRST: their ids feed the payload/driver generation below.
    let mut recipient_ids = Vec::new();
    for i in 0..n_recipients {
        let recipient = mc
            .add_existing_wallet(Auth::IncrNonce)
            .with_context(|| format!("adding recipient wallet {i}"))?;
        recipient_ids.push(recipient.id());
    }
    let recipient_id = recipient_ids[0];
    let (driver_srcs, seeded_notes) = driver_srcs_for(&recipient_ids);
    for note in &seeded_notes {
        mc.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let library = assemble_xreserve_lib()?;
    let empty = || Word::from([0u32, 0, 0, 0]);
    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![
            // ALL FIVE domain-config slots EMPTY: domain_init (tx S1b) is the production writer.
            StorageSlot::with_value(
                StorageSlotName::new(DOMAIN_CONFIG_SLOT_LABEL).context("domain slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)
                    .context("identifier slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(SOURCE_DOMAIN_CONFIG_SLOT_LABEL)
                    .context("source_domain slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_HI_SLOT_LABEL)
                    .context("xreserve_contract_hi slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_LO_SLOT_LABEL)
                    .context("xreserve_contract_lo slot label")?,
                empty(),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
                StorageMap::new(),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
                    .context("xReserveAttesters slot label")?,
                StorageMap::new(),
            ),
        ],
        AccountComponentMetadata::new("xusdc-assembled-faucet"),
    )
    .context("binding the xreserve library + all seven slots as a component")?;

    let mut drivers = Vec::new();
    let mut driver_components = Vec::new();
    for (i, src) in driver_srcs.iter().enumerate() {
        let path = format!("xusdc::test_fixtures::assembled_driver_{i}");
        let code = CodeBuilder::new()
            .with_dynamically_linked_library(&library)
            .with_context(|| format!("linking xreserve into assembled driver {i}"))?
            .compile_component_code(&path, src)
            .with_context(|| format!("assembled driver {i} failed to compile"))?;
        driver_components.push(
            AccountComponent::new(
                code.clone(),
                vec![],
                AccountComponentMetadata::new(format!("xusdc-assembled-driver-{i}")),
            )
            .with_context(|| format!("binding assembled driver {i}"))?,
        );
        drivers.push((path, code));
    }

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .is_max_supply_mutable(true)
        .build()
        .context("failed to build FungibleFaucet")?;

    let mut components = xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .map_err(|e| anyhow::anyhow!("composing the assembled faucet: {e}"))?;
    components.extend(driver_components);

    let account = mc
        .add_existing_account_from_components(Auth::IncrNonce, components)
        .context("adding the assembled faucet account")?;
    let mock_chain = mc.build().context("building the assembled MockChain")?;
    let first = drivers[0].1.clone();
    Ok((
        AssembledFaucet {
            harness: CompositionHarness {
                mock_chain,
                account_id: account.id(),
                driver_code: first.clone(),
                probe_code: first,
            },
            drivers,
            recipient_id,
            seeded_notes,
        },
        recipient_ids,
    ))
}

// CMP-B1 PRODUCTION-FAUCET HARNESS (real-note transport; NO driver/probe components)
// ================================================================================================

/// The CMP-B1 real-note fixture: the PRODUCTION component set only (the
/// `XReserveStablecoinBuilder::build_components` output — no driver, no probe), plus a recipient
/// wallet (the P2ID target embedded in the DepositIntent payloads) and a producer/relayer wallet
/// (the mint-note sender). Admin bring-up notes (domain_init / set_attester) are seeded ON-CHAIN
/// at build so each admin tx is block-provable, mirroring `setup_assembled_faucet`.
pub struct ProductionFaucet {
    pub mock_chain: MockChain,
    pub faucet_id: AccountId,
    pub recipient_id: AccountId,
    pub producer_id: AccountId,
    pub seeded_notes: Vec<Note>,
}

/// Builds the production-component-set faucet fixture. `seed_notes_for` receives the recipient
/// wallet's `AccountId` (payloads embed `remoteRecipient = account_id_to_bytes32(recipient)`) and
/// returns the admin notes to seed at genesis. The faucet account carries EXACTLY the components
/// `XReserveStablecoinBuilder::build_components` returns — proving the real-note mint needs no
/// test-only component.
pub fn setup_production_faucet(
    max_supply: u64,
    token_supply: u64,
    seed_notes_for: impl FnOnce(AccountId) -> Vec<Note>,
) -> Result<ProductionFaucet> {
    let mut mc = MockChain::builder();
    let recipient = mc.add_existing_wallet(Auth::IncrNonce).context("adding recipient wallet")?;
    let producer = mc.add_existing_wallet(Auth::IncrNonce).context("adding producer wallet")?;
    let seeded_notes = seed_notes_for(recipient.id());
    for note in &seeded_notes {
        mc.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let library = assemble_xreserve_lib()?;
    let empty = || Word::from([0u32, 0, 0, 0]);
    let xreserve_component = AccountComponent::new(
        library,
        vec![
            // ALL FIVE domain-config slots EMPTY: domain_init (the seeded owner note) is the
            // production writer; the attester allowlist ships EMPTY (set_attester writes it).
            StorageSlot::with_value(
                StorageSlotName::new(DOMAIN_CONFIG_SLOT_LABEL).context("domain slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)
                    .context("identifier slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(SOURCE_DOMAIN_CONFIG_SLOT_LABEL)
                    .context("source_domain slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_HI_SLOT_LABEL)
                    .context("xreserve_contract_hi slot label")?,
                empty(),
            ),
            StorageSlot::with_value(
                StorageSlotName::new(XRESERVE_CONTRACT_LO_SLOT_LABEL)
                    .context("xreserve_contract_lo slot label")?,
                empty(),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
                StorageMap::new(),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
                    .context("xReserveAttesters slot label")?,
                StorageMap::new(),
            ),
        ],
        AccountComponentMetadata::new("xusdc-production-faucet"),
    )
    .context("binding the xreserve library + all seven slots as a component")?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .is_max_supply_mutable(true)
        .build()
        .context("failed to build FungibleFaucet")?;

    let components = xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .map_err(|e| anyhow::anyhow!("composing the production faucet: {e}"))?;

    // F5: the production faucet is finalized under the stock AuthNetworkAccount (keyless network
    // account) with the frozen note-script allowlist and an EMPTY tx-script allowlist — the same
    // single-source frozen set the deploy path composes via `AccountBuilder::with_auth_component`.
    let account = mc
        .add_existing_account_from_components(
            Auth::NetworkAccount {
                allowed_script_roots:
                    xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::allowed_note_scripts(),
                allowed_tx_script_roots: std::collections::BTreeSet::new(),
            },
            components,
        )
        .context("adding the production faucet account")?;
    let mock_chain = mc.build().context("building the production MockChain")?;
    Ok(ProductionFaucet {
        mock_chain,
        faucet_id: account.id(),
        recipient_id: recipient.id(),
        producer_id: producer.id(),
        seeded_notes,
    })
}

/// Emits `note` (with any attachments) from `producer` in a REAL in-block tx and commits block N:
/// `output_note::create` from the recipient digest + metadata, then `output_note::add_attachment`
/// per attachment with the elements in the PRODUCER tx's advice map (the upstream
/// `note_script_that_creates_notes` pattern, miden-testing/src/utils.rs:245-315 — producer-side
/// advice is legitimate: the producer knows the data it is publishing). The full note details are
/// registered via `RawOutputNote::Full` so the kernel resolves the PUBLIC note, mirroring
/// `try_emit_burn_note`. Asset-less (the mint-note shape).
pub async fn emit_note_with_attachments(
    chain: &mut MockChain,
    producer: AccountId,
    note: &Note,
) -> Result<()> {
    let recipient = note.recipient().digest();
    let note_type = Felt::from(note.metadata().note_type());
    let tag = Felt::from(note.metadata().tag());

    let mut src = format!(
        "use miden::protocol::output_note\n\
         \n\
         begin\n\
         \x20\x20\x20\x20push.{recipient}\n\
         \x20\x20\x20\x20push.{note_type}\n\
         \x20\x20\x20\x20push.{tag}\n\
         \x20\x20\x20\x20exec.output_note::create\n"
    );
    let mut advice = AdviceInputs::default();
    for attachment in note.attachments().iter() {
        let scheme = attachment.attachment_scheme().as_u16();
        let commitment = attachment.content().to_commitment();
        src.push_str(&format!(
            "\x20\x20\x20\x20dup\n\
             \x20\x20\x20\x20push.{commitment}\n\
             \x20\x20\x20\x20push.{scheme}\n\
             \x20\x20\x20\x20exec.output_note::add_attachment\n"
        ));
        advice = advice.with_map([(commitment, attachment.content().to_elements())]);
    }
    src.push_str(
        "\x20\x20\x20\x20drop\n\
         \x20\x20\x20\x20exec.::miden::core::sys::truncate_stack\n\
         end\n",
    );

    let tx_script = CodeBuilder::new().compile_tx_script(src)?;
    let tx = chain
        .build_tx_context(producer, &[], &[])?
        .tx_script(tx_script)
        .extend_advice_inputs(advice)
        .extend_expected_output_notes(vec![RawOutputNote::Full(note.clone())])
        .build()?
        .execute()
        .await?;
    anyhow::ensure!(
        tx.output_notes().num_notes() == 1 && tx.output_notes().get_note(0).id() == note.id(),
        "the producer tx must emit exactly the constructed note (id parity)"
    );
    chain.add_pending_executed_transaction(&tx)?;
    chain.prove_next_block()?;
    anyhow::ensure!(chain.is_note_committed(&note.id()), "the emitted note must be committed");
    Ok(())
}
