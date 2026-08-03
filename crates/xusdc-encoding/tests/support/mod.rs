//! Shared test-support for the faucet mint-precondition shell suite.
//!
//! OWNERSHIP NOTE: the `ERR_XRESERVE_*` constants and the config-slot labels below are
//! faucet-owned TEST-SIDE mirrors — the encoding library crate owns none of them (the shared
//! parser is encoding-owned;
//! the faucet owns only mint-specific assertions). They are the single Rust source for both the
//! fixture slot bindings and the generated-driver interpolation; the shell modules declare
//! byte-identical production `word("…")` slot consts, and the constant-parity suite pins the
//! production labels against these.
//!
//! Harness mechanics mirror `tests/masm_dual.rs` (assemble → bind → MockChain →
//! execute), extended so that the shell reads config slots via
//! `active_account::get_item`, which the kernel authenticates as account-origin, so the
//! driver is a CALL-entered account component proc that stages the preimage in its own
//! (account-context) memory and `exec`s the shell — exactly the production
//! `xreserve_mint` calling shape.

#![allow(dead_code)]

pub mod mint_transport;
pub mod w2admin;

// The standard pause / blocklist admin-note factories live with the rest of the standard-admin
// fixtures; re-exported here so every suite reaches them through `support::*` as before.
// Each test binary compiles this module separately and pulls in only the helpers it uses, so the
// re-export is legitimately unused in most of them.
#[allow(unused_imports)]
pub use w2admin::{
    raw_stock_block_note, stock_block_note, stock_pause_action_note, stock_pause_note,
    stock_unblock_note, stock_unpause_note,
};

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use miden_processor::advice::AdviceInputs;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    Account, AccountComponent, AccountId, AccountIdVersion, AccountProcedureRoot, AccountType,
    AssetCallbackFlag, RoleSymbol, StorageMap, StorageMapKey, StorageSlot, StorageSlotName,
};
use miden_protocol::assembly::{Linkage, Package, Path as MasmPath};
use miden_protocol::asset::{AssetAmount, AssetCallbacks, FungibleAsset, TokenSymbol};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote, TransactionKernel};
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Pausable, PausableManager, RoleBasedAccessControl};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::BurnNote;
use miden_standards::testing::note::NoteBuilder;
use miden_standards::StandardsLib;
use miden_testing::{AccountState, Auth, MockChain, MockChainBuilder};
use miden_tx::TransactionExecutorError;
use xusdc_encoding::account::xreserve::{
    XReserveAdminAuthority, XReserveStablecoinBuilderError, ATTESTATION_MINT_POLICY_PROC_PATH,
    BLK_MANAGER_ROLE, DOM_MANAGER_ROLE, DOM_PAUSER_ROLE,
};
use xusdc_encoding::xreserve::encoding::masm_error_by_name;

// Attestation fixtures — deterministic secp256k1 keys and signatures generated IN-TEST (the
// canonical vector artifact is untouched), mirroring the `gen_vectors` att_* helpers: k256 the
// keypair+signature, sha3 the keccak digest, miden-crypto `PublicKey::to_commitment` the
// allowlist-key oracle, miden_protocol `bytes_to_packed_u32_elements` the advice felt packing.
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey};
use miden_crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_crypto::utils::Deserializable;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha3::{Digest, Keccak256};

// TEST-ONLY FAUCET CONFIG (the domain id and the identifier encoding are Circle-owned and OPEN)
// ================================================================================================
// The real Miden domain id is Circle-assigned and OPEN — `TEST_DOMAIN` exists
// solely to match the canonical accept vectors' `remote_domain` (= 7) and must never
// be presented as the real value. The AccountId↔bytes32 identifier encoding is likewise
// Circle-OPEN; the test identifier is the accept vector's remoteToken bytes, nothing
// more.

/// Matches `di-pos-hookdata` / `di-pos-empty-hookdata` `fields.remote_domain`.
pub const TEST_DOMAIN: u32 = 7;
/// Any value != the vectors' remote_domain, for the wrong-domain reject.
pub const TEST_WRONG_DOMAIN: u32 = 8;
/// Test `source_domain` (config-only; nonzero so read-backs are distinguishable). Build-seeded
/// by the production fixtures (there is no runtime writer).
pub const TEST_SOURCE_DOMAIN: u32 = 3;

/// Test `xreserve_contract` bytes32 (sequential distinct bytes) — the third build-seeded
/// domain-config field the production fixtures pass to `with_domain_config`.
pub fn test_xreserve_contract() -> [u8; 32] {
    core::array::from_fn(|i| 0x10 + i as u8)
}

/// Slot labels (frozen `XReserveDomainConfig` field names under the product namespace), which the
/// MASM modules must declare as byte-identical `word("…")` consts (parity-enforced).
// RE-EXPORTED from the production crate (the MIN_BURN_SIZE_SLOT_LABEL precedent, single Rust
// source: the builder's slot-presence guard and these test bindings can never drift). The two
// `xreserve_contract` slots carry the raw 8×u32-LE realization (hi = packed felts[0..4]
// / wire bytes 0..16, lo = felts[4..8]); `identifier` stays the D5a-consumer-forced hash-Word;
// `source_domain`/`xreserve_contract` are written ONLY by `domain_init` (off-chain identity,
// `GetAccount`-readable).
pub use xusdc_encoding::account::xreserve::{
    DOMAIN_CONFIG_SLOT_LABEL, IDENTIFIER_CONFIG_SLOT_LABEL, SOURCE_DOMAIN_CONFIG_SLOT_LABEL,
    XRESERVE_CONTRACT_HI_SLOT_LABEL, XRESERVE_CONTRACT_LO_SLOT_LABEL,
};

/// Label of the `usedNonces` map slot — the registry the replay guard reads. The MASM declares a
/// `word("…")` const with the byte-identical label (parity-enforced). Re-exported from the
/// production crate (single Rust source with the builder's slot-presence guard).
pub use xusdc_encoding::account::xreserve::USED_NONCES_SLOT_LABEL;

/// Label of the faucet's `token_config` value slot — the slot the standard `FungibleFaucet` component
/// installs (`[token_supply, max_supply, decimals, token_symbol]`), which the standard
/// `mint_and_send` reads and writes. Bound here as the single Rust source for the constant-parity row.
pub const TOKEN_CONFIG_SLOT_LABEL: &str = "miden::standards::faucets::fungible::token_config";

/// Label of the `xReserveAttesters` map slot — the attester allowlist the attestation check reads.
/// The MASM `attestation_verify.masm` declares a `word("…")` const with the byte-identical label
/// (parity-enforced); the `set_attester` admin path co-owns the SAME slot. Re-exported
/// from the production crate (single Rust source with the builder's slot-presence guard).
pub use xusdc_encoding::account::xreserve::XRESERVE_ATTESTERS_SLOT_LABEL;

// NOTE: there is no custom `min_burn_size` slot label — the minimum-burn floor lives in the
// STOCK `MinBurnAmount::slot_name()` slot (read via [`read_min_burn_size`]).

// FAUCET ERROR MIRRORS (frozen names)
// ================================================================================================

/// Name → constant table for the faucet-owned shell errors (string `MasmError`
/// pattern). The implementation must declare byte-identical strings in MASM. The two
/// amount/fee errors and every other row are pinned here so the
/// behavior tests can name their EXACT expected error.
pub static SHELL_ERR_TABLE: [(&str, MasmError); 24] = [
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
    // The maxFee/fee staging's too-large guard (deposit_intent_parser.masm); the amount
    // field's distinct standards string lives in STANDARDS_ERR_TABLE.
    (
        "ERR_X_TOO_LARGE",
        MasmError::from_static_str("larger than 2**128"),
    ),
    // The nonce replay guard's error, pinned here so the replay test can name its EXACT
    // expected error, byte-identical to the MASM const.
    (
        "ERR_XRESERVE_NONCE_REPLAY",
        MasmError::from_static_str("deposit intent nonce has already been used"),
    ),
    // The two attestation rejects (attestation_verify.masm). Parity-pinned against the MASM consts.
    (
        "ERR_XRESERVE_BAD_PK_COMMITMENT",
        MasmError::from_static_str("deposit attester pubkey commitment is not allowlisted"),
    ),
    (
        "ERR_XRESERVE_SIG_INVALID",
        MasmError::from_static_str("deposit attestation signature verification failed"),
    ),
    // The fee gate (deposit_intent_parser.masm): the faucet pays no relayer fee, so the parser rejects
    // a non-zero advice feeAmount; parity-pinned against the MASM const.
    (
        "ERR_XRESERVE_FEE_NONZERO",
        MasmError::from_static_str("mint fee amount must be zero"),
    ),
    // recipient AccountId helper (extract_recipient_account_id, mint_policy.masm). This is the
    // LOCAL layout error (the pad check); the limb and canonical-range rejects surface the
    // STANDARDS `eth::build_felt` constants (`ERR_NOT_U32` / `ERR_MERGE_OVERFLOW`, resolved via
    // the `masm_error_by_name` fallback), and the suffix-shape and unknown-version rejects
    // surface the PROTOCOL `account_id::validate` `ERR_ACCOUNT_ID_*` constants directly. Pinned
    // here so the behavior tests can name their EXACT expected error, byte-identical to the MASM
    // consts.
    (
        "ERR_XRESERVE_RECIPIENT_OUT_OF_RANGE",
        MasmError::from_static_str("deposit intent remote recipient address pad is not zero"),
    ),
    // The attestation mint policy (mint_policy.masm) — the TRANSPORT-shape guards on the
    // stock MintNote's attachments: the scheme-4 intent + scheme-5 attestation + scheme-2 routing
    // target must all be present, exactly three in total; the hash-committed intent word count
    // must cover the header and match the embedded hookDataLen claim; the attestation is exactly
    // 11 words ([feeAmount(8), pubkey(16), signature(17), pad(3)]).
    (
        "ERR_XRESERVE_MINT_NOTE_INTENT_MISSING",
        MasmError::from_static_str("mint note deposit intent attachment is missing"),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_ATTESTATION_MISSING",
        MasmError::from_static_str("mint note attestation attachment is missing"),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_TARGET_MISSING",
        MasmError::from_static_str("mint note routing target attachment is missing"),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_ATTACHMENT_COUNT",
        MasmError::from_static_str("mint note must carry exactly three attachments"),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_INTENT_TOO_SHORT",
        MasmError::from_static_str(
            "mint note deposit intent attachment is shorter than the deposit intent header",
        ),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_HOOK_LEN_LIMB",
        MasmError::from_static_str(
            "mint note deposit intent hook data length limb is not a valid u32",
        ),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_INTENT_WORDS",
        MasmError::from_static_str(
            "mint note deposit intent attachment word count does not match the intent length",
        ),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_ATTESTATION_NUM_WORDS",
        MasmError::from_static_str("mint note attestation attachment word count is invalid"),
    ),
    // The ASSERT-MATCH binding (mint_policy.masm): the note-supplied output-note
    // RECIPIENT / ASSET_VALUE / tag / note_type must EQUAL their attested derivations.
    (
        "ERR_XRESERVE_MINT_RECIPIENT_MISMATCH",
        MasmError::from_static_str(
            "mint note recipient does not match the attested deposit intent",
        ),
    ),
    (
        "ERR_XRESERVE_MINT_AMOUNT_MISMATCH",
        MasmError::from_static_str(
            "mint note asset amount does not match the attested deposit intent",
        ),
    ),
    (
        "ERR_XRESERVE_MINT_TAG_MISMATCH",
        MasmError::from_static_str("mint note tag does not match the attested recipient target"),
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_TYPE_NOT_PUBLIC",
        MasmError::from_static_str("mint note output note type must be public"),
    ),
    // Identifier init-once (identifier_init.masm; the identifier-only runtime init — the other
    // domain-config fields are build-seeded). The second write traps REINIT; an EMPTY input
    // identifier (which could never arm the sentinel) traps EMPTY; a note-committed identifier
    // that is not the faucet's OWN on-chain-derived id key traps MISMATCH (the anti-
    // front-run binding: `bytes32_to_key(account_id_to_bytes32(get_id()))` derived in-proc).
    (
        "ERR_XRESERVE_IDENTIFIER_REINIT",
        MasmError::from_static_str("identifier has already been initialized"),
    ),
    (
        "ERR_XRESERVE_IDENTIFIER_EMPTY",
        MasmError::from_static_str("identifier must be non-empty"),
    ),
    (
        "ERR_XRESERVE_IDENTIFIER_MISMATCH",
        MasmError::from_static_str("identifier does not match the faucet's own account id key"),
    ),
];

/// The min-burn admin note's zero-floor guard
/// (`xreserve_set_min_burn_size_note.masm`; the stock `set_min_burn_amount` accepts 0, so the
/// note rejects a sub-floor `new_min` BEFORE calling it). A NOTE-script error, not an
/// account-proc shell error — kept beside the table for the same exact-error discipline.
pub fn err_min_burn_below_floor() -> MasmError {
    MasmError::from_static_str("minimum burn size must be at least one")
}

/// The stock `MinBurnAmount::check_policy` reject (min_burn_amount.masm) — the burn-side floor
/// error (there are no custom burn errors: with the floor `>= 1`, a
/// zero-amount burn rejects HERE).
pub fn err_burn_below_min_burn_amount() -> MasmError {
    MasmError::from_static_str("amount to be burned must exceed specified minimum burn amount")
}

/// Looks up an expected MASM error: faucet-owned shell errors first, then the encoding
/// library's table (`ERR_DI_*` rows of the ratified seam mapping).
pub fn shell_error_by_name(name: &str) -> &'static MasmError {
    SHELL_ERR_TABLE
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, e)| e)
        .or_else(|| masm_error_by_name(name))
        .unwrap_or_else(|| panic!("test names unknown MASM error constant {name}"))
}

// TRIPWIRE SERIALIZATION
// ================================================================================================

/// Serializes the security-tripwire tests: they flake under parallel `cargo test`, so every
/// tripwire holds this lock for its whole body — the in-tree equivalent of `serial_test`'s
/// `#[serial]` (that crate is not in the pinned offline `Cargo.lock`, so the guard lives here
/// instead of a new dependency; cargo runs test BINARIES sequentially, so a per-binary process
/// lock is exactly the scope `serial_test` would give). The async-aware `tokio::sync::Mutex`
/// is deliberate: an async tripwire holds its guard across `.await` points
/// (`clippy::await_holding_lock` forbids a `std` guard there), and tokio's mutex has no
/// poisoning, so a panicking holder cannot cascade spurious failures into later tripwires.
static TRIPWIRE_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The async-test guard: `let _serial = tripwire_serial_guard().await;`.
pub async fn tripwire_serial_guard() -> tokio::sync::MutexGuard<'static, ()> {
    TRIPWIRE_SERIAL.lock().await
}

/// The sync-test guard (blocks the test thread; sync tests run outside any tokio runtime, which
/// `blocking_lock` requires): `let _serial = tripwire_serial_guard_blocking();`.
pub fn tripwire_serial_guard_blocking() -> tokio::sync::MutexGuard<'static, ()> {
    TRIPWIRE_SERIAL.blocking_lock()
}

// HARNESS (assemble → bind components+slots → MockChain account)
// ================================================================================================

/// Memory base for preimages staged by the driver proc in ITS OWN call context
/// (word-aligned; same base convention as `masm_dual.rs`). Test-fixture-only global
/// staging: the driver owns the entire fresh call context, so the
/// `masm-locals-over-globals` scratch rule is deliberately not applied here (recorded
/// deviation; the shell itself uses no memory at all).
pub const INTENT_PTR: u64 = 1024;

fn collect_masm_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("asm directory must be readable") {
        let path = entry.expect("directory entry must be readable").path();
        if path.is_dir() {
            collect_masm_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "masm") {
            out.push(path);
        }
    }
}

/// Memory bases for the attestation operands the drivers stage alongside the preimage, mirroring
/// how the production policy hands `assert_mint_amounts` and `verify_attestation` pointers into
/// the hash-verified attestation attachment. All word-aligned and clear of `INTENT_PTR`.
pub const FEE_AMOUNT_PTR: u64 = 0;
pub const PUBKEY_PTR: u64 = 8;
pub const SIGNATURE_PTR: u64 = 24;

/// Module path of the generated per-case shell driver component.
pub const SHELL_DRIVER_PATH: &str = "xusdc::test_fixtures::shell_driver";
/// Module path of the slot-binding probe component.
pub const SLOT_PROBE_PATH: &str = "xusdc::test_fixtures::slot_probe";

/// Assembles the `asm/standards/xreserve` tree into one library under namespace
/// `xreserve` — lifted from `masm_dual.rs:41-47` (test scaffolding, not an owned
/// routine; kept byte-equivalent).
/// A deterministic dummy `AccountId` for the builder's `owner` / DOM role-holder inputs and for the
/// role-holder / non-holder note senders in the `set_attester` suite. Mirrors
/// `miden-testing/tests/scripts/rbac.rs:49-51`.
pub fn test_account_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

/// A deterministic PUBLIC dummy account id representing THIS (policed) faucet — usable as a faucet
/// target for the scheme-2 `NetworkAccountTarget` routing attachment (mint/burn/admin notes require
/// a PUBLIC faucet id) and as a fungible-asset issuer in note-construction unit tests. Carries
/// `AssetCallbackFlag::Enabled`: the deployed faucet is Enabled (policed), so a dummy standing in
/// for it must not misrepresent it as a basic (callback-disabled) asset issuer.
pub fn test_faucet_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Enabled,
    )
}

/// Adds a faucet account to the mock chain from its composed `components`, deriving the immutable
/// `AssetCallbackFlag` FROM THE COMPOSITION: `Enabled` when a protocol asset-callback slot is present
/// (a transfer policy is wired — the policed asset), else `Disabled` (basic asset). This
/// mirrors what a real `AccountBuilder` deploy does. The stock
/// `MockChainBuilder::add_existing_account_from_components` hardcodes `Disabled`, which would leave a
/// policed faucet's transfer-policy callbacks silently never firing (an audited foot-gun), so
/// every PRODUCTION-builder faucet fixture routes through here instead.
pub fn add_faucet_account(
    builder: &mut MockChainBuilder,
    auth: Auth,
    components: Vec<AccountComponent>,
) -> Result<Account> {
    let has_callbacks = components.iter().any(|c| {
        c.storage_slots().iter().any(|s| {
            s.name() == AssetCallbacks::on_before_asset_added_to_note_slot()
                || s.name() == AssetCallbacks::on_before_asset_added_to_account_slot()
        })
    });
    let flag = if has_callbacks {
        AssetCallbackFlag::Enabled
    } else {
        AssetCallbackFlag::Disabled
    };
    let mut account_builder = Account::builder(rand::random())
        .account_type(AccountType::Public)
        .with_asset_callbacks(flag);
    for component in components {
        account_builder = account_builder.with_component(component);
    }
    builder
        .add_account_from_builder(auth, account_builder, AccountState::Exists)
        .context("adding a faucet account from its composed components (callback-flag derived)")
}

/// Adds the production network faucet to the chain under the PRODUCTION auth composition —
/// `XReserveStablecoinBuilder::auth_component()`, the `custom()`-based `AuthNetworkAccount` plus
/// its fee-policy companions — instead of the `miden-testing` `Auth::NetworkAccount` fixture. The
/// fixture routes through `AuthNetworkAccount::new()`, which force-inserts the config-note and
/// fee-sponsorship script roots into the note allowlist; the preserved posture is the EXACT
/// 9-root allowlist, so the composition must go through `custom()` (which inserts nothing) —
/// `config_note_absence.rs` is the tripwire. Registering the account without an authenticator
/// matches the fixture's behavior for the keyless network account (its authenticator is `None`
/// either way). The callback flag is derived exactly as in [`add_faucet_account`].
pub fn add_network_faucet_account(
    builder: &mut MockChainBuilder,
    components: Vec<AccountComponent>,
) -> Result<Account> {
    let has_callbacks = components.iter().any(|c| {
        c.storage_slots().iter().any(|s| {
            s.name() == AssetCallbacks::on_before_asset_added_to_note_slot()
                || s.name() == AssetCallbacks::on_before_asset_added_to_account_slot()
        })
    });
    let flag = if has_callbacks {
        AssetCallbackFlag::Enabled
    } else {
        AssetCallbackFlag::Disabled
    };
    let mut account_builder = Account::builder(rand::random())
        .account_type(AccountType::Public)
        .with_asset_callbacks(flag);
    for component in components {
        account_builder = account_builder.with_component(component);
    }
    account_builder = account_builder.with_components(
        xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::auth_component()
            .map_err(|e| anyhow::anyhow!("the production auth component must build: {e}"))?,
    );
    let account = account_builder
        .build_existing()
        .context("building the production network faucet account")?;
    builder
        .add_account(account.clone())
        .context("registering the production network faucet account")?;
    Ok(account)
}

pub fn assemble_xreserve_lib() -> Result<Package> {
    // Link the standards library (mirrors CodeBuilder's own `with_dynamic_library(StandardsLib)`):
    // attester_admin::set_attester calls the stock `authority::assert_authorized` /
    // `pausable::assert_not_paused`, which live in StandardsLib. The other xreserve modules stay
    // core+protocol-only; linking standards only adds resolvable symbols (it does not change their
    // MAST roots).
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

pub fn production_component_set(
    max_supply: u64,
    token_supply: u64,
) -> Result<Vec<AccountComponent>> {
    production_builder_outcome(max_supply, token_supply, None, None)?
        .map_err(|e| anyhow::anyhow!("composing the production faucet components: {e}"))
}

/// The PRODUCTION builder verdict with the fixture SETUP errors separated from the builder's own
/// typed outcome: the outer `Result` carries test-fixture setup failures (library assembly, slot
/// binding, faucet construction), the inner `Result` is `build_components`' typed
/// [`XReserveStablecoinBuilderError`] verdict — so the builder-reject tripwires can
/// `assert_matches!` the CONCRETE variant (the specific error, never a stringified word
/// search). `min_burn_size = None` keeps the builder default; `mint_policy_override = None`
/// keeps the attestation policy (the production shape).
pub fn production_builder_outcome(
    max_supply: u64,
    token_supply: u64,
    min_burn_size: Option<u64>,
    mint_policy_override: Option<MintPolicy>,
) -> Result<std::result::Result<Vec<AccountComponent>, XReserveStablecoinBuilderError>> {
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

    let mut builder = xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
    )
    .with_domain_config(TEST_DOMAIN, TEST_SOURCE_DOMAIN, test_xreserve_contract());
    if let Some(min_burn_size) = min_burn_size {
        builder = builder.min_burn_size(min_burn_size);
    }
    if let Some(policy) = mint_policy_override {
        builder = builder.with_active_mint_policy(policy);
    }
    Ok(builder.build_components())
}

pub struct ShellHarness {
    pub mock_chain: MockChain,
    pub account_id: AccountId,
    pub driver_code: AccountComponentCode,
    pub driver_path: &'static str,
}

/// Builds the MockChain account carrying [the xreserve component WITH the two named value
/// config slots + the `usedNonces` map slot] + [the generated driver component], per the
/// proven binding (`StorageSlotName::new(label)` ↔ MASM `word("label")`) and the
/// proven `StorageSlot::with_map` map-slot path. The `usedNonces` map starts EMPTY
/// (unused nonces read `EMPTY_WORD`); use `setup_shell_account_with_nonce_seed` to
/// pre-populate it so the replay guard sees a spent nonce.
pub fn setup_shell_account(
    domain: Word,
    identifier: Word,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
    setup_shell_account_with_nonce_seed(domain, identifier, None, driver_src, driver_path)
}

/// Like `setup_shell_account`, but optionally seeds the `usedNonces` map with a single
/// `key -> marker` entry (the replay fixture): `Some((key, marker))` pre-populates the
/// map so a real `active_account::get_map_item` read returns the non-empty marker; `None`
/// leaves it empty. The guard only READS the map — this seeding is a test fixture standing in for
/// the marker the mint tail would have written.
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

fn setup_shell_account_with_lib(
    library: Package,
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
        .with_dynamically_linked_package(&library)
        .context("linking the xreserve library into the driver component")?
        .compile_component_code(driver_path, driver_src)
        .with_context(|| {
            format!("driver component failed to compile\n--- driver ---\n{driver_src}")
        })?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-shell-driver"),
    )
    .context("binding the driver component")?;

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(
            Auth::IncrNonce,
            [xreserve_component, driver_component],
        )
        .context("adding the shell harness account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(ShellHarness {
        mock_chain,
        account_id: account.id(),
        driver_code,
        driver_path,
    })
}

/// Executes `call.driver::<proc>` from a trivial tx script (alias-import pattern)
/// — the call enters the driver component proc in the ACCOUNT context.
pub async fn run_call_driver(
    h: &ShellHarness,
    proc_name: &str,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src = format!(
        "use {path} as driver\n@transaction_script\npub proc main\n    call.driver::{proc_name}\nend\n",
        path = h.driver_path
    );
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(&h.driver_code)
        .expect("linking the driver component into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| {
            panic!("driver call script failed to compile: {e}\n--- script ---\n{src}")
        });
    h.mock_chain
        .build_transaction(h.account_id)
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
/// (zero-padding the trailing word) at `base_ptr`, inside the driver proc's own call context.
/// `base_ptr` must be word-aligned.
fn stage_felts(src: &mut String, felts: &[Felt], base_ptr: u64) {
    for (i, chunk) in felts.chunks(4).enumerate() {
        let mut w = [miden_protocol::ZERO; 4];
        w[..chunk.len()].copy_from_slice(chunk);
        let addr = base_ptr + 4 * i as u64;
        writeln!(src, "    push.{} mem_storew_le.{addr} dropw", word_of(&w)).unwrap();
    }
}

/// Stages the DepositIntent preimage at `INTENT_PTR` — the `masm_dual.rs` staging convention.
fn stage_preimage(src: &mut String, felts: &[Felt]) {
    stage_felts(src, felts, INTENT_PTR);
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
         @account_procedure\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    writeln!(src, "    push.{len_felts}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.deposit_intent_parser::assert_deposit_intent\n");
    match expected_hook_data_len {
        // happy path: pin the shell's output, restoring the 16-depth call boundary
        Some(expected) => {
            writeln!(
                src,
                "    push.{expected} assert_eq.err=\"driver: hook_data_len mismatch\""
            )
            .unwrap();
        }
        // reject path: balance the would-be output so an unexpected non-trapping run
        // returns cleanly and the test's exact-error assertion reports the mismatch
        None => src.push_str("    drop\n"),
    }
    src.push_str("end\n");
    src
}

/// The first felt of the DepositIntent `remoteToken` field in a staged preimage (wire bytes
/// 44..76, four wire bytes per felt).
const REMOTE_TOKEN_FELT_OFF: u64 = 11;

/// The eight advice felts [`shell_driver_src_own_token`] splices into a staged intent: the packed
/// limbs of `account_id_to_bytes32(faucet_id)`, produced by the RUST encoder.
pub fn own_token_advice(faucet_id: AccountId) -> Vec<Felt> {
    xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts(
        &xusdc_encoding::xreserve::encoding::account_id_to_bytes32(faucet_id),
    )
    .to_vec()
}

/// Like [`shell_driver_src`], but overwrites the staged intent's `remoteToken` with eight felts
/// taken from the advice stack before running the assertion.
///
/// The faucet compares `remoteToken` against its OWN account id, and an account id is a hash over
/// the account's code — which includes this very driver. A driver that baked the bound token into
/// its source would therefore change the id it is trying to match. Taking the eight limbs as
/// transaction inputs breaks that circularity: the account is built first, and the Rust encoder
/// then produces the bytes for the id it actually got ([`own_token_advice`]).
pub fn shell_driver_src_own_token(
    preimage: &[Felt],
    len_felts: u64,
    expected_hook_data_len: Option<u32>,
) -> String {
    let mut src = String::from(
        "use xreserve::deposit_intent_parser\n\n\
         #! Test driver: stages a DepositIntent preimage in the account context, splices the\n\
         #! caller-supplied remoteToken limbs into it, and execs the faucet assertion shell.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         @account_procedure\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    for i in 0..8 {
        let addr = INTENT_PTR + REMOTE_TOKEN_FELT_OFF + i;
        writeln!(src, "    adv_push mem_store.{addr}").unwrap();
    }
    writeln!(src, "    push.{len_felts}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.deposit_intent_parser::assert_deposit_intent\n");
    match expected_hook_data_len {
        Some(expected) => {
            writeln!(
                src,
                "    push.{expected} assert_eq.err=\"driver: hook_data_len mismatch\""
            )
            .unwrap();
        }
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
         @account_procedure\n\
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

// AMOUNT / FEE HELPERS
// ================================================================================================

/// Felt offsets of the two uint256 money fields in a staged DepositIntent preimage: `amount` at
/// felts 2..9 and `maxFee` at felts 43..50.
///
/// Each is the field's byte offset in the wire format divided by four, since one felt packs four
/// bytes. They mirror the MASM layout constants of the same names, and the two definitions are
/// held together by `constant_parity.rs`.
pub const AMOUNT_FELT_OFF: usize = 2;
pub const MAX_FEE_FELT_OFF: usize = 43;

/// Clones a base accept preimage and overwrites the `amount` and `maxFee` fields with the
/// 8 u32-LE limbs of the chosen canonical `amt-*` vectors (read from the shared artifact — no
/// copied vector tables). The rest of the DepositIntent envelope (magic / version /
/// nonzero fields / length) is unchanged, so the shared-encoding structural parse stays valid and
/// execution reaches the amount reduction and its compares.
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

/// The 8 u32-LE `feeAmount` limbs as felts (`Felt::from(u32)`, infallible —
/// `felt-construction`), in the order the reducer reads them out of memory.
pub fn fee_amount_felts(limbs: [u32; 8]) -> Vec<Felt> {
    limbs.iter().map(|l| Felt::from(*l)).collect()
}

/// Generates the per-case amount/fee driver: stages the (spliced) preimage and the operator
/// `feeAmount` limbs in the account context, pushes `[intent_ptr, fee_amount_ptr, scale_exp,
/// amount_y]` (the amount witness the standards conversion verifier proves), and `exec`s the
/// faucet `assert_mint_amounts` shell. The proc returns `[]`, so the staged-then-consumed
/// stack restores the 16-depth `call` boundary.
pub fn mint_amounts_driver_src(
    preimage: &[Felt],
    fee_amount: &[Felt],
    scale_exp: u32,
    amount_y: u64,
) -> String {
    let mut src = String::from(
        "use xreserve::deposit_intent_parser\n\n\
         #! Test driver: stages a DepositIntent preimage and a feeAmount in the account context\n\
         #! and execs the amount/fee precondition shell.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         @account_procedure\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    stage_felts(&mut src, fee_amount, FEE_AMOUNT_PTR);
    writeln!(src, "    push.{amount_y}").unwrap();
    writeln!(src, "    push.{scale_exp}").unwrap();
    writeln!(src, "    push.{FEE_AMOUNT_PTR}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.deposit_intent_parser::assert_mint_amounts\n");
    src.push_str("end\n");
    src
}

/// Like `run_call_driver`, but stages an optional `feeAmount` advice stack into the tx
/// context (`extend_advice_inputs`). `None` ⇒ no advice staged (the missing-advice case,
/// which must error). `AdviceInputs::with_stack` preserves order:
/// the first felt is the first one `adv_push` returns.
pub async fn run_call_driver_with_advice(
    h: &ShellHarness,
    proc_name: &str,
    advice_stack: Option<Vec<Felt>>,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src = format!(
        "use {path} as driver\n@transaction_script\npub proc main\n    call.driver::{proc_name}\nend\n",
        path = h.driver_path
    );
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(&h.driver_code)
        .expect("linking the driver component into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| {
            panic!("driver call script failed to compile: {e}\n--- script ---\n{src}")
        });
    let mut ctx = h
        .mock_chain
        .build_transaction(h.account_id)
        .tx_script(tx_script);
    if let Some(stack) = advice_stack {
        ctx = ctx.extend_advice_inputs(AdviceInputs::default().with_stack(stack));
    }
    ctx.build()
        .expect("building the transaction")
        .execute()
        .await
}

// D5C NONCE REPLAY HELPERS
// ================================================================================================

/// Generates the per-case replay-guard driver: stages the preimage in the account context, pushes
/// `[intent_ptr]`, and `exec`s the faucet `assert_nonce_unused` shell. The shell returns `[]`
/// (the guard is read-only — it asserts the entry is empty and writes nothing), so the staged-then-consumed stack restores
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
         @account_procedure\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.deposit_intent_parser::assert_nonce_unused\n");
    src.push_str("end\n");
    src
}

// D5D ATTESTATION VERIFY HELPERS
// ================================================================================================

/// A deterministically-generated attester: its 16-felt affine pubkey + 17-felt
/// signature (as advice felts) over a payload's keccak digest, and its `xReserveAttesters`
/// allowlist commitment (the miden-crypto `PublicKey::to_commitment` oracle == the on-chain MASM
/// `pubkey_commitment`).
pub struct AttesterVector {
    /// 16-felt affine pubkey coordinates `qx_le_u32[8] || qy_le_u32[8]` (the candidate pubkey the
    /// driver stages in memory; the Circle wire form stays the 33-byte compressed key below).
    pub pubkey_felts: Vec<Felt>,
    /// 17-felt u32-LE-packed r||s||v signature over keccak256(payload).
    pub sig_felts: Vec<Felt>,
    /// Poseidon2 commitment Word = the `xReserveAttesters` allowlist key for this pubkey.
    pub commitment: Word,
    /// Raw 33-byte compressed SEC1 pubkey (what the relayer hands `XUsdcMintNote::create`).
    pub pubkey_bytes: [u8; 33],
    /// Raw 65-byte `r||s||v` signature (what the relayer hands `XUsdcMintNote::create`).
    pub sig_bytes: [u8; 65],
}

/// Deterministically generates an attester keypair (k256 + seeded StdRng) and signs
/// `keccak256(payload)` (sha3) with it — the SAME independent path
/// `gen_vectors` uses. Two distinct seeds over the SAME payload give the seam's key A / key B.
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

    let (sig, recid): (K256Signature, RecoveryId) = sk
        .sign_prehash_recoverable(&digest)
        .expect("k256 prehash sign");
    let mut sig65 = [0u8; 65];
    sig65[..64].copy_from_slice(sig.to_bytes().as_slice());
    sig65[64] = recid.to_byte();

    let commitment = PublicKey::read_from_bytes(&pk33)
        .expect("valid compressed secp256k1 pubkey")
        .to_commitment();

    AttesterVector {
        pubkey_felts: xusdc_encoding::xreserve::encoding::affine_pubkey_felts(&pk33)
            .expect("the deterministic attester key is a valid curve point")
            .to_vec(),
        sig_felts: bytes_to_packed_u32_elements(&sig65),
        commitment,
        pubkey_bytes: pk33,
        sig_bytes: sig65,
    }
}

/// Builds the MockChain account carrying [the xreserve component WITH the `xReserveAttesters` map
/// slot] + [the generated driver]. `attesters_seed = Some((commitment, marker))` pre-populates the
/// allowlist (an enabled attester); `None` leaves it empty (no attester allowlisted). The seeding
/// is a TEST fixture — the real `set_attester` admin setter is a separate path.
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
        .with_dynamically_linked_package(&library)
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
        .add_existing_account_from_components(
            Auth::IncrNonce,
            [xreserve_component, driver_component],
        )
        .context("adding the attestation harness account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(ShellHarness {
        mock_chain,
        account_id: account.id(),
        driver_code,
        driver_path,
    })
}

/// Generates the per-case attestation driver: stages the DepositIntent payload preimage, the
/// candidate pubkey and the signature in the account context, pushes
/// `[intent_ptr, intent_num_bytes, pubkey_ptr, signature_ptr]`, and `exec`s the faucet
/// `verify_attestation` shell. The shell returns `[]` (assert-only gate), so the
/// staged-then-consumed stack restores the 16-depth `call` boundary.
///
/// Taking the pubkey and signature separately is what lets the seam cases pair one attester's
/// pubkey with another's signature.
pub fn attestation_driver_src(
    preimage: &[Felt],
    len_bytes: u64,
    pubkey_felts: &[Felt],
    sig_felts: &[Felt],
) -> String {
    let mut src = String::from(
        "use xreserve::attestation_verify\n\n\
         #! Test driver: stages a DepositIntent payload, a candidate pubkey and a signature in\n\
         #! the account context and execs the attestation verify shell.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         @account_procedure\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    stage_felts(&mut src, pubkey_felts, PUBKEY_PTR);
    stage_felts(&mut src, sig_felts, SIGNATURE_PTR);
    writeln!(src, "    push.{SIGNATURE_PTR}").unwrap();
    writeln!(src, "    push.{PUBKEY_PTR}").unwrap();
    writeln!(src, "    push.{len_bytes}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.attestation_verify::verify_attestation\n");
    src.push_str("end\n");
    src
}

// FIXTURE COMPONENT PATHS + FIELD OFFSETS
// ================================================================================================

/// Module path of the guarded fixture's caller-supplied probe component.
pub const MINT_PROBE_PATH: &str = "xusdc::test_fixtures::mint_probe";

/// Module path of the guarded fixture's caller-supplied driver component (compile-only in the
/// recomposed suites: the fixtures drive behavior through REAL notes; the slot remains for
/// probes that want a call-entered account proc).
pub const GUARDED_DRIVER_PATH: &str = "xusdc::test_fixtures::guarded_driver";

pub const REMOTE_RECIPIENT_FELT_OFF: usize = 19;

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

pub struct CompositionHarness {
    pub mock_chain: MockChain,
    pub account_id: AccountId,
    pub driver_code: AccountComponentCode,
    pub probe_code: AccountComponentCode,
}

pub fn setup_bare_immutable_faucet(
    token_supply: u64,
    max_supply: u64,
) -> Result<CompositionHarness> {
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
    let mock_chain = builder
        .build()
        .context("building the bare-faucet MockChain")?;
    Ok(CompositionHarness {
        mock_chain,
        account_id: account.id(),
        driver_code: placeholder.clone(),
        probe_code: placeholder,
    })
}

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
         @account_procedure\n\
         pub proc check\n\
         \x20\x20\x20\x20push.PROBE_TOKEN_CONFIG_SLOT[0..2] exec.active_account::get_item\n\
         \x20\x20\x20\x20push.{expected} assert_eq.err=\"no-effect: token_supply changed\"\n\
         \x20\x20\x20\x20dropw\n\
         end\n",
        cfg = TOKEN_CONFIG_SLOT_LABEL,
        expected = expected_token_supply,
    )
}

pub fn set_attester_note(
    sender: AccountId,
    commitment: Word,
    enabled: u8,
    seed: u64,
) -> Result<Note> {
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
        .with_dynamically_linked_package(&lib)
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
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
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

/// Builds a note SENT BY `sender` whose script calls the stock `PausableManager::pause`. The
/// procedure IS installed, so this note is the probe for WHO may use it: sent by the Domain pauser
/// it pauses the faucet, and sent by anyone else — including the administrator — it traps the role error,
/// which is what `administrator_has_no_pause_path` pins. It assembles without an xreserve link, since
/// StandardsLib is pre-linked.
pub fn manager_pause_call_note(sender: AccountId, seed: u64) -> Result<Note> {
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
/// the CompositionHarness-shaped twin of [`run_pause_against`]. The procedure IS installed, so the
/// verdict is the role gate's: the Domain pauser succeeds and anyone else traps the role error.
pub async fn run_pause_tx(
    h: &CompositionHarness,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = manager_pause_call_note(sender, seed)
        .expect("building the manager pause-call note (test-setup invariant)");
    h.mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the pause transaction")
        .execute()
        .await
}

// raw self-block (TEST-ONLY) — arms the faucet-blocked callback sentinel past the self-block guard
// ================================================================================================

/// TEST-ONLY component path for the unguarded raw self-block proc.
pub const RAW_BLOCKLIST_PATH: &str = "xusdc::test_fixtures::raw_blocklist";

/// A TEST-ONLY account component exposing an UNGUARDED raw self-block proc (`block_self_unchecked`):
/// it `exec`s the low-level `blocklist::block_account` primitive on the NATIVE id directly,
/// bypassing both the BLK_MANAGER role gate and the self-block guard in
/// the stock `BlocklistManager::block_account`. Its sole use is arming the faucet-blocked sentinel in
/// `transfer_blocklist_semantics::faucet_side_burn_consume_is_callback_unaffected`: with the
/// self-block guard in place the
/// production admin surface cannot block the faucet, so the sentinel writes
/// `blocked_accounts[faucet]=1` via the SAME underlying primitive the admin wrapper delegates to
/// (the exact storage write, minus the new guard). It declares NO storage slots — it shares the
/// `blocked_accounts` slot the `BasicBlocklist` companion installs (the `blocklist_admin` pattern of
/// referencing a companion's slot by name).
pub fn raw_blocklist_component() -> Result<AccountComponent> {
    let src = "use miden::protocol::native_account\n\
               use miden::standards::faucets::policies::transfer::blocklist\n\
               \n\
               #! TEST-ONLY: writes blocked_accounts[self] = 1 via the low-level primitive,\n\
               #! bypassing the BLK_MANAGER role gate AND the PA2 self-block guard.\n\
               #!\n\
               #! Inputs:  [pad(16)]\n\
               #! Outputs: [pad(16)]\n\
               #!\n\
               #! Invocation: call\n\
               @account_procedure\n\
               pub proc block_self_unchecked\n\
               \x20\x20\x20\x20exec.native_account::get_id\n\
               \x20\x20\x20\x20exec.blocklist::block_account\n\
               end\n";
    let code = CodeBuilder::new()
        .compile_component_code(RAW_BLOCKLIST_PATH, src)
        .context("raw self-block test component failed to compile")?;
    AccountComponent::new(
        code,
        vec![],
        AccountComponentMetadata::new("xusdc-raw-blocklist-test"),
    )
    .context("binding the raw self-block test component")
}

/// A TEST-ONLY note (sent by `sender`) whose script `call`s `raw_blocklist::block_self_unchecked` on
/// the consuming faucet — arms `blocked_accounts[faucet]=1` for the callback sentinel WITHOUT the
/// self-block guard. The consuming faucet MUST have [`raw_blocklist_component`] installed (the note's linked
/// library and the account's proc share one MAST root, so the `call` resolves).
pub fn raw_self_block_note(sender: AccountId, seed: u64) -> Result<Note> {
    let component = raw_blocklist_component()?;
    let src = format!(
        "use {path}\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.16 push.0 end\n\
         \x20\x20\x20\x20call.raw_blocklist::block_self_unchecked\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
        path = RAW_BLOCKLIST_PATH,
    );
    let script = CodeBuilder::new()
        .with_dynamically_linked_package(component.component_code().clone())
        .context("linking the raw-blocklist test component into the note script")?
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("raw self-block note script failed to compile: {e}\n{src}"))?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(11u32),
        Felt::from(12u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

// identifier_init — administrator-gated init-once identifier seeding note
// ================================================================================================

/// The exact stock error the RBAC role assertion traps (`rbac.masm` ERR_SENDER_LACKS_ROLE). Under
/// the account's role-based authority this is what an unauthorized sender gets from EVERY
/// authority-gated procedure: the ones with a role assigned (the pause and blocklist managers) and
/// the ones without, which fall back to the administrator role (`set_attester`, `identifier_init`,
/// the supply cap, the burn floor, the policy setters). No procedure gates on an administrator slot any
/// more — the faucet installs no ownership component, so there is no owner error to raise.
pub fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

/// Builds an unauthenticated note SENT BY `sender` whose script `call`s the MINIMIZED
/// `xreserve::identifier_init::init_identifier(IDENTIFIER)` (the identifier is the one
/// domain-config field the account-id fixpoint forces past build time; the other three fields are
/// build-seeded). The authority gate reads the note sender (`active_note::get_sender`), so the
/// sender is what the administrator-role check tests. `identifier` is the pre-hashed `bytes32_to_key` Word
/// stored verbatim. The note script links the `xreserve` library so the `call` resolves to the
/// same proc installed on the faucet account.
pub fn identifier_init_note(sender: AccountId, identifier: Word, seed: u64) -> Result<Note> {
    let lib = assemble_xreserve_lib()?;
    // Stack contract: [IDENTIFIER, pad(12)] (IDENTIFIER element-0 on top). Push 12 pads (deepest)
    // then the IDENTIFIER word (pushed e3..e0 so element 0 ends on top): 12 + 4 = 16.
    let src = format!(
        "use xreserve::identifier_init\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.12 push.0 end\n\
         \x20\x20\x20\x20push.{i3}.{i2}.{i1}.{i0}\n\
         \x20\x20\x20\x20call.identifier_init::init_identifier\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
        i0 = identifier[0],
        i1 = identifier[1],
        i2 = identifier[2],
        i3 = identifier[3],
    );
    let script = CodeBuilder::new()
        .with_dynamically_linked_package(&lib)
        .context("linking xreserve into the identifier_init note script")?
        .compile_note_script(src.clone())
        .map_err(|e| {
            anyhow::anyhow!("identifier_init note script failed to compile: {e}\n{src}")
        })?;
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

/// Executes an `identifier_init` note (sent by `sender`) against the faucet `account`, returning
/// the raw execution result so callers can assert success or the exact trap. Mirrors
/// `run_set_attester_tx`.
pub async fn run_identifier_init_tx(
    h: &CompositionHarness,
    account: &Account,
    sender: AccountId,
    identifier: Word,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = identifier_init_note(sender, identifier, seed)
        .expect("building the identifier_init note (test-setup invariant)");
    h.mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the identifier_init transaction")
        .execute()
        .await
}

/// Reads the FIVE domain-config words `[domain, source_domain, xrc_hi, xrc_lo, identifier]` from a
/// committed/evolved account — the 4-field read-back (+ the no-write assert of the guard
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

// set_min_burn_size — ADMIN-gated minBurnSize setter note + slot read-back
// ================================================================================================

/// Builds an unauthenticated note SENT BY `sender` whose script `call`s the STOCK
/// `min_burn_amount::set_min_burn_amount(new_min)`. Like `set_attester`,
/// the authority gate reads the note sender, so the sender is what the `ADMIN` role check tests.
/// `new_min` is the single felt written as element 0 of the stock floor slot. NOTE: this is the
/// RAW driver — it deliberately BYPASSES the production note script's zero-floor guard so tests
/// can probe the stock proc directly; the floor-guard behavior itself is tested through the
/// production `XReserveSetMinBurnSizeNote` factory.
pub fn set_min_burn_size_note(sender: AccountId, new_min: u64, seed: u64) -> Result<Note> {
    // Stack contract: [new_min, pad(15)] (new_min on top). Push 15 pad felts (deepest) then new_min so
    // it ends on top: 15 + 1 = 16. A pure standards proc — CodeBuilder pre-links StandardsLib.
    let src = format!(
        "use miden::standards::faucets::policies::burn::min_burn_amount\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.15 push.0 end\n\
         \x20\x20\x20\x20push.{new_min}\n\
         \x20\x20\x20\x20call.min_burn_amount::set_min_burn_amount\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| {
            anyhow::anyhow!("set_min_burn_size note script failed to compile: {e}\n{src}")
        })?;
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
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the set_min_burn_size transaction")
        .execute()
        .await
}

/// Reads the STOCK `MinBurnAmount` floor slot word `[min_burn_amount, 0, 0, 0]` from a
/// committed/evolved account — the full-word read-back the write-integrity + no-state-change
/// tests use (the slot the stock `check_policy` reads and the stock `set_min_burn_amount`
/// writes; there is no custom `min_burn_size` slot). Mirrors
/// [`read_token_config`].
pub fn read_min_burn_size(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(miden_standards::account::policies::MinBurnAmount::slot_name())
        .map_err(|e| anyhow::anyhow!("reading the stock MinBurnAmount floor slot: {e}"))
}

// set_max_supply — stock admin setter note + token_config read-back
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
/// gated on the same owner authority, the not-paused check, and the build-time mutability flag,
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
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
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
        .get_item(
            &StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL).context("token_config slot label")?,
        )
        .map_err(|e| anyhow::anyhow!("reading the token_config value slot: {e}"))
}

pub enum GuardSelection {
    /// PRODUCTION `XReserveStablecoinBuilder::build_components` (the attestation mint policy ONLY,
    /// no reserved alternates — the sole-supply-surface invariant).
    ProductionAttestation,
    /// TEST-ONLY oracle (test-harness [`oracle_components`]): allow-all mint + allow-all burn
    /// ACTIVE — the builder-bypassing contrast fixture for non-vacuity controls.
    OracleAllowAll,
}

/// A guarded mint harness: the composition account WITH the `TokenPolicyManager` (the attestation
/// policy or allow-all per the [`GuardSelection`]), plus the resolved ACTIVE mint-policy proc
/// root. The production path is composed by `XReserveStablecoinBuilder::build_components`; the
/// allow-all oracle by the test-only [`oracle_components`] helper. Pause is the stock
/// `PausableManager` gated on the Domain pauser role by the account's procedure-role map; the
/// `is_paused` slot it writes is installed by the base `Pausable` component (v0.16 #2944 moved it
/// out of `FungibleFaucet`).
pub struct GuardedMint {
    pub harness: CompositionHarness,
    pub policy_root: Word,
}

/// Like [`setup_mint_composition_account`] but ALSO installs the `TokenPolicyManager` (the
/// attestation policy or allow-all per `selection`) via [`XReserveStablecoinBuilder`]. The
/// attestation policy rides the same `xreserve` library component (its
/// `mint_policy::check_policy` proc). The production arm build-seeds the caller's `domain` word
/// (element 0) plus the canonical test `source_domain`/`xreserve_contract` through
/// `with_domain_config`; the `identifier` slot carries the caller's pre-seed verbatim.
///
/// `is_max_supply_mutable` configures the built faucet's stock max-supply mutability flag (threaded
/// into the `FungibleFaucet::builder()` chain). The production builder REJECTS an immutable
/// max_supply at build time, so every `ProductionAttestation` caller must pass `true`; the
/// `OracleAllowAll` path bypasses the builder and is unaffected. The immutable control
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

    // The identifier slot ships EMPTY (the ProductionAttestation builder REJECTS a
    // non-empty fixpoint seed; the allow-all bypass arm's mint skips the intent asserts, so it
    // never reads the identifier). The caller's `identifier` param is retained only as the value
    // an OracleAllowAll isolated test may want to observe; it is NOT build-seeded into the
    // fixpoint slot.
    let _ = identifier;
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
                Word::empty(),
            ),
            // 4-field domain-config closure: the two new scalar/bytes32 config slots, EMPTY at assembly
            // (domain_init is the sole writer; the fixtures never read them).
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
            .with_dynamically_linked_package(&library)
            .with_context(|| format!("linking the xreserve library into the {what}"))?
            .compile_component_code(path, src)
            .with_context(|| format!("{what} failed to compile\n--- src ---\n{src}"))
    };
    let driver_code = link(GUARDED_DRIVER_PATH, driver_src, "guarded fixture driver")?;
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

    // Resolve the attestation-policy root from the assembled component (a benign read-only
    // proc-root lookup; the same value the production builder registers as the active mint policy).
    let attestation_root: Word = xreserve_component
        .get_procedure_root_by_path(ATTESTATION_MINT_POLICY_PROC_PATH)
        .map(Word::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "xreserve component does not export the attestation mint policy procedure \
                 '{ATTESTATION_MINT_POLICY_PROC_PATH}'"
            )
        })?;
    let (mut components, policy_root) = match selection {
        // PRODUCTION path: the real builder — attestation policy ONLY (no reserved alternates).
        // The caller's `domain` word (element 0) is build-seeded; the identifier slot
        // carries the caller's pre-seed verbatim (the builder never writes it).
        GuardSelection::ProductionAttestation => {
            let domain_u32 = u32::try_from(domain[0].as_canonical_u64())
                .context("the fixture domain word element 0 must be a u32")?;
            let components = xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::new(
                faucet,
                xreserve_component,
                test_account_id(1),
                test_account_id(2),
                test_account_id(3),
                test_account_id(4),
            )
            .with_domain_config(domain_u32, TEST_SOURCE_DOMAIN, test_xreserve_contract())
            .build_components()
            .map_err(|e| anyhow::anyhow!("composing the production attestation faucet: {e}"))?;
            (components, attestation_root)
        }
        // TEST-ONLY oracle: allow-all mint + allow-all burn ACTIVE (builder-bypassing contrast).
        GuardSelection::OracleAllowAll => {
            let components = oracle_components(faucet, xreserve_component)
                .context("composing the oracle allow-all faucet")?;
            (components, Word::from(MintPolicy::allow_all().root()))
        }
    };
    components.push(driver_component);
    components.push(probe_component);

    let mut mc = MockChain::builder();
    let account = add_faucet_account(&mut mc, Auth::IncrNonce, components)
        .context("adding guarded faucet")?;
    let mock_chain = mc.build().context("building MockChain")?;
    Ok(GuardedMint {
        harness: CompositionHarness {
            mock_chain,
            account_id: account.id(),
            driver_code,
            probe_code,
        },
        policy_root,
    })
}

/// TEST-ONLY allow-all oracle composition: the stock `MintAllowAll` + `BurnAllowAll` ACTIVE — the
/// builder-bypassing contrast fixture for non-vacuity controls (the production builder REJECTS
/// any active mint policy that is not the attestation policy, so this shape is constructible only
/// here, in the test harness).
fn oracle_components(
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
) -> Result<Vec<AccountComponent>> {
    let manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .build();
    // No PausableManager (the Domain-Pauser-only model); the base Pausable component installs the
    // is_paused slot execute_mint_policy's assert_not_paused reads (v16 — #2944 moved it out of
    // FungibleFaucet). The manager iterator yields [manager, then one companion per distinct
    // policy root] — here the two stock allow-all companions, both kept.
    let mut parts = manager.into_iter();
    let manager_component = parts.next().expect("manager component first");
    let companions: Vec<AccountComponent> = parts.collect();
    anyhow::ensure!(
        companions.len() == 2,
        "allow-all-oracle seam: expected the 2 stock allow-all companions, got {}",
        companions.len()
    );
    let mut components = vec![
        faucet.into(),
        Pausable::unpaused().into(),
        xreserve_component,
    ];
    components.push(manager_component);
    components.extend(companions); // [MintAllowAll, BurnAllowAll]
    Ok(components)
}

fn felt_from_u64(value: u64) -> Felt {
    Felt::new(value).expect("a burn magnitude (< 2^63) is a valid field element")
}

pub enum BurnGuardSelection {
    /// TEST-ONLY oracle: the real `burn_policy::check_policy` (`Custom(burn_root)`) ACTIVE, allow-all
    /// RESERVED. The arm the zero-burn/below-minimum rejects + the valid-burn positive run against.
    OracleBurnReal,
    /// TEST-ONLY oracle: stock `BurnAllowAll` ACTIVE, the real burn policy RESERVED. The non-vacuity
    /// control: the SAME below-min burn succeeds + decrements here, proving the real arm's trap is
    /// policy-caused.
    OracleBurnAllowAll,
}

/// A burn-policy harness: a built [`MockChain`] holding the composed faucet (real burn policy active or
/// allow-all per [`BurnGuardSelection`]) + a user wallet seeded with the burn asset + the canonical
/// asset-bearing [`BurnNote`] the tests reproduce in-block and consume via the 2-block
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
/// replica of the production builder's private `seeded_dom_roles_rbac` (both stock RBAC maps
/// direct-seeded with the two Circle Domain role members `DOM_PAUSER`→`pauser_holder` and
/// `DOM_MANAGER`→`manager_holder`; `DOM_PAUSER` administration delegated to `DOM_MANAGER` — the
/// seed `role_config[DOM_PAUSER] = [1, DOM_MANAGER, 0, 0]`). The burn oracle needs the RBAC foundation
/// so the DOM_PAUSER-sent stock `PausableManager::pause` clears its role gate (the pause gate
/// `burn_paused_rejects` exercises). Reuses the stock RBAC code + slot names + metadata verbatim.
/// Replica fidelity to the production seed is pinned by
/// `set_min_burn.rs::support_replica_carries_delegation_seed` (the production twin is
/// `role_admin.rs::shipped_delegation_reads_back`).
fn seeded_dom_roles_rbac_component(
    owner: AccountId,
    pauser_holder: AccountId,
    manager_holder: AccountId,
    blocklist_manager_holder: AccountId,
) -> AccountComponent {
    let pauser = RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol");
    let manager =
        RoleSymbol::new(DOM_MANAGER_ROLE).expect("DOM_MANAGER is a fixed valid role symbol");
    let blk_manager =
        RoleSymbol::new(BLK_MANAGER_ROLE).expect("BLK_MANAGER is a fixed valid role symbol");
    // v16 (#3215): the administrator has no implicit super-admin standing — the stock ADMIN role is
    // seeded on the administrator's account, mirroring the production seed.
    let admin = RoleBasedAccessControl::admin_role();
    let member_word = Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    // [1, DOM_MANAGER, 0, 0]: member_count = 1 with administration delegated to DOM_MANAGER.
    let delegated_config_word = Word::from([
        Felt::from(1u32),
        Felt::from(&manager),
        Felt::ZERO,
        Felt::ZERO,
    ]);

    let role_config = StorageMap::with_entries([
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&pauser),
            ])),
            delegated_config_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&manager),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&admin),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&blk_manager),
            ])),
            member_word,
        ),
    ])
    .expect("the four-role role_config seed is valid");

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
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&admin),
                owner.suffix(),
                owner.prefix().as_felt(),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&blk_manager),
                blocklist_manager_holder.suffix(),
                blocklist_manager_holder.prefix().as_felt(),
            ])),
            member_word,
        ),
    ])
    .expect("the four-role role_membership seed is valid");

    AccountComponent::new(
        RoleBasedAccessControl::code().clone(),
        vec![
            StorageSlot::with_map(
                RoleBasedAccessControl::role_config_slot().clone(),
                role_config,
            ),
            StorageSlot::with_map(
                RoleBasedAccessControl::role_membership_slot().clone(),
                role_membership,
            ),
        ],
        RoleBasedAccessControl::component_metadata(),
    )
    .expect("the seeded RBAC component mirrors the stock From impl and is valid")
}

/// TEST-ONLY burn-oracle composition: registers the attestation mint policy ACTIVE (the
/// production mint slot) AND BOTH burn policies (the STOCK [`MinBurnAmount`] floor policy — the
/// production burn gate — + stock `BurnAllowAll`), one `Active` and one `Reserved` per
/// `burn_real_active`, so the real-vs-allow-all pair is CODE-IDENTICAL (both stock burn
/// companions present in both variants, the SAME floor seed) and differs ONLY in
/// `active_burn_policy_proc_root`. Mirrors the production
/// `XReserveStablecoinBuilder::{assemble_components, build_components}` RBAC foundation, but is
/// the TEST harness — production composition installs the MinBurnAmount policy ONLY (no reserved
/// allow-all), so no shipped API can construct an allow-all-active burn faucet.
fn oracle_burn_components(
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
    min_burn_size: u64,
    burn_real_active: bool,
    administrator: AccountId,
    pauser_holder: AccountId,
    manager_holder: AccountId,
    blocklist_manager_holder: AccountId,
) -> Result<Vec<AccountComponent>> {
    let min_burn =
        AssetAmount::new(min_burn_size).map_err(|e| anyhow::anyhow!("oracle floor: {e}"))?;
    let real_burn = BurnPolicy::min_burn_amount(min_burn);
    let allow_burn = BurnPolicy::allow_all();
    let (active_burn, reserved_burn) = if burn_real_active {
        (real_burn, allow_burn)
    } else {
        (allow_burn, real_burn)
    };
    let attestation_root: Word = xreserve_component
        .get_procedure_root_by_path(ATTESTATION_MINT_POLICY_PROC_PATH)
        .map(Word::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "xreserve component does not export '{ATTESTATION_MINT_POLICY_PROC_PATH}'"
            )
        })?;
    let manager = TokenPolicyManager::builder()
        .active_mint_policy(
            MintPolicy::custom(
                AccountProcedureRoot::from_raw(attestation_root),
                [xreserve_component.clone()],
            )
            .map_err(|e| anyhow::anyhow!("oracle attestation mint policy: {e}"))?,
        )
        .active_burn_policy(active_burn)
        .allowed_burn_policy(reserved_burn)
        .build();

    // Component order/contents mirror XReserveStablecoinBuilder::{assemble_components,
    // build_components}, including the v16 policy-companion seam: the manager iterator yields
    // [manager, then one companion copy per distinct policy root] — here the attestation custom
    // carries the xreserve component (dropped: it is installed once below) and the two stock burn
    // policies carry the MinBurnAmount (with the floor slot) + BurnAllowAll companions (BOTH
    // kept: the code-identical pair needs them in both variants). The base Pausable component
    // installs the is_paused slot (v16 — #2944 moved it out of FungibleFaucet) and the stock
    // PausableManager writes it, gated on the Domain pauser role by the procedure-role map.
    let xreserve_code = xreserve_component.component_code().clone();
    let mut parts = manager.into_iter();
    let manager_component = parts.next().expect("manager component first");
    let companions: Vec<AccountComponent> = parts.collect();
    let (dup, keep): (Vec<_>, Vec<_>) = companions
        .into_iter()
        .partition(|c| c.component_code().as_package() == xreserve_code.as_package());
    anyhow::ensure!(
        dup.len() == 1 && keep.len() == 2,
        "burn-oracle seam: expected 1 xreserve companion copy + 2 stock burn companions, got \
         {} + {}",
        dup.len(),
        keep.len()
    );
    let mut components = vec![
        faucet.into(),
        Pausable::unpaused().into(),
        xreserve_component,
    ];
    components.push(manager_component);
    components.extend(keep); // [MinBurnAmount (floor slot), BurnAllowAll]
    components.push(PausableManager.into());
    components.push(seeded_dom_roles_rbac_component(
        administrator,
        pauser_holder,
        manager_holder,
        blocklist_manager_holder,
    ));
    components.push(XReserveAdminAuthority::new().into());
    Ok(components)
}

/// Builds the burn-policy harness: assembles the `xreserve` component with the full production slot set
/// (domain/identifier value slots, usedNonces/xReserveAttesters map slots, AND the NET-NEW minBurnSize
/// value slot seeded `[min_burn_size, 0, 0, 0]`), composes the faucet via [`oracle_burn_components`]
/// (`administrator` = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3)), adds a user wallet seeded with the single burn asset, and
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
                StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)
                    .context("identifier slot label")?,
                Word::from([11u32, 12, 13, 14]),
            ),
            // 4-field domain-config closure: the two new scalar/bytes32 config slots, EMPTY at assembly
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
            // NOTE: the floor slot rides the STOCK MinBurnAmount policy companion
            // (seeded by `oracle_burn_components`), not the xreserve component.
        ],
        AccountComponentMetadata::new("xusdc-burn-policy-harness"),
    )
    .context("binding the xreserve library + all composition slots as a component")?;

    let burn_root = Word::from(miden_standards::account::policies::MinBurnAmount::root());

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
        min_burn_size,
        burn_real_active,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
    )?;

    let mut builder = MockChain::builder();
    let faucet_account = builder
        .add_existing_account_from_components(Auth::IncrNonce, components)
        .context("adding the burn-policy faucet account")?;
    let faucet_id = faucet_account.id();

    // The user wallet seeded with exactly the burn asset (faucet_id known only now).
    let asset = FungibleAsset::new(faucet_id, burn_amount).context("invalid burn asset")?;
    let user = add_emitting_wallet(&mut builder, Auth::IncrNonce, [asset.into()])
        .context("adding the burn user wallet")?;
    let user_id = user.id();

    // The canonical burn note (random serial) — created while the builder rng is live.
    // v16 (#2283): the stock BurnNote is a bon builder; the faucet id is derived from the
    // asset itself and the builder yields a BurnNote that converts into the Note the harness
    // threads around.
    let burn_note: Note = BurnNote::builder()
        .sender(user_id)
        .asset(asset)
        .generate_serial_number(builder.rng_mut())
        .build()
        .context("creating the canonical burn note")?
        .into();

    let chain = builder
        .build()
        .context("building the burn-policy MockChain")?;
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

/// The user send tx-script that emits `burn_note` exactly (ported from the grounding test
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
    let asset_id = fungible_asset.id().to_word();
    let asset_value = fungible_asset.to_value_word();
    // v0.16 #3204: output_note::create / add_attachment execute only from the active account's own
    // procedures, so note creation runs in ACCOUNT context — the STOCK wallet's `create_note`
    // (defined in `miden::standards::note::note_creator` and re-exported by the BasicWallet
    // component, so the account exposes its root) for the attachment-less stock BurnNote, and the
    // user-installed emit helper for the single-attachment XReserveBurnNote (whose scheme-2 routing target must be reproduced so the
    // emitted note's id == burn_note.id(); NoteId commits to attachments). The content is supplied
    // via the advice map keyed by its commitment (`attachment_advice`, extended in
    // `try_emit_burn_note`). The returned note_idx feeds move_asset_to_note.
    let attachments: Vec<_> = burn_note.attachments().iter().collect();
    let create_src = match attachments.as_slice() {
        [] => "    repeat.10 push.0 end\n\
               \x20\x20\x20\x20push.{recipient}\n\
               \x20\x20\x20\x20push.{note_type}\n\
               \x20\x20\x20\x20push.{tag}\n\
               \x20\x20\x20\x20call.note_creator::create_note\n"
            .to_string(),
        [attachment] => format!(
            "    repeat.5 push.0 end\n\
             \x20\x20\x20\x20push.{commitment}\n\
             \x20\x20\x20\x20push.{scheme}\n\
             \x20\x20\x20\x20push.{{recipient}}\n\
             \x20\x20\x20\x20push.{{note_type}}\n\
             \x20\x20\x20\x20push.{{tag}}\n\
             \x20\x20\x20\x20call.emit_helper::emit_note_with_attachment\n",
            commitment = attachment.content().to_commitment(),
            scheme = attachment.attachment_scheme().as_u16(),
        ),
        other => panic!(
            "send_burn_note_script emits a 0- or 1-attachment burn note, got {}",
            other.len()
        ),
    };
    let create_src = create_src
        .replace("{recipient}", &recipient.to_string())
        .replace("{note_type}", &note_type.to_string())
        .replace("{tag}", &tag.to_string());
    format!(
        r#"
use miden::standards::note::note_creator
use miden::standards::wallets::basic as wallet
use xusdc::test_fixtures::emit_helper

@transaction_script
pub proc main
    # create the burn note (empty) carrying burn_note's recipient + metadata (+ routing target).
{create_src}
    # => [note_idx, pad(15)]

    # move the user's single fungible asset from the vault into the note.
    push.{asset_value}
    push.{asset_id}
    # => [ASSET_ID, ASSET_VALUE, note_idx, pad(15)]
    call.wallet::move_asset_to_note
    # => [pad(16)]

    exec.::miden::core::sys::truncate_stack
end
"#
    )
}

/// The advice-map inputs carrying each of `note`'s attachment contents keyed by its commitment — the
/// witness the `output_note::add_attachment` emit path resolves (the scheme-2 routing target).
pub fn attachment_advice(note: &Note) -> AdviceInputs {
    let mut advice = AdviceInputs::default();
    for attachment in note.attachments().iter() {
        advice = advice.with_map([(
            attachment.content().to_commitment(),
            attachment.content().to_elements(),
        )]);
    }
    advice
}

/// Reads the faucet's committed `token_supply` from its `token_config` slot post-block (ported from
/// the grounding test `burn_canary.rs:94-97`).
pub fn committed_token_supply(chain: &MockChain, faucet_id: AccountId) -> Result<AssetAmount> {
    let storage = chain.committed_account(faucet_id)?.storage();
    Ok(FungibleFaucet::try_from(storage)?.token_supply())
}

/// Reads the ACTIVE burn-policy procedure root committed in the faucet account's
/// `TokenPolicyManager` storage slot (the burn-slot twin of the mint-policy slot). Asserting this
/// stored root equals the expected `burn_policy_root()` is the storage-COMMITMENT proof that the sole
/// supply-decrement path (stock `receive_and_burn`) is burn-policy-gated — stronger than resolving
/// the merely-EXPORTED proc root via `get_procedure_root_by_path`.
pub fn read_active_burn_policy_root(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(TokenPolicyManager::active_burn_policy_slot())
        .map_err(|e| anyhow::anyhow!("reading the active burn policy root slot: {e}"))
}

/// Returns the names of the procedures in a vendored pinned-standards MASM source that
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

/// Returns the names of the procedures in a vendored pinned-standards MASM source that
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
                    if toks.contains(&"sub") {
                        Some("sub")
                    } else if toks.contains(&"add") {
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
        .with_dynamically_linked_package(
            emit_helper_component()
                .expect("the emit helper compiles")
                .component_code()
                .clone(),
        )
        .expect("linking the emit helper into the burn emit script")
        .compile_tx_script(send_burn_note_script(burn_note, asset, faucet_id))
        .expect("the user send-burn-note script compiles");
    let mut ctx = chain
        .build_transaction(user_id)
        .tx_script(tx_script)
        // The attachment contents (routing target) keyed by commitment for `add_attachment`.
        .extend_advice_inputs(attachment_advice(burn_note))
        // Register the full note details so the kernel's `before_created` event can resolve the PUBLIC
        // note's details when tx0 creates it.
        .expected_output_note(RawOutputNote::Full(burn_note.clone()));
    // A POLICED (callback-Enabled) faucet's asset fires the SEND callback when the holder
    // emits a note moving it out of their vault (native = the holder), so the kernel dyncalls the
    // issuing faucet to run `basic_blocklist::check_policy` — attach it as a foreign account. A basic
    // (Disabled) faucet — e.g. the burn oracle fixtures — fires no callback, so it is skipped.
    if faucet_id.asset_callback_flag() == AssetCallbackFlag::Enabled {
        let foreign = chain
            .get_foreign_account_inputs(faucet_id)
            .expect("faucet foreign-account inputs (committed)");
        ctx = ctx.foreign_accounts([foreign]);
    }
    ctx.build()
        .expect("building the user emit tx")
        .execute()
        .await
}

/// Runs the 2-block burn lifecycle against `chain`: the user emits `burn_note` at block N (tx0,
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
        .build_transaction(faucet_id)
        .authenticated_input_note(burn_note.id())
        .build()
        .expect("building the faucet consume tx")
        .execute()
        .await
}

/// Executes a stock `PausableManager::pause` note SENT BY `sender` against the faucet `account` on a
/// bare `&MockChain` (the note is provided unauthenticated). Under the Domain-Pauser-only model the
/// stock proc is NOT installed — this is the NEGATIVE PROBE `administrator_has_no_pause_path` drives: the tx
/// must trap `UnknownAccountProcedure` and never flip `is_paused`. To actually pause, use
/// [`run_dom_pauser_pause`] (the DOM_PAUSER custom proc — the only pause surface).
pub async fn run_pause_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = manager_pause_call_note(sender, seed)
        .expect("building the manager pause-call note (test-setup invariant)");
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the pause transaction")
        .execute()
        .await
}

/// Builds a note SENT BY `sender` whose script calls the stock `PausableManager::unpause` — the
/// unpause twin of [`manager_pause_call_note`]. Serial tail [25, 26] keeps note serials disjoint
/// from the other admin-note families.
pub fn manager_unpause_call_note(sender: AccountId, seed: u64) -> Result<Note> {
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
    let note = manager_unpause_call_note(sender, seed)
        .expect("building the manager unpause-call note (test-setup invariant)");
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
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
        messages
            .iter()
            .any(|m| m.contains("is not in the account procedure index map")),
        "expected the exact UnknownAccountProcedure failure (the called proc root is not part of \
         the account code); actual error chain: {messages:?}"
    );
}

// DOM_PAUSER PAUSE — notes + runners for the stock PausableManager procs
// ================================================================================================

/// Builds a note SENT BY `sender` whose script `call`s the stock `PausableManager::{proc}`, which
/// the account's procedure-role map gates on the Domain pauser role.
///
/// This is the same underlying procedure [`manager_pause_call_note`] targets — the pause surface is
/// the stock manager for every caller now, and who may use it is decided by the role map, not by
/// which procedure the note calls. The two helpers differ only in their serial tails, which keeps
/// note ids from colliding across the admin-note families.
fn dom_pauser_manager_note(
    sender: AccountId,
    seed: u64,
    proc: &str,
    tail0: u32,
    tail1: u32,
) -> Result<Note> {
    let src = format!(
        "use miden::standards::access::pausable::manager\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.16 push.0 end\n\
         \x20\x20\x20\x20call.manager::{proc}\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| {
            anyhow::anyhow!("dom_pauser {proc} note script failed to compile: {e}\n{src}")
        })?;
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

/// A `PausableManager::pause` note sent by `sender` (the Domain pauser, for success).
pub fn dom_pauser_pause_note(sender: AccountId, seed: u64) -> Result<Note> {
    dom_pauser_manager_note(sender, seed, "pause", 21, 22)
}

/// A `PausableManager::unpause` note sent by `sender` (the Domain pauser, for success).
pub fn dom_pauser_unpause_note(sender: AccountId, seed: u64) -> Result<Note> {
    dom_pauser_manager_note(sender, seed, "unpause", 23, 24)
}

/// Executes a `PausableManager::pause` note (sent by `sender`) against the faucet `account` on a
/// bare `&MockChain`; the caller applies the returned delta (the unauthenticated note is not
/// block-proven).
pub async fn run_dom_pauser_pause(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = dom_pauser_pause_note(sender, seed)
        .expect("building the dom_pauser pause note (test-setup invariant)");
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
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
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the dom_pauser unpause transaction")
        .execute()
        .await
}

/// Reads the `Pausable`-installed `is_paused` value slot (v0.16 #2944 moved it out of
/// `FungibleFaucet`; `[0,0,0,0]` unpaused, `[1,0,0,0]` paused)
/// from a committed/evolved account — the `GetAccount` pause-state observability read (Circle
/// requires the pause state be publicly observable). Mirrors
/// [`read_min_burn_size`] / [`read_token_config`]; the slot is installed by the base `Pausable` component, so it is
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

// RBAC ROLE ADMINISTRATION — grant/revoke/set_role_admin notes + runners + role read-backs
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
        .map_err(|e| {
            anyhow::anyhow!("rbac {proc_name} note script failed to compile: {e}\n{src}")
        })?;
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

/// A `grant_role(role, member)` note sent by `sender` (stock gate at v0.16: the granted role's
/// EFFECTIVE admin).
pub fn grant_role_note(
    sender: AccountId,
    role: &RoleSymbol,
    member: AccountId,
    seed: u64,
) -> Result<Note> {
    rbac_member_note(sender, "grant_role", role, member, seed, 11, 12)
}

/// A `revoke_role(role, member)` note sent by `sender` (same role-admin gate: the revoked role's
/// effective admin).
pub fn revoke_role_note(
    sender: AccountId,
    role: &RoleSymbol,
    member: AccountId,
    seed: u64,
) -> Result<Note> {
    rbac_member_note(sender, "revoke_role", role, member, seed, 13, 14)
}

/// A `set_role_admin(role, admin_role)` note sent by `sender`. Stock gate at v0.16: the MANAGED
/// role's EFFECTIVE admin — its delegated admin, else the built-in `ADMIN` role
/// (`assert_sender_is_role_admin`, rbac.masm:200).
/// `admin_role = None` pushes 0 — the stock "clear the delegation" sentinel, after which the role
/// is `ADMIN`-administered. PROC-LEVEL CHARACTERIZATION ONLY (permissive-auth fixtures): in
/// production the `set_role_admin` capability is structurally unreachable — its note is not in
/// the allowlist, so the deployed role-admin graph is
/// frozen at the build seed.
/// Stack contract: `[role_symbol, admin_role_symbol, pad(14)]` (role on top).
pub fn set_role_admin_note(
    sender: AccountId,
    role: &RoleSymbol,
    admin_role: Option<&RoleSymbol>,
    seed: u64,
) -> Result<Note> {
    let role_felt = Felt::from(role).as_canonical_u64();
    let admin_felt = admin_role
        .map(|r| Felt::from(r).as_canonical_u64())
        .unwrap_or(0);
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
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
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

/// Reads a role's `role_config` word `[member_count, admin_role_symbol, 0, 0]` from a
/// committed/evolved account (stock key encoding `[0,0,0,role_symbol]`, rbac.masm:12).
pub fn read_role_config(account: &Account, role: &RoleSymbol) -> Result<Word> {
    let key = Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(role)]);
    account
        .storage()
        .get_map_item(
            RoleBasedAccessControl::role_config_slot(),
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading the role_config entry: {e}"))
}

/// Reads a member's `role_membership` word `[is_member, 0, 0, 0]` from a committed/evolved account
/// (stock key encoding `[0, role_symbol, account_suffix, account_prefix]`, rbac.masm:15).
pub fn read_role_membership(
    account: &Account,
    role: &RoleSymbol,
    member: AccountId,
) -> Result<Word> {
    let key = Word::from([
        Felt::ZERO,
        Felt::from(role),
        member.suffix(),
        member.prefix().as_felt(),
    ]);
    account
        .storage()
        .get_map_item(
            RoleBasedAccessControl::role_membership_slot(),
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading the role_membership entry: {e}"))
}

// STOCK MinBurnAmount DIRECT-POLICY DRIVER — exec check_policy with a crafted [ASSET_ID, ASSET_VALUE]
// ================================================================================================

/// Module path of the generated direct burn-policy driver component.
pub const BURN_POLICY_DRIVER_PATH: &str = "xusdc::test_fixtures::burn_policy_driver";

/// Generates a direct-policy driver: a CALL-entered account proc that pushes a crafted
/// `[ASSET_ID, ASSET_VALUE]` burn-policy stack (`ASSET_VALUE = [amount, 0, 0, 0]`) and `exec`s
/// the STOCK `min_burn_amount::check_policy` (the production burn gate). The policy
/// consumes the 8 cells and returns `[]`, restoring the 16-depth `call` boundary. Drives the
/// floor boundary DIRECTLY as a SUPPLEMENTARY, belt-and-suspenders proof beside the
/// note-reachable rejects.
pub fn burn_policy_direct_driver_src(asset_key: Word, amount: u64) -> String {
    let asset_value = Word::from([felt_from_u64(amount), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    format!(
        "use miden::standards::faucets::policies::burn::min_burn_amount\n\n\
         #! Test driver: pushes [ASSET_ID, ASSET_VALUE] and execs the stock burn policy directly.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         @account_procedure\n\
         pub proc drive\n\
         \x20\x20\x20\x20push.{asset_value}\n\
         \x20\x20\x20\x20push.{asset_key}\n\
         \x20\x20\x20\x20exec.min_burn_amount::check_policy\n\
         end\n",
    )
}

/// Builds a MockChain account carrying [the STOCK `MinBurnAmount` component with its floor slot
/// seeded] + [the generated direct burn-policy driver], reusing [`ShellHarness`] +
/// [`run_call_driver`]. Used by the direct floor-boundary proofs: the stock `check_policy` reads
/// only `amount` + its own floor slot.
pub fn setup_burn_policy_direct_account(
    min_burn_size: u64,
    driver_src: &str,
) -> Result<ShellHarness> {
    let min_burn = miden_standards::account::policies::MinBurnAmount::new(
        AssetAmount::new(min_burn_size).context("invalid min_burn_size")?,
    );

    let driver_code = CodeBuilder::new()
        .compile_component_code(BURN_POLICY_DRIVER_PATH, driver_src)
        .with_context(|| {
            format!("direct driver failed to compile\n--- driver ---\n{driver_src}")
        })?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-burn-policy-direct-driver"),
    )
    .context("binding the direct driver component")?;

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [min_burn.into(), driver_component])
        .context("adding the direct burn-policy account")?;
    let mock_chain = builder
        .build()
        .context("building the direct-policy MockChain")?;
    Ok(ShellHarness {
        mock_chain,
        account_id: account.id(),
        driver_code,
        driver_path: BURN_POLICY_DRIVER_PATH,
    })
}

// FULL-ASSEMBLY E2E HARNESS — the production-assembled faucet with
// EMPTY domain config + a real recipient wallet, run sequentially through the whole lifecycle.
// ================================================================================================

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
    seed_notes_for: impl FnOnce(AccountId, AccountId) -> Vec<Note>,
) -> Result<ProductionFaucet> {
    let mut mc = MockChain::builder();
    let recipient = mc
        .add_existing_wallet(Auth::IncrNonce)
        .context("adding recipient wallet")?;
    let producer =
        add_emitting_wallet(&mut mc, Auth::IncrNonce, []).context("adding producer wallet")?;

    let library = assemble_xreserve_lib()?;
    let empty = || Word::from([0u32, 0, 0, 0]);
    let xreserve_component = AccountComponent::new(
        library,
        vec![
            // the five domain-config slots are DECLARED here; the builder BUILD-SEEDS domain /
            // source_domain / xreserve_contract, the identifier stays EMPTY until the
            // seeded identifier_init owner note writes it; the attester allowlist ships EMPTY
            // (set_attester writes it).
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
        test_account_id(4),
    )
    .with_domain_config(TEST_DOMAIN, TEST_SOURCE_DOMAIN, test_xreserve_contract())
    .build_components()
    .map_err(|e| anyhow::anyhow!("composing the production faucet: {e}"))?;

    // The production faucet is finalized under the stock AuthNetworkAccount (keyless
    // network account) with the frozen note-script allowlist, a tx-script allowlist of EXACTLY
    // the one canonical `ExpirationTransactionScript::script_root()`,
    // and the provisional zero-fee configuration — installed via the deploy path's OWN
    // `XReserveStablecoinBuilder::auth_component()` (the `custom()`-based composition; the
    // `Auth::NetworkAccount` fixture is deliberately bypassed because it routes through the
    // force-inserting `new()` constructor and would grow the 9-root allowlist).
    let account = add_network_faucet_account(&mut mc, components)
        .context("adding the production faucet account")?;
    // The faucet id is now known, so the seed-notes closure binds its notes (the
    // identifier_init note derives the identifier from THIS faucet id — the own-id fixpoint) and
    // its mint payloads (`remoteToken = account_id_to_bytes32(faucet_id)`) to the REAL faucet
    // identity. Seeded AFTER the account is built; order relative to `mc.build()` is all that
    // matters for genesis notes.
    let seeded_notes = seed_notes_for(recipient.id(), account.id());
    for note in &seeded_notes {
        mc.add_output_note(RawOutputNote::Full(note.clone()));
    }
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
/// `try_emit_burn_note`. No asset is attached (the mint-note shape: the amount travels in the
/// note's storage).
/// Module path of the note-emission helper component (v0.16 #3204: `output_note::create` /
/// `add_attachment` execute only from the active account's own procedures, so the emit tx
/// scripts route through these call-exposed wrappers instead of exec'ing the kernel API
/// directly — the same pattern as the stock `note_creator::create_note`).
pub const EMIT_HELPER_PATH: &str = "xusdc::test_fixtures::emit_helper";

/// The FIXED emit-helper component source: create-plus-two-attachments (the mint note's exact
/// shape — 16 call-window felts, zero padding) and create-plus-one-attachment returning the
/// note index (the burn note's shape; the index feeds the subsequent `move_asset_to_note`).
fn emit_helper_src() -> String {
    "use miden::protocol::output_note\n\
     \n\
     #! Creates an output note and adds its two attachments in account context.\n\
     #!\n\
     #! Inputs:  [tag, note_type, RECIPIENT, scheme_a, COMM_A, scheme_b, COMM_B]\n\
     #! Outputs: [pad(16)]\n\
     #!\n\
     #! Invocation: call\n\
     @account_procedure\n\
     pub proc emit_note_with_two_attachments\n\
     \x20\x20\x20\x20exec.output_note::create\n\
     \x20\x20\x20\x20# => [note_idx, scheme_a, COMM_A, scheme_b, COMM_B]\n\
     \x20\x20\x20\x20dup movdn.6\n\
     \x20\x20\x20\x20# => [note_idx, scheme_a, COMM_A, note_idx, scheme_b, COMM_B]\n\
     \x20\x20\x20\x20movdn.5\n\
     \x20\x20\x20\x20# => [scheme_a, COMM_A, note_idx, note_idx, scheme_b, COMM_B]\n\
     \x20\x20\x20\x20exec.output_note::add_attachment\n\
     \x20\x20\x20\x20# => [note_idx, scheme_b, COMM_B]\n\
     \x20\x20\x20\x20movdn.5\n\
     \x20\x20\x20\x20# => [scheme_b, COMM_B, note_idx]\n\
     \x20\x20\x20\x20exec.output_note::add_attachment\n\
     end\n\
     \n\
     #! Creates an output note, adds its single attachment, and returns the note index.\n\
     #!\n\
     #! Inputs:  [tag, note_type, RECIPIENT, scheme, COMM, pad(5)]\n\
     #! Outputs: [note_idx, pad(15)]\n\
     #!\n\
     #! Invocation: call\n\
     @account_procedure\n\
     pub proc emit_note_with_attachment\n\
     \x20\x20\x20\x20exec.output_note::create\n\
     \x20\x20\x20\x20# => [note_idx, scheme, COMM, pad(5)]\n\
     \x20\x20\x20\x20dup movdn.6\n\
     \x20\x20\x20\x20# => [note_idx, scheme, COMM, note_idx, pad(5)]\n\
     \x20\x20\x20\x20movdn.5\n\
     \x20\x20\x20\x20# => [scheme, COMM, note_idx, note_idx, pad(5)]\n\
     \x20\x20\x20\x20exec.output_note::add_attachment\n\
     \x20\x20\x20\x20# => [note_idx, pad(5)]\n\
     end\n\
     \n\
     #! Adds one attachment to an already-created output note (the third-attachment leg of the\n\
     #! stock-MintNote emit: create-plus-two leaves the note index on the caller stack, this\n\
     #! appends one more attachment to that note).\n\
     #!\n\
     #! Inputs:  [scheme, COMM, note_idx, pad(10)]\n\
     #! Outputs: [pad(16)]\n\
     #!\n\
     #! Invocation: call\n\
     @account_procedure\n\
     pub proc add_note_attachment\n\
     \x20\x20\x20\x20exec.output_note::add_attachment\n\
     \x20\x20\x20\x20# => [pad(10)]\n\
     end\n"
        .to_string()
}

/// The compiled zero-storage emit-helper `AccountComponent`.
pub fn emit_helper_component() -> Result<AccountComponent> {
    let code = CodeBuilder::new()
        .compile_component_code(EMIT_HELPER_PATH, emit_helper_src())
        .context("emit helper component failed to compile")?;
    AccountComponent::new(
        code,
        vec![],
        AccountComponentMetadata::new("xusdc-emit-helper"),
    )
    .context("binding the emit helper component")
}

/// Adds an existing BasicWallet account CARRYING the emit helper (assets optional) — the
/// note-emitting producer/user accounts the emit-realness paths drive.
pub fn add_emitting_wallet(
    builder: &mut miden_testing::MockChainBuilder,
    auth: Auth,
    assets: impl IntoIterator<Item = miden_protocol::asset::Asset>,
) -> Result<Account> {
    let account_builder = Account::builder(rand::random())
        .account_type(AccountType::Public)
        .with_component(BasicWallet)
        .with_component(emit_helper_component()?)
        .with_assets(assets);
    builder
        .add_account_from_builder(auth, account_builder, AccountState::Exists)
        .context("adding an emitting wallet")
}

pub async fn emit_note_with_attachments(
    chain: &mut MockChain,
    producer: AccountId,
    note: &Note,
) -> Result<()> {
    let recipient = note.recipient().digest();
    let note_type = Felt::from(note.metadata().note_type());
    let tag = Felt::from(note.metadata().tag());

    // v0.16 #3204: output_note::create/add_attachment execute only from account procedures —
    // the script calls the producer-installed emit helper. Two attachments (the legacy
    // mint-note shape) ride one create-plus-two call (16 call-window felts, zero padding); the
    // three-attachment stock-MintNote shape appends the third via a second `add_note_attachment`
    // call consuming the note index the first call leaves on the caller stack.
    let attachments: Vec<_> = note.attachments().iter().collect();
    anyhow::ensure!(
        (2..=4).contains(&attachments.len()),
        "emit_note_with_attachments emits the two- to four-attachment mint-note shapes, got {}",
        attachments.len()
    );
    let (scheme_a, comm_a) = (
        attachments[0].attachment_scheme().as_u16(),
        attachments[0].content().to_commitment(),
    );
    let (scheme_b, comm_b) = (
        attachments[1].attachment_scheme().as_u16(),
        attachments[1].content().to_commitment(),
    );
    let mut advice = AdviceInputs::default();
    for attachment in &attachments {
        advice = advice.with_map([(
            attachment.content().to_commitment(),
            attachment.content().to_elements(),
        )]);
    }
    // the create-plus-two call consumes the note index (its window returns as pad(16)); each
    // optional extra-attachment leg re-supplies it explicitly — the producer tx creates exactly
    // ONE output note, so its index is deterministically 0 — and calls the appender (insertion
    // order preserved).
    let mut third_leg = String::new();
    for attachment in attachments.iter().skip(2) {
        let scheme_n = attachment.attachment_scheme().as_u16();
        let comm_n = attachment.content().to_commitment();
        third_leg.push_str(&format!(
            "\x20\x20\x20\x20push.0\n\
             \x20\x20\x20\x20push.{comm_n}\n\
             \x20\x20\x20\x20push.{scheme_n}\n\
             \x20\x20\x20\x20call.emit_helper::add_note_attachment\n"
        ));
    }
    let src = format!(
        "use xusdc::test_fixtures::emit_helper\n\
         \n\
         @transaction_script\n\
         pub proc main\n\
         \x20\x20\x20\x20push.{comm_b}\n\
         \x20\x20\x20\x20push.{scheme_b}\n\
         \x20\x20\x20\x20push.{comm_a}\n\
         \x20\x20\x20\x20push.{scheme_a}\n\
         \x20\x20\x20\x20push.{recipient}\n\
         \x20\x20\x20\x20push.{note_type}\n\
         \x20\x20\x20\x20push.{tag}\n\
         \x20\x20\x20\x20call.emit_helper::emit_note_with_two_attachments\n\
         {third_leg}\
         \x20\x20\x20\x20exec.::miden::core::sys::truncate_stack\n\
         end\n"
    );

    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(emit_helper_component()?.component_code().clone())?
        .compile_tx_script(src)?;
    let tx = chain
        .build_transaction(producer)
        .tx_script(tx_script)
        .extend_advice_inputs(advice)
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute()
        .await?;
    anyhow::ensure!(
        tx.output_notes().num_notes() == 1 && tx.output_notes().get_note(0).id() == note.id(),
        "the producer tx must emit exactly the constructed note (id parity)"
    );
    chain.add_pending_executed_transaction(&tx)?;
    chain.prove_next_block()?;
    anyhow::ensure!(
        chain.is_note_committed(&note.id()),
        "the emitted note must be committed"
    );
    Ok(())
}
