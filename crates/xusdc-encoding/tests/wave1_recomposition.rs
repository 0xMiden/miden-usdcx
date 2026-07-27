//! WAVE-1 S1 RECOMPOSITION TRIPWIRES — the new-posture pins for the faucet recomposition
//! (stock `MintNote` transport + attestation MintPolicy + build-seeded config with an
//! identifier-only init note + stock `MinBurnAmount` with a zero-floor guard).
//!
//! Written RED-FIRST (anneal test-first protocol): every test below FAILS against the pre-slice
//! composition (mint-deny guard active, custom `XReserveMintNote` transport, custom burn policy,
//! four-field `domain_init`, custom `min_burn_admin`) and flips GREEN when the recomposition
//! lands. The file then STAYS in the suite as the permanent posture tripwire set:
//!
//! - INV-MINT-SECURITY (restated): every supply increase passes the attestation mint policy —
//!   the active mint policy IS `xreserve::mint_policy::check_policy`, the allowed-mint map is
//!   EXACTLY that one root, and a build with any other active mint policy is rejected.
//! - The mint-deny guard DISSOLVES (its job — trapping the stock path — dissolves because the
//!   stock path IS now the attestation-gated path).
//! - The burn floor: the ACTIVE burn policy is the stock `MinBurnAmount`, its floor slot is
//!   seeded `>= 1` (R-BURN-1 zero-burn invariant preserved by construction: `amount >= min >= 1`),
//!   the builder REJECTS `min_burn_size < 1`, and the reworked admin note (targeting the stock
//!   `set_min_burn_amount`) asserts `new_min >= 1` before calling it.
//! - The note-script allowlist pins the STOCK `MintNote` root (row 1) and drops the custom
//!   mint-note root; the four-field `domain_init` surface is replaced by the minimized
//!   identifier-only init (DEC-4 — the identifier is a provable fixpoint of the account id).
//! - The e2e legs drive the NEW transport end-to-end: a stock `MintNote` carrying the
//!   DepositIntent (scheme 4) + attestation (scheme 5) + `NetworkAccountTarget` (scheme 2)
//!   attachments mints the attested amount, and the assert-match binding (ratified: the policy
//!   asserts note-supplied RECIPIENT/ASSET_VALUE equal the attested intent, never overrides)
//!   rejects a tampered recipient with its EXACT error; fee != 0 and nonce replay keep their
//!   frozen errors through the new transport.
//!
//! Fixture-evolution note (recorded for the auditor): the e2e fixtures below bring the faucet up
//! through the CURRENT admin surface at RED time; when the recomposition swaps that surface
//! (identifier-only init, build-seeded domain config) the fixture INTERNALS evolve with it while
//! every `assert…` in the test bodies stays untouched.

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    Account, AccountComponent, AccountId, StorageMapKey, StorageSlot, StorageSlotContent,
    StorageSlotName,
};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteAttachment, NoteAttachmentScheme, NoteId, NoteTag, NoteType};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::{MinBurnAmount, MintPolicy, TokenPolicyManager};
use miden_standards::note::{
    MintNote, MintNoteStorage, NetworkAccountTarget, NoteExecutionHint, P2idNoteStorage,
};
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::note::xreserve_admin::{
    XReserveIdentifierInitNote, XReserveSetAttesterNote, XReserveSetMinBurnSizeNote,
};
use xusdc_encoding::vectors::{load, DiVector};
use xusdc_encoding::xreserve::encoding::{
    account_id_to_bytes32, bytes32_to_storage_map_key, deposit_intent_to_packed_felts,
};

// THE RATIFIED TO-BE CONSTANTS (independent test-side pins; the production Rust/MASM constants
// are parity-tested against each other — these literals keep the RATIFIED values honest)
// ================================================================================================

/// The attestation mint policy's library path inside the assembled `xreserve` component.
const ATTESTATION_MINT_POLICY_PROC_PATH: &str = "xreserve::mint_policy::check_policy";

/// The dissolved mint-deny guard's former library path (must resolve NOWHERE post-slice).
const FORMER_MINT_DENY_GUARD_PROC_PATH: &str = "xreserve::mint_deny_guard::check_policy";

/// The former custom mint-note script root (`XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX` before the
/// slice) — pinned as a LITERAL so the allowlist test can prove its removal after the factory
/// type itself is deleted.
const FORMER_CUSTOM_MINT_NOTE_ROOT_HEX: &str =
    "0x530e20b39e77a111f00a162835823ff503202d05c182b98728387853e07d19d5";

/// Rider A8 (ratified): the xUSDC attachment schemes move OFF the reserved value 1 (the protocol
/// "none" default) and clear of the standard values 2 (`NetworkAccountTarget`) and 3 (`Pswap`).
/// Scheme 4 carries the DepositIntent preimage; scheme 5 carries the attestation.
const XUSDC_MINT_INTENT_ATTACHMENT_SCHEME: u16 = 4;
const XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME: u16 = 5;

/// The attestation attachment word count: [feeAmount(8), pubkey(16), signature(17), pad(3)]
/// = 44 felts = 11 words (unchanged from the pre-slice transport).
const XUSDC_MINT_ATTESTATION_NUM_WORDS: usize = 11;

// EXPECTED NEW-POSTURE ERRORS (byte-frozen here first; the MASM must declare these exact strings)
// ================================================================================================

/// The assert-match binding: the note-supplied output-note RECIPIENT must equal the P2ID recipe
/// derived from the attested DepositIntent (target = remoteRecipient, serial = nonce key).
fn err_mint_recipient_mismatch() -> MasmError {
    MasmError::from_static_str("mint note recipient does not match the attested deposit intent")
}

/// The reworked min-burn admin note's zero-floor guard (asserted BEFORE the stock
/// `set_min_burn_amount` is called — the stock setter itself accepts 0).
fn err_min_burn_below_floor() -> MasmError {
    MasmError::from_static_str("minimum burn size must be at least one")
}

// SHARED FIXTURE VALUES (the mint_scale_conformance conventions)
// ================================================================================================

const BASE_VECTOR: &str = "di-pos-empty-hookdata";
const MAX_SUPPLY: u64 = 1_000_000_000_000;
const MINT_AMOUNT: u64 = 250_000_000;
const MAX_FEE_RAW: u64 = 1;
const MIN_BURN_VALID: u64 = 5;

/// First byte of the 32-byte `remoteRecipient` field (felt 19 x 4 bytes; DC-1).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// First byte of the 32-byte `remoteToken` field (felt 11 x 4 bytes; DC-1).
const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;
/// First byte of the 32-byte `nonce` field (felt 51 x 4 bytes; DC-1).
const NONCE_BYTE_OFF: usize = 51 * 4;

fn owner() -> AccountId {
    test_account_id(1)
}

fn di(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

/// The canonical accept payload with the wire amount / maxFee spliced in, `remoteRecipient`
/// replaced by the real recipient wallet, `remoteToken` bound to the faucet's own-id identifier
/// fixpoint (what D5a compares against), and one nonce byte perturbed per variant so each mint
/// consumes a fresh D5c nonce.
fn payload_for(
    recipient: AccountId,
    faucet_id: AccountId,
    amount: u64,
    nonce_variant: u8,
) -> Vec<u8> {
    let mut payload = di(BASE_VECTOR).bytes();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(amount));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(MAX_FEE_RAW));
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&account_id_to_bytes32(recipient));
    payload[REMOTE_TOKEN_BYTE_OFF..REMOTE_TOKEN_BYTE_OFF + 32]
        .copy_from_slice(&account_id_to_bytes32(faucet_id));
    payload[NONCE_BYTE_OFF] ^= nonce_variant;
    payload
}

/// The usedNonces key (== the attested output-note serial) for a payload's nonce bytes.
fn nonce_key_of_payload(payload: &[u8]) -> Word {
    let nonce: [u8; 32] = payload[NONCE_BYTE_OFF..NONCE_BYTE_OFF + 32]
        .try_into()
        .expect("32 nonce bytes");
    Word::from(bytes32_to_storage_map_key(&nonce))
}

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]))
}

fn marker() -> Word {
    Word::from([1u32, 0, 0, 0])
}

// COMPONENT-SET INSPECTION HELPERS (the basic_asset_tripwire pattern)
// ================================================================================================

fn find_slot<'a>(
    components: &'a [AccountComponent],
    name: &StorageSlotName,
) -> Option<&'a StorageSlot> {
    components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|s| s.name() == name)
}

fn map_slot<'a>(
    components: &'a [AccountComponent],
    name: &StorageSlotName,
) -> Result<&'a miden_protocol::account::StorageMap> {
    let slot = find_slot(components, name)
        .with_context(|| format!("the policy manager must register the '{name}' slot"))?;
    match slot.content() {
        StorageSlotContent::Map(map) => Ok(map),
        StorageSlotContent::Value(_) => anyhow::bail!("'{name}' must be a MAP slot"),
    }
}

fn value_slot(components: &[AccountComponent], name: &StorageSlotName) -> Result<Word> {
    let slot = find_slot(components, name)
        .with_context(|| format!("the composition must register the '{name}' slot"))?;
    match slot.content() {
        StorageSlotContent::Value(v) => Ok(*v),
        StorageSlotContent::Map(_) => anyhow::bail!("'{name}' must be a VALUE slot"),
    }
}

/// Resolves a library-path procedure root across the composed component set.
fn resolve_proc_root(components: &[AccountComponent], path: &str) -> Option<Word> {
    components
        .iter()
        .find_map(|c| c.get_procedure_root_by_path(path))
        .map(Word::from)
}

fn shipped_masm_path(rel: &str) -> std::path::PathBuf {
    xusdc_encoding::xreserve_asm_dir().join(rel)
}

fn shipped_note_masm_path(file: &str) -> std::path::PathBuf {
    xusdc_encoding::xreserve_asm_dir()
        .parent()
        .expect("asm/standards/xreserve has a parent")
        .join("notes")
        .join(file)
}

// 1 — POSTURE: the attestation policy IS the active mint policy (INV-MINT-SECURITY restated)
// ================================================================================================

/// TRIPWIRE: the production composition's ACTIVE mint policy resolves to the attestation policy
/// (`xreserve::mint_policy::check_policy`) installed on the xreserve component — every supply
/// increase passes the attestation gate.
#[test]
fn active_mint_policy_is_the_attestation_policy() -> Result<()> {
    let components = production_component_set(MAX_SUPPLY, 0)?;
    let attestation_root = resolve_proc_root(&components, ATTESTATION_MINT_POLICY_PROC_PATH)
        .context(
        "the composed set must carry the attestation mint policy (xreserve::mint_policy::check_policy)",
    )?;
    let active = value_slot(&components, TokenPolicyManager::active_mint_policy_slot())?;
    assert_eq!(
        active, attestation_root,
        "the ACTIVE mint policy slot must hold the attestation policy root (INV-MINT-SECURITY: \
         every supply increase passes the attestation policy)"
    );
    Ok(())
}

/// TRIPWIRE: the allowed-mint-policy map is EXACTLY {the attestation policy root} — no reserved
/// alternate mint policy exists, so the attestation gate can never be swapped out at runtime.
#[test]
fn allowed_mint_policy_map_is_exactly_the_attestation_root() -> Result<()> {
    let components = production_component_set(MAX_SUPPLY, 0)?;
    let attestation_root = resolve_proc_root(&components, ATTESTATION_MINT_POLICY_PROC_PATH)
        .context("the composed set must carry the attestation mint policy")?;
    let map = map_slot(
        &components,
        TokenPolicyManager::allowed_mint_policies_slot(),
    )?;
    assert_eq!(
        map.num_entries(),
        1,
        "the allowed-mint map must carry EXACTLY one root (the attestation policy) — a superset \
         would leave a runtime path to a weaker mint policy"
    );
    let flag = map.get(&StorageMapKey::new(attestation_root));
    assert_ne!(
        flag,
        Word::empty(),
        "the allowed-mint map's single entry must be the attestation policy root"
    );
    Ok(())
}

/// TRIPWIRE: a build whose active mint policy is NOT the attestation policy CANNOT exist — the
/// builder rejects it (the mutation-test half of the restated INV-MINT-SECURITY).
#[test]
fn builder_rejects_a_non_attestation_mint_policy() -> Result<()> {
    let err = production_component_set_with_policy_override(MAX_SUPPLY, 0, MintPolicy::allow_all())
        .err()
        .context(
            "a build with MintPolicy::allow_all() as the active mint policy MUST be rejected",
        )?;
    assert!(
        err.to_string().to_lowercase().contains("attestation"),
        "the rejection must name the missing attestation mint policy, got: {err}"
    );
    Ok(())
}

/// TRIPWIRE: the mint-deny guard is fully dissolved — its module resolves nowhere in the
/// composition and its source file is gone (its job dissolved: the stock path IS the gated path).
#[test]
fn mint_deny_guard_is_fully_dissolved() -> Result<()> {
    let components = production_component_set(MAX_SUPPLY, 0)?;
    assert!(
        resolve_proc_root(&components, FORMER_MINT_DENY_GUARD_PROC_PATH).is_none(),
        "the mint-deny guard must not resolve anywhere in the composed set"
    );
    assert!(
        !shipped_masm_path("mint_deny_guard.masm").exists(),
        "asm/standards/xreserve/mint_deny_guard.masm must be deleted"
    );
    Ok(())
}

// 2 — POSTURE: the custom mint transport deletes; the attestation policy + identifier init land
// ================================================================================================

/// TRIPWIRE: the custom mint transport MASM is deleted and the attestation mint policy module is
/// its replacement (the deletion ledger, executable).
#[test]
fn custom_mint_transport_masm_is_deleted() -> Result<()> {
    for gone in [
        "xreserve_mint.masm",
        "xreserve_mint_note_entry.masm",
        "mint_deny_guard.masm",
    ] {
        assert!(
            !shipped_masm_path(gone).exists(),
            "asm/standards/xreserve/{gone} must be deleted by the recomposition"
        );
    }
    assert!(
        !shipped_note_masm_path("xreserve_mint_note.masm").exists(),
        "the custom mint note script must be deleted (the stock MintNote is the transport)"
    );
    assert!(
        shipped_masm_path("mint_policy.masm").exists(),
        "asm/standards/xreserve/mint_policy.masm (the attestation mint policy) must exist"
    );
    Ok(())
}

/// TRIPWIRE: the legacy config/burn admin MASM is replaced — `domain_config`/`min_burn_admin`/
/// `burn_policy` delete; the minimized `identifier_init` module + note land (DEC-4: the
/// identifier is a provable fixpoint of the account id, so ONLY it gets an init note; the other
/// three domain-config fields are build-seeded).
#[test]
fn legacy_config_and_burn_masm_are_replaced() -> Result<()> {
    for gone in [
        "domain_config.masm",
        "min_burn_admin.masm",
        "burn_policy.masm",
    ] {
        assert!(
            !shipped_masm_path(gone).exists(),
            "asm/standards/xreserve/{gone} must be deleted by the recomposition"
        );
    }
    assert!(
        shipped_masm_path("identifier_init.masm").exists(),
        "asm/standards/xreserve/identifier_init.masm (the minimized init surface) must exist"
    );
    assert!(
        !shipped_note_masm_path("xreserve_domain_init_note.masm").exists(),
        "the four-field domain_init note script must be deleted"
    );
    assert!(
        shipped_note_masm_path("xreserve_identifier_init_note.masm").exists(),
        "the identifier-only init note script must exist"
    );
    Ok(())
}

// 3 — POSTURE: the burn side is the stock MinBurnAmount with the zero floor preserved
// ================================================================================================

/// TRIPWIRE: the ACTIVE burn policy is the STOCK `MinBurnAmount` (allowed-map exactly that one
/// root) and its floor slot ships seeded `>= 1` — the R-BURN-1 zero-burn invariant preserved by
/// construction (`amount >= min >= 1`).
#[test]
fn burn_policy_is_stock_min_burn_amount_with_a_positive_floor() -> Result<()> {
    let components = production_component_set(MAX_SUPPLY, 0)?;
    let active = value_slot(&components, TokenPolicyManager::active_burn_policy_slot())?;
    assert_eq!(
        active,
        MinBurnAmount::root().as_word(),
        "the ACTIVE burn policy slot must hold the stock MinBurnAmount root"
    );
    let map = map_slot(
        &components,
        TokenPolicyManager::allowed_burn_policies_slot(),
    )?;
    assert_eq!(
        map.num_entries(),
        1,
        "the allowed-burn map must carry EXACTLY the one MinBurnAmount root"
    );
    let floor = value_slot(&components, MinBurnAmount::slot_name())?;
    assert!(
        floor[0].as_canonical_u64() >= 1,
        "the MinBurnAmount floor slot must ship >= 1 (zero-floor invariant), got {floor}"
    );
    assert_eq!(
        Word::from([
            floor[0],
            Felt::from(0u32),
            Felt::from(0u32),
            Felt::from(0u32)
        ]),
        floor,
        "the floor slot layout is [min_burn_amount, 0, 0, 0]"
    );
    Ok(())
}

/// TRIPWIRE: the builder REJECTS `min_burn_size < 1` at build time (the build-side half of the
/// zero-floor guard).
#[test]
fn builder_rejects_a_zero_min_burn_floor() -> Result<()> {
    let err = production_component_set_with_min_burn(MAX_SUPPLY, 0, Some(0))
        .err()
        .context("a build with min_burn_size = 0 MUST be rejected (zero-floor invariant)")?;
    assert!(
        err.to_string().to_lowercase().contains("min"),
        "the rejection must name the min-burn floor, got: {err}"
    );
    Ok(())
}

/// TRIPWIRE: the min-burn admin note script targets the STOCK `set_min_burn_amount` and carries
/// the note-side zero-floor assert (the runtime half of the guard; the stock setter itself
/// accepts 0, so the note MUST reject it first).
#[test]
fn min_burn_note_targets_the_stock_setter_with_a_floor_guard() -> Result<()> {
    let src = std::fs::read_to_string(shipped_note_masm_path(
        "xreserve_set_min_burn_size_note.masm",
    ))
    .context("reading the shipped set_min_burn_size note script")?;
    assert!(
        src.contains("call.min_burn_amount::set_min_burn_amount"),
        "the min-burn admin note must call the STOCK set_min_burn_amount account procedure"
    );
    assert!(
        src.contains("ERR_XRESERVE_MIN_BURN_BELOW_FLOOR"),
        "the min-burn admin note must declare the zero-floor guard error"
    );
    assert!(
        !src.contains("min_burn_admin::set_min_burn_size"),
        "the custom min_burn_admin target is deleted — the note must not reference it"
    );
    Ok(())
}

// 4 — POSTURE: the note-script allowlist pins the stock MintNote (row 1 re-materialized)
// ================================================================================================

/// TRIPWIRE: the frozen 14-root allowlist's mint row is the STOCK `MintNote::script_root()`; the
/// former custom mint-note root is gone.
#[test]
fn note_allowlist_pins_the_stock_mint_note() -> Result<()> {
    let allowlist =
        xusdc_encoding::account::xreserve::XReserveStablecoinBuilder::allowed_note_scripts();
    assert_eq!(allowlist.len(), 14, "the ratified allowlist stays 14 rows");
    assert!(
        allowlist.contains(&MintNote::script_root()),
        "row 1 must be the STOCK miden-standards MintNote script root"
    );
    let former = miden_protocol::note::NoteScriptRoot::from_raw(
        Word::parse(FORMER_CUSTOM_MINT_NOTE_ROOT_HEX).expect("pinned former root hex parses"),
    );
    assert!(
        !allowlist.contains(&former),
        "the former custom XReserveMintNote root must be REMOVED from the allowlist"
    );
    Ok(())
}

// 5 — E2E: the stock MintNote transport mints the attested amount (the recomposed happy path)
// ================================================================================================

/// The production-faucet fixture brought up through the admin surface (attester allowlisted,
/// the identifier seeded by the minimized init note — domain/source_domain/xreserve_contract are
/// BUILD-SEEDED by the production fixture, DEC-4), returning the fixture ready to mint. The
/// bring-up drives the recomposed admin surface; the e2e assertions below are the fixed contract.
fn fixture() -> Result<ProductionFaucet> {
    setup_production_faucet(MAX_SUPPLY, 0, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, faucet_id, MINT_AMOUNT, 0)).commitment;
        vec![
            XReserveIdentifierInitNote::create(owner(), faucet_id, &mut note_rng(951))
                .expect("building the owner identifier_init note"),
            XReserveSetAttesterNote::create(owner(), faucet_id, commitment, 1, &mut note_rng(952))
                .expect("building the owner set_attester note"),
        ]
    })
}

/// Consumes the seeded admin notes, committing a block each (the production bring-up path).
async fn bring_up(pf: &mut ProductionFaucet) -> Result<()> {
    for (i, note) in pf.seeded_notes.clone().iter().enumerate() {
        let tx = pf
            .mock_chain
            .build_tx_context(pf.faucet_id, &[note.id()], &[])
            .with_context(|| format!("bring-up note {i}: tx context"))?
            .build()
            .with_context(|| format!("bring-up note {i}: tx build"))?
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("bring-up note {i} must succeed: {e}"))?;
        pf.mock_chain.add_pending_executed_transaction(&tx)?;
        pf.mock_chain.prove_next_block()?;
    }
    Ok(())
}

/// The DepositIntent preimage as a scheme-4 attachment: the u32-LE packed felts, zero-padded to
/// the word boundary (the attachment content is word-granular; the on-chain policy re-derives the
/// exact felt length from the embedded hookDataLen and binds it to the committed word count).
fn intent_attachment(payload: &[u8]) -> Result<NoteAttachment> {
    let mut felts = deposit_intent_to_packed_felts(payload)
        .map_err(|e| anyhow::anyhow!("packing the deposit intent: {e}"))?;
    while felts.len() % 4 != 0 {
        felts.push(Felt::from(0u32));
    }
    let words: Vec<Word> = felts
        .chunks_exact(4)
        .map(|c| Word::from([c[0], c[1], c[2], c[3]]))
        .collect();
    NoteAttachment::with_words(
        NoteAttachmentScheme::new(XUSDC_MINT_INTENT_ATTACHMENT_SCHEME).expect("scheme 4 is valid"),
        words,
    )
    .map_err(|e| anyhow::anyhow!("building the intent attachment: {e}"))
}

/// The attestation as a scheme-5 attachment: [feeAmount(8), pubkey(16), signature(17), pad(3)]
/// = 11 words, the frozen advice order the D5b/D5d stages consume.
fn attestation_attachment(
    fee_limbs: [Felt; 8],
    attester: &AttesterVector,
) -> Result<NoteAttachment> {
    let mut felts: Vec<Felt> = fee_limbs.to_vec();
    felts.extend(attester.pubkey_felts.iter().copied());
    felts.extend(attester.sig_felts.iter().copied());
    felts.extend([Felt::from(0u32); 3]);
    let words: Vec<Word> = felts
        .chunks_exact(4)
        .map(|c| Word::from([c[0], c[1], c[2], c[3]]))
        .collect();
    assert_eq!(words.len(), XUSDC_MINT_ATTESTATION_NUM_WORDS);
    NoteAttachment::with_words(
        NoteAttachmentScheme::new(XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME)
            .expect("scheme 5 is valid"),
        words,
    )
    .map_err(|e| anyhow::anyhow!("building the attestation attachment: {e}"))
}

/// The 8 zero limbs of the MVP feeAmount.
fn zero_fee_limbs() -> [Felt; 8] {
    [Felt::from(0u32); 8]
}

/// The packed limbs of a NONZERO uint256 feeAmount (the fee != 0 negative).
fn fee_limbs_of(fee: u64) -> [Felt; 8] {
    bytes_to_packed_u32_elements(&uint256_be(fee))
        .try_into()
        .expect("a uint256 packs to exactly 8 limbs")
}

/// Builds the recomposed transport: a STOCK `MintNote` (public fungible storage: P2ID recipe with
/// serial = the attested nonce key, asset = the attested amount for THIS faucet, tag = the
/// attested recipient's account target) carrying the intent (scheme 4) + attestation (scheme 5) +
/// `NetworkAccountTarget` (scheme 2) attachments. `storage_recipient` lets the binding negatives
/// embed a recipe the attestation does NOT cover.
fn stock_mint_note(
    pf: &ProductionFaucet,
    payload: &[u8],
    storage_recipient: AccountId,
    fee_limbs: [Felt; 8],
    rng_seed: u64,
) -> Result<Note> {
    let amount = MINT_AMOUNT;
    let attester = gen_attester(1, payload);
    let serial = nonce_key_of_payload(payload);
    let recipient_recipe = P2idNoteStorage::new(storage_recipient).into_recipient(serial);
    let asset = FungibleAsset::new(pf.faucet_id, amount)
        .map_err(|e| anyhow::anyhow!("the attested amount is a valid fungible asset: {e}"))?;
    // the output-note tag always targets the ATTESTED recipient (so the binding negatives isolate
    // the RECIPIENT recipe mismatch, not a tag mismatch)
    let tag = NoteTag::with_account_target(pf.recipient_id);
    let storage = MintNoteStorage::new_fungible_public(recipient_recipe, asset, tag)
        .map_err(|e| anyhow::anyhow!("building the public fungible mint storage: {e}"))?;
    let mint_note = MintNote::builder()
        .sender(pf.producer_id)
        .mint_storage(storage)
        .serial_number(note_rng(rng_seed).draw_word())
        .attachment(intent_attachment(payload)?)
        .attachment(attestation_attachment(fee_limbs, &attester)?)
        .attachment(NoteAttachment::from(
            NetworkAccountTarget::new(pf.faucet_id, NoteExecutionHint::Always)
                .map_err(|e| anyhow::anyhow!("building the routing attachment: {e}"))?,
        ))
        .build()
        .map_err(|e| anyhow::anyhow!("building the stock mint note: {e}"))?;
    Ok(Note::from(mint_note))
}

/// Consumes a committed mint note on the faucet with NO tx script and NO consume-side advice —
/// the stock `MintNote` script -> `mint_and_send` -> attestation-policy transport.
async fn consume_mint_note(
    chain: &MockChain,
    faucet_id: AccountId,
    note_id: NoteId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    chain
        .build_tx_context(faucet_id, &[note_id], &[])
        .expect("building the consume tx context")
        .build()
        .expect("building the consume tx")
        .execute()
        .await
}

fn commit(chain: &mut MockChain, tx: &ExecutedTransaction) -> Result<()> {
    chain.add_pending_executed_transaction(tx)?;
    chain.prove_next_block()?;
    Ok(())
}

fn committed(chain: &MockChain, id: AccountId) -> Result<Account> {
    Ok(chain.committed_account(id)?.clone())
}

fn read_map_word(account: &Account, slot_label: &str, key: Word) -> Result<Word> {
    account
        .storage()
        .get_map_item(
            &StorageSlotName::new(slot_label)
                .with_context(|| format!("slot label {slot_label}"))?,
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading map slot {slot_label}: {e}"))
}

/// E2E: the stock `MintNote` carrying the attested transport mints EXACTLY the attested amount to
/// the attested recipient — one PUBLIC P2ID output note with the nonce-derived serial recipe, the
/// nonce marker set, and token_supply raised by the attested amount.
#[tokio::test]
async fn stock_mint_note_mints_the_attested_amount() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 1);
    let note = stock_mint_note(&pf, &payload, pf.recipient_id, zero_fee_limbs(), 71)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;

    let tx = consume_mint_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the recomposed attested mint must succeed: {e}"))?;

    // exactly one PUBLIC recipient note carrying the attested amount of THIS faucet's asset
    assert_eq!(
        tx.output_notes().num_notes(),
        1,
        "an attested mint emits exactly one recipient note"
    );
    let out = tx.output_notes().get_note(0);
    let asset = out
        .assets()
        .iter_fungible()
        .next()
        .context("the recipient note carries a fungible asset")?;
    assert_eq!(
        asset.faucet_id(),
        pf.faucet_id,
        "the asset is this faucet's"
    );
    assert_eq!(
        u64::from(asset.amount()),
        MINT_AMOUNT,
        "the minted amount is EXACTLY the attested wire amount (scale-0 identity)"
    );
    assert_eq!(
        out.metadata().note_type(),
        NoteType::Public,
        "the recipient note is Public"
    );
    assert_eq!(
        out.metadata().tag(),
        NoteTag::with_account_target(pf.recipient_id),
        "the recipient note is tagged for the attested recipient"
    );

    let mut chain = pf.mock_chain;
    commit(&mut chain, &tx)?;
    let faucet = committed(&chain, pf.faucet_id)?;
    assert_eq!(
        read_map_word(
            &faucet,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(&payload)
        )?,
        marker(),
        "the attested nonce must be marked used (the policy's nonce-ledger write)"
    );
    assert_eq!(
        committed_token_supply(&chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(MINT_AMOUNT)?,
        "token_supply rises by exactly the attested amount"
    );
    Ok(())
}

// 6 — E2E: the assert-match binding + the frozen fee/replay negatives through the new transport
// ================================================================================================

/// E2E NEGATIVE (the NEW binding): a mint note whose embedded output-note recipe targets an
/// account the attestation does NOT cover is rejected with the exact recipient-mismatch error —
/// the ratified ASSERT-MATCH binding (the policy never overrides; it keeps the note honest).
#[tokio::test]
async fn stock_mint_note_rejects_a_recipient_mismatch() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 2);
    // the recipe targets the PRODUCER; the attested intent targets the recipient wallet
    let note = stock_mint_note(&pf, &payload, pf.producer_id, zero_fee_limbs(), 72)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;

    let result = consume_mint_note(&pf.mock_chain, pf.faucet_id, note.id()).await;
    assert_transaction_executor_error!(result, &err_mint_recipient_mismatch());

    // fail-closed: no nonce burned, no supply raised
    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    assert_eq!(
        read_map_word(
            &faucet,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(&payload)
        )?,
        Word::empty(),
        "a rejected mint must not consume the nonce"
    );
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(0)?,
        "a rejected mint must not raise supply"
    );
    Ok(())
}

/// E2E NEGATIVE (DEC-2 keep-zero): a nonzero feeAmount in the attestation attachment trips the
/// frozen `ERR_XRESERVE_FEE_NONZERO` through the new transport.
#[tokio::test]
async fn stock_mint_note_rejects_a_nonzero_fee() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 3);
    let note = stock_mint_note(&pf, &payload, pf.recipient_id, fee_limbs_of(1), 73)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;

    let result = consume_mint_note(&pf.mock_chain, pf.faucet_id, note.id()).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_FEE_NONZERO"));
    Ok(())
}

/// E2E NEGATIVE (R-MINT-12): replaying an attested nonce through the new transport trips the
/// frozen `ERR_XRESERVE_NONCE_REPLAY` — the policy's nonce-ledger write is load-bearing.
#[tokio::test]
async fn stock_mint_note_rejects_a_replay() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 4);

    let first = stock_mint_note(&pf, &payload, pf.recipient_id, zero_fee_limbs(), 74)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &first).await?;
    let tx = consume_mint_note(&pf.mock_chain, pf.faucet_id, first.id())
        .await
        .map_err(|e| anyhow::anyhow!("the first attested mint must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;

    // the SAME payload (same nonce), a fresh note serial — the nonce ledger must reject it
    let replay = stock_mint_note(&pf, &payload, pf.recipient_id, zero_fee_limbs(), 75)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &replay).await?;
    let result = consume_mint_note(&pf.mock_chain, pf.faucet_id, replay.id()).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_NONCE_REPLAY"));
    Ok(())
}

// 7 — E2E: the reworked min-burn admin note enforces the floor at runtime
// ================================================================================================

/// E2E: the PRODUCTION min-burn admin note (retargeted at the stock `set_min_burn_amount`)
/// REJECTS `new_min = 0` with the exact floor error, and a valid `new_min >= 1` write lands in
/// the STOCK MinBurnAmount slot.
#[tokio::test]
async fn min_burn_note_rejects_a_zero_floor_at_runtime() -> Result<()> {
    let mut pf = setup_production_faucet(MAX_SUPPLY, 0, |_recipient, faucet_id| {
        vec![
            XReserveSetMinBurnSizeNote::create(owner(), faucet_id, 0, &mut note_rng(961))
                .expect("building the zero-floor min-burn note"),
            XReserveSetMinBurnSizeNote::create(
                owner(),
                faucet_id,
                MIN_BURN_VALID,
                &mut note_rng(962),
            )
            .expect("building the valid min-burn note"),
        ]
    })?;
    let zero_note = pf.seeded_notes[0].clone();
    let valid_note = pf.seeded_notes[1].clone();

    let result = consume_mint_note(&pf.mock_chain, pf.faucet_id, zero_note.id()).await;
    assert_transaction_executor_error!(result, &err_min_burn_below_floor());

    let tx = consume_mint_note(&pf.mock_chain, pf.faucet_id, valid_note.id())
        .await
        .map_err(|e| anyhow::anyhow!("a floor-respecting min-burn write must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;
    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    let floor = faucet
        .storage()
        .get_item(MinBurnAmount::slot_name())
        .map_err(|e| anyhow::anyhow!("reading the stock MinBurnAmount slot: {e}"))?;
    assert_eq!(
        floor,
        Word::from([
            Felt::from(u32::try_from(MIN_BURN_VALID).expect("test floor fits u32")),
            Felt::from(0u32),
            Felt::from(0u32),
            Felt::from(0u32)
        ]),
        "the reworked admin note writes the STOCK MinBurnAmount slot"
    );
    Ok(())
}
