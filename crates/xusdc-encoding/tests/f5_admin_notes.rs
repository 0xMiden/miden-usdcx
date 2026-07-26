//! F5 admin note scripts — layered-auth E2E under the production `AuthNetworkAccount`. Each shipped
//! admin note is allowlisted (so it PASSES network auth) and reads its params from note STORAGE
//! (never NOTE_ARGS); the sender-gated admin proc is the second layer. Reference op: `set_attester`
//! (row 3).
//!
//! EXCEPTION — `set_role_admin` (S21 disposition flip, human-ratified 2026-07-14): its runtime
//! note was REMOVED from the allowlist (the role-admin graph is build-seeded and frozen; rotation
//! is `grant_role`/`revoke_role`). Its section below consumes the PRESERVED former note and proves
//! the auth component now REJECTS it — negative coverage, not a driving suite.

mod support;

use core::slice;
use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    Account, AccountId, RoleSymbol, StorageMapKey, StorageSlotName, StorageSlotPatch,
};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachments, NoteRecipient, NoteScript, NoteScriptRoot,
    NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_testing::{assert_transaction_executor_error, MockChain};
use support::*;
use xusdc_encoding::account::xreserve::{DOM_MANAGER_ROLE, DOM_PAUSER_ROLE};
use xusdc_encoding::note::xreserve_admin::{
    XReserveAcceptOwnershipNote, XReserveBlockAccountNote, XReserveDomainInitNote,
    XReserveGrantRoleNote, XReservePauseNote, XReserveRevokeRoleNote, XReserveSetAttesterNote,
    XReserveSetMaxSupplyNote, XReserveSetMinBurnSizeNote, XReserveTransferOwnershipNote,
    XReserveUnblockAccountNote, XReserveUnpauseNote,
};

/// The exact stock role error the DOM_PAUSER gate traps (rbac.masm:50 ERR_SENDER_LACKS_ROLE).
/// Defined per-file (as in pause_admin.rs / role_admin.rs); not exported from the shared harness.
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

/// The exact stock RBAC delegation error (v0.16: rbac.masm:66 ERR_SENDER_NOT_ROLE_ADMIN — #3215
/// re-keyed the v15 ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN and dropped its owner leg).
fn err_not_role_admin() -> MasmError {
    // v16 #3215: the owner path is gone — the stock error re-keyed from
    // ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN to ERR_SENDER_NOT_ROLE_ADMIN (rbac.masm:66).
    MasmError::from_static_str("note sender does not hold the role's admin role")
}

fn pauser_sym() -> RoleSymbol {
    RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol")
}

fn manager_sym() -> RoleSymbol {
    RoleSymbol::new(DOM_MANAGER_ROLE).expect("DOM_MANAGER is a fixed valid role symbol")
}

/// The `[is_member,0,0,0]` / marker word.
fn member_marker() -> Word {
    Word::from([1u32, 0, 0, 0])
}

/// The standardized stock `is_paused` value slot label (installed by the base `Pausable`
/// component at v0.16 — #2944 moved it out of `FungibleFaucet`).
const IS_PAUSED_LABEL: &str = "miden::standards::access::pausable::is_paused";

const MAX_SUPPLY: u64 = 1_000_000;

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// The shipped `set_attester` admin note, consumed against the production network-auth faucet:
/// owner-sent SUCCEEDS and writes the attester marker at the creator-committed commitment key (the
/// storage-param marshaling is correct); a non-owner sender PASSES network auth (the script is
/// allowlisted) but TRAPS at the proc's owner gate — the layered-auth proof.
#[tokio::test]
async fn set_attester_admin_note_owner_writes_and_nonowner_traps() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    // setup_production_faucet seeds the owner as test_account_id(1).
    let owner = test_account_id(1);
    let commitment = gen_attester(1, b"attester").commitment;

    // Owner-sent: PASSES network auth (allowlisted) AND the proc owner gate — writes state.
    let note = XReserveSetAttesterNote::create(owner, faucet_id, commitment, 1, &mut note_rng(1))
        .context("building the owner set_attester note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("owner set_attester tx context")?
        .build()
        .context("owner set_attester tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("owner-sent set_attester must succeed under network auth: {e}")
        })?;

    // Marshaling correct: the account delta writes the enabled marker [1,0,0,0] at the CREATOR-
    // committed commitment key (a scrambled marshaling would write a different key).
    let attesters =
        StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL).context("attesters slot")?;
    let StorageSlotPatch::Map(delta) = tx
        .account_patch()
        .storage()
        .get(&attesters)
        .context("xReserveAttesters slot delta")?
    else {
        panic!("xReserveAttesters must be a Map slot delta");
    };
    let written = delta
        .entries()
        .expect("map patch carries entries")
        .as_map()
        .get(&StorageMapKey::new(commitment))
        .copied()
        .context("the commitment key must appear in the xReserveAttesters delta")?;
    assert_eq!(
        written,
        Word::from([1u32, 0, 0, 0]),
        "owner set_attester must write the enabled marker at the creator-committed commitment key \
         (storage-param marshaling correct)",
    );

    // Non-owner-sent: PASSES network auth (allowlisted script) but TRAPS at the proc owner gate.
    let bad = XReserveSetAttesterNote::create(
        test_account_id(9),
        faucet_id,
        commitment,
        0,
        &mut note_rng(2),
    )
    .context("building the non-owner set_attester note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&bad))
        .context("non-owner set_attester tx context")?
        .build()
        .context("non-owner set_attester tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    Ok(())
}

/// masm-rust-constant-parity: the compiled set_attester note-script root must equal the pinned
/// constant, so any edit to the script (or the proc it calls) forces a conscious re-pin.
#[test]
fn set_attester_note_script_root_is_pinned() {
    assert_eq!(
        XReserveSetAttesterNote::script_root(),
        XReserveSetAttesterNote::pinned_script_root(),
        "masm-rust-constant-parity: compiled set_attester note-script root == the pinned constant",
    );
}

// DOMAIN_INIT (allowlist row 12) — owner-gated, init-once config setter
// ================================================================================================

const DOMAIN: u32 = 7;
const SOURCE_DOMAIN: u32 = 3;

/// A distinct-bytes test `xreserve_contract` (mirrors `xreserve_mint_note.rs::test_xreserve_contract`).
fn xrc_bytes() -> [u8; 32] {
    core::array::from_fn(|i| 0x10 + i as u8)
}

/// A pre-hashed test identifier Word (stored verbatim by `domain_init`).
fn identifier() -> Word {
    Word::from([111u32, 222, 333, 444])
}

/// The five config words as `read_domain_config_words` returns them:
/// `[domain, source_domain, xrc_hi, xrc_lo, identifier]`.
fn expected_domain_config() -> [Word; 5] {
    let xrc = xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts(&xrc_bytes());
    [
        Word::from([
            Felt::from(DOMAIN),
            Felt::from(0u32),
            Felt::from(0u32),
            Felt::from(0u32),
        ]),
        Word::from([
            Felt::from(SOURCE_DOMAIN),
            Felt::from(0u32),
            Felt::from(0u32),
            Felt::from(0u32),
        ]),
        Word::from([xrc[0], xrc[1], xrc[2], xrc[3]]),
        Word::from([xrc[4], xrc[5], xrc[6], xrc[7]]),
        identifier(),
    ]
}

/// Reads a single value-slot's post-tx word from the account delta (the slot's new value).
fn value_delta(tx: &ExecutedTransaction, label: &str) -> Word {
    let slot = StorageSlotName::new(label).expect("valid slot label");
    match tx.account_patch().storage().get(&slot) {
        Some(StorageSlotPatch::Value(w)) => w.value().expect("value patch carries a value"),
        other => panic!("value slot {label} expected a value delta, got {other:?}"),
    }
}

/// Reads the FIVE config words from a tx's account delta, in the order
/// `[domain, source_domain, xrc_hi, xrc_lo, identifier]` (each is a value-slot write empty -> value).
fn domain_config_delta(tx: &ExecutedTransaction) -> [Word; 5] {
    [
        value_delta(tx, DOMAIN_CONFIG_SLOT_LABEL),
        value_delta(tx, SOURCE_DOMAIN_CONFIG_SLOT_LABEL),
        value_delta(tx, XRESERVE_CONTRACT_HI_SLOT_LABEL),
        value_delta(tx, XRESERVE_CONTRACT_LO_SLOT_LABEL),
        value_delta(tx, IDENTIFIER_CONFIG_SLOT_LABEL),
    ]
}

/// A single felt as its value-slot word `[f, 0, 0, 0]`.
fn scalar_word(f: Felt) -> Word {
    Word::from([f, Felt::from(0u32), Felt::from(0u32), Felt::from(0u32)])
}

/// Consumes `owner`'s domain_init note against a fresh production faucet, PASSING network auth
/// (allowlisted) AND the proc's owner gate, and writes all five config slots at the creator-
/// committed params (read back from the account delta — the storage-param marshaling is correct).
#[tokio::test]
async fn domain_init_owner_writes_all_five_config_slots() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let owner = test_account_id(1);

    let note = XReserveDomainInitNote::create(
        owner,
        faucet_id,
        DOMAIN,
        SOURCE_DOMAIN,
        &xrc_bytes(),
        identifier(),
        &mut note_rng(13),
    )
    .context("building the owner domain_init note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("owner domain_init tx context")?
        .build()
        .context("owner domain_init tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("owner-sent domain_init must succeed under network auth: {e}")
        })?;
    assert_eq!(
        domain_config_delta(&tx),
        expected_domain_config(),
        "owner domain_init must write all five §5.9 config slots at the creator-committed params",
    );
    Ok(())
}

/// A non-owner domain_init note PASSES network auth (allowlisted) but TRAPS at the proc's owner gate.
async fn assert_domain_init_nonowner_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = XReserveDomainInitNote::create(
        sender,
        faucet_id,
        DOMAIN,
        SOURCE_DOMAIN,
        &xrc_bytes(),
        identifier(),
        &mut note_rng(seed),
    )
    .context("building the non-owner domain_init note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("non-owner domain_init tx context")?
        .build()
        .context("non-owner domain_init tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    Ok(())
}

#[tokio::test]
async fn domain_init_dom_pauser_traps() -> Result<()> {
    assert_domain_init_nonowner_traps(test_account_id(2), 14).await
}

#[tokio::test]
async fn domain_init_third_party_traps() -> Result<()> {
    assert_domain_init_nonowner_traps(test_account_id(99), 15).await
}

/// init-once: a SECOND domain_init — even from the owner — traps `ERR_XRESERVE_DOMAIN_REINIT`. The
/// first init is SEEDED on-chain (block-provable) so the second sees initialized state. The seeded
/// note's routing target is a placeholder PUBLIC id (routing-only, not consume-gated; the script
/// root — hence the allowlist entry — is attachment-independent, so it still passes auth).
#[tokio::test]
async fn domain_init_reinit_traps_even_from_owner() -> Result<()> {
    let route = test_faucet_id(1);
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| {
        vec![XReserveDomainInitNote::create(
            test_account_id(1),
            route,
            DOMAIN,
            SOURCE_DOMAIN,
            &xrc_bytes(),
            identifier(),
            &mut note_rng(16),
        )
        .expect("building the seeded first domain_init note")]
    })
    .context("building the production faucet with a seeded first domain_init")?;
    let mut chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;

    for note in pf.seeded_notes.clone() {
        let tx = chain
            .build_tx_context(faucet_id, &[note.id()], &[])
            .context("first domain_init bring-up tx context")?
            .build()
            .context("first domain_init bring-up tx build")?
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("first domain_init bring-up must succeed: {e}"))?;
        chain.add_pending_executed_transaction(&tx)?;
        chain.prove_next_block()?;
    }

    let note2 = XReserveDomainInitNote::create(
        test_account_id(1),
        faucet_id,
        DOMAIN,
        SOURCE_DOMAIN,
        &xrc_bytes(),
        identifier(),
        &mut note_rng(17),
    )
    .context("building the second domain_init note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note2))
        .context("second domain_init tx context")?
        .build()
        .context("second domain_init tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_DOMAIN_REINIT"));
    Ok(())
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the written config (params
/// come from note storage, never NOTE_ARGS).
#[tokio::test]
async fn domain_init_note_args_are_inert() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let owner = test_account_id(1);

    let note = XReserveDomainInitNote::create(
        owner,
        faucet_id,
        DOMAIN,
        SOURCE_DOMAIN,
        &xrc_bytes(),
        identifier(),
        &mut note_rng(18),
    )
    .context("building the owner domain_init note")?;
    let bogus_args = Word::from([424_242u32, 7, 7, 7]);
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("domain_init note-args tx context")?
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("domain_init note-args tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("owner domain_init with bogus NOTE_ARGS must still succeed: {e}")
        })?;
    assert_eq!(
        domain_config_delta(&tx),
        expected_domain_config(),
        "domain_init must write the storage-committed params regardless of executor NOTE_ARGS",
    );
    Ok(())
}

/// masm-rust-constant-parity: the compiled domain_init note-script root must equal the pinned const.
#[test]
fn domain_init_note_script_root_is_pinned() {
    assert_eq!(
        XReserveDomainInitNote::script_root(),
        XReserveDomainInitNote::pinned_script_root(),
        "masm-rust-constant-parity: compiled domain_init note-script root == the pinned constant",
    );
}

// SET_MIN_BURN_SIZE (allowlist row 4) — owner-gated minBurnSize setter
// ================================================================================================

const NEW_MIN_BURN: u64 = 5_000;

fn expected_min_burn() -> Word {
    scalar_word(Felt::try_from(NEW_MIN_BURN).expect("min burn within the field"))
}

/// Owner-sent set_min_burn_size PASSES auth (allowlisted) + the proc owner gate and writes
/// `[new_min,0,0,0]` at `MIN_BURN_SIZE_SLOT`.
#[tokio::test]
async fn set_min_burn_size_owner_writes_slot() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let owner = test_account_id(1);

    let note =
        XReserveSetMinBurnSizeNote::create(owner, faucet_id, NEW_MIN_BURN, &mut note_rng(40))
            .context("building the owner set_min_burn_size note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("owner set_min_burn_size tx context")?
        .build()
        .context("owner set_min_burn_size tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("owner-sent set_min_burn_size must succeed under network auth: {e}")
        })?;
    assert_eq!(
        value_delta(&tx, MIN_BURN_SIZE_SLOT_LABEL),
        expected_min_burn(),
        "owner set_min_burn_size must write [new_min,0,0,0] at MIN_BURN_SIZE_SLOT",
    );
    Ok(())
}

/// A non-owner set_min_burn_size note PASSES auth but TRAPS at the proc's owner gate.
async fn assert_set_min_burn_nonowner_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note =
        XReserveSetMinBurnSizeNote::create(sender, faucet_id, NEW_MIN_BURN, &mut note_rng(seed))
            .context("building the non-owner set_min_burn_size note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("non-owner set_min_burn_size tx context")?
        .build()
        .context("non-owner set_min_burn_size tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    Ok(())
}

#[tokio::test]
async fn set_min_burn_size_dom_pauser_traps() -> Result<()> {
    assert_set_min_burn_nonowner_traps(test_account_id(2), 41).await
}

#[tokio::test]
async fn set_min_burn_size_dom_manager_traps() -> Result<()> {
    assert_set_min_burn_nonowner_traps(test_account_id(3), 42).await
}

#[tokio::test]
async fn set_min_burn_size_third_party_traps() -> Result<()> {
    assert_set_min_burn_nonowner_traps(test_account_id(99), 43).await
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the written min burn size.
#[tokio::test]
async fn set_min_burn_size_note_args_are_inert() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let owner = test_account_id(1);

    let note =
        XReserveSetMinBurnSizeNote::create(owner, faucet_id, NEW_MIN_BURN, &mut note_rng(44))
            .context("building the owner set_min_burn_size note")?;
    let bogus_args = Word::from([999u32, 1, 2, 3]);
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("set_min_burn_size note-args tx context")?
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("set_min_burn_size note-args tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("set_min_burn_size with bogus NOTE_ARGS must still succeed: {e}")
        })?;
    assert_eq!(
        value_delta(&tx, MIN_BURN_SIZE_SLOT_LABEL),
        expected_min_burn(),
        "set_min_burn_size must write the storage-committed param regardless of executor NOTE_ARGS",
    );
    Ok(())
}

/// masm-rust-constant-parity for the set_min_burn_size note (the failure prints the actual hex).
#[test]
fn set_min_burn_size_note_script_root_is_pinned() {
    let root = XReserveSetMinBurnSizeNote::script_root();
    assert_eq!(
        root,
        XReserveSetMinBurnSizeNote::pinned_script_root(),
        "masm-rust-constant-parity: set_min_burn_size note-script root == the pinned constant (actual = {})",
        root.to_hex(),
    );
}

// PAUSE (allowlist row 6) — DOM_PAUSER-gated emergency halt (owner has NO pause path)
// ================================================================================================

/// DOM_PAUSER-sent pause PASSES auth (allowlisted) + the proc's DOM_PAUSER gate and sets is_paused=1.
#[tokio::test]
async fn pause_dom_pauser_sets_is_paused() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;

    let note = XReservePauseNote::create(test_account_id(2), faucet_id, &mut note_rng(50))
        .context("building the DOM_PAUSER pause note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("DOM_PAUSER pause tx context")?
        .build()
        .context("DOM_PAUSER pause tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("DOM_PAUSER pause must succeed under network auth: {e}"))?;
    assert_eq!(
        value_delta(&tx, IS_PAUSED_LABEL),
        scalar_word(Felt::from(1u32)),
        "DOM_PAUSER pause must set is_paused = 1",
    );
    Ok(())
}

/// A non-DOM_PAUSER pause note PASSES auth but TRAPS at the proc's role gate — including the OWNER
/// (Circle model: the owner has NO pause path).
async fn assert_pause_nonpauser_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = XReservePauseNote::create(sender, faucet_id, &mut note_rng(seed))
        .context("building the non-pauser pause note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("non-pauser pause tx context")?
        .build()
        .context("non-pauser pause tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

#[tokio::test]
async fn pause_owner_traps() -> Result<()> {
    assert_pause_nonpauser_traps(test_account_id(1), 51).await
}

#[tokio::test]
async fn pause_third_party_traps() -> Result<()> {
    assert_pause_nonpauser_traps(test_account_id(99), 52).await
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the pause effect.
#[tokio::test]
async fn pause_note_args_are_inert() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;

    let note = XReservePauseNote::create(test_account_id(2), faucet_id, &mut note_rng(53))
        .context("building the DOM_PAUSER pause note")?;
    let bogus_args = Word::from([5u32, 5, 5, 5]);
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("pause note-args tx context")?
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("pause note-args tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("pause with bogus NOTE_ARGS must still succeed: {e}"))?;
    assert_eq!(
        value_delta(&tx, IS_PAUSED_LABEL),
        scalar_word(Felt::from(1u32)),
        "pause must set is_paused=1 regardless of executor NOTE_ARGS",
    );
    Ok(())
}

/// masm-rust-constant-parity for the pause note (the failure prints the actual hex).
#[test]
fn pause_note_script_root_is_pinned() {
    let root = XReservePauseNote::script_root();
    assert_eq!(
        root,
        XReservePauseNote::pinned_script_root(),
        "masm-rust-constant-parity: pause note-script root == the pinned constant (actual = {})",
        root.to_hex(),
    );
}

/// masm-rust-constant-parity for the F4-reversal block_account note (allowlist row 13). Binds
/// transitively to `blocklist_admin::block_account`'s digest — any edit of the note or the proc it
/// calls trips this and forces a conscious re-pin.
#[test]
fn block_account_note_script_root_is_pinned() {
    let root = XReserveBlockAccountNote::script_root();
    assert_eq!(
        root,
        XReserveBlockAccountNote::pinned_script_root(),
        "masm-rust-constant-parity: block_account note-script root == the pinned constant (actual = {})",
        root.to_hex(),
    );
}

/// masm-rust-constant-parity for the F4-reversal unblock_account note (allowlist row 14). Binds
/// transitively to `blocklist_admin::unblock_account`'s digest.
#[test]
fn unblock_account_note_script_root_is_pinned() {
    let root = XReserveUnblockAccountNote::script_root();
    assert_eq!(
        root,
        XReserveUnblockAccountNote::pinned_script_root(),
        "masm-rust-constant-parity: unblock_account note-script root == the pinned constant (actual = {})",
        root.to_hex(),
    );
}

// UNPAUSE (allowlist row 7) — DOM_PAUSER-gated resume
// ================================================================================================

/// A production faucet paused by a SEEDED DOM_PAUSER pause note (brought up on-chain), so an unpause
/// tx has a 1 -> 0 `is_paused` transition to observe. Placeholder PUBLIC routing target (routing-only).
async fn paused_faucet() -> Result<(MockChain, AccountId)> {
    let route = test_faucet_id(1);
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| {
        vec![
            XReservePauseNote::create(test_account_id(2), route, &mut note_rng(60))
                .expect("building the seeded pause note"),
        ]
    })
    .context("building the production faucet with a seeded pause")?;
    let mut chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    for note in pf.seeded_notes.clone() {
        let tx = chain
            .build_tx_context(faucet_id, &[note.id()], &[])
            .context("pause bring-up tx context")?
            .build()
            .context("pause bring-up tx build")?
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("pause bring-up must succeed: {e}"))?;
        chain.add_pending_executed_transaction(&tx)?;
        chain.prove_next_block()?;
    }
    Ok((chain, faucet_id))
}

/// DOM_PAUSER-sent unpause PASSES auth + the proc's DOM_PAUSER gate and clears is_paused to 0.
#[tokio::test]
async fn unpause_dom_pauser_clears_is_paused() -> Result<()> {
    let (chain, faucet_id) = paused_faucet().await?;
    let note = XReserveUnpauseNote::create(test_account_id(2), faucet_id, &mut note_rng(61))
        .context("building the DOM_PAUSER unpause note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("DOM_PAUSER unpause tx context")?
        .build()
        .context("DOM_PAUSER unpause tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("DOM_PAUSER unpause must succeed under network auth: {e}"))?;
    assert_eq!(
        value_delta(&tx, IS_PAUSED_LABEL),
        scalar_word(Felt::from(0u32)),
        "DOM_PAUSER unpause must clear is_paused to 0",
    );
    Ok(())
}

/// A non-DOM_PAUSER unpause note PASSES auth but TRAPS at the proc's role gate (owner included).
async fn assert_unpause_nonpauser_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = XReserveUnpauseNote::create(sender, faucet_id, &mut note_rng(seed))
        .context("building the non-pauser unpause note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("non-pauser unpause tx context")?
        .build()
        .context("non-pauser unpause tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

#[tokio::test]
async fn unpause_owner_traps() -> Result<()> {
    assert_unpause_nonpauser_traps(test_account_id(1), 62).await
}

#[tokio::test]
async fn unpause_third_party_traps() -> Result<()> {
    assert_unpause_nonpauser_traps(test_account_id(99), 63).await
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the unpause effect.
#[tokio::test]
async fn unpause_note_args_are_inert() -> Result<()> {
    let (chain, faucet_id) = paused_faucet().await?;
    let note = XReserveUnpauseNote::create(test_account_id(2), faucet_id, &mut note_rng(64))
        .context("building the DOM_PAUSER unpause note")?;
    let bogus_args = Word::from([8u32, 8, 8, 8]);
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("unpause note-args tx context")?
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("unpause note-args tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("unpause with bogus NOTE_ARGS must still succeed: {e}"))?;
    assert_eq!(
        value_delta(&tx, IS_PAUSED_LABEL),
        scalar_word(Felt::from(0u32)),
        "unpause must clear is_paused=0 regardless of executor NOTE_ARGS",
    );
    Ok(())
}

/// masm-rust-constant-parity for the unpause note (the failure prints the actual hex).
#[test]
fn unpause_note_script_root_is_pinned() {
    let root = XReserveUnpauseNote::script_root();
    assert_eq!(
        root,
        XReserveUnpauseNote::pinned_script_root(),
        "masm-rust-constant-parity: unpause note-script root == the pinned constant (actual = {})",
        root.to_hex(),
    );
}

// GRANT_ROLE (allowlist row 8) — STOCK RBAC grant (CANARY: a note calling a stock component proc)
// ================================================================================================

/// Authorized grant: `sender` grants DOM_PAUSER to id(4); the membership map is written. Proves the
/// note's absolute-path `call` resolves to the installed stock `rbac::grant_role` root (the canary).
async fn assert_grant_role_authorized(
    sender: AccountId,
    role: RoleSymbol,
    seed: u64,
) -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let grantee = test_account_id(4);
    let note = XReserveGrantRoleNote::create(
        sender,
        faucet_id,
        Felt::from(&role),
        grantee,
        &mut note_rng(seed),
    )
    .context("building the grant_role note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("grant_role tx context")?
        .build()
        .context("grant_role tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("authorized grant_role must succeed under network auth: {e}")
        })?;
    let mut evolved = chain
        .committed_account(faucet_id)
        .context("committed faucet")?
        .clone();
    evolved.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved, &role, grantee)?,
        member_marker(),
        "authorized grant_role must make id(4) a role member",
    );
    Ok(())
}

/// v16 #3215 (S2, operator-approved): the owner's role administration flows through its ADMIN
/// membership — it administers DOM_MANAGER (whose effective admin defaults to ADMIN), no longer
/// the delegated DOM_PAUSER.
#[tokio::test]
async fn grant_role_owner_authorized() -> Result<()> {
    assert_grant_role_authorized(test_account_id(1), manager_sym(), 70).await
}

#[tokio::test]
async fn grant_role_dom_manager_authorized() -> Result<()> {
    assert_grant_role_authorized(test_account_id(3), pauser_sym(), 71).await
}

/// v16 #3215 (S2): delegation is EXCLUSIVE — the owner (an ADMIN member, not a DOM_MANAGER
/// holder) can no longer grant the DOM_MANAGER-administered DOM_PAUSER; the delegation gate
/// traps it like any non-admin sender.
#[tokio::test]
async fn grant_role_owner_on_delegated_role_traps() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = XReserveGrantRoleNote::create(
        test_account_id(1),
        faucet_id,
        Felt::from(&pauser_sym()),
        test_account_id(4),
        &mut note_rng(73),
    )
    .context("building the owner grant-on-delegated-role note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("owner delegated-role grant tx context")?
        .build()
        .context("owner delegated-role grant tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_not_role_admin());
    Ok(())
}

/// A third party (neither owner nor DOM_MANAGER) PASSES auth but TRAPS at the delegation gate.
#[tokio::test]
async fn grant_role_third_party_traps() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = XReserveGrantRoleNote::create(
        test_account_id(99),
        faucet_id,
        Felt::from(&pauser_sym()),
        test_account_id(4),
        &mut note_rng(72),
    )
    .context("building the third-party grant_role note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("third-party grant_role tx context")?
        .build()
        .context("third-party grant_role tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_not_role_admin());
    Ok(())
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the granted membership.
#[tokio::test]
async fn grant_role_note_args_are_inert() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let grantee = test_account_id(5);
    // v16 #3215 (S2): DOM_PAUSER's effective admin is DOM_MANAGER — the grant is manager-sent.
    let note = XReserveGrantRoleNote::create(
        test_account_id(3),
        faucet_id,
        Felt::from(&pauser_sym()),
        grantee,
        &mut note_rng(73),
    )
    .context("building the owner grant_role note")?;
    let bogus_args = Word::from([7u32, 7, 7, 7]);
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("grant_role note-args tx context")?
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("grant_role note-args tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("grant_role with bogus NOTE_ARGS must still succeed: {e}"))?;
    let mut evolved = chain
        .committed_account(faucet_id)
        .context("committed faucet")?
        .clone();
    evolved.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), grantee)?,
        member_marker(),
        "grant_role must write the storage-committed member regardless of executor NOTE_ARGS",
    );
    Ok(())
}

/// masm-rust-constant-parity for the grant_role note (the failure prints the actual hex).
#[test]
fn grant_role_note_script_root_is_pinned() {
    let root = XReserveGrantRoleNote::script_root();
    assert_eq!(
        root,
        XReserveGrantRoleNote::pinned_script_root(),
        "masm-rust-constant-parity: grant_role note-script root == the pinned constant (actual = {})",
        root.to_hex(),
    );
}

// SET_MAX_SUPPLY (allowlist row 5) — owner-gated stock max-supply setter
// ================================================================================================

const NEW_MAX_SUPPLY: u64 = 2_000_000;

/// Owner-sent set_max_supply PASSES auth + the owner Authority gate (the production faucet is
/// max-supply-mutable + unpaused) and writes word[1] (max_supply) of the token_config slot.
#[tokio::test]
async fn set_max_supply_owner_writes_cap() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = XReserveSetMaxSupplyNote::create(
        test_account_id(1),
        faucet_id,
        NEW_MAX_SUPPLY,
        &mut note_rng(90),
    )
    .context("building the owner set_max_supply note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("owner set_max_supply tx context")?
        .build()
        .context("owner set_max_supply tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("owner-sent set_max_supply must succeed under network auth: {e}")
        })?;
    assert_eq!(
        value_delta(&tx, TOKEN_CONFIG_SLOT_LABEL)[1],
        Felt::try_from(NEW_MAX_SUPPLY).expect("cap within the field"),
        "owner set_max_supply must write word[1] = the new cap",
    );
    Ok(())
}

/// A non-owner set_max_supply note PASSES auth but TRAPS at the owner Authority gate.
async fn assert_set_max_supply_nonowner_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note =
        XReserveSetMaxSupplyNote::create(sender, faucet_id, NEW_MAX_SUPPLY, &mut note_rng(seed))
            .context("building the non-owner set_max_supply note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("non-owner set_max_supply tx context")?
        .build()
        .context("non-owner set_max_supply tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    Ok(())
}

#[tokio::test]
async fn set_max_supply_dom_pauser_traps() -> Result<()> {
    assert_set_max_supply_nonowner_traps(test_account_id(2), 91).await
}

#[tokio::test]
async fn set_max_supply_dom_manager_traps() -> Result<()> {
    assert_set_max_supply_nonowner_traps(test_account_id(3), 92).await
}

#[tokio::test]
async fn set_max_supply_third_party_traps() -> Result<()> {
    assert_set_max_supply_nonowner_traps(test_account_id(99), 93).await
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the written cap.
#[tokio::test]
async fn set_max_supply_note_args_are_inert() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = XReserveSetMaxSupplyNote::create(
        test_account_id(1),
        faucet_id,
        NEW_MAX_SUPPLY,
        &mut note_rng(94),
    )
    .context("building the owner set_max_supply note")?;
    let bogus_args = Word::from([3u32, 3, 3, 3]);
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("set_max_supply note-args tx context")?
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("set_max_supply note-args tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("set_max_supply with bogus NOTE_ARGS must still succeed: {e}")
        })?;
    assert_eq!(
        value_delta(&tx, TOKEN_CONFIG_SLOT_LABEL)[1],
        Felt::try_from(NEW_MAX_SUPPLY).expect("cap within the field"),
        "set_max_supply must write the storage-committed cap regardless of executor NOTE_ARGS",
    );
    Ok(())
}

/// masm-rust-constant-parity for the set_max_supply note (the failure prints the actual hex).
#[test]
fn set_max_supply_note_script_root_is_pinned() {
    let root = XReserveSetMaxSupplyNote::script_root();
    assert_eq!(
        root,
        XReserveSetMaxSupplyNote::pinned_script_root(),
        "masm-rust-constant-parity: set_max_supply note-script root == the pinned constant (actual = {})",
        root.to_hex(),
    );
}

// REVOKE_ROLE (allowlist row 9) — STOCK RBAC revoke (needs a prior grant)
// ================================================================================================

/// A production faucet where id(4) has been granted DOM_PAUSER by the owner, applied as a delta to an
/// evolved (not-committed) account. Returns (chain, faucet_id, evolved account, grantee).
async fn faucet_with_granted_role(
    role: RoleSymbol,
    grantor: AccountId,
    grant_seed: u64,
) -> Result<(MockChain, AccountId, Account, AccountId)> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let grantee = test_account_id(4);
    // v16 #3215 (S2): each role is seeded by its effective admin — DOM_PAUSER by the
    // DOM_MANAGER holder (delegated admin), DOM_MANAGER by the owner (ADMIN member).
    let grant = XReserveGrantRoleNote::create(
        grantor,
        faucet_id,
        Felt::from(&role),
        grantee,
        &mut note_rng(grant_seed),
    )
    .context("building the seeding grant note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&grant))
        .context("grant seed tx context")?
        .build()
        .context("grant seed tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("seeding the manager grant must succeed: {e}"))?;
    let mut evolved = chain
        .committed_account(faucet_id)
        .context("committed faucet")?
        .clone();
    evolved.apply_patch(tx.account_patch())?;
    Ok((chain, faucet_id, evolved, grantee))
}

/// Authorized revoke: `sender` (the role's v16 effective admin) revokes id(4)'s `role`
/// membership; membership cleared. v16 #3215 (S2): DOM_PAUSER revocation is DOM_MANAGER's
/// (delegated admin); DOM_MANAGER revocation is the owner's (ADMIN member).
async fn assert_revoke_authorized(
    sender: AccountId,
    role: RoleSymbol,
    grantor: AccountId,
    grant_seed: u64,
    revoke_seed: u64,
) -> Result<()> {
    let (chain, faucet_id, evolved, grantee) =
        faucet_with_granted_role(role.clone(), grantor, grant_seed).await?;
    let note = XReserveRevokeRoleNote::create(
        sender,
        faucet_id,
        Felt::from(&role),
        grantee,
        &mut note_rng(revoke_seed),
    )
    .context("building the revoke note")?;
    let tx = chain
        .build_tx_context(evolved.clone(), &[], slice::from_ref(&note))
        .context("authorized revoke tx context")?
        .build()
        .context("authorized revoke tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("authorized revoke must succeed under network auth: {e}"))?;
    let mut evolved2 = evolved.clone();
    evolved2.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved2, &role, grantee)?,
        Word::from([0u32, 0, 0, 0]),
        "authorized revoke must clear id(4)'s role membership",
    );
    Ok(())
}

/// v16 #3215 (S2): the owner (ADMIN member) administers DOM_MANAGER — grant seeded by the owner,
/// revoked by the owner.
#[tokio::test]
async fn revoke_role_owner_authorized() -> Result<()> {
    assert_revoke_authorized(
        test_account_id(1),
        manager_sym(),
        test_account_id(1),
        110,
        100,
    )
    .await
}

#[tokio::test]
async fn revoke_role_dom_manager_authorized() -> Result<()> {
    assert_revoke_authorized(
        test_account_id(3),
        pauser_sym(),
        test_account_id(3),
        111,
        101,
    )
    .await
}

/// A third party (neither owner nor DOM_MANAGER) PASSES auth but TRAPS at the delegation gate.
#[tokio::test]
async fn revoke_role_third_party_traps() -> Result<()> {
    let (chain, faucet_id, evolved, grantee) =
        faucet_with_granted_role(pauser_sym(), test_account_id(3), 112).await?;
    let note = XReserveRevokeRoleNote::create(
        test_account_id(99),
        faucet_id,
        Felt::from(&pauser_sym()),
        grantee,
        &mut note_rng(102),
    )
    .context("building the third-party revoke note")?;
    let result = chain
        .build_tx_context(evolved, &[], slice::from_ref(&note))
        .context("third-party revoke tx context")?
        .build()
        .context("third-party revoke tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_not_role_admin());
    Ok(())
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the revocation.
#[tokio::test]
async fn revoke_role_note_args_are_inert() -> Result<()> {
    let (chain, faucet_id, evolved, grantee) =
        faucet_with_granted_role(pauser_sym(), test_account_id(3), 113).await?;
    // v16 #3215 (S2): DOM_PAUSER's effective admin is DOM_MANAGER — the revoke is manager-sent.
    let note = XReserveRevokeRoleNote::create(
        test_account_id(3),
        faucet_id,
        Felt::from(&pauser_sym()),
        grantee,
        &mut note_rng(103),
    )
    .context("building the manager revoke note")?;
    let bogus_args = Word::from([6u32, 6, 6, 6]);
    let tx = chain
        .build_tx_context(evolved.clone(), &[], slice::from_ref(&note))
        .context("revoke note-args tx context")?
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("revoke note-args tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("revoke with bogus NOTE_ARGS must still succeed: {e}"))?;
    let mut evolved2 = evolved.clone();
    evolved2.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved2, &pauser_sym(), grantee)?,
        Word::from([0u32, 0, 0, 0]),
        "revoke must clear membership regardless of executor NOTE_ARGS",
    );
    Ok(())
}

/// masm-rust-constant-parity for the revoke_role note (the failure prints the actual hex).
#[test]
fn revoke_role_note_script_root_is_pinned() {
    let root = XReserveRevokeRoleNote::script_root();
    assert_eq!(
        root,
        XReserveRevokeRoleNote::pinned_script_root(),
        "masm-rust-constant-parity: revoke_role note-script root == the pinned constant (actual = {})",
        root.to_hex(),
    );
}

// SET_ROLE_ADMIN — REMOVED from the allowlist (S21 disposition flip, human-ratified 2026-07-14):
// the runtime re-delegation capability is structurally unreachable. The role-admin graph the
// faucet deploys with is the BUILD-TIME seed; rotation is grant_role/revoke_role (CIR-ADMIN-3).
// The FORMER production note script is preserved VERBATIM below as a negative-coverage fixture:
// these tests consume the exact removed note against the production network-auth faucet and prove
// the auth component now REJECTS it (`ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED`) — the same
// executing proof shape as `the_auth_component_rejects_a_non_allowlisted_note` (S12), specialized
// to the removed root. Membership/MAST-sweep legs: `account_callable_surface.rs`.
// ================================================================================================

/// The FORMER `xreserve_set_role_admin_note.masm` source, preserved verbatim from the removed
/// shipped file (git history: `asm/standards/notes/xreserve_set_role_admin_note.masm` before the
/// S21 removal) so the rejection tests below drive the EXACT root that used to be allowlist row 10.
/// It stages the creator-committed `[role_symbol, admin_role_symbol]` note storage and `call`s the
/// stock `rbac::set_role_admin` — which the account still exposes (present-but-unreachable).
const FORMER_SET_ROLE_ADMIN_NOTE_SCRIPT_SRC: &str = r#"# xreserve_set_role_admin_note — the shipped, root-pinned set_role_admin admin note script (F5).
#
# The production admin surface for the STOCK `set_role_admin` under the network account: a fixed-root
# note whose parameters are CREATOR-COMMITTED in note storage (never NOTE_ARGS). It stages the note
# storage into memory, marshals the creator's params onto the stack in the proc's Inputs order, and
# `call`s the stock `miden::standards::access::rbac::set_role_admin`. The `call` resolves to the SAME
# proc root the faucet exposes via the RBAC component re-exports. A scheme-2 NetworkAccountTarget
# routing attachment addresses the note at the faucet (routing-only).
#
# AUTHORIZATION (v0.16 — protocol #3215; MIGRATION-V16-ALPHA2.md S2/S21, the owner-only gate is
# GONE): the stock proc gates on the MANAGED ROLE's EFFECTIVE ADMIN — the role's configured
# delegated admin, else the built-in `ADMIN` role. On this faucet that means: re-delegating
# DOM_PAUSER (whose admin is DOM_MANAGER, the CMP-F5 seed) requires a DOM_MANAGER holder, while
# re-delegating DOM_MANAGER (admin unset -> ADMIN) requires an ADMIN member — the OWNER's account,
# which the builder seeds into ADMIN. The owner reaches DOM_PAUSER's delegation by first taking
# DOM_MANAGER (which it may, as the ADMIN member). The note sender is kernel-forced.
#
# Note storage layout (2 felts): [role_symbol, admin_role_symbol]. `admin_role_symbol = 0` clears the
# delegation (the managed role falls back to ADMIN-administered) — the stock sentinel.

use miden::protocol::active_note
use miden::standards::access::rbac
use miden::core::sys

# CONSTANTS
# =================================================================================================

const PARAM_PTR = 1024
const SET_ROLE_ADMIN_NOTE_NUM_ITEMS = 2

# ERRORS
# =================================================================================================

const ERR_XRESERVE_SET_ROLE_ADMIN_NOTE_STORAGE = "set_role_admin note storage item count is invalid"

# PUBLIC INTERFACE
# =================================================================================================

#! Consumes the `set_role_admin` admin note and drives the role-admin write (gated on the managed
#! role's effective admin — v0.16 #3215, see the module header).
#!
#! Stages the creator-committed params (`[role_symbol, admin_role_symbol]`) into memory at PARAM_PTR,
#! marshals them onto the stack as `[role_symbol, admin_role_symbol, pad(14)]`, and `call`s the stock
#! `rbac::set_role_admin`. The note ARGS are unused.
#!
#! Requires that the account exposes:
#! - miden::standards::access::rbac::set_role_admin procedure.
#!
#! Inputs:  [ARGS, pad(12)]
#! Outputs: [pad(16)]
#!
#! Note storage is assumed to be as follows:
#! - role_symbol is the RoleSymbol felt of the managed role (item 0).
#! - admin_role_symbol is the admin RoleSymbol felt (item 1); 0 clears the delegation (the stock
#!   sentinel).
#!
#! Panics if:
#! - the note storage does not carry exactly 2 items.
#! - the note sender does not hold the managed role's effective admin role
#!   (rbac::set_role_admin, ERR_SENDER_NOT_ROLE_ADMIN).
#!
#! Invocation: dyncall
@note_script
pub proc main
    dropw
    # => [pad(16)]

    push.PARAM_PTR exec.active_note::get_storage
    # => [num_items, pad(16)]

    eq.SET_ROLE_ADMIN_NOTE_NUM_ITEMS assert.err=ERR_XRESERVE_SET_ROLE_ADMIN_NOTE_STORAGE
    # => [pad(16)]

    push.PARAM_PTR add.1 mem_load
    push.PARAM_PTR mem_load
    # => [role_symbol, admin_role_symbol, pad(16)]
    # (the call consumes the top 16: [role_symbol, admin_role_symbol, pad(14)])

    call.rbac::set_role_admin
    # => [pad(16)]

    exec.sys::truncate_stack
end
"#;

/// The FORMER pinned `set_role_admin` note-script root (was
/// `XRESERVE_SET_ROLE_ADMIN_NOTE_SCRIPT_ROOT_HEX`). The fixture-integrity test below asserts the
/// preserved source still compiles to exactly this root, so the rejection tests provably drive the
/// removed production root — not a lookalike.
const FORMER_SET_ROLE_ADMIN_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x0c69fe1a19ee27196780be8d7815920e6a5da49e05ee10b9a615c4ee7a778648";

static FORMER_SET_ROLE_ADMIN_NOTE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    CodeBuilder::new()
        .compile_note_script(FORMER_SET_ROLE_ADMIN_NOTE_SCRIPT_SRC)
        .expect("the preserved former set_role_admin note script compiles")
});

/// Builds the FORMER `set_role_admin` admin note exactly as the removed
/// `XReserveSetRoleAdminNote::create` factory did: creator-committed
/// `[role_symbol, admin_role_symbol]` note storage, PUBLIC, faucet-tagged, empty assets, and the
/// scheme-2 `NetworkAccountTarget` routing attachment.
fn former_set_role_admin_note(
    sender: AccountId,
    faucet_id: AccountId,
    role_symbol: Felt,
    admin_role_symbol: Felt,
    rng: &mut RandomCoin,
) -> Result<Note> {
    let storage = NoteStorage::new(vec![role_symbol, admin_role_symbol])
        .context("the former set_role_admin note storage")?;
    let recipient = NoteRecipient::new(
        rng.draw_word(),
        FORMER_SET_ROLE_ADMIN_NOTE_SCRIPT.clone(),
        storage,
    );
    let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
        .with_tag(NoteTag::with_account_target(faucet_id));
    let target = NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always)
        .context("the faucet id is a public network account")?;
    let attachments = NoteAttachments::new(vec![NoteAttachment::from(target)])
        .context("the former set_role_admin note attachments")?;
    Ok(Note::with_attachments(
        NoteAssets::new(vec![]).context("empty note assets")?,
        metadata,
        recipient,
        attachments,
    ))
}

/// FIXTURE INTEGRITY (masm-rust-constant-parity, inverted): the PRESERVED former source still
/// compiles to the FORMER pinned root — so the rejection tests below demonstrably consume the
/// exact note the allowlist used to admit (a drifting fixture would silently weaken them to a
/// generic non-allowlisted probe).
#[test]
fn former_set_role_admin_note_script_still_compiles_to_the_former_root() {
    let root = FORMER_SET_ROLE_ADMIN_NOTE_SCRIPT.root();
    assert_eq!(
        root,
        NoteScriptRoot::from_raw(
            Word::parse(FORMER_SET_ROLE_ADMIN_NOTE_SCRIPT_ROOT_HEX)
                .expect("the former set_role_admin note-script root hex is a valid word"),
        ),
        "the preserved former set_role_admin note script must still compile to the former pinned \
         root (actual = {})",
        root.to_hex(),
    );
}

/// REJECTED (the S21 executing proof, formerly the owner-sent SUCCESS test): the exact former
/// set_role_admin note — owner-sent, well-formed, previously allowlist row 10 — now FAILS network
/// auth with the allowlist error. The note script itself EXECUTES (the allowlist is an epilogue
/// `@auth_script`) and the owner passes the ADMIN-role proc gate, so the rejection is attributable
/// ONLY to the removed allowlist membership; the committed delegation graph stays the build seed.
#[tokio::test]
async fn set_role_admin_note_is_rejected_as_non_allowlisted() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = former_set_role_admin_note(
        test_account_id(1),
        faucet_id,
        Felt::from(&manager_sym()),
        Felt::from(&pauser_sym()),
        &mut note_rng(120),
    )
    .context("building the former owner set_role_admin note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("owner set_role_admin tx context")?
        .build()
        .context("owner set_role_admin tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);

    // The committed role-admin graph is untouched: DOM_MANAGER stays ADMIN-administered (the
    // build seed), so the runtime graph is provably frozen.
    let committed = chain
        .committed_account(faucet_id)
        .context("committed faucet")?;
    assert_eq!(
        read_role_config(committed, &manager_sym())?[1],
        Felt::ZERO,
        "a rejected set_role_admin note must leave DOM_MANAGER's admin_role at the build seed \
         (ADMIN-administered)",
    );
    Ok(())
}

/// REJECTED regardless of executor NOTE_ARGS (formerly the NOTE_ARGS-inert SUCCESS test): a bogus
/// NOTE_ARGS word changes nothing — the former note still fails the allowlist check.
#[tokio::test]
async fn set_role_admin_note_is_rejected_regardless_of_note_args() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = former_set_role_admin_note(
        test_account_id(1),
        faucet_id,
        Felt::from(&manager_sym()),
        Felt::from(&pauser_sym()),
        &mut note_rng(123),
    )
    .context("building the former owner set_role_admin note")?;
    let bogus_args = Word::from([4u32, 4, 4, 4]);
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("set_role_admin note-args tx context")?
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("set_role_admin note-args tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);
    Ok(())
}

/// LAYER-ORDER pin (preserved negative coverage): a NON-admin-sent former set_role_admin note
/// still traps at the stock role-admin PROC gate — the note body executes BEFORE the epilogue
/// allowlist check, so the proc's own gate fires first (`ERR_SENDER_NOT_ROLE_ADMIN`). Identical
/// behavior before and after the S21 removal: the inner authorization layer never weakened.
async fn assert_set_role_admin_nonadmin_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = former_set_role_admin_note(
        sender,
        faucet_id,
        Felt::from(&manager_sym()),
        Felt::from(&pauser_sym()),
        &mut note_rng(seed),
    )
    .context("building the former non-admin set_role_admin note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("non-admin set_role_admin tx context")?
        .build()
        .context("non-admin set_role_admin tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_not_role_admin());
    Ok(())
}

#[tokio::test]
async fn set_role_admin_dom_manager_traps() -> Result<()> {
    assert_set_role_admin_nonadmin_traps(test_account_id(3), 121).await
}

#[tokio::test]
async fn set_role_admin_third_party_traps() -> Result<()> {
    assert_set_role_admin_nonadmin_traps(test_account_id(99), 122).await
}

// TRANSFER_OWNERSHIP (allowlist row 10) — current-owner-gated, step 1 of the 2-step transfer
// ================================================================================================

const OWNER_CONFIG_LABEL: &str = "miden::standards::access::ownable2step::owner_config";

/// The Ownable2Step `owner_config` word `[owner_suffix, owner_prefix, nominee_suffix, nominee_prefix]`.
fn owner_config_word(owner: AccountId, nominee: AccountId) -> Word {
    Word::from([
        owner.suffix(),
        owner.prefix().as_felt(),
        nominee.suffix(),
        nominee.prefix().as_felt(),
    ])
}

/// Owner-sent transfer_ownership PASSES auth + the owner gate and nominates id(5); the CURRENT owner
/// half is UNCHANGED (the 2-step invariant).
#[tokio::test]
async fn transfer_ownership_owner_nominates() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let new_owner = test_account_id(5);
    let note = XReserveTransferOwnershipNote::create(
        test_account_id(1),
        faucet_id,
        new_owner,
        &mut note_rng(130),
    )
    .context("building the owner transfer_ownership note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("owner transfer_ownership tx context")?
        .build()
        .context("owner transfer_ownership tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("owner-sent transfer_ownership must succeed under network auth: {e}")
        })?;
    assert_eq!(
        value_delta(&tx, OWNER_CONFIG_LABEL),
        owner_config_word(test_account_id(1), new_owner),
        "transfer_ownership must nominate id(5) with the owner half UNCHANGED (2-step)",
    );
    Ok(())
}

/// A non-owner transfer_ownership note PASSES auth but TRAPS at the owner gate.
async fn assert_transfer_ownership_nonowner_traps(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = XReserveTransferOwnershipNote::create(
        sender,
        faucet_id,
        test_account_id(5),
        &mut note_rng(seed),
    )
    .context("building the non-owner transfer_ownership note")?;
    let result = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("non-owner transfer_ownership tx context")?
        .build()
        .context("non-owner transfer_ownership tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    Ok(())
}

#[tokio::test]
async fn transfer_ownership_dom_pauser_traps() -> Result<()> {
    assert_transfer_ownership_nonowner_traps(test_account_id(2), 131).await
}

#[tokio::test]
async fn transfer_ownership_dom_manager_traps() -> Result<()> {
    assert_transfer_ownership_nonowner_traps(test_account_id(3), 132).await
}

#[tokio::test]
async fn transfer_ownership_third_party_traps() -> Result<()> {
    assert_transfer_ownership_nonowner_traps(test_account_id(99), 133).await
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the nomination.
#[tokio::test]
async fn transfer_ownership_note_args_are_inert() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let new_owner = test_account_id(5);
    let note = XReserveTransferOwnershipNote::create(
        test_account_id(1),
        faucet_id,
        new_owner,
        &mut note_rng(134),
    )
    .context("building the owner transfer_ownership note")?;
    let bogus_args = Word::from([2u32, 2, 2, 2]);
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("transfer_ownership note-args tx context")?
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("transfer_ownership note-args tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("transfer_ownership with bogus NOTE_ARGS must still succeed: {e}")
        })?;
    assert_eq!(
        value_delta(&tx, OWNER_CONFIG_LABEL),
        owner_config_word(test_account_id(1), new_owner),
        "transfer_ownership must nominate the storage-committed owner regardless of executor NOTE_ARGS",
    );
    Ok(())
}

/// masm-rust-constant-parity for the transfer_ownership note (the failure prints the actual hex).
#[test]
fn transfer_ownership_note_script_root_is_pinned() {
    let root = XReserveTransferOwnershipNote::script_root();
    assert_eq!(
        root,
        XReserveTransferOwnershipNote::pinned_script_root(),
        "masm-rust-constant-parity: transfer_ownership note-script root == the pinned constant (actual = {})",
        root.to_hex(),
    );
}

// ACCEPT_OWNERSHIP (allowlist row 11) — nominated-owner-gated, step 2 of the 2-step transfer
// ================================================================================================

/// The exact stock error accept_ownership traps for a non-nominated sender
/// (ownable2step.masm:39 ERR_SENDER_NOT_NOMINATED_OWNER). Defined locally (a stock error not in
/// SHELL_ERR_TABLE); no existing harness helper covers it.
fn err_sender_not_nominated_owner() -> MasmError {
    MasmError::from_static_str("note sender is not the nominated owner")
}

/// A production faucet with `nominee` set as the pending owner (an owner transfer_ownership applied as
/// a delta to an evolved, not-committed account). Returns (chain, faucet_id, evolved account).
async fn faucet_with_pending_owner(
    nominee: AccountId,
    transfer_seed: u64,
) -> Result<(MockChain, AccountId, Account)> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let transfer = XReserveTransferOwnershipNote::create(
        test_account_id(1),
        faucet_id,
        nominee,
        &mut note_rng(transfer_seed),
    )
    .context("building the owner transfer note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&transfer))
        .context("transfer seed tx context")?
        .build()
        .context("transfer seed tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("seeding the owner transfer must succeed: {e}"))?;
    let mut evolved = chain
        .committed_account(faucet_id)
        .context("committed faucet")?
        .clone();
    evolved.apply_patch(tx.account_patch())?;
    Ok((chain, faucet_id, evolved))
}

/// The post-accept owner_config: the nominee is promoted to owner, the nomination cleared to (0,0).
fn accepted_owner_config(nominee: AccountId) -> Word {
    Word::from([
        nominee.suffix(),
        nominee.prefix().as_felt(),
        Felt::from(0u32),
        Felt::from(0u32),
    ])
}

/// The nominated (pending) owner accepts: it PASSES auth + the pending-owner gate and becomes owner.
#[tokio::test]
async fn accept_ownership_pending_owner_becomes_owner() -> Result<()> {
    let nominee = test_account_id(5);
    let (chain, faucet_id, evolved) = faucet_with_pending_owner(nominee, 140).await?;
    let note = XReserveAcceptOwnershipNote::create(nominee, faucet_id, &mut note_rng(141))
        .context("building the pending-owner accept note")?;
    let tx = chain
        .build_tx_context(evolved.clone(), &[], slice::from_ref(&note))
        .context("accept_ownership tx context")?
        .build()
        .context("accept_ownership tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("pending-owner accept_ownership must succeed under network auth: {e}")
        })?;
    let mut evolved2 = evolved.clone();
    evolved2.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_owner_config(&evolved2)?,
        accepted_owner_config(nominee),
        "accept_ownership must promote the nominee to owner and clear the nomination",
    );
    Ok(())
}

/// A non-nominated sender (the current owner or a third party) PASSES auth but TRAPS at the
/// pending-owner gate.
async fn assert_accept_wrong_sender_traps(sender: AccountId, seed: u64) -> Result<()> {
    let nominee = test_account_id(5);
    let (chain, faucet_id, evolved) = faucet_with_pending_owner(nominee, 150 + seed).await?;
    let note = XReserveAcceptOwnershipNote::create(sender, faucet_id, &mut note_rng(seed))
        .context("building the wrong-sender accept note")?;
    let result = chain
        .build_tx_context(evolved, &[], slice::from_ref(&note))
        .context("wrong-sender accept tx context")?
        .build()
        .context("wrong-sender accept tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_sender_not_nominated_owner());
    Ok(())
}

#[tokio::test]
async fn accept_ownership_current_owner_traps() -> Result<()> {
    assert_accept_wrong_sender_traps(test_account_id(1), 142).await
}

#[tokio::test]
async fn accept_ownership_third_party_traps() -> Result<()> {
    assert_accept_wrong_sender_traps(test_account_id(99), 143).await
}

/// NOTE_ARGS-inert: an executor-supplied NOTE_ARGS word does NOT change the ownership promotion.
#[tokio::test]
async fn accept_ownership_note_args_are_inert() -> Result<()> {
    let nominee = test_account_id(5);
    let (chain, faucet_id, evolved) = faucet_with_pending_owner(nominee, 144).await?;
    let note = XReserveAcceptOwnershipNote::create(nominee, faucet_id, &mut note_rng(145))
        .context("building the pending-owner accept note")?;
    let bogus_args = Word::from([9u32, 9, 9, 9]);
    let tx = chain
        .build_tx_context(evolved.clone(), &[], slice::from_ref(&note))
        .context("accept note-args tx context")?
        .extend_note_args(BTreeMap::from([(note.id(), bogus_args)]))
        .build()
        .context("accept note-args tx build")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!("accept_ownership with bogus NOTE_ARGS must still succeed: {e}")
        })?;
    let mut evolved2 = evolved.clone();
    evolved2.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_owner_config(&evolved2)?,
        accepted_owner_config(nominee),
        "accept_ownership must promote the nominee regardless of executor NOTE_ARGS",
    );
    Ok(())
}

/// masm-rust-constant-parity for the accept_ownership note (the failure prints the actual hex).
#[test]
fn accept_ownership_note_script_root_is_pinned() {
    let root = XReserveAcceptOwnershipNote::script_root();
    assert_eq!(
        root,
        XReserveAcceptOwnershipNote::pinned_script_root(),
        "masm-rust-constant-parity: accept_ownership note-script root == the pinned constant (actual = {})",
        root.to_hex(),
    );
}
