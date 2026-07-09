//! F5 admin note scripts — layered-auth E2E under the production `AuthNetworkAccount` (Option A,
//! per-op red-before-green). Each shipped admin note is allowlisted (so it PASSES network auth) and
//! reads its params from note STORAGE (never NOTE_ARGS); the sender-gated admin proc is the second
//! layer. Reference op: `set_attester` (row 3).

mod support;

use core::slice;
use std::collections::BTreeMap;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{
    AccountId, RoleSymbol, StorageMapKey, StorageSlotDelta, StorageSlotName,
};
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_testing::{MockChain, assert_transaction_executor_error};
use support::*;
use xusdc_encoding::account::xreserve::{DOM_MANAGER_ROLE, DOM_PAUSER_ROLE};
use xusdc_encoding::note::xreserve_admin::{
    XReserveDomainInitNote, XReserveGrantRoleNote, XReservePauseNote, XReserveSetAttesterNote,
    XReserveSetMaxSupplyNote, XReserveSetMinBurnSizeNote, XReserveUnpauseNote,
};

/// The exact stock role error the DOM_PAUSER gate traps (rbac.masm:50 ERR_SENDER_LACKS_ROLE).
/// Defined per-file (as in pause_admin.rs / role_admin.rs); not exported from the shared harness.
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

/// The exact stock RBAC delegation error (rbac.masm:51 ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN).
fn err_not_owner_or_role_admin() -> MasmError {
    MasmError::from_static_str("note sender is not the owner or a role admin")
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

/// The standardized stock `is_paused` value slot label (FungibleFaucet-installed).
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
        .map_err(|e| anyhow::anyhow!("owner-sent set_attester must succeed under network auth: {e}"))?;

    // Marshaling correct: the account delta writes the enabled marker [1,0,0,0] at the CREATOR-
    // committed commitment key (a scrambled marshaling would write a different key).
    let attesters = StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL).context("attesters slot")?;
    let StorageSlotDelta::Map(delta) = tx
        .account_delta()
        .storage()
        .get(&attesters)
        .context("xReserveAttesters slot delta")?
    else {
        panic!("xReserveAttesters must be a Map slot delta");
    };
    let written = delta
        .entries()
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
    let bad = XReserveSetAttesterNote::create(test_account_id(9), faucet_id, commitment, 0, &mut note_rng(2))
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

// DOMAIN_INIT (allowlist row 13) — owner-gated, init-once §5.9 config setter
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

/// The five §5.9 config words as `read_domain_config_words` returns them:
/// `[domain, source_domain, xrc_hi, xrc_lo, identifier]`.
fn expected_domain_config() -> [Word; 5] {
    let xrc = xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts(&xrc_bytes());
    [
        Word::from([Felt::from(DOMAIN), Felt::from(0u32), Felt::from(0u32), Felt::from(0u32)]),
        Word::from([Felt::from(SOURCE_DOMAIN), Felt::from(0u32), Felt::from(0u32), Felt::from(0u32)]),
        Word::from([xrc[0], xrc[1], xrc[2], xrc[3]]),
        Word::from([xrc[4], xrc[5], xrc[6], xrc[7]]),
        identifier(),
    ]
}

/// Reads a single value-slot's post-tx word from the account delta (the slot's new value).
fn value_delta(tx: &ExecutedTransaction, label: &str) -> Word {
    let slot = StorageSlotName::new(label).expect("valid slot label");
    match tx.account_delta().storage().get(&slot) {
        Some(StorageSlotDelta::Value(w)) => *w,
        other => panic!("value slot {label} expected a value delta, got {other:?}"),
    }
}

/// Reads the FIVE §5.9 config words from a tx's account delta, in the order
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
/// (allowlisted) AND the proc's owner gate, and writes all five §5.9 config slots at the creator-
/// committed params (read back from the account delta — the storage-param marshaling is correct).
#[tokio::test]
async fn domain_init_owner_writes_all_five_config_slots() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let owner = test_account_id(1);

    let note = XReserveDomainInitNote::create(
        owner, faucet_id, DOMAIN, SOURCE_DOMAIN, &xrc_bytes(), identifier(), &mut note_rng(13),
    )
    .context("building the owner domain_init note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("owner domain_init tx context")?
        .build()
        .context("owner domain_init tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("owner-sent domain_init must succeed under network auth: {e}"))?;
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
        sender, faucet_id, DOMAIN, SOURCE_DOMAIN, &xrc_bytes(), identifier(), &mut note_rng(seed),
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
        vec![
            XReserveDomainInitNote::create(
                test_account_id(1), route, DOMAIN, SOURCE_DOMAIN, &xrc_bytes(), identifier(),
                &mut note_rng(16),
            )
            .expect("building the seeded first domain_init note"),
        ]
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
        test_account_id(1), faucet_id, DOMAIN, SOURCE_DOMAIN, &xrc_bytes(), identifier(),
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
        owner, faucet_id, DOMAIN, SOURCE_DOMAIN, &xrc_bytes(), identifier(), &mut note_rng(18),
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
        .map_err(|e| anyhow::anyhow!("owner domain_init with bogus NOTE_ARGS must still succeed: {e}"))?;
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

    let note = XReserveSetMinBurnSizeNote::create(owner, faucet_id, NEW_MIN_BURN, &mut note_rng(40))
        .context("building the owner set_min_burn_size note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("owner set_min_burn_size tx context")?
        .build()
        .context("owner set_min_burn_size tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("owner-sent set_min_burn_size must succeed under network auth: {e}"))?;
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
    let note = XReserveSetMinBurnSizeNote::create(sender, faucet_id, NEW_MIN_BURN, &mut note_rng(seed))
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

    let note = XReserveSetMinBurnSizeNote::create(owner, faucet_id, NEW_MIN_BURN, &mut note_rng(44))
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
        .map_err(|e| anyhow::anyhow!("set_min_burn_size with bogus NOTE_ARGS must still succeed: {e}"))?;
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
async fn assert_grant_role_authorized(sender: AccountId, seed: u64) -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let grantee = test_account_id(4);
    let note = XReserveGrantRoleNote::create(
        sender, faucet_id, Felt::from(&pauser_sym()), grantee, &mut note_rng(seed),
    )
    .context("building the grant_role note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("grant_role tx context")?
        .build()
        .context("grant_role tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("authorized grant_role must succeed under network auth: {e}"))?;
    let mut evolved = chain.committed_account(faucet_id).context("committed faucet")?.clone();
    evolved.apply_delta(tx.account_delta())?;
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), grantee)?,
        member_marker(),
        "authorized grant_role must make id(4) a DOM_PAUSER member",
    );
    Ok(())
}

#[tokio::test]
async fn grant_role_owner_authorized() -> Result<()> {
    assert_grant_role_authorized(test_account_id(1), 70).await
}

#[tokio::test]
async fn grant_role_dom_manager_authorized() -> Result<()> {
    assert_grant_role_authorized(test_account_id(3), 71).await
}

/// A third party (neither owner nor DOM_MANAGER) PASSES auth but TRAPS at the delegation gate.
#[tokio::test]
async fn grant_role_third_party_traps() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let note = XReserveGrantRoleNote::create(
        test_account_id(99), faucet_id, Felt::from(&pauser_sym()), test_account_id(4),
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
    assert_transaction_executor_error!(result, err_not_owner_or_role_admin());
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
    let note = XReserveGrantRoleNote::create(
        test_account_id(1), faucet_id, Felt::from(&pauser_sym()), grantee, &mut note_rng(73),
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
    let mut evolved = chain.committed_account(faucet_id).context("committed faucet")?.clone();
    evolved.apply_delta(tx.account_delta())?;
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
    let note = XReserveSetMaxSupplyNote::create(test_account_id(1), faucet_id, NEW_MAX_SUPPLY, &mut note_rng(90))
        .context("building the owner set_max_supply note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note))
        .context("owner set_max_supply tx context")?
        .build()
        .context("owner set_max_supply tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("owner-sent set_max_supply must succeed under network auth: {e}"))?;
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
    let note = XReserveSetMaxSupplyNote::create(sender, faucet_id, NEW_MAX_SUPPLY, &mut note_rng(seed))
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
    let note = XReserveSetMaxSupplyNote::create(test_account_id(1), faucet_id, NEW_MAX_SUPPLY, &mut note_rng(94))
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
        .map_err(|e| anyhow::anyhow!("set_max_supply with bogus NOTE_ARGS must still succeed: {e}"))?;
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
