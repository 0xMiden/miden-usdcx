//! F5 admin note scripts — layered-auth E2E under the production `AuthNetworkAccount` (Option A,
//! per-op red-before-green). Each shipped admin note is allowlisted (so it PASSES network auth) and
//! reads its params from note STORAGE (never NOTE_ARGS); the sender-gated admin proc is the second
//! layer. Reference op: `set_attester` (row 3).

mod support;

use core::slice;
use std::collections::BTreeMap;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotDelta, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::note::xreserve_admin::{XReserveDomainInitNote, XReserveSetAttesterNote};

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

/// Consumes `owner`'s domain_init note against a fresh production faucet, PASSING network auth
/// (allowlisted) AND the proc's owner gate, and writes all five §5.9 config slots at the creator-
/// committed params (read back from the evolved account — the storage-param marshaling is correct).
#[tokio::test]
async fn domain_init_owner_writes_all_five_config_slots() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let mut chain = pf.mock_chain;
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
    chain.add_pending_executed_transaction(&tx)?;
    chain.prove_next_block()?;

    let account = chain.committed_account(faucet_id).context("evolved faucet account")?;
    assert_eq!(
        read_domain_config_words(&account)?,
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

/// init-once: a SECOND domain_init — even from the owner — traps `ERR_XRESERVE_DOMAIN_REINIT`.
#[tokio::test]
async fn domain_init_reinit_traps_even_from_owner() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let mut chain = pf.mock_chain;
    let faucet_id = pf.faucet_id;
    let owner = test_account_id(1);

    let note1 = XReserveDomainInitNote::create(
        owner, faucet_id, DOMAIN, SOURCE_DOMAIN, &xrc_bytes(), identifier(), &mut note_rng(16),
    )
    .context("building the first domain_init note")?;
    let tx = chain
        .build_tx_context(faucet_id, &[], slice::from_ref(&note1))
        .context("first domain_init tx context")?
        .build()
        .context("first domain_init tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("first domain_init must succeed: {e}"))?;
    chain.add_pending_executed_transaction(&tx)?;
    chain.prove_next_block()?;

    let note2 = XReserveDomainInitNote::create(
        owner, faucet_id, DOMAIN, SOURCE_DOMAIN, &xrc_bytes(), identifier(), &mut note_rng(17),
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
    let mut chain = pf.mock_chain;
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
    chain.add_pending_executed_transaction(&tx)?;
    chain.prove_next_block()?;

    let account = chain.committed_account(faucet_id).context("evolved faucet account")?;
    assert_eq!(
        read_domain_config_words(&account)?,
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
