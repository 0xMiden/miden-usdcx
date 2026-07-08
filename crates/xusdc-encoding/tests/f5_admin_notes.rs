//! F5 admin note scripts — layered-auth E2E under the production `AuthNetworkAccount` (Option A,
//! per-op red-before-green). Each shipped admin note is allowlisted (so it PASSES network auth) and
//! reads its params from note STORAGE (never NOTE_ARGS); the sender-gated admin proc is the second
//! layer. Reference op: `set_attester` (row 3).

mod support;

use core::slice;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{StorageMapKey, StorageSlotDelta, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;

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
