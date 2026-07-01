//! P5-01 `set_attester` suite, reconciled to the Circle-faithful OWNER-gated model
//! (DECISION-ADMIN-ROLE-MODEL). The allowlist setter's MASM is UNCHANGED — it calls the account-wide
//! `authority::assert_authorized`, which after the reconciliation (`Authority::OwnerControlled`, the
//! built `ATTEST_ADMIN` role removed) resolves to the Ownable2Step owner. This file covers the owner
//! gate (the security core), the production-deny regression, and the pause gate. The non-vacuity
//! set->verify seam (`set_attester_enables_attestation`, remove-denies, and the 5-step rotation) lives
//! in `xreserve_mint.rs`, alongside the shared mint-composition fixtures it reuses. The DOM role SEED
//! itself is proven in `set_min_burn.rs` (`dom_roles_seeded_correctly`).

mod support;

use anyhow::Result;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotDelta, StorageSlotName};
use miden_protocol::errors::MasmError;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;

// The seeded principals the reconciled builder installs: owner = id(1) (Ownable2Step). DOM_PAUSER = id(2)
// is a seeded role-holder who is NOT the owner AND is the FORMER ATTEST_ADMIN holder — the owner-ONLY /
// ATTEST_ADMIN-removed non-owner sender.
fn owner() -> AccountId {
    test_account_id(1)
}
fn dom_holder() -> AccountId {
    test_account_id(2)
}

/// Config words the builder does not read (these tests invoke `set_attester` via a note, never the
/// mint driver).
fn dummy_config() -> (Word, Word) {
    (Word::from([7u32, 0, 0, 0]), Word::from([11u32, 12, 13, 14]))
}

/// A guarded production faucet (owner-gated, deny active) with a trivial driver/probe — the base for the
/// owner-gate tests. `attesters_seed = None` (empty allowlist).
fn guarded_faucet() -> Result<GuardedMint> {
    let driver = mint_composition_driver_src(&[Felt::from(0u32)], 60, 6);
    let probe = composition_supply_probe_src(0);
    let (domain, identifier) = dummy_config();
    setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        None,
        &driver,
        &probe,
        true,
    )
}

/// Reads the `xReserveAttesters` allowlist entry for `commitment` from a committed account (EMPTY_WORD
/// when unset) — the no-state-change read-back the non-owner reject uses.
fn read_attester(account: &miden_protocol::account::Account, commitment: Word) -> Result<Word> {
    let slot = StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)?;
    Ok(account.storage().get_map_item(&slot, commitment)?)
}

// EXPORT PROBE (green scaffold — D-1A flat-path check for the setter)
// ================================================================================================

#[test]
fn probe_attester_admin_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::attester_admin::set_attester";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical setter path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// PRODUCTION REGRESSION GATE — the owner-gated build must not perturb the R-MINT-16 deny path
// ================================================================================================

/// The owner-gated production builder still denies stock `mint_and_send` at the EXACT
/// ERR_XRESERVE_MINT_DENIED (mint execution is Authority-independent: policy_manager.masm:284-297).
#[tokio::test]
async fn production_build_still_denies_stock_mint() -> Result<()> {
    let gm = guarded_faucet()?;
    let result = run_mint_and_send(&gm.harness, Word::from([0u32, 1, 2, 3]), 0, 4, 100, 0).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_MINT_DENIED"));
    Ok(())
}

// OWNER GATE (the security core) — RED until the Authority is flipped to OwnerControlled (green)
// ================================================================================================

/// An OWNER-sent `set_attester(K, true)` note succeeds and the allowlist entry lands.
#[tokio::test]
async fn set_attester_owner_succeeds() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([10u32, 11, 12, 13]);

    let executed = run_set_attester_tx(&gm.harness, &account, owner(), commitment, 1, 7)
        .await
        .expect("the owner's set_attester(K, true) must succeed");

    // the allowlist entry landed: xReserveAttesters[K] == [1,0,0,0].
    let attesters = StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)?;
    let StorageSlotDelta::Map(delta) = executed
        .account_delta()
        .storage()
        .get(&attesters)
        .expect("xReserveAttesters slot delta")
    else {
        panic!("xReserveAttesters must be a Map slot delta");
    };
    let written = delta
        .entries()
        .get(&StorageMapKey::new(commitment))
        .copied()
        .expect("the commitment KEY must appear in the xReserveAttesters delta");
    assert_eq!(written, Word::from([1u32, 0, 0, 0]), "enabled marker written");
    Ok(())
}

/// A NON-owner-sent `set_attester` note traps the EXACT ERR_SENDER_NOT_OWNER and leaves the allowlist
/// unchanged. The sender is the seeded DOM_PAUSER holder id(2) — who is BOTH the former `ATTEST_ADMIN`
/// holder (proving the removed role grants no access) AND a privileged non-owner (the owner-ONLY proof).
#[tokio::test]
async fn set_attester_former_admin_non_owner_rejects() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([20u32, 21, 22, 23]);

    let result = run_set_attester_tx(&gm.harness, &account, dom_holder(), commitment, 1, 7).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());

    // no state change: the allowlist entry for the attempted key never landed (reads EMPTY_WORD).
    assert_eq!(
        read_attester(&account, commitment)?,
        Word::from([0u32, 0, 0, 0]),
        "a rejected non-owner set_attester leaves xReserveAttesters[K] empty"
    );
    Ok(())
}

// PAUSE GATE — set_attester traps the EXACT pause error when the faucet is paused
// ================================================================================================

/// After the OWNER pauses the faucet (stock `PausableManager::pause`), an owner-sent `set_attester` note
/// passes the owner gate but traps the EXACT ERR_PAUSABLE_IS_PAUSED — proving the pause guard is real
/// (the `is_paused` slot is installed by FungibleFaucet, so this is never a missing-slot trap). The
/// pause test sends from the OWNER so it clears `assert_authorized` first and isolates the pause gate.
#[tokio::test]
async fn set_attester_paused_rejects() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);

    // tx1: the owner pauses the faucet (is_paused := true).
    let paused = run_pause_tx(&gm.harness, &account, owner(), 5)
        .await
        .expect("the owner can pause the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;

    // tx2: set_attester by the owner now traps the EXACT pause error (gate passes, pause fails).
    let result =
        run_set_attester_tx(&gm.harness, &evolved, owner(), Word::from([1u32, 2, 3, 4]), 1, 7).await;
    assert_transaction_executor_error!(result, MasmError::from_static_str("the contract is paused"));
    Ok(())
}
