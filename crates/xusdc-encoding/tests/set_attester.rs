//! P5-01 `set_attester` suite, reconciled to the Circle-faithful OWNER-gated model
//! (DECISION-ADMIN-ROLE-MODEL). The allowlist setter's MASM is UNCHANGED — it calls the account-wide
//! `authority::assert_authorized`, which after the reconciliation (`Authority::OwnerControlled`, the
//! built `ATTEST_ADMIN` role removed) resolves to the Ownable2Step owner. This file covers the owner
//! gate (the security core), the production-deny regression, and the pause gate. The non-vacuity
//! set->verify seam (`set_attester_enables_attestation`, remove-denies, and the 5-step rotation) lives
//! in `xreserve_mint.rs`, alongside the shared mint-composition fixtures it reuses. The DOM role SEED
//! itself is proven in `role_admin.rs` (`shipped_delegation_reads_back`, production builder) and
//! `set_min_burn.rs` (`support_replica_carries_delegation_seed`, the burn-oracle replica).

mod support;

use anyhow::Result;
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotDelta, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;

// The seeded principals the reconciled builder installs: owner = id(1) (Ownable2Step); the two seeded
// DOM role-holders DOM_PAUSER = id(2) (also the FORMER ATTEST_ADMIN holder) and DOM_MANAGER = id(3) —
// privileged non-owners the owner-ONLY proof rejects.
fn owner() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn dom_manager() -> AccountId {
    test_account_id(3)
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

/// Shared owner-ONLY assertion for `set_attester`: a NON-owner `sender` traps the EXACT
/// ERR_SENDER_NOT_OWNER AND leaves the allowlist entry for the attempted key EMPTY (no partial write).
async fn assert_set_attester_non_owner_rejected(sender: AccountId, key_seed: u32) -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([key_seed, key_seed + 1, key_seed + 2, key_seed + 3]);

    let result = run_set_attester_tx(&gm.harness, &account, sender, commitment, 1, 7).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());

    // no state change: the allowlist entry for the attempted key never landed (reads EMPTY_WORD).
    assert_eq!(
        read_attester(&account, commitment)?,
        Word::from([0u32, 0, 0, 0]),
        "a rejected non-owner set_attester leaves xReserveAttesters[K] empty"
    );
    Ok(())
}

/// Owner-ONLY: the seeded DOM_PAUSER holder id(2) — who is BOTH the former `ATTEST_ADMIN` holder
/// (proving the removed role grants no access) AND a privileged non-owner — is rejected from `set_attester`.
#[tokio::test]
async fn set_attester_former_admin_dom_pauser_non_owner_rejects() -> Result<()> {
    assert_set_attester_non_owner_rejected(dom_pauser(), 20).await
}

/// Owner-ONLY: the seeded DOM_MANAGER holder id(3) — a privileged non-owner — is rejected from
/// `set_attester` (completing the owner-ONLY cross-product for this setter).
#[tokio::test]
async fn set_attester_dom_manager_non_owner_rejects() -> Result<()> {
    assert_set_attester_non_owner_rejected(dom_manager(), 30).await
}

// SETTER NOT PAUSE-GATED (F6) — the OWNER may set_attester while the faucet is paused
// ================================================================================================

/// After the DOM_PAUSER pauses the faucet (custom `xreserve::pause_admin::pause` — the ONLY pause
/// surface under Option 1), an OWNER-sent `set_attester` note SUCCEEDS while paused: F6 reconciles the
/// admin setters to Circle's `onlyOwner` (deliberately NOT pause-gated), so a compromised attester can
/// be disabled during a pause. The enabled marker lands despite is_paused == true. The owner gate still
/// governs it — the `*_non_owner_rejects` tests above prove that half.
#[tokio::test]
async fn set_attester_owner_succeeds_while_paused() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([1u32, 2, 3, 4]);

    // tx1: the DOM_PAUSER pauses the faucet (is_paused := true).
    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;

    // tx2: the OWNER's set_attester(K, true) SUCCEEDS while paused (F6: setters are not pause-gated).
    let executed = run_set_attester_tx(&gm.harness, &evolved, owner(), commitment, 1, 7)
        .await
        .expect("the owner's set_attester(K, true) must succeed while the faucet is paused");

    // the allowlist entry landed despite the pause: xReserveAttesters[K] == [1,0,0,0].
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
    assert_eq!(written, Word::from([1u32, 0, 0, 0]), "enabled marker written while paused");
    Ok(())
}
