//! `set_attester` suite, reconciled to the Circle-faithful OWNER-gated model.
//! The allowlist setter's MASM is UNCHANGED — it calls the account-wide
//! `authority::assert_authorized`, which after the reconciliation (`Authority::OwnerControlled`, the
//! built `ATTEST_ADMIN` role removed) resolves to the Ownable2Step owner. This file covers the owner
//! gate (the security core), the production attestation-gate posture pin, and the pause gate. The
//! non-vacuity set->verify seam (attestation enable/remove/rotation through the REAL transport)
//! lives in the mint E2E suites (`mint_policy_e2e.rs` / `wave1_recomposition.rs`), alongside the
//! production-faucet fixtures they own. The DOM role SEED itself is proven in `role_admin.rs`
//! (`shipped_delegation_reads_back`, production builder) and `set_min_burn.rs`
//! (`support_replica_carries_delegation_seed`, the burn-oracle replica).

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName, StorageSlotPatch};
use miden_protocol::Word;
use miden_standards::account::policies::TokenPolicyManager;
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::account::xreserve::ATTESTATION_MINT_POLICY_PROC_PATH;

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

/// A compilable stand-in for the DELETED custom mint driver (the Wave-1 S1 recomposition removed
/// `xreserve::xreserve_mint`, so the former generated driver no longer assembles): these tests
/// never invoke the driver proc — the guarded fixture only needs a driver component that compiles.
fn placeholder_driver_src() -> String {
    "#! Test driver stand-in: never invoked by this suite (the custom mint entry was deleted by\n\
     #! the Wave-1 S1 recomposition); the guarded fixture only requires a compilable component.\n\
     #!\n\
     #! Inputs:  [pad(16)]\n\
     #! Outputs: [pad(16)]\n\
     #!\n\
     #! Invocation: call\n\
     @account_procedure\n\
     pub proc drive\n\
     \x20\x20\x20\x20push.0 drop\n\
     end\n"
        .to_string()
}

/// A guarded production faucet (owner-gated, attestation-policy active) with a trivial driver/probe
/// — the base for the owner-gate tests. `attesters_seed = None` (empty allowlist).
fn guarded_faucet() -> Result<GuardedMint> {
    let driver = placeholder_driver_src();
    let probe = composition_supply_probe_src(0);
    let (domain, identifier) = dummy_config();
    setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
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
    Ok(account
        .storage()
        .get_map_item(&slot, StorageMapKey::new(commitment))?)
}

// EXPORT PROBE (green scaffold — flat-path check for the setter)
// ================================================================================================

#[test]
fn probe_attester_admin_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::attester_admin::set_attester";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical setter path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// PRODUCTION REGRESSION GATE — the owner-gated build must not perturb the mint-gate posture
// ================================================================================================

/// The owner-gated production builder gates the mint on the ATTESTATION policy: the composed set's
/// ACTIVE mint-policy slot (`TokenPolicyManager::active_mint_policy_slot()`) holds exactly the root
/// resolved via `ATTESTATION_MINT_POLICY_PROC_PATH` from the installed `xreserve` component
/// (INV-MINT-SECURITY restated — every supply increase passes the attestation gate; the executing
/// halves are `mint_policy_e2e.rs` / `wave1_recomposition.rs`).
#[test]
fn production_build_gates_mint_on_the_attestation_policy() -> Result<()> {
    let components = production_component_set(1_000_000, 0)?;
    let attestation_root = components
        .iter()
        .find_map(|c| c.get_procedure_root_by_path(ATTESTATION_MINT_POLICY_PROC_PATH))
        .map(Word::from)
        .context("the composed set must carry the attestation mint policy proc")?;
    let active = components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|slot| slot.name() == TokenPolicyManager::active_mint_policy_slot())
        .context("the composed set must carry the active-mint-policy slot")?
        .value();
    assert_eq!(
        active, attestation_root,
        "the ACTIVE mint policy slot must hold the attestation policy root (the owner-gated build \
         leaves the mint gate on the attestation policy)"
    );
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
    let StorageSlotPatch::Map(delta) = executed
        .account_patch()
        .storage()
        .get(&attesters)
        .expect("xReserveAttesters slot delta")
    else {
        panic!("xReserveAttesters must be a Map slot delta");
    };
    let written = delta
        .entries()
        .expect("map patch carries entries")
        .as_map()
        .get(&StorageMapKey::new(commitment))
        .copied()
        .expect("the commitment KEY must appear in the xReserveAttesters delta");
    assert_eq!(
        written,
        Word::from([1u32, 0, 0, 0]),
        "enabled marker written"
    );
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
/// surface in the Domain-Pauser-only model), an OWNER-sent `set_attester` note SUCCEEDS while paused:
/// F6 reconciles the
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
    evolved.apply_patch(paused.account_patch())?;

    // tx2: the OWNER's set_attester(K, true) SUCCEEDS while paused (F6: setters are not pause-gated).
    let executed = run_set_attester_tx(&gm.harness, &evolved, owner(), commitment, 1, 7)
        .await
        .expect("the owner's set_attester(K, true) must succeed while the faucet is paused");

    // the allowlist entry landed despite the pause: xReserveAttesters[K] == [1,0,0,0].
    let attesters = StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)?;
    let StorageSlotPatch::Map(delta) = executed
        .account_patch()
        .storage()
        .get(&attesters)
        .expect("xReserveAttesters slot delta")
    else {
        panic!("xReserveAttesters must be a Map slot delta");
    };
    let written = delta
        .entries()
        .expect("map patch carries entries")
        .as_map()
        .get(&StorageMapKey::new(commitment))
        .copied()
        .expect("the commitment KEY must appear in the xReserveAttesters delta");
    assert_eq!(
        written,
        Word::from([1u32, 0, 0, 0]),
        "enabled marker written while paused"
    );
    Ok(())
}
