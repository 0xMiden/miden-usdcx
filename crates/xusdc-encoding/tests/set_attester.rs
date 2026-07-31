//! `set_attester` suite, reconciled to the Circle-faithful administrator-gated model.
//! The allowlist setter's MASM is UNCHANGED — it calls the account-wide
//! `authority::assert_authorized`, which under the account's role-based authority resolves this
//! procedure to the built-in `ADMIN` role, since it carries no role of its own. `ADMIN` is seeded on
//! the administrator's account, so the identity is today's; it is account-bound and does not follow an
//! administrator handover. This file covers the administrator
//! gate (the security core), the production attestation-gate posture pin, and the pause gate. The
//! non-vacuity seam — that enabling, removing, and rotating an attester actually changes which
//! attestations a real mint accepts — lives in the mint end-to-end suites, alongside the
//! production-faucet fixtures they own. The role seeding this file's non-administrator rejects rely on is
//! proven in `role_admin.rs::shipped_delegation_reads_back` against a production-built account and
//! in `set_min_burn.rs::support_replica_carries_delegation_seed` against the test replica.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::{AccountId, StorageMapKey, StorageSlotName, StorageSlotPatch};
use miden_protocol::Word;
use miden_standards::account::policies::TokenPolicyManager;
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::account::xreserve::ATTESTATION_MINT_POLICY_PROC_PATH;

// The seeded principals the reconciled builder installs: the administrator = id(1) (the sole ADMIN member); the two seeded
// DOM role-holders DOM_PAUSER = id(2) (also the FORMER ATTEST_ADMIN holder) and DOM_MANAGER = id(3) —
// privileged non-administrators the administrator-ONLY proof rejects.
fn administrator() -> AccountId {
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

/// A do-nothing component that satisfies the shared fixture's requirement for a driver.
///
/// These tests reach the account through admin notes and never invoke it, so it only has to
/// compile.
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

/// A guarded production faucet (administrator-gated, attestation-policy active) with a trivial driver/probe
/// — the base for the administrator-gate tests. `attesters_seed = None` (empty allowlist).
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
/// when unset) — the no-state-change read-back the non-administrator reject uses.
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

// PRODUCTION REGRESSION GATE — the administrator-gated build must not perturb the mint-gate posture
// ================================================================================================

/// Making the attester setter administrator-gated did not disturb what actually guards minting.
///
/// The composed account's active mint-policy slot must still hold exactly the root of the
/// attestation policy resolved from the installed component. That is the structural form of the
/// property everything else depends on: every increase in supply goes through the attestation
/// gate. The executing halves — real mints accepted and rejected — live in the mint end-to-end
/// suites.
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
        "the ACTIVE mint policy slot must hold the attestation policy root (the administrator-gated build \
         leaves the mint gate on the attestation policy)"
    );
    Ok(())
}

// ADMINISTRATOR GATE (the security core) — the unmapped setter resolves to the ADMIN role
// ================================================================================================

/// An OWNER-sent `set_attester(K, true)` note succeeds and the allowlist entry lands.
#[tokio::test]
async fn set_attester_owner_succeeds() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([10u32, 11, 12, 13]);

    let executed = run_set_attester_tx(&gm.harness, &account, administrator(), commitment, 1, 7)
        .await
        .expect("the administrator's set_attester(K, true) must succeed");

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

/// Shared ADMIN-only assertion for `set_attester`: a `sender` without the administrator role traps the EXACT
/// ERR_SENDER_LACKS_ROLE AND leaves the allowlist entry for the attempted key EMPTY (no partial write).
async fn assert_set_attester_non_owner_rejected(sender: AccountId, key_seed: u32) -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([key_seed, key_seed + 1, key_seed + 2, key_seed + 3]);

    let result = run_set_attester_tx(&gm.harness, &account, sender, commitment, 1, 7).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());

    // no state change: the allowlist entry for the attempted key never landed (reads EMPTY_WORD).
    assert_eq!(
        read_attester(&account, commitment)?,
        Word::from([0u32, 0, 0, 0]),
        "a rejected non-administrator set_attester leaves xReserveAttesters[K] empty"
    );
    Ok(())
}

/// ADMIN-only: the seeded DOM_PAUSER holder id(2) — who is BOTH the former `ATTEST_ADMIN` holder
/// (proving the removed role grants no access) AND privileged without being an administrator — is
/// rejected from `set_attester`.
#[tokio::test]
async fn set_attester_former_admin_dom_pauser_non_owner_rejects() -> Result<()> {
    assert_set_attester_non_owner_rejected(dom_pauser(), 20).await
}

/// ADMIN-only: the seeded DOM_MANAGER holder id(3) — privileged, but not an administrator — is
/// rejected from `set_attester` (completing the administrator-only cross-product for this setter).
#[tokio::test]
async fn set_attester_dom_manager_non_owner_rejects() -> Result<()> {
    assert_set_attester_non_owner_rejected(dom_manager(), 30).await
}

// THE SETTER IS NOT PAUSE-GATED — the OWNER may set_attester while the faucet is paused
// ================================================================================================

/// After the Domain Pauser pauses the faucet (the stock `PausableManager`, role-gated), an
/// `ADMIN`-sent `set_attester` note SUCCEEDS while paused: the admin setters are deliberately NOT
/// pause-gated, so a compromised attester can be disabled during a pause — which is exactly when it
/// is needed. The enabled marker lands despite is_paused == true. The administrator gate still
/// governs it — the rejection tests above prove that half.
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

    // tx2: the OWNER's set_attester(K, true) SUCCEEDS while paused — setters are not pause-gated.
    let executed = run_set_attester_tx(&gm.harness, &evolved, administrator(), commitment, 1, 7)
        .await
        .expect(
            "the administrator's set_attester(K, true) must succeed while the faucet is paused",
        );

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
