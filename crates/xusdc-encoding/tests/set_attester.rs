//! P5-01 `set_attester` + RBAC-foundation suite: the `ATTEST_ADMIN`-gated allowlist setter installed
//! into the production `XReserveStablecoinBuilder`. This file covers the role gate (the security
//! core), the RBAC seed parity, and the production-deny regression. The non-vacuity set->verify seam
//! (`set_attester_enables_attestation` and friends) + the paused gate ride the shared mint-composition
//! fixtures and land in a follow-up.
//!
//! RED-SUITE (executing-red): `attester_admin.masm` holds only the NAMED placeholder trap
//! (ERR_SET_ATTESTER_UNIMPLEMENTED). Each behavior test asserts its FINAL (green) expectation and is
//! therefore RED here — the holder/non-holder note reaches the `call.set_attester`, then the terminal
//! placeholder reverts the tx. `probe_attester_admin_exports`, `rbac_seed_parity`, and
//! `production_build_with_rbac_still_denies_stock_mint` are declared GREEN scaffolds/controls.

mod support;

use anyhow::Result;
use miden_protocol::account::{
    RoleSymbol, StorageMapKey, StorageSlotDelta, StorageSlotName,
};
use miden_protocol::errors::MasmError;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::RoleBasedAccessControl;
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::account::xreserve::ATTEST_ADMIN_ROLE;

// The seeded admin_holder / owner the production builder installs (support::test_account_id seeds
// admin_holder = id(2) into ATTEST_ADMIN; owner = id(1)). A non-holder is any other id.
fn holder() -> miden_protocol::account::AccountId {
    test_account_id(2)
}
fn non_holder() -> miden_protocol::account::AccountId {
    test_account_id(99)
}

fn role() -> RoleSymbol {
    RoleSymbol::new(ATTEST_ADMIN_ROLE).expect("ATTEST_ADMIN is valid")
}

// Stock RBAC map-key encodings (miden-testing/tests/scripts/rbac.rs:57-63).
fn role_config_key(role: &RoleSymbol) -> Word {
    Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(role)])
}
fn role_membership_key(role: &RoleSymbol, id: miden_protocol::account::AccountId) -> Word {
    Word::from([Felt::ZERO, Felt::from(role), id.suffix(), id.prefix().as_felt()])
}

/// The exact stock error `rbac::assert_sender_has_role` traps (rbac.masm:50). Constructed inline (a
/// stock error, not an xusdc shell error, so it is not in `SHELL_ERR_TABLE`).
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

/// Config words the builder does not read (these tests invoke `set_attester` via a note, never the
/// mint driver).
fn dummy_config() -> (Word, Word) {
    (Word::from([7u32, 0, 0, 0]), Word::from([11u32, 12, 13, 14]))
}

/// A guarded production faucet (RBAC seeded, deny active) with a trivial driver/probe — the base for
/// the role-gate tests. `attesters_seed = None` (empty allowlist).
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
    )
}

// EXPORT PROBE (declared green scaffold — D-1A flat-path check for the setter)
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

// RBAC SEED PARITY (green control) — Option A seeded both maps, consistent with grant_role's post-state
// ================================================================================================

#[tokio::test]
async fn rbac_seed_parity() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let r = role();

    // role_config[{0,0,0,ATTEST_ADMIN}] = [member_count=1, admin_role=0, 0, 0]
    let config = account
        .storage()
        .get_map_item(RoleBasedAccessControl::role_config_slot(), role_config_key(&r))?;
    assert_eq!(config[0], Felt::from(1u32), "member_count == 1");
    assert_eq!(config[1], Felt::ZERO, "admin_role_symbol == 0 (owner-administered)");

    // role_membership[{0,ATTEST_ADMIN,holder.suffix,holder.prefix}] = [1,0,0,0]
    let membership = account.storage().get_map_item(
        RoleBasedAccessControl::role_membership_slot(),
        role_membership_key(&r, holder()),
    )?;
    assert_eq!(membership[0], Felt::from(1u32), "admin_holder is a member of ATTEST_ADMIN");

    // a non-holder is NOT a member.
    let non = account.storage().get_map_item(
        RoleBasedAccessControl::role_membership_slot(),
        role_membership_key(&r, non_holder()),
    )?;
    assert_eq!(non[0], Felt::ZERO, "a non-holder is not a member");
    Ok(())
}

// PRODUCTION REGRESSION GATE — installing RBAC must not perturb the R-MINT-16 deny path
// ================================================================================================

/// The RBAC-equipped production builder still denies stock `mint_and_send` at the EXACT
/// ERR_XRESERVE_MINT_DENIED (mint execution is Authority-independent: policy_manager.masm:284-297).
#[tokio::test]
async fn production_build_with_rbac_still_denies_stock_mint() -> Result<()> {
    let gm = guarded_faucet()?;
    let result = run_mint_and_send(&gm.harness, Word::from([0u32, 1, 2, 3]), 0, 4, 100, 0).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_MINT_DENIED"));
    Ok(())
}

// ROLE GATE (the security core) — RED until the green body wires assert_authorized
// ================================================================================================

/// An ATTEST_ADMIN-holder-sent `set_attester(K, true)` note succeeds and the allowlist entry lands.
/// RED: the placeholder traps ERR_SET_ATTESTER_UNIMPLEMENTED before any write.
#[tokio::test]
async fn set_attester_role_holder_succeeds() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([10u32, 11, 12, 13]);

    let executed = run_set_attester_tx(&gm.harness, &account, holder(), commitment, 1, 7)
        .await
        .expect("an ATTEST_ADMIN holder's set_attester(K, true) must succeed");

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

/// A NON-holder-sent `set_attester` note traps the EXACT ERR_SENDER_LACKS_ROLE and leaves storage
/// unchanged (the gate fires before any write). RED: the placeholder traps the wrong error.
#[tokio::test]
async fn set_attester_non_holder_rejects() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);
    let commitment = Word::from([20u32, 21, 22, 23]);

    let result = run_set_attester_tx(&gm.harness, &account, non_holder(), commitment, 1, 7).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());

    // storage unchanged: a fresh tx by the holder still sees an empty slot (no prior write).
    let executed = run_set_attester_tx(&gm.harness, &account, holder(), commitment, 1, 9)
        .await
        .expect("the holder's write proves the slot was untouched by the rejected non-holder tx");
    let attesters = StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)?;
    let StorageSlotDelta::Map(delta) = executed
        .account_delta()
        .storage()
        .get(&attesters)
        .expect("xReserveAttesters slot delta")
    else {
        panic!("xReserveAttesters must be a Map slot delta");
    };
    assert!(
        delta.entries().contains_key(&StorageMapKey::new(commitment)),
        "the holder write lands on a slot the non-holder never touched"
    );
    Ok(())
}

// PAUSE GATE — set_attester traps the EXACT pause error when the faucet is paused (forbidden #8)
// ================================================================================================

/// After the ATTEST_ADMIN holder pauses the faucet (stock `PausableManager::pause`), a holder-sent
/// `set_attester` note passes the role gate but traps the EXACT ERR_PAUSABLE_IS_PAUSED — proving the
/// pause guard is real (the `is_paused` slot is installed by FungibleFaucet, so this is never a
/// missing-slot trap). The pause test sends from the HOLDER so it clears `assert_authorized` first
/// and isolates the pause gate.
#[tokio::test]
async fn set_attester_paused_rejects() -> Result<()> {
    let gm = guarded_faucet()?;
    let account = faucet_account(&gm.harness);

    // tx1: the holder pauses the faucet (is_paused := true).
    let paused = run_pause_tx(&gm.harness, &account, holder(), 5)
        .await
        .expect("the ATTEST_ADMIN holder can pause the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;

    // tx2: set_attester by the holder now traps the EXACT pause error (gate passes, pause fails).
    let result =
        run_set_attester_tx(&gm.harness, &evolved, holder(), Word::from([1u32, 2, 3, 4]), 1, 7).await;
    assert_transaction_executor_error!(result, MasmError::from_static_str("the contract is paused"));
    Ok(())
}
