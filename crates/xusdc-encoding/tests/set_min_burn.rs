//! `set_min_burn_size` suite (component CMP-F2): the OWNER-gated setter for the `minBurnSize` value
//! slot CMP-A10's `burn_policy::check_policy` reads for R-BURN-2. Under the ratified Circle-faithful
//! admin model, all three faucet setters gate on the Ownable2Step OWNER via the
//! account-wide `Authority::OwnerControlled`; the built `ATTEST_ADMIN` role is removed and the RBAC
//! foundation is repurposed to seed `DOM_PAUSER` + `DOM_MANAGER` role MEMBERS (their consumers —
//! custom pause CMP-F3, role management CMP-F5 — are built later, NOT here).
//!
//! This file covers the setter's owner gate (the security core), write integrity, the pause gate, the
//! owner-ONLY proof (a seeded non-owner DOM role-holder is rejected), and the DOM seed itself. The
//! burn-min SEAM (set the floor, then a below-floor burn traps R-BURN-2 end-to-end) lives in
//! `xreserve_receive_and_burn.rs`, alongside the burn-note machinery it reuses.
//!
//! RED-SUITE (executing-red): `min_burn_admin.masm` holds only a NON-SECURING placeholder (no gate, no
//! write), and the builder still seeds `ATTEST_ADMIN` (not the owner gate, not the DOM roles). Every
//! behavior test asserts its FINAL (green) expectation and is therefore RED here — the notes reach real
//! MockChain execution against the placeholder / un-flipped Authority. `probe_min_burn_admin_exports`
//! is a green scaffold (the placeholder still exports the proc path).

mod support;

use anyhow::Result;
use miden_protocol::account::{Account, AccountId, RoleSymbol, StorageMapKey};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::RoleBasedAccessControl;
use miden_testing::assert_transaction_executor_error;
use support::*;

// The seeded principals the reconciled production builder installs: owner = id(1) (Ownable2Step), and
// the two DOM role members DOM_PAUSER = id(2), DOM_MANAGER = id(3). A plain non-owner is any other id.
fn owner() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn dom_manager() -> AccountId {
    test_account_id(3)
}
fn plain_non_owner() -> AccountId {
    test_account_id(99)
}

// The fixed role aliases. Inlined as strings (not the green-only Rust consts) so the red-suite
// compiles + executes against the un-flipped build.
const DOM_PAUSER_SYMBOL: &str = "DOM_PAUSER";
const DOM_MANAGER_SYMBOL: &str = "DOM_MANAGER";

const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
/// The initial (builder-seeded) minBurnSize floor for the setter tests.
const SEED_MIN: u64 = 1_000;

// Stock RBAC map-key encodings (miden-testing/tests/scripts/rbac.rs:57-63).
fn role_membership_key(role: &RoleSymbol, id: AccountId) -> Word {
    Word::from([
        Felt::ZERO,
        Felt::from(role),
        id.suffix(),
        id.prefix().as_felt(),
    ])
}
fn role_config_key(role: &RoleSymbol) -> Word {
    Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(role)])
}

/// The `MIN_BURN_SIZE_SLOT` value word for a floor `v` (`[v,0,0,0]`) — the read-back the write-integrity
/// and no-state-change tests compare against. Test floors are small, so `as u32` is exact.
fn min_word(v: u64) -> Word {
    Word::from([Felt::from(v as u32), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

/// A burn-policy production faucet (owner-gated post-green, deny active) with the `minBurnSize` slot
/// seeded `SEED_MIN`. The burn_amount arg only feeds the (unconsumed here) canonical burn note.
fn faucet_harness() -> Result<BurnPolicyHarness> {
    setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        SEED_MIN,
        SEED_MIN,
    )
}

/// The faucet's CURRENT committed account (the setter tx's starting point).
fn faucet(h: &BurnPolicyHarness) -> Result<Account> {
    Ok(h.chain.committed_account(h.faucet_id)?.clone())
}

// EXPORT PROBE (green scaffold — flat-path check for the new setter module)
// ================================================================================================

#[test]
fn probe_min_burn_admin_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::min_burn_admin::set_min_burn_size";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical setter path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// OWNER GATE + WRITE INTEGRITY (the security core) — RED until green wires assert_authorized + set_item
// ================================================================================================

/// An OWNER-sent `set_min_burn_size(M)` succeeds and writes the FULL word `[M,0,0,0]` to the shared
/// slot (write integrity). RED: the placeholder performs no write, so the read-back stays `SEED_MIN`.
#[tokio::test]
async fn set_min_burn_owner_succeeds() -> Result<()> {
    let h = faucet_harness()?;
    let account = faucet(&h)?;
    const NEW_MIN: u64 = 5_000;

    let executed = run_set_min_burn_size_against(&h.chain, &account, owner(), NEW_MIN, 7)
        .await
        .expect("the owner's set_min_burn_size(M) must succeed");
    let mut evolved = account.clone();
    evolved.apply_patch(executed.account_patch())?;

    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(NEW_MIN),
        "set_min_burn_size writes the full [new_min,0,0,0] word to MIN_BURN_SIZE_SLOT"
    );
    Ok(())
}

/// A PLAIN non-owner-sent `set_min_burn_size` traps the EXACT `ERR_SENDER_NOT_OWNER` and leaves the slot
/// unchanged (no partial write before the trap). RED: the placeholder has no gate, so the tx succeeds.
#[tokio::test]
async fn set_min_burn_plain_non_owner_rejects() -> Result<()> {
    assert_non_owner_rejected(plain_non_owner()).await
}

/// OWNER-ONLY (the seeded `DOM_PAUSER` member, who is NOT the owner, is rejected). Proves the gate is the
/// Ownable2Step owner specifically — a privileged role-holder gains no setter access. Doubles as the
/// `former ATTEST_ADMIN` removal proof: id(2) held ATTEST_ADMIN pre-reconciliation and is rejected now.
#[tokio::test]
async fn set_min_burn_dom_pauser_non_owner_rejects() -> Result<()> {
    assert_non_owner_rejected(dom_pauser()).await
}

/// OWNER-ONLY (the seeded `DOM_MANAGER` member, who is NOT the owner, is rejected). The second DOM role,
/// so both seeded role-holders are proven non-authorizing for the setter.
#[tokio::test]
async fn set_min_burn_dom_manager_non_owner_rejects() -> Result<()> {
    assert_non_owner_rejected(dom_manager()).await
}

/// Shared non-owner assertion: `sender` (a non-owner) traps the EXACT `ERR_SENDER_NOT_OWNER`, AND the
/// `MIN_BURN_SIZE_SLOT` reads back the seeded `[SEED_MIN,0,0,0]` (byte-identical) — no partial write.
async fn assert_non_owner_rejected(sender: AccountId) -> Result<()> {
    let h = faucet_harness()?;
    let account = faucet(&h)?;

    let result = run_set_min_burn_size_against(&h.chain, &account, sender, 5_000, 7).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());

    // no state change: the slot is byte-identical to the seed (the trap precedes any write).
    assert_eq!(
        read_min_burn_size(&account)?,
        min_word(SEED_MIN),
        "a rejected non-owner set_min_burn_size leaves MIN_BURN_SIZE_SLOT unchanged"
    );
    Ok(())
}

// SETTER NOT PAUSE-GATED (F6) — the OWNER may set_min_burn_size while the faucet is paused
// ================================================================================================

/// After the DOM_PAUSER pauses the faucet (custom `xreserve::pause_admin::pause` — the ONLY pause
/// surface in the Domain-Pauser-only model), an OWNER-sent `set_min_burn_size` SUCCEEDS while paused:
/// F6 reconciles the
/// setters to Circle's `onlyOwner` (deliberately NOT pause-gated), so the burn floor can be adjusted
/// during a pause. The full word `[new_min,0,0,0]` lands despite is_paused == true; the owner gate still
/// governs it (the `*_non_owner_rejects` tests above prove that half).
#[tokio::test]
async fn set_min_burn_owner_succeeds_while_paused() -> Result<()> {
    let h = faucet_harness()?;
    let account = faucet(&h)?;
    const NEW_MIN: u64 = 5_000;

    // tx1: the DOM_PAUSER pauses the faucet (is_paused := true).
    let paused = run_dom_pauser_pause(&h.chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;

    // tx2: the OWNER's set_min_burn_size(M) SUCCEEDS while paused (F6: setters are not pause-gated).
    let executed = run_set_min_burn_size_against(&h.chain, &evolved, owner(), NEW_MIN, 7)
        .await
        .expect("the owner's set_min_burn_size(M) must succeed while the faucet is paused");
    evolved.apply_patch(executed.account_patch())?;

    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(NEW_MIN),
        "set_min_burn_size writes [new_min,0,0,0] to MIN_BURN_SIZE_SLOT while paused"
    );
    Ok(())
}

// DOM ROLE SEEDING (owner-ONLY foundation) — the DOM_PAUSER/DOM_MANAGER members are seeded + valid
// ================================================================================================

/// REPLICA FIDELITY (CMP-F5): this test reads the burn-oracle SUPPORT-REPLICA account (the
/// `setup_burn_policy_account` composition installs the test-side `seeded_dom_roles_rbac_component`,
/// NOT the production builder) and pins that replica to the PRODUCTION seed shape — `DOM_PAUSER`
/// config `[1, DOM_MANAGER, 0, 0]` (the CMP-F5 delegation), `DOM_MANAGER` config `[1, 0, 0, 0]`
/// (owner-administered), and both seeded memberships `[1,0,0,0]`. It is the SOLE tripwire for
/// replica drift: every burn-oracle-fixture test (pause rejects, setter rejects here) leans on this
/// replica. The PRODUCTION-account twin of these assertions is
/// `role_admin.rs::shipped_delegation_reads_back`. RED (CMP-F5): the replica still seeds
/// `admin_role = 0`.
#[tokio::test]
async fn support_replica_carries_delegation_seed() -> Result<()> {
    let pauser =
        RoleSymbol::new(DOM_PAUSER_SYMBOL).expect("DOM_PAUSER is a valid <=12 role symbol");
    let manager =
        RoleSymbol::new(DOM_MANAGER_SYMBOL).expect("DOM_MANAGER is a valid <=12 role symbol");

    let h = faucet_harness()?;
    let account = faucet(&h)?;

    // role_config[{0,0,0,DOM_PAUSER}] = [member_count=1, admin_role=DOM_MANAGER, 0, 0] (the CMP-F5
    // delegation: the Domain Manager rotates the Pauser); DOM_MANAGER keeps admin_role=0, which at
    // v0.16 resolves to the built-in ADMIN role the builder seeds on the OWNER — so DOM_MANAGER
    // stays owner-administered (#3215 replaced the v15 owner-only gate with the effective-admin
    // gate; MIGRATION-V16-ALPHA2.md S2/S21).
    let pauser_config = account.storage().get_map_item(
        RoleBasedAccessControl::role_config_slot(),
        StorageMapKey::new(role_config_key(&pauser)),
    )?;
    assert_eq!(
        pauser_config[0],
        Felt::from(1u32),
        "DOM_PAUSER member_count == 1"
    );
    assert_eq!(
        pauser_config[1],
        Felt::from(&manager),
        "DOM_PAUSER admin_role == DOM_MANAGER (the CMP-F5 delegation, replica seed)"
    );

    let manager_config = account.storage().get_map_item(
        RoleBasedAccessControl::role_config_slot(),
        StorageMapKey::new(role_config_key(&manager)),
    )?;
    assert_eq!(
        manager_config[0],
        Felt::from(1u32),
        "DOM_MANAGER member_count == 1"
    );
    assert_eq!(
        manager_config[1],
        Felt::ZERO,
        "DOM_MANAGER admin_role == 0 (owner-administered)"
    );

    // role_membership[{0,<role>,holder.suffix,holder.prefix}] = [1,0,0,0] for each DOM holder.
    let pauser_membership = account.storage().get_map_item(
        RoleBasedAccessControl::role_membership_slot(),
        StorageMapKey::new(role_membership_key(&pauser, dom_pauser())),
    )?;
    assert_eq!(
        pauser_membership[0],
        Felt::from(1u32),
        "DOM_PAUSER holder id(2) is a seeded member"
    );

    let manager_membership = account.storage().get_map_item(
        RoleBasedAccessControl::role_membership_slot(),
        StorageMapKey::new(role_membership_key(&manager, dom_manager())),
    )?;
    assert_eq!(
        manager_membership[0],
        Felt::from(1u32),
        "DOM_MANAGER holder id(3) is a seeded member"
    );
    Ok(())
}

/// A wrong-key membership read stays EMPTY: a non-member id is not a `DOM_PAUSER` member (proves the
/// seed is keyed on the intended holder, not blanket-true).
#[tokio::test]
async fn dom_non_member_reads_empty() -> Result<()> {
    let pauser = RoleSymbol::new(DOM_PAUSER_SYMBOL).expect("DOM_PAUSER is a valid role symbol");
    let h = faucet_harness()?;
    let account = faucet(&h)?;

    let non = account.storage().get_map_item(
        RoleBasedAccessControl::role_membership_slot(),
        StorageMapKey::new(role_membership_key(&pauser, plain_non_owner())),
    )?;
    assert_eq!(
        non[0],
        Felt::ZERO,
        "a non-member id is not a DOM_PAUSER member"
    );
    Ok(())
}
