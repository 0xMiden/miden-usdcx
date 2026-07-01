//! P5-01 `set_min_burn_size` (CMP-F2) suite: the OWNER-gated setter for the `minBurnSize` value slot
//! CMP-A10's `burn_policy::check_policy` reads for R-BURN-2. Under the ratified Circle-faithful admin
//! model (DECISION-ADMIN-ROLE-MODEL), all three faucet setters gate on the Ownable2Step OWNER via the
//! account-wide `Authority::OwnerControlled`; the built `ATTEST_ADMIN` role is removed and the RBAC
//! foundation is repurposed to seed `DOM_PAUSER` + `DOM_MANAGER` role MEMBERS (their consumers — custom
//! pause, role management — are later slices, NOT built here).
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
use miden_protocol::account::{Account, AccountId, RoleSymbol};
use miden_protocol::errors::MasmError;
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

// ORCHESTRATOR-FIXED role aliases (DECISION-ADMIN-ROLE-MODEL). Inlined as strings (not the green-only
// Rust consts) so the red-suite compiles + executes against the un-flipped build.
const DOM_PAUSER_SYMBOL: &str = "DOM_PAUSER";
const DOM_MANAGER_SYMBOL: &str = "DOM_MANAGER";

const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
/// The initial (builder-seeded) minBurnSize floor for the setter tests.
const SEED_MIN: u64 = 1_000;

// Stock RBAC map-key encodings (miden-testing/tests/scripts/rbac.rs:57-63).
fn role_membership_key(role: &RoleSymbol, id: AccountId) -> Word {
    Word::from([Felt::ZERO, Felt::from(role), id.suffix(), id.prefix().as_felt()])
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

// EXPORT PROBE (green scaffold — D-1A flat-path check for the new setter module)
// ================================================================================================

#[test]
fn probe_min_burn_admin_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
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
    evolved.apply_delta(executed.account_delta())?;

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

// PAUSE GATE — set_min_burn_size traps the EXACT pause error when the faucet is paused
// ================================================================================================

/// After the OWNER pauses the faucet, an OWNER-sent `set_min_burn_size` passes the owner gate but traps
/// the EXACT `ERR_PAUSABLE_IS_PAUSED` (the `is_paused` slot is FungibleFaucet-installed, so never a
/// missing-slot artifact). Sends from the owner so the pause gate is isolated after auth passes.
#[tokio::test]
async fn set_min_burn_paused_rejects() -> Result<()> {
    let h = faucet_harness()?;
    let account = faucet(&h)?;

    // tx1: the owner pauses the faucet (is_paused := true).
    let paused = run_pause_against(&h.chain, &account, owner(), 5)
        .await
        .expect("the owner can pause the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;

    // tx2: set_min_burn_size by the owner now traps the EXACT pause error (auth passes, pause fails).
    let result = run_set_min_burn_size_against(&h.chain, &evolved, owner(), 5_000, 7).await;
    assert_transaction_executor_error!(result, MasmError::from_static_str("the contract is paused"));
    Ok(())
}

// DOM ROLE SEEDING (owner-ONLY foundation) — the DOM_PAUSER/DOM_MANAGER members are seeded + valid
// ================================================================================================

/// `DOM_PAUSER` (10) and `DOM_MANAGER` (11) are valid `RoleSymbol`s and are SEEDED into the RBAC — each
/// role's membership for its holder reads back `[1,0,0,0]`. RED: the un-flipped builder seeds only
/// `ATTEST_ADMIN`, so the DOM membership reads back EMPTY. (MASM↔Rust DOM parity is deferred to the
/// first DOM-consumer MASM slice, CMP-F3 — no MASM references the DOM symbols in this slice.)
#[tokio::test]
async fn dom_roles_seeded_correctly() -> Result<()> {
    let pauser = RoleSymbol::new(DOM_PAUSER_SYMBOL).expect("DOM_PAUSER is a valid <=12 role symbol");
    let manager = RoleSymbol::new(DOM_MANAGER_SYMBOL).expect("DOM_MANAGER is a valid <=12 role symbol");

    let h = faucet_harness()?;
    let account = faucet(&h)?;

    // role_config[{0,0,0,<role>}] = [member_count=1, admin_role=0, 0, 0] for each DOM role (admin_role=0
    // == owner-administered; set_role_admin is owner-only, rbac.masm:159).
    let pauser_config = account
        .storage()
        .get_map_item(RoleBasedAccessControl::role_config_slot(), role_config_key(&pauser))?;
    assert_eq!(pauser_config[0], Felt::from(1u32), "DOM_PAUSER member_count == 1");
    assert_eq!(pauser_config[1], Felt::ZERO, "DOM_PAUSER admin_role == 0 (owner-administered)");

    let manager_config = account
        .storage()
        .get_map_item(RoleBasedAccessControl::role_config_slot(), role_config_key(&manager))?;
    assert_eq!(manager_config[0], Felt::from(1u32), "DOM_MANAGER member_count == 1");
    assert_eq!(manager_config[1], Felt::ZERO, "DOM_MANAGER admin_role == 0 (owner-administered)");

    // role_membership[{0,<role>,holder.suffix,holder.prefix}] = [1,0,0,0] for each DOM holder.
    let pauser_membership = account.storage().get_map_item(
        RoleBasedAccessControl::role_membership_slot(),
        role_membership_key(&pauser, dom_pauser()),
    )?;
    assert_eq!(
        pauser_membership[0],
        Felt::from(1u32),
        "DOM_PAUSER holder id(2) is a seeded member"
    );

    let manager_membership = account.storage().get_map_item(
        RoleBasedAccessControl::role_membership_slot(),
        role_membership_key(&manager, dom_manager()),
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
        role_membership_key(&pauser, plain_non_owner()),
    )?;
    assert_eq!(non[0], Felt::ZERO, "a non-member id is not a DOM_PAUSER member");
    Ok(())
}
