//! Setting the minimum burn size: who may change the floor, and what changing it writes.
//!
//! The floor is not stored by the faucet. It lives in the standard minimum-burn policy's own value
//! slot as `[min, 0, 0, 0]`, which is exactly the slot the standard `check_policy` reads when it
//! decides whether a burn is large enough. The setter is the standard
//! `min_burn_amount::set_min_burn_amount`; the faucet contributes no setter of its own.
//!
//! Authority follows Circle's admin model: this setter carries no role of its own, so the
//! account-wide role-based authority resolves it to the built-in `ADMIN` role, seeded on the
//! administrator's account. The account also seeds two Domain roles — Pauser and Manager — but neither may
//! set the floor, and their own powers are tested in the pause and role suites. `ADMIN` membership
//! is account-bound: it is the faucet's only authority handle.
//!
//! The authorization gate itself is the standard setter's, and it is driven through the production
//! note in `f5_admin_notes.rs`. What is left here is what belongs to this repository: that the
//! composition installs the very setter root the production note targets, that the setter is
//! deliberately NOT blocked while the faucet is paused, and that the role seeding the support
//! replica hands to every suite running against it matches what the builder seeds. The end-to-end
//! consequence — set the floor, then watch a below-floor burn trap — lives with the burn-note
//! machinery in `xreserve_receive_and_burn.rs`.

mod support;

use anyhow::Result;
use miden_protocol::account::{Account, AccountId, RoleSymbol, StorageMapKey};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Ownable2Step, RoleBasedAccessControl};
use miden_standards::account::policies::MinBurnAmount;
use support::*;

// The seeded principals the reconciled production builder installs: the administrator = id(1) (the
// sole seeded `ADMIN` member), and
// the two DOM role members DOM_PAUSER = id(2), DOM_MANAGER = id(3). A plain non-administrator is any other id.
fn administrator() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn dom_manager() -> AccountId {
    test_account_id(3)
}
fn plain_non_administrator() -> AccountId {
    test_account_id(99)
}

// The fixed role aliases. Inlined as strings (not the green-only Rust consts) so the red-suite
// compiles + executes against the un-flipped build.
const DOM_PAUSER_SYMBOL: &str = "DOM_PAUSER";
const DOM_MANAGER_SYMBOL: &str = "DOM_MANAGER";

const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
/// The initial (fixture-seeded) burn floor for the setter tests (always `>= 1` — the zero-floor
/// invariant the production surface enforces at build and note level).
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

/// The STOCK `MinBurnAmount` floor-slot value word for a floor `v` (`[v,0,0,0]`) — the read-back
/// the write-integrity and no-state-change tests compare against (via [`read_min_burn_size`]).
/// Test floors are small, so `as u32` is exact.
fn min_word(v: u64) -> Word {
    Word::from([Felt::from(v as u32), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

/// A burn-oracle faucet (stock `MinBurnAmount` active) with the STOCK floor slot seeded
/// `SEED_MIN`. The burn_amount arg only feeds the (unconsumed here) canonical burn note.
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

// SETTER-INSTALLED PROBE (the stock setter is part of the composed production surface)
// ================================================================================================

/// The production component set actually installs the setter the production note targets.
///
/// The note script calls the standard `min_burn_amount::set_min_burn_amount` by root, so if the
/// composition ever stopped including that procedure the note would fail at runtime with an
/// unhelpful "procedure not found". Checking the installed procedure roots here turns that into a
/// build-time-shaped failure with an obvious cause.
#[test]
fn probe_stock_min_burn_setter_installed() -> Result<()> {
    let components = production_component_set(MAX_SUPPLY, 0)?;
    assert!(
        components
            .iter()
            .any(|c| c.has_procedure(MinBurnAmount::set_min_burn_amount_root())),
        "the production component set must expose the stock MinBurnAmount::set_min_burn_amount \
         root (the setter the production admin note targets)"
    );
    Ok(())
}

// THE SETTER IS NOT PAUSE-GATED — the ADMINISTRATOR may set_min_burn_size while the faucet is paused
// ================================================================================================

/// After the Domain Pauser pauses the faucet (the stock `PausableManager`, role-gated), an
/// `ADMIN`-sent `set_min_burn_size` SUCCEEDS while paused: the admin setters are deliberately NOT
/// pause-gated, so the burn floor can be adjusted during a pause. The full word `[new_min,0,0,0]`
/// lands despite is_paused == true; the administrator gate still governs it (the rejection tests
/// above prove that half).
#[tokio::test]
async fn set_min_burn_administrator_succeeds_while_paused() -> Result<()> {
    let h = faucet_harness()?;
    let account = faucet(&h)?;
    const NEW_MIN: u64 = 5_000;

    // tx1: the DOM_PAUSER pauses the faucet (is_paused := true).
    let paused = run_dom_pauser_pause(&h.chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;

    // tx2: the OWNER's set_min_burn_size(M) SUCCEEDS while paused — setters are not pause-gated.
    let executed = run_set_min_burn_size_against(&h.chain, &evolved, administrator(), NEW_MIN, 7)
        .await
        .expect("the administrator's set_min_burn_size(M) must succeed while the faucet is paused");
    evolved.apply_patch(executed.account_patch())?;

    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(NEW_MIN),
        "the stock set_min_burn_amount writes [new_min,0,0,0] to the stock MinBurnAmount floor \
         slot while paused"
    );
    Ok(())
}

// DOM ROLE SEEDING (administrator-ONLY foundation) — the DOM_PAUSER/DOM_MANAGER members are seeded + valid
// ================================================================================================

/// The test-side role seeding matches the shape the production builder seeds.
///
/// Several suites — the pause rejects, the non-administrator setter reject below — run against a support
/// harness that installs its own role-seeding component rather than the production builder. Those
/// tests are only meaningful while the replica seeds the same thing production does, and nothing
/// else checks that. So this reads the replica's storage directly and pins all three facts: the
/// Domain Pauser role is administered by the Domain Manager (one member, admin role = Domain
/// Manager), the Domain Manager is administered by the built-in admin role (one member, admin role
/// 0), and both memberships are present — and that the replica installs no ownership component,
/// because the shipped account does not either. The equivalent assertions against a production-built
/// account live in `role_admin.rs::shipped_delegation_reads_back`.
#[tokio::test]
async fn support_replica_carries_delegation_seed() -> Result<()> {
    let pauser =
        RoleSymbol::new(DOM_PAUSER_SYMBOL).expect("DOM_PAUSER is a valid <=12 role symbol");
    let manager =
        RoleSymbol::new(DOM_MANAGER_SYMBOL).expect("DOM_MANAGER is a valid <=12 role symbol");

    let h = faucet_harness()?;
    let account = faucet(&h)?;

    // The Domain Pauser's config records one member and names the Domain Manager as its admin
    // role — that delegation is what lets the Manager rotate the Pauser without administrator
    // involvement. The Domain Manager itself records admin role 0, the built-in admin role, whose
    // membership the builder seeds on the administrator's account. Note that this admin membership
    // is bound to that ACCOUNT, so an administratorship handover has to re-seat the role explicitly
    // (grant-new / revoke-old).
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
        "DOM_MANAGER admin_role == 0 (resolves to ADMIN = the seeded administrator account)"
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

    // And the replica must not carry an authority handle the shipped account has retired: the
    // ownership component is gone from production, so a replica that still installs it would give
    // the suites running against it an administrator slot and five callable procedures the real faucet does
    // not have — the divergence that makes a replica stop being evidence.
    assert!(
        Ownable2Step::try_from_storage(account.storage()).is_err(),
        "the replica must carry no owner-config slot — the shipped composition installs no          ownership component, and the built-in ADMIN role is its only authority handle"
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
        StorageMapKey::new(role_membership_key(&pauser, plain_non_administrator())),
    )?;
    assert_eq!(
        non[0],
        Felt::ZERO,
        "a non-member id is not a DOM_PAUSER member"
    );
    Ok(())
}
