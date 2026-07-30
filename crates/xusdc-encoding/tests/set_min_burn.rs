//! Setting the minimum burn size: who may change the floor, and what changing it writes.
//!
//! The floor is not stored by the faucet. It lives in the standard minimum-burn policy's own value
//! slot as `[min, 0, 0, 0]`, which is exactly the slot the standard `check_policy` reads when it
//! decides whether a burn is large enough. The setter is the standard
//! `min_burn_amount::set_min_burn_amount`; the faucet contributes no setter of its own.
//!
//! Authority follows Circle's admin model: this setter is gated on the account OWNER, through the
//! account-wide owner-controlled authority, rather than on a role. The account does seed two roles
//! — Domain Pauser and Domain Manager — but neither may set the floor, and their own powers are
//! tested in the pause and role suites.
//!
//! The gate tests here call the standard setter directly through a bare test-local note, on
//! purpose: the production note script also enforces its own "never below one" floor guard, and
//! going through it would mean testing that guard instead of the setter's authorization. The floor
//! guard itself is covered where the production note factory is exercised.
//!
//! So this file covers the owner gate, that a successful write lands the right value in the right
//! slot, that the setter is deliberately NOT blocked while the faucet is paused, that a seeded
//! role-holder who is not the owner is still rejected, and that the role seeding it relies on is
//! itself correct. The end-to-end consequence — set the floor, then watch a below-floor burn trap —
//! lives with the burn-note machinery in `xreserve_receive_and_burn.rs`.

mod support;

use anyhow::Result;
use miden_protocol::account::{Account, AccountId, RoleSymbol, StorageMapKey};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::RoleBasedAccessControl;
use miden_standards::account::policies::MinBurnAmount;
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

// OWNER GATE + WRITE INTEGRITY (the security core) — against the STOCK setter
// ================================================================================================

/// An OWNER-sent `set_min_burn_size(M)` succeeds and writes the FULL word `[M,0,0,0]` to the STOCK
/// `MinBurnAmount` floor slot (write integrity).
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
        "the stock set_min_burn_amount writes the full [new_min,0,0,0] word to the stock \
         MinBurnAmount floor slot"
    );
    Ok(())
}

/// A PLAIN non-owner-sent `set_min_burn_size` traps the EXACT `ERR_SENDER_NOT_OWNER` and leaves the
/// slot unchanged (no partial write before the trap).
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

/// Shared non-owner assertion: `sender` (a non-owner) traps the EXACT `ERR_SENDER_NOT_OWNER`, AND
/// the STOCK `MinBurnAmount` floor slot reads back the seeded `[SEED_MIN,0,0,0]` (byte-identical)
/// — no partial write.
async fn assert_non_owner_rejected(sender: AccountId) -> Result<()> {
    let h = faucet_harness()?;
    let account = faucet(&h)?;

    let result = run_set_min_burn_size_against(&h.chain, &account, sender, 5_000, 7).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());

    // no state change: the slot is byte-identical to the seed (the trap precedes any write).
    assert_eq!(
        read_min_burn_size(&account)?,
        min_word(SEED_MIN),
        "a rejected non-owner set_min_burn_size leaves the stock MinBurnAmount floor slot unchanged"
    );
    Ok(())
}

// THE SETTER IS NOT PAUSE-GATED — the OWNER may set_min_burn_size while the faucet is paused
// ================================================================================================

/// After the DOM_PAUSER pauses the faucet (custom `xreserve::pause_admin::pause` — the ONLY pause
/// surface in the Domain-Pauser-only model), an OWNER-sent `set_min_burn_size` SUCCEEDS while paused:
/// the admin setters follow Circle's owner-only model and are deliberately NOT pause-gated, so the
/// burn floor can be adjusted during a pause. The full word `[new_min,0,0,0]` lands despite is_paused == true; the owner gate still
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

    // tx2: the OWNER's set_min_burn_size(M) SUCCEEDS while paused — setters are not pause-gated.
    let executed = run_set_min_burn_size_against(&h.chain, &evolved, owner(), NEW_MIN, 7)
        .await
        .expect("the owner's set_min_burn_size(M) must succeed while the faucet is paused");
    evolved.apply_patch(executed.account_patch())?;

    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(NEW_MIN),
        "the stock set_min_burn_amount writes [new_min,0,0,0] to the stock MinBurnAmount floor \
         slot while paused"
    );
    Ok(())
}

// DOM ROLE SEEDING (owner-ONLY foundation) — the DOM_PAUSER/DOM_MANAGER members are seeded + valid
// ================================================================================================

/// The test-side role seeding matches the shape the production builder seeds.
///
/// Several suites — the pause rejects, the non-owner setter reject below — run against a support
/// harness that installs its own role-seeding component rather than the production builder. Those
/// tests are only meaningful while the replica seeds the same thing production does, and nothing
/// else checks that. So this reads the replica's storage directly and pins all three facts: the
/// Domain Pauser role is administered by the Domain Manager (one member, admin role = Domain
/// Manager), the Domain Manager is administered by the built-in admin role (one member, admin role
/// 0), and both memberships are present. The equivalent assertions against a production-built
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
    // role — that delegation is what lets the Manager rotate the Pauser without owner involvement.
    // The Domain Manager itself records admin role 0, the built-in admin role, whose membership the
    // builder seeds on the owner's account. Note that this admin membership is bound to that
    // ACCOUNT, not to whoever currently holds ownership: transferring ownership does not move it,
    // so an ownership handover has to re-seat the role explicitly.
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
        "DOM_MANAGER admin_role == 0 (resolves to ADMIN = the seeded owner account)"
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
