//! `seeded_dom_roles_rbac` — hand-builds the seeded `RoleBasedAccessControl`
//! component for the xUSDC faucet.

use miden_protocol::account::{
    AccountComponent, AccountId, RoleSymbol, StorageMap, StorageMapKey, StorageSlot,
};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::RoleBasedAccessControl;

use super::{BLOCK_LISTER_ROLE, DOM_MANAGER_ROLE, DOM_PAUSER_ROLE};

/// Hand-builds the seeded `RoleBasedAccessControl` `AccountComponent` with four memberships:
///
/// * `DOM_PAUSER` (→ `pauser_holder`) and `DOM_MANAGER` (→ `manager_holder`), the two Circle
///   Domain roles.
/// * `BLOCK_LISTER` (→ `block_lister_holder`), the transfer-blocklist administrator. It is
///   capability-isolated — the holder can ONLY block and unblock — and its admin resolves to the
///   built-in `ADMIN`, so the administrator rotates or revokes it through the standard role-action
///   note.
/// * the stock `ADMIN` role, whose single member is the bootstrap administrator's account.
///
/// Seeding `ADMIN` with the administrator's account is what grants it role administration. `ADMIN`
/// is the built-in default admin role (`rbac.masm`) that any role with no delegated admin resolves
/// to, so this seed gives that one account authority over `DOM_MANAGER` and `BLOCK_LISTER` — and,
/// since the faucet installs no ownership component, `ADMIN` membership is the account's ONLY
/// authority handle.
///
/// This seed is the STARTING role-admin graph, not a permanent one. The standard role-action note
/// is allowlisted, and its single script root carries `set_role_admin` alongside grant and revoke,
/// so `role_config[*].admin_role` is runtime-mutable: each role's effective admin may re-point the
/// role it administers, and because delegation is exclusive, `ADMIN` cannot re-point, grant or
/// revoke `DOM_PAUSER` — `DOM_MANAGER` governs it exclusively. Rotating the administrator itself is
/// a grant of `ADMIN` to the incoming account and a revoke from the outgoing one, through that same
/// note.
///
/// Both stock RBAC maps are direct-seeded at build, matching the stock procs' post-state for a
/// single first grant per role — `role_membership[{0, <role>, holder.suffix, holder.prefix}] =
/// [1,0,0,0]` and `role_config[{0,0,0,DOM_PAUSER}] = [member_count=1, admin_role=DOM_MANAGER, 0, 0]`
/// (the seeded delegation: the Domain Manager rotates the Pauser), while
/// `role_config[{0,0,0,DOM_MANAGER}]` and `role_config[{0,0,0,ADMIN}]` are `[1, 0, 0, 0]`
/// (admin_role = 0 → resolves to the built-in `ADMIN`, so `ADMIN` is self-administered). It reuses
/// the stock RBAC code, slot names, and component metadata verbatim, and only the maps differ from
/// the stock `From<RoleBasedAccessControl>` impl, which seeds them empty. Note that
/// `AccountComponent::new` does not validate slots against the metadata schema, so a malformed seed
/// would not be caught here. Construction failures are invariants, so this mirrors the stock
/// `.expect()` pattern.
pub(super) fn seeded_dom_roles_rbac(
    owner: AccountId,
    pauser_holder: AccountId,
    manager_holder: AccountId,
    block_lister_holder: AccountId,
) -> AccountComponent {
    let pauser =
        RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol (≤12)");
    let manager =
        RoleSymbol::new(DOM_MANAGER_ROLE).expect("DOM_MANAGER is a fixed valid role symbol (≤12)");
    let block_lister = RoleSymbol::new(BLOCK_LISTER_ROLE)
        .expect("BLOCK_LISTER is a fixed valid role symbol (≤12)");
    let admin = RoleBasedAccessControl::admin_role();
    // [1,0,0,0]: role_config member_count = 1 (admin_role = 0 → the built-in ADMIN), and
    // role_membership is_member = 1.
    let member_word = Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    // [1, DOM_MANAGER, 0, 0]: member_count = 1 with administration delegated to DOM_MANAGER.
    let delegated_config_word = Word::from([
        Felt::from(1u32),
        Felt::from(&manager),
        Felt::ZERO,
        Felt::ZERO,
    ]);

    let role_config = StorageMap::with_entries([
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&pauser),
            ])),
            delegated_config_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&manager),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&admin),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&block_lister),
            ])),
            member_word,
        ),
    ])
    .expect("the four-role role_config seed is valid");

    let role_membership = StorageMap::with_entries([
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&pauser),
                pauser_holder.suffix(),
                pauser_holder.prefix().as_felt(),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&manager),
                manager_holder.suffix(),
                manager_holder.prefix().as_felt(),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&admin),
                owner.suffix(),
                owner.prefix().as_felt(),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&block_lister),
                block_lister_holder.suffix(),
                block_lister_holder.prefix().as_felt(),
            ])),
            member_word,
        ),
    ])
    .expect("the four-role role_membership seed is valid");

    AccountComponent::new(
        RoleBasedAccessControl::code().clone(),
        vec![
            StorageSlot::with_map(
                RoleBasedAccessControl::role_config_slot().clone(),
                role_config,
            ),
            StorageSlot::with_map(
                RoleBasedAccessControl::role_membership_slot().clone(),
                role_membership,
            ),
        ],
        RoleBasedAccessControl::component_metadata(),
    )
    .expect("the seeded DOM-roles RBAC component mirrors the stock From impl and is valid")
}
