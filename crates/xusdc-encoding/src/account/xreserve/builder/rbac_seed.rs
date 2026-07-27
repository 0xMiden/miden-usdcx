//! `seeded_dom_roles_rbac` — hand-builds the seeded `RoleBasedAccessControl`
//! component for the xUSDC faucet, moved verbatim from the builder module
//! to satisfy the file-size gate.

use miden_protocol::account::{
    AccountComponent, AccountId, RoleSymbol, StorageMap, StorageMapKey, StorageSlot,
};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::RoleBasedAccessControl;

use super::{BLK_MANAGER_ROLE, DOM_MANAGER_ROLE, DOM_PAUSER_ROLE};

/// Hand-builds the seeded `RoleBasedAccessControl` `AccountComponent` with the two Circle Domain
/// role members — `DOM_PAUSER` (→ `pauser_holder`) and `DOM_MANAGER` (→ `manager_holder`) — the
/// F4-reversal `BLK_MANAGER` transfer-blocklist administrator (→ `blocklist_manager_holder`, whose
/// admin resolves to the built-in `ADMIN` so the owner rotates/revokes it via the existing
/// grant/revoke notes; capability-isolated — it can ONLY block/unblock), plus,
/// since the v16 migration (#3215 removed the Ownable2Step owner's implicit super-admin standing
/// over the role graph; MIGRATION-V16-ALPHA2.md S2, operator-approved 2026-07-13), the stock
/// `ADMIN` role seeded with the OWNER's account as its single member. `ADMIN` is the built-in
/// default admin role (`rbac.masm`): a role whose delegated admin is unset resolves to it, so
/// this seed preserves the ratified owner-administers-roles model — the owner-held account
/// administers `DOM_MANAGER` (grant/revoke), now via its `ADMIN` membership rather
/// than owner status (NO new capability: `ADMIN` resolves to the same owner account). This seed
/// is the ENTIRE role-admin graph the faucet will ever have: the runtime `set_role_admin` note is
/// not allowlisted (S21 flip, 2026-07-14), so `role_config[*].admin_role` is immutable
/// post-deploy. KNOWN
/// DIVERGENCE (documented, operator-approved): after `transfer_ownership`/`accept_ownership`,
/// `ADMIN` membership does not auto-follow — the rotation runbook grants `ADMIN` to the new
/// owner and revokes the old one via the existing grant/revoke admin notes.
///
/// Both stock RBAC maps are direct-seeded at build, consistent with the stock procs' post-state
/// for a single first grant per role — `role_membership[{0, <role>, holder.suffix,
/// holder.prefix}] = [1,0,0,0]` AND `role_config[{0,0,0,DOM_PAUSER}] = [member_count=1,
/// admin_role=DOM_MANAGER, 0, 0]` (the CMP-F5 delegation: the Domain Manager rotates the Pauser)
/// while `role_config[{0,0,0,DOM_MANAGER}] = [1, 0, 0, 0]` and `role_config[{0,0,0,ADMIN}] =
/// [1, 0, 0, 0]` (admin_role = 0 → resolves to the built-in `ADMIN`; `ADMIN` is thereby
/// self-administered). It reuses the stock RBAC code + slot names + component metadata verbatim
/// (NO custom RBAC logic); only the maps are non-empty (the stock `From<RoleBasedAccessControl>`
/// seeds them empty). The key encodings mirror the stock readers. `grant_role` is NOT used (it
/// would add a tx). Seed correctness is locked by the `shipped_delegation_reads_back` +
/// rotation-seam + ADMIN-gating tests, not by construction (`AccountComponent::new` does not
/// validate slots against the metadata schema). Construction failures are invariants, so this
/// mirrors the stock `.expect()` pattern.
pub(super) fn seeded_dom_roles_rbac(
    owner: AccountId,
    pauser_holder: AccountId,
    manager_holder: AccountId,
    blocklist_manager_holder: AccountId,
) -> AccountComponent {
    let pauser =
        RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol (≤12)");
    let manager =
        RoleSymbol::new(DOM_MANAGER_ROLE).expect("DOM_MANAGER is a fixed valid role symbol (≤12)");
    let blk_manager =
        RoleSymbol::new(BLK_MANAGER_ROLE).expect("BLK_MANAGER is a fixed valid role symbol (≤12)");
    let admin = RoleBasedAccessControl::admin_role();
    // [1,0,0,0]: role_config member_count = 1 (admin_role = 0 → the built-in ADMIN), and
    // role_membership is_member = 1.
    let member_word = Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    // [1, DOM_MANAGER, 0, 0]: member_count = 1 with administration delegated to DOM_MANAGER (CMP-F5).
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
                Felt::from(&blk_manager),
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
                Felt::from(&blk_manager),
                blocklist_manager_holder.suffix(),
                blocklist_manager_holder.prefix().as_felt(),
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
