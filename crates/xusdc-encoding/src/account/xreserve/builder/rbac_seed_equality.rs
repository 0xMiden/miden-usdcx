//! D5 byte-equality probe (test-only): proves the stock RBAC seeding builder used by
//! [`super::seeded_dom_roles_rbac`] is byte-identical to the retired hand-rolled direct-seed. Lives
//! in its own module/file (G3) rather than inline with the builder; it reaches the production helper
//! through `super::`.

use miden_protocol::account::{
    AccountIdVersion, AccountType, AssetCallbackFlag, StorageMap, StorageMapKey,
};

use super::*;

/// A deterministic dummy `AccountId` for the probe's role holders (the `testing` feature is on).
fn dummy_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

/// A FROZEN copy of the retired hand-rolled direct-seed: it direct-seeds both stock RBAC maps
/// (`role_config` and `role_membership`) with the four roles and their memberships, reusing the
/// stock RBAC code, slot names and metadata verbatim. It is the independent oracle the probe below
/// measures the stock builder against; it must NOT be "simplified" to call the builder, or the
/// equality proof becomes circular.
fn hand_rolled_seed(
    owner: AccountId,
    pauser_holder: AccountId,
    manager_holder: AccountId,
    blocklist_manager_holder: AccountId,
) -> AccountComponent {
    let pauser = RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role");
    let manager = RoleSymbol::new(DOM_MANAGER_ROLE).expect("DOM_MANAGER is a fixed valid role");
    let blk_manager = RoleSymbol::new(BLK_MANAGER_ROLE).expect("BLK_MANAGER is a fixed valid role");
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
    .expect("the frozen hand-rolled DOM-roles RBAC component is valid")
}

/// D5 byte-equality probe: the stock RBAC seeding builder produces a component byte-identical to the
/// hand-rolled direct-seed. `AccountComponent`, `StorageSlot` and `StorageMap` derive
/// order-independent `PartialEq` (the maps are an SMT plus a key-sorted `BTreeMap`), so the
/// whole-component `assert_eq!` compares code, slots (in order), maps (entry for entry, key and
/// value) and metadata by CONTENT — insertion order does not matter. This proves the adoption moves
/// no storage (so the account commitment stays unmoved); kept, it is a regression guard against
/// upstream drift in the seeding.
#[test]
fn stock_builder_seed_is_byte_equal() {
    let (owner, pauser, manager, blk) = (dummy_id(1), dummy_id(2), dummy_id(3), dummy_id(4));

    let hand_rolled = hand_rolled_seed(owner, pauser, manager, blk);
    let via_builder = seeded_dom_roles_rbac(owner, pauser, manager, blk);

    // slot set + ORDER: same number of slots, same name and content position by position.
    assert_eq!(
        hand_rolled.storage_slots().len(),
        via_builder.storage_slots().len(),
        "same number of storage slots",
    );
    for (hand_slot, builder_slot) in hand_rolled
        .storage_slots()
        .iter()
        .zip(via_builder.storage_slots())
    {
        assert_eq!(
            hand_slot, builder_slot,
            "slot name, kind and map contents match in the same order",
        );
    }

    // component metadata (name, description, storage schema).
    assert_eq!(
        hand_rolled.metadata(),
        via_builder.metadata(),
        "component metadata matches",
    );

    // the whole component — code, slots and metadata together — is byte-equal.
    assert_eq!(
        hand_rolled, via_builder,
        "the stock RBAC seeding builder is byte-equal to the hand-rolled direct-seed",
    );
}
