//! F4 basic-asset tripwire — locks in the human decision (2026-07-08) that xUSDC ships as a
//! BASIC, transfer-free fungible asset: the production faucet composition registers NO send/receive
//! transfer policy, so minted xUSDC carries `AssetCallbackFlag::Disabled` and holder-to-holder
//! transfers are unpoliced — behaviourally identical to Circle's reference `USDCx.sol`.
//!
//! This test is GREEN on the shipped build and flips RED the moment anyone wires a transfer policy
//! (`with_send_policy` / `with_receive_policy`, Active OR Reserved) into `build_components`.
//! Registering a policy would (a) insert its root into an `allowed_{send,receive}_policy_proc_roots`
//! map and (b) install the protocol asset-callback slots — this test asserts BOTH are absent, so
//! either facet of a wire trips it. It is the executable half of the decision record; the prose half
//! is the `build_components` comment in `builder.rs`. See
//! `circle-integration/07-implementation-readiness/DECISION-F4-BASIC-ASSET-NO-TRANSFER-POLICY.md`.
//!
//! Why absence-of-callback-slots proves callback-DISABLED minting: `faucet::has_callbacks`
//! (protocol `faucet.masm`) returns 1 only when a callback storage slot is present AND non-empty;
//! with no transfer policy the manager omits those slots entirely, so `create_fungible_asset`
//! stamps `AssetCallbackFlag::Disabled` on every minted asset — no foreign-account (FPI) dispatch on
//! any transfer/consume.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::{
    AccountComponent, StorageMap, StorageSlot, StorageSlotContent, StorageSlotName,
};
use miden_protocol::asset::AssetCallbacks;
use miden_standards::account::policies::TokenPolicyManager;
use support::production_component_set;

const MAX_SUPPLY: u64 = 1_000_000;

/// First storage slot named `name` across the whole composed component set, if any.
fn find_slot<'a>(
    components: &'a [AccountComponent],
    name: &StorageSlotName,
) -> Option<&'a StorageSlot> {
    components.iter().flat_map(|c| c.storage_slots().iter()).find(|s| s.name() == name)
}

/// The `StorageMap` backing a map slot the manager always registers (the allowed-policy maps exist
/// on every build, empty until a policy is registered).
fn map_slot<'a>(
    components: &'a [AccountComponent],
    name: &StorageSlotName,
) -> Result<&'a StorageMap> {
    let slot = find_slot(components, name)
        .with_context(|| format!("the policy manager must register the '{name}' slot"))?;
    match slot.content() {
        StorageSlotContent::Map(map) => Ok(map),
        StorageSlotContent::Value(_) => anyhow::bail!("'{name}' must be a MAP slot"),
    }
}

/// TRIPWIRE: the production faucet composition registers NO transfer policy — neither the
/// `allowed_{send,receive}_policy_proc_roots` maps carry a root, nor are the protocol
/// asset-callback slots installed. Wiring any send/receive policy (Active or Reserved) flips this
/// RED. Do not "fix" it by adding a policy — read the module docs and the decision record.
#[test]
fn production_build_registers_no_transfer_policy() -> Result<()> {
    let components = production_component_set(MAX_SUPPLY, 0)?;

    // (1) No send/receive transfer policy is registered: the allowed-roots maps are EMPTY. A wire —
    // even a Reserved one that never becomes active — inserts its root here.
    let send = map_slot(&components, TokenPolicyManager::allowed_send_policies_slot())?;
    let receive = map_slot(&components, TokenPolicyManager::allowed_receive_policies_slot())?;
    assert_eq!(
        send.num_entries(),
        0,
        "a SEND transfer policy has been wired into build_components — xUSDC must ship transfer-free \
         (basic asset). See DECISION-F4-BASIC-ASSET-NO-TRANSFER-POLICY.md before changing this."
    );
    assert_eq!(
        receive.num_entries(),
        0,
        "a RECEIVE transfer policy has been wired into build_components — xUSDC must ship \
         transfer-free (basic asset). See DECISION-F4-BASIC-ASSET-NO-TRANSFER-POLICY.md."
    );

    // (2) No protocol asset-callback slots are installed → `faucet::has_callbacks` returns 0 → every
    // minted xUSDC carries AssetCallbackFlag::Disabled (no FPI dispatch on transfer/consume).
    assert!(
        find_slot(&components, AssetCallbacks::on_before_asset_added_to_note_slot()).is_none(),
        "the on_before_asset_added_to_note callback slot is installed — a transfer policy was wired; \
         minted xUSDC would be a POLICED asset. xUSDC must stay callback-disabled (basic asset)."
    );
    assert!(
        find_slot(&components, AssetCallbacks::on_before_asset_added_to_account_slot()).is_none(),
        "the on_before_asset_added_to_account callback slot is installed — a transfer policy was \
         wired; minted xUSDC would be a POLICED asset. xUSDC must stay callback-disabled."
    );
    Ok(())
}
