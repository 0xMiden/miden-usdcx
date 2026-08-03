//! The PROVISIONAL fee-configuration pin: the faucet's fee-policy storage holds exactly the
//! zero-fee placeholder configuration it is composed with, and nothing else.
//!
//! Every `AuthNetworkAccount` requires a `FeePolicyManager` — an active fee policy plus the
//! fee-asset faucet id — with no none-variant. Fee economics for
//! the keyless xReserve faucet are a Circle-owned OPEN decision, so the composition pins a
//! PROVISIONAL configuration: the stock `BasicConstantFeePolicy` charging an EXPLICIT ZERO fee
//! for every note script the account can consume (the auth procedure prices EVERY input note
//! through the active policy, and an unscheduled root aborts consumption — so "zero fee" means a
//! zero entry per allowlisted root, not an empty schedule), in the asset of a placeholder faucet
//! id that deploy-time configuration must replace. The whole configuration is inert on MockChain:
//! the verification base fee is 0, so no fee note is ever created, and every admissible note
//! prices to 0, so no sponsorship is ever required.
//!
//! Because the configuration is provisional, this file pins it exactly, so that replacing it is a
//! deliberate act: any drift — a different active policy, an extra allowed policy, a nonzero or
//! missing schedule entry, a changed fee-asset id — is RED.

mod support;

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use miden_protocol::account::{AccountComponent, AccountId, StorageSlotContent, StorageSlotName};
use miden_protocol::asset::AssetId;
use miden_protocol::{Felt, Word};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

/// The faucet max supply used by the production-faucet fixture (mirrors the sibling suites).
const MAX_SUPPLY: u64 = 1_000_000;

/// Independent duplicate of the placeholder fee-faucet id the production builder pins
/// (`XReserveStablecoinBuilder::TBD_DEPLOY_FEE_FAUCET_ID_HEX`). Duplicated HERE as a literal so a
/// silent change of the builder constant cannot re-pin this test along with it — drift between
/// the two copies is RED.
const EXPECTED_TBD_DEPLOY_FEE_FAUCET_ID_HEX: &str = "0xaaaaaaaaaaaaaa112aaaaaaaaaaaaa";

/// The upstream `FeePolicyManager` encoding of an allowed fee-policy map entry.
fn allowed_flag() -> Word {
    Word::from([1u32, 0, 0, 0])
}

/// The upstream `BasicConstantFeePolicy` encoding of a scheduled zero fee: the asset value word
/// with the set-marker element (`[fee_amount = 0, 0, 0, 1]`) — the marker distinguishes an
/// explicit zero-fee entry from an unset key (storage maps prune zero words).
fn zero_fee_entry() -> Word {
    Word::from([
        Felt::from(0u32),
        Felt::from(0u32),
        Felt::from(0u32),
        Felt::from(1u32),
    ])
}

/// The auth component + the fee-policy component of the production composition.
fn production_auth_components() -> Result<Vec<AccountComponent>> {
    Ok(XReserveStablecoinBuilder::auth_component()
        .map_err(|e| anyhow::anyhow!("auth_component() must build: {e}"))?
        .into_iter()
        .collect())
}

/// Reads the named VALUE slot's word from a component.
fn slot_value(component: &AccountComponent, slot: &StorageSlotName) -> Word {
    component
        .storage_slots()
        .iter()
        .find(|s| s.name() == slot)
        .unwrap_or_else(|| panic!("the component must carry the {slot} slot"))
        .value()
}

/// Reads the named MAP slot's non-empty entries from a component.
fn map_entries(component: &AccountComponent, slot: &StorageSlotName) -> BTreeMap<Word, Word> {
    let content = component
        .storage_slots()
        .iter()
        .find(|s| s.name() == slot)
        .unwrap_or_else(|| panic!("the component must carry the {slot} slot"))
        .content();
    let StorageSlotContent::Map(map) = content else {
        panic!("the {slot} slot must be a MAP slot");
    };
    map.entries()
        .filter(|(_key, value)| **value != Word::empty())
        .map(|(key, value)| (key.as_word(), *value))
        .collect()
}

/// The placeholder id itself: the builder constant parses to a valid account id and equals this
/// file's independent duplicate (drift between the two copies is RED).
#[test]
fn tbd_deploy_fee_faucet_id_is_pinned() {
    assert_eq!(
        XReserveStablecoinBuilder::TBD_DEPLOY_FEE_FAUCET_ID_HEX,
        EXPECTED_TBD_DEPLOY_FEE_FAUCET_ID_HEX,
        "the builder's placeholder fee-faucet id drifted from this pin"
    );
    AccountId::from_hex(EXPECTED_TBD_DEPLOY_FEE_FAUCET_ID_HEX)
        .expect("the placeholder fee-faucet id hex must parse as a valid account id");
}

/// Component layer: the auth component's three fee-policy slots hold EXACTLY the provisional
/// configuration — `BasicConstantFeePolicy` active, itself the only allowed policy, fees priced
/// in the placeholder faucet's asset.
#[test]
fn auth_component_fee_slots_hold_the_provisional_config() -> Result<()> {
    let components = production_auth_components()?;
    let auth = &components[0];

    assert_eq!(
        slot_value(auth, FeePolicyManager::active_fee_policy_slot()),
        BasicConstantFeePolicy::root().as_word(),
        "the ACTIVE fee policy must be the stock BasicConstantFeePolicy (provisional zero-fee)"
    );

    let allowed = map_entries(auth, FeePolicyManager::allowed_fee_policies_slot());
    let expected: BTreeMap<Word, Word> =
        BTreeMap::from([(BasicConstantFeePolicy::root().as_word(), allowed_flag())]);
    assert_eq!(
        allowed, expected,
        "the allowed fee-policy map must hold EXACTLY the BasicConstantFeePolicy root — a second \
         allowed policy would be a runtime path to different fee economics"
    );

    let tbd = AccountId::from_hex(EXPECTED_TBD_DEPLOY_FEE_FAUCET_ID_HEX)
        .expect("the placeholder fee-faucet id hex must parse");
    assert_eq!(
        slot_value(auth, FeePolicyManager::fee_asset_id_slot()),
        AssetId::new_fungible(tbd).to_word(),
        "the fee asset must be the PLACEHOLDER faucet's fungible asset (deploy-time \
         configuration replaces it — Circle owns the real fee economics)"
    );
    Ok(())
}

/// Policy layer: the `BasicConstantFeePolicy` component's fee schedule holds an EXPLICIT ZERO fee
/// for EXACTLY the 14 allowlisted note script roots — every note the account can consume is free,
/// and nothing else is scheduled. A nonzero entry, a missing entry, or an extra entry is RED
/// (this is the assert the fee-mutation demo flips).
#[test]
fn fee_schedule_is_zero_for_exactly_the_allowlisted_roots() -> Result<()> {
    let components = production_auth_components()?;
    let policy = components
        .iter()
        .find(|c| {
            c.storage_slots()
                .iter()
                .any(|s| s.name() == BasicConstantFeePolicy::fee_schedule_slot_name())
        })
        .context("the composition must yield the BasicConstantFeePolicy component")?;

    let schedule = map_entries(policy, BasicConstantFeePolicy::fee_schedule_slot_name());
    let expected: BTreeMap<Word, Word> = XReserveStablecoinBuilder::allowed_note_scripts()
        .iter()
        .map(|root| (root.as_word(), zero_fee_entry()))
        .collect();
    assert_eq!(
        schedule, expected,
        "the provisional fee schedule must hold an explicit ZERO fee for exactly the 14 \
         allowlisted note script roots (zero-fee provisional config; the revert slice replaces \
         it with Circle's ratified economics)"
    );
    Ok(())
}

/// On-chain layer: the BUILT production faucet's storage materializes the same four fee slots —
/// the executable tripwire the revert slice will flip.
#[test]
fn built_account_fee_storage_matches_the_provisional_config() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("the production faucet must be committed")?
        .clone();
    let storage = account.storage();

    assert_eq!(
        storage
            .get_item(FeePolicyManager::active_fee_policy_slot())
            .map_err(|e| anyhow::anyhow!("reading the active fee policy slot: {e}"))?,
        BasicConstantFeePolicy::root().as_word(),
        "on-chain ACTIVE fee policy must be the stock BasicConstantFeePolicy"
    );

    let tbd = AccountId::from_hex(EXPECTED_TBD_DEPLOY_FEE_FAUCET_ID_HEX)
        .expect("the placeholder fee-faucet id hex must parse");
    assert_eq!(
        storage
            .get_item(FeePolicyManager::fee_asset_id_slot())
            .map_err(|e| anyhow::anyhow!("reading the fee asset id slot: {e}"))?,
        AssetId::new_fungible(tbd).to_word(),
        "on-chain fee asset must be the placeholder faucet's fungible asset"
    );

    // No runtime path to different fee economics: the on-chain allowed-policy map holds EXACTLY
    // the active BasicConstantFeePolicy root — with no second allowed policy, the administrator-gated
    // `set_fee_policy` (direct-entry-unreachable: in neither allowlist) would have nothing to
    // switch to even if it were ever driven.
    let allowed_slot = storage
        .get(FeePolicyManager::allowed_fee_policies_slot())
        .context("the account must carry the allowed fee-policy map slot")?;
    let StorageSlotContent::Map(allowed_map) = allowed_slot.content() else {
        panic!("the allowed fee-policy slot must be a MAP slot");
    };
    let allowed: BTreeMap<Word, Word> = allowed_map
        .entries()
        .filter(|(_key, value)| **value != Word::empty())
        .map(|(key, value)| (key.as_word(), *value))
        .collect();
    assert_eq!(
        allowed,
        BTreeMap::from([(BasicConstantFeePolicy::root().as_word(), allowed_flag())]),
        "the on-chain allowed fee-policy map must hold EXACTLY the BasicConstantFeePolicy root \
         (a second allowed policy would be a runtime path to different fee economics)"
    );

    for root in XReserveStablecoinBuilder::allowed_note_scripts() {
        let entry = storage
            .get_map_item(
                BasicConstantFeePolicy::fee_schedule_slot_name(),
                miden_protocol::account::StorageMapKey::new(root.as_word()),
            )
            .map_err(|e| anyhow::anyhow!("reading a fee schedule entry: {e}"))?;
        assert_eq!(
            entry,
            zero_fee_entry(),
            "every allowlisted note script must carry an explicit on-chain ZERO fee entry"
        );
    }
    Ok(())
}
