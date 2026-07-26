//! F4-REVERSAL capability-isolation suite for `XReserveStablecoinBuilder` (split out of
//! `builder_api.rs` for the G3 file-size ceiling). The transfer-blocklist administrator
//! (`blocklist_manager_holder`, the seeded `BLK_MANAGER` member) MUST be an EXTERNAL entity with NO
//! other faucet-admin capability. `build_components` rejects a `BLK_MANAGER` holder that collides with
//! the owner, the `DOM_PAUSER` holder, or the `DOM_MANAGER` holder — packaging cannot ship a faucet
//! whose blocklist admin also holds another privileged role (two-way capability isolation).

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent, AccountId, StorageMap, StorageSlot, StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::Word;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use rstest::rstest;
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError,
};

// Dummy faucet config words (the builder does not read them; they only bind the xreserve component's
// value slots so it assembles). Mirrors `builder_api.rs`.
const DUMMY_DOMAIN: u32 = 7;

/// The SEVEN required xreserve slot labels (the builder's slot-presence guard).
const ALL_XRESERVE_SLOT_LABELS: [&str; 7] = [
    DOMAIN_CONFIG_SLOT_LABEL,
    IDENTIFIER_CONFIG_SLOT_LABEL,
    SOURCE_DOMAIN_CONFIG_SLOT_LABEL,
    XRESERVE_CONTRACT_HI_SLOT_LABEL,
    XRESERVE_CONTRACT_LO_SLOT_LABEL,
    USED_NONCES_SLOT_LABEL,
    XRESERVE_ATTESTERS_SLOT_LABEL,
];

/// Assembles the xreserve component carrying exactly `labels` (the composition fixture; the two
/// well-known map labels get empty maps, the domain/identifier pair a dummy word).
fn xreserve_component_with_slots(labels: &[&str]) -> Result<AccountComponent> {
    let library = assemble_xreserve_lib()?;
    let mut slots = Vec::new();
    for label in labels {
        let name = StorageSlotName::new(*label).with_context(|| format!("slot label {label}"))?;
        let slot = match *label {
            USED_NONCES_SLOT_LABEL | XRESERVE_ATTESTERS_SLOT_LABEL => {
                StorageSlot::with_map(name, StorageMap::new())
            }
            l if l == DOMAIN_CONFIG_SLOT_LABEL => {
                StorageSlot::with_value(name, Word::from([DUMMY_DOMAIN, 0, 0, 0]))
            }
            l if l == IDENTIFIER_CONFIG_SLOT_LABEL => {
                StorageSlot::with_value(name, Word::from([11u32, 12, 13, 14]))
            }
            _ => StorageSlot::with_value(name, Word::from([0u32, 0, 0, 0])),
        };
        slots.push(slot);
    }
    AccountComponent::new(
        library,
        slots,
        AccountComponentMetadata::new("xusdc-builder-isolation-xreserve"),
    )
    .context("binding the xreserve library + composition slots as a component")
}

/// Builds a `FungibleFaucet` with the shipped token config (`decimals=6`, the `USDCX` symbol guard).
fn production_faucet(is_max_supply_mutable: bool) -> Result<FungibleFaucet> {
    FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(1_000_000).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(0).context("invalid token_supply")?)
        .is_max_supply_mutable(is_max_supply_mutable)
        .build()
        .context("failed to build FungibleFaucet")
}

/// A fresh `(FungibleFaucet, AccountComponent)` pair — the two inputs `new` consumes by value.
fn faucet_and_component(is_max_supply_mutable: bool) -> Result<(FungibleFaucet, AccountComponent)> {
    Ok((
        production_faucet(is_max_supply_mutable)?,
        xreserve_component_with_slots(&ALL_XRESERVE_SLOT_LABELS)?,
    ))
}

// The production builder seeds owner = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3), BLK_MANAGER =
// id(4). A BLK_MANAGER holder equal to id(1)/(2)/(3) collides with the owner/DOM_PAUSER/DOM_MANAGER.

/// A `BLK_MANAGER` holder colliding with a privileged identity (owner / DOM_PAUSER / DOM_MANAGER) is
/// rejected at build time with the SPECIFIC error naming the collided role — the two-way capability
/// isolation the F4-reversal decision requires. Parametrized over the three collisions (G4 /
/// parametrize-related-tests).
#[rstest]
#[case::owner(test_account_id(1), "owner")]
#[case::dom_pauser(test_account_id(2), "DOM_PAUSER")]
#[case::dom_manager(test_account_id(3), "DOM_MANAGER")]
fn build_rejects_blk_manager_colliding_with_a_privileged_role(
    #[case] blk_manager: AccountId,
    #[case] expected_role: &str,
) -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(false)?;
    let err = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1), // owner
        test_account_id(2), // DOM_PAUSER
        test_account_id(3), // DOM_MANAGER
        blk_manager,
    )
    .build_components()
    .expect_err("a BLK_MANAGER holder colliding with a privileged role must be rejected");
    match err {
        XReserveStablecoinBuilderError::BlocklistManagerNotIsolated { collides_with } => {
            assert_eq!(
                collides_with, expected_role,
                "the rejection must name the collided privileged role"
            );
        }
        other => panic!("expected BlocklistManagerNotIsolated{{{expected_role}}}, got {other:?}"),
    }
    Ok(())
}

/// POSITIVE: with the `BLK_MANAGER` holder DISTINCT from owner/DOM_PAUSER/DOM_MANAGER, the build
/// succeeds — the isolation guard does not reject a properly external administrator.
#[test]
fn build_accepts_isolated_blk_manager() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4), // distinct external BLK_MANAGER
    )
    .build_components()
    .context("a properly isolated BLK_MANAGER holder must build")?;
    Ok(())
}
