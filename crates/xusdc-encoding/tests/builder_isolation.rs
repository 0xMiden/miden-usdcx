//! `build_components` refuses a DOM_PAUSER holder that holds any other role.
//! It also isolates BLK_MANAGER from every other holder; ADMIN, ATTEST_ADMIN and DOM_UNPAUSER may overlap.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use rstest::rstest;
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError,
};

fn builder_with_holders(
    attest_admin: AccountId,
    pauser: AccountId,
    unpauser: AccountId,
    blk_manager: AccountId,
) -> Result<XReserveStablecoinBuilder> {
    XReserveStablecoinBuilder::builder()
        .token_supply(AssetAmount::new(0).context("valid token supply")?)
        .owner(test_account_id(1))
        .attest_admin_holder(attest_admin)
        .pauser_holder(pauser)
        .unpauser_holder(unpauser)
        .blocklist_manager_holder(blk_manager)
        .fee_parameters(test_fee_parameters())
        .domain(TEST_DOMAIN)
        .build()
        .context("the fixed-identity USDCx faucet builds")
}

/// Every blocklist-holder collision is rejected with the offending role named.
#[rstest]
#[case::administrator(test_account_id(1), "ADMIN")]
#[case::attest_admin(test_account_id(5), "ATTEST_ADMIN")]
#[case::dom_pauser(test_account_id(2), "DOM_PAUSER")]
#[case::dom_unpauser(test_account_id(3), "DOM_UNPAUSER")]
fn build_rejects_blk_manager_colliding_with_a_privileged_role(
    #[case] blk_manager: AccountId,
    #[case] expected_role: &str,
) -> Result<()> {
    let err = builder_with_holders(
        test_account_id(5),
        test_account_id(2),
        test_account_id(3),
        blk_manager,
    )?
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

/// A pause holder cannot also carry a higher-consequence role.
#[rstest]
#[case::administrator(test_account_id(1), "ADMIN")]
#[case::attest_admin(test_account_id(5), "ATTEST_ADMIN")]
#[case::dom_unpauser(test_account_id(3), "DOM_UNPAUSER")]
fn build_rejects_dom_pauser_colliding_with_any_other_holder(
    #[case] pauser: AccountId,
    #[case] expected_role: &str,
) -> Result<()> {
    let err = builder_with_holders(
        test_account_id(5),
        pauser,
        test_account_id(3),
        test_account_id(4),
    )?
    .build_components()
    .expect_err("a DOM_PAUSER holder colliding with another role must be rejected");
    match err {
        XReserveStablecoinBuilderError::PauserNotIsolated { collides_with } => {
            assert_eq!(
                collides_with, expected_role,
                "the rejection must name the collided role"
            );
        }
        other => panic!("expected PauserNotIsolated{{{expected_role}}}, got {other:?}"),
    }
    Ok(())
}

/// Isolated pause/blocklist holders build while ADMIN and ATTEST_ADMIN share the owner account.
#[test]
fn build_accepts_isolated_blk_manager() -> Result<()> {
    builder_with_holders(
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
    )?
    .build_components()
    .context("a properly isolated BLK_MANAGER holder must build")?;
    Ok(())
}
