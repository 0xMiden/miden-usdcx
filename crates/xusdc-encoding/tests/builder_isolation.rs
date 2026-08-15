//! Capability isolation for the transfer-blocklist administrator, enforced when the account is
//! built.
//!
//! The account that may block transfers is meant to be an external party — a compliance function —
//! and it must hold no other privilege over the faucet. Concentrating blocking power in an account
//! that can also pause, rotate roles, or spend would defeat the separation the blocklist exists to
//! provide, in both directions: the blocklist admin must not gain other powers, and the other
//! admins must not gain blocking power.
//!
//! Rather than trusting deployment to get this right, `build_components` refuses to compose an
//! account at all when the blocklist manager collides with the administrator, the Domain Pauser, or the
//! Domain Manager. These tests pin each refusal and the specific error naming the collided role.
//! (They live apart from `builder_api.rs` only to keep that file within its size ceiling.)

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use rstest::rstest;
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError,
};

// The production builder seeds owner = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3), BLOCK_LISTER =
// id(4). A BLOCK_LISTER holder equal to id(1)/(2)/(3) collides with the administrator/DOM_PAUSER/DOM_MANAGER.

/// A blocklist manager that collides with any privileged identity is rejected at build time, with
/// an error naming which one it collided with.
///
/// Naming the role matters operationally: a generic "invalid configuration" would leave a deployer
/// guessing which of the three accounts they reused. The three collisions are parametrized rather
/// than copy-pasted.
#[rstest]
#[case::administrator(test_account_id(1), "ADMIN")]
#[case::dom_pauser(test_account_id(2), "DOM_PAUSER")]
#[case::dom_manager(test_account_id(3), "DOM_MANAGER")]
fn build_rejects_block_lister_colliding_with_a_privileged_role(
    #[case] block_lister: AccountId,
    #[case] expected_role: &str,
) -> Result<()> {
    let err = XReserveStablecoinBuilder::builder()
        .max_supply(AssetAmount::new(1_000_000).context("valid max supply")?)
        .token_supply(AssetAmount::new(0).context("valid token supply")?)
        .owner(test_account_id(1))
        .pauser_holder(test_account_id(2))
        .manager_holder(test_account_id(3))
        .block_lister_holder(block_lister)
        .fee_faucet_id(test_fee_faucet_id())
        .fee_policy(test_fee_policy())
        .domain(TEST_DOMAIN)
        .source_domain(TEST_SOURCE_DOMAIN)
        .xreserve_contract(test_xreserve_contract())
        .build()
        .context("the fixed-identity USDCx faucet builds")?
        .build_components()
        .expect_err("a BLOCK_LISTER holder colliding with a privileged role must be rejected");
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

/// POSITIVE: with the `BLOCK_LISTER` holder DISTINCT from owner/DOM_PAUSER/DOM_MANAGER, the build
/// succeeds — the isolation guard does not reject a properly external administrator.
#[test]
fn build_accepts_isolated_block_lister() -> Result<()> {
    XReserveStablecoinBuilder::builder()
        .max_supply(AssetAmount::new(1_000_000).context("valid max supply")?)
        .token_supply(AssetAmount::new(0).context("valid token supply")?)
        .owner(test_account_id(1))
        .pauser_holder(test_account_id(2))
        .manager_holder(test_account_id(3))
        .block_lister_holder(test_account_id(4)) // distinct external BLOCK_LISTER
        .fee_faucet_id(test_fee_faucet_id())
        .fee_policy(test_fee_policy())
        .domain(TEST_DOMAIN)
        .source_domain(TEST_SOURCE_DOMAIN)
        .xreserve_contract(test_xreserve_contract())
        .build()
        .context("the fixed-identity USDCx faucet builds")?
        .build_components()
        .context("a properly isolated BLOCK_LISTER holder must build")?;
    Ok(())
}
