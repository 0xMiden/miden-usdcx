//! The one account this tool builds: the genesis xUSDC faucet.

use anyhow::{Context, Result};
use miden_protocol::account::Account;
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::FeeParameters;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

use crate::config::{GenesisToolConfig, Role};

/// Builds the genesis faucet from the validated config.
///
/// The role-account ids are provided in the config; this tool builds nothing else. The faucet is
/// built as the native fee faucet — its fee parameters carry the OPERATOR's id during the seed
/// grind, rebound to the faucet's own asset by `build_genesis_account` — and comes out in
/// genesis form: nonce one, no seed. Role-collision rules are enforced by the builder.
pub fn build_faucet(config: &GenesisToolConfig) -> Result<Account> {
    let faucet_config = &config.faucet;
    let fee_parameters = FeeParameters::new(
        config.role_id(Role::Operator),
        faucet_config.verification_base_fee,
    );
    let min_burn_amount = faucet_config
        .min_burn_amount
        .map(AssetAmount::new)
        .transpose()
        .context("min_burn_amount is not a valid asset amount")?;
    XReserveStablecoinBuilder::builder()
        .max_supply(AssetAmount::new(faucet_config.max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(faucet_config.token_supply).context("invalid token_supply")?)
        .owner(config.role_id(Role::Owner))
        .attest_admin_holder(config.role_id(Role::AttestAdmin))
        .pauser_holder(config.role_id(Role::Pauser))
        .unpauser_holder(config.role_id(Role::Unpauser))
        .blocklist_manager_holder(config.role_id(Role::BlocklistManager))
        .fee_parameters(fee_parameters)
        .domain(faucet_config.domain)
        .maybe_min_burn_amount(min_burn_amount)
        .build()
        .context("composing the xUSDC faucet builder")?
        .build_genesis_account(faucet_config.seed.as_bytes())
        .context("building the genesis faucet account")
}
