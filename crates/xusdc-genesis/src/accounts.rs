//! The one account this tool builds: the genesis xUSDC faucet.

use anyhow::{Context, Result};
use miden_protocol::account::{
    Account, AccountId, AccountIdVersion, AccountType, AssetCallbackFlag,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::FeeParameters;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

use crate::config::GenesisToolConfig;

/// The dummy fee faucet id the fee parameters carry while the faucet's own id is derived.
fn placeholder_fee_faucet_id() -> AccountId {
    AccountId::dummy(
        [0; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// Builds the genesis faucet from the config, with the supply cap at [`AssetAmount::MAX`].
pub fn build_faucet(config: &GenesisToolConfig) -> Result<Account> {
    let faucet_config = &config.faucet;
    let fee_parameters = FeeParameters::new(
        placeholder_fee_faucet_id(),
        faucet_config.verification_base_fee,
    );
    let min_burn_amount = faucet_config
        .min_burn_amount
        .map(AssetAmount::new)
        .transpose()
        .context("min_burn_amount is not a valid asset amount")?;
    XReserveStablecoinBuilder::builder()
        .max_supply(AssetAmount::MAX)
        .token_supply(faucet_config.token_supply)
        .owner(config.accounts.owner)
        .attest_admin_holders(config.accounts.attest_admins.clone())
        .pauser_holders(config.accounts.pausers.clone())
        .unpauser_holders(config.accounts.unpausers.clone())
        .blocklist_manager_holders(config.accounts.blocklist_managers.clone())
        .fee_parameters(fee_parameters)
        .domain(faucet_config.domain)
        .attesters(faucet_config.attesters.clone())
        .maybe_min_burn_amount(min_burn_amount)
        .build()
        .context("composing the xUSDC faucet builder")?
        .build_genesis_account(faucet_config.seed, &faucet_config.used_nonces)
        .context("building the genesis faucet account")
}
