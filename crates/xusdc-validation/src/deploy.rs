//! The production faucet composition + the account the harness deploys.
//!
//! EXACTLY the production shape, consumed by reference (single-owner rule — nothing here
//! re-implements the shared-encoding crate's encoding or the faucet component's composition):
//! - the `xreserve` faucet extension, whose MASM is assembled at build time by `xusdc-encoding` and
//!   embedded in the shipped `XReserveFaucetExtension` component. Its six slots are seeded by the
//!   builder: `domain`/`source_domain`/`xreserve_contract_{hi,lo}` from the required domain-config
//!   inputs, plus the two empty maps (the nonce registry and the attester allowlist). The faucet's
//!   identifier is NOT among them — it is the account's own id, which the mint path reads from the
//!   kernel, so there is no identifier slot and nothing to initialize post-deploy;
//! - `FungibleFaucet` with the shipped token config (USDCx / on-chain `USDCX`, 6 decimals,
//!   mutable max supply, zero initial supply), built by the builder from `max_supply`;
//! - `XReserveStablecoinBuilder::build_components()` (the ATTESTATION mint policy active on the
//!   stock mint path, the stock `MinBurnAmount` burn policy, the seeded RBAC roles — `ADMIN` on the
//!   owner, `DOM_PAUSER`/`DOM_MANAGER`/`BLK_MANAGER` on their holders — under the
//!   `XReserveAdminAuthority`);
//! - finalized for deploy by `XReserveStablecoinBuilder::build_account`, which installs the stock
//!   `AuthNetworkAccount` under the frozen note allowlist + the single-root tx-script allowlist
//!   (the `ExpirationTransactionScript` root).
//!
//! The `fee_parameters` come from the chain the faucet is deployed to (the latest block header's
//! fee parameters — see [`crate::client::node_fee_parameters`]): the auth component prices every
//! allowlisted note against them, so a faucet built with foreign fee parameters would carry a fee
//! schedule the node disagrees with.
//!
//! MockChain finalizes the same composition in the repo's F5 suite; this is the REAL-deploy twin of
//! that fixture. [`production_components`] is public so the synthetic assertion fixtures can compose
//! the same component set into an EXISTING (nonce-1) account, which the deploy path cannot produce.

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountComponent, AccountId};
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::FeeParameters;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

use crate::config::DomainParams;

/// Assembles the production builder from the run's admin ids, supply cap, domain config, and the
/// chain's fee parameters. The faucet starts at zero supply; its min-burn floor is left at the
/// builder's default.
fn production_builder(
    owner: AccountId,
    pauser: AccountId,
    manager: AccountId,
    blk_manager: AccountId,
    max_supply: u64,
    domain: &DomainParams,
    fee_parameters: FeeParameters,
) -> Result<XReserveStablecoinBuilder> {
    XReserveStablecoinBuilder::builder()
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(0).context("zero token_supply")?)
        .owner(owner)
        .pauser_holder(pauser)
        .manager_holder(manager)
        .blocklist_manager_holder(blk_manager)
        .fee_parameters(fee_parameters)
        .domain(domain.domain)
        .source_domain(domain.source_domain)
        .xreserve_contract(domain.xreserve_contract)
        .build()
        .map_err(|e| anyhow::anyhow!("composing the production faucet builder: {e}"))
}

/// The full production component list for the given admin ids, supply cap, and domain config.
pub fn production_components(
    owner: AccountId,
    pauser: AccountId,
    manager: AccountId,
    blk_manager: AccountId,
    max_supply: u64,
    domain: &DomainParams,
    fee_parameters: FeeParameters,
) -> Result<Vec<AccountComponent>> {
    production_builder(
        owner,
        pauser,
        manager,
        blk_manager,
        max_supply,
        domain,
        fee_parameters,
    )?
    .build_components()
    .map_err(|e| anyhow::anyhow!("composing the production faucet: {e}"))
}

/// Builds the deployable production faucet `Account` (new, nonce 0, seed embedded) under the frozen
/// `AuthNetworkAccount` auth component, using `init_seed` for the account-id derivation.
///
/// The account id is created `AssetCallbackFlag::Enabled`: the transfer blocklist is wired as the
/// active send + receive policy, so the kernel dispatches the policy callbacks on every transfer — a
/// REQUIREMENT that is an immutable property of the account id (building Disabled would silently
/// disable the callbacks, the audited foot-gun). The builder derives the flag from the composition
/// itself, so it cannot drift from the installed policy.
#[allow(clippy::too_many_arguments)]
pub fn build_faucet_account(
    owner: AccountId,
    pauser: AccountId,
    manager: AccountId,
    blk_manager: AccountId,
    max_supply: u64,
    domain: &DomainParams,
    fee_parameters: FeeParameters,
    init_seed: [u8; 32],
) -> Result<Account> {
    production_builder(
        owner,
        pauser,
        manager,
        blk_manager,
        max_supply,
        domain,
        fee_parameters,
    )?
    .build_account(init_seed)
    .map_err(|e| anyhow::anyhow!("building the deployable production faucet account: {e}"))
}
