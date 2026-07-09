//! The production faucet composition + the account the harness deploys.
//!
//! EXACTLY the production shape, consumed by reference (single-owner rule — nothing here
//! re-implements 04-owned encoding or 01-owned composition):
//! - the `xreserve` MASM library assembled from the shipped `asm/standards/xreserve` tree
//!   (`xusdc_encoding::xreserve_asm_dir()`), all seven caller-declared slots EMPTY — `domain_init`
//!   (the first admin note) is the production writer;
//! - `FungibleFaucet` with the shipped token config (USDCx / on-chain `USDCX`, 6 decimals,
//!   mutable max supply, zero initial supply);
//! - `XReserveStablecoinBuilder::build_components()` (deny-guard mint policy, burn policy,
//!   Ownable2Step owner, seeded DOM roles, OwnerControlled authority);
//! - finalized for deploy with `AccountBuilder::with_auth_component(auth_component())` — the
//!   stock `AuthNetworkAccount` under the frozen 13-root note allowlist + EMPTY tx allowlist.
//!
//! MockChain finalizes the same composition via `Auth::NetworkAccount` in the repo's F5 suite;
//! this is the REAL-deploy twin of that fixture. The `_seeded` variant exists for SYNTHETIC
//! assertion fixtures only (pre-initialized domain slots — the builder validates slot PRESENCE,
//! not emptiness); the deploy path always ships the slots EMPTY.

use anyhow::Result;
use miden_protocol::account::{Account, AccountComponent, AccountId};

use crate::config::DomainParams;

/// Assembles the shipped `xreserve` library and binds it with the seven caller-declared storage
/// slots. With `domain: None` (the deploy path) all slots are EMPTY; with `Some(params)` the five
/// §5.9 domain-config slots are pre-seeded at the params' values (synthetic fixtures only).
pub fn build_xreserve_component_seeded(domain: Option<&DomainParams>) -> Result<AccountComponent> {
    let _ = domain;
    todo!("LNV-1 driver: assemble the shipped xreserve MASM library + the seven slots")
}

/// The deploy-path `xreserve` component: the shipped library + all seven slots EMPTY.
pub fn build_xreserve_component() -> Result<AccountComponent> {
    build_xreserve_component_seeded(None)
}

/// Runs the supplied `xreserve` component through `XReserveStablecoinBuilder` with the shipped
/// token config and the given admin ids, returning the full production component list.
pub fn production_components(
    xreserve_component: AccountComponent,
    owner: AccountId,
    pauser: AccountId,
    manager: AccountId,
    max_supply: u64,
) -> Result<Vec<AccountComponent>> {
    let _ = (xreserve_component, owner, pauser, manager, max_supply);
    todo!("LNV-1 driver: FungibleFaucet + XReserveStablecoinBuilder::build_components")
}

/// Builds the deployable production faucet `Account` (new, nonce 0, seed embedded) under the
/// frozen `AuthNetworkAccount` auth component, using `init_seed` for the account-id derivation.
pub fn build_faucet_account(
    owner: AccountId,
    pauser: AccountId,
    manager: AccountId,
    max_supply: u64,
    init_seed: [u8; 32],
) -> Result<Account> {
    let _ = (owner, pauser, manager, max_supply, init_seed);
    todo!("LNV-1 driver: compose the production faucet under AuthNetworkAccount for deploy")
}
