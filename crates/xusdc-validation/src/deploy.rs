//! The production faucet composition + the account the harness deploys.
//!
//! EXACTLY the production shape, consumed by reference (single-owner rule — nothing here
//! re-implements the shared-encoding crate's encoding or the faucet component's composition):
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

use std::sync::Arc;

use anyhow::{Context, Result};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account, AccountBuilder, AccountComponent, AccountId, AccountType, StorageMap, StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::metadata::AccountBuilderSchemaCommitmentExt;
use miden_standards::StandardsLib;
use xusdc_encoding::account::xreserve::{
    XReserveStablecoinBuilder, DOMAIN_CONFIG_SLOT_LABEL, IDENTIFIER_CONFIG_SLOT_LABEL,
    SOURCE_DOMAIN_CONFIG_SLOT_LABEL, USDCX_DECIMALS, USED_NONCES_SLOT_LABEL,
    XRESERVE_ATTESTERS_SLOT_LABEL, XRESERVE_CONTRACT_HI_SLOT_LABEL,
    XRESERVE_CONTRACT_LO_SLOT_LABEL,
};
use xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts;

use crate::config::DomainParams;

/// Assembles the shipped `xreserve` library and binds it with the seven caller-declared storage
/// slots. With `domain: None` (the deploy path) all slots are EMPTY; with `Some(params)` the five
/// domain-config slots are pre-seeded at the params' values (synthetic fixtures only).
pub fn build_xreserve_component_seeded(domain: Option<&DomainParams>) -> Result<AccountComponent> {
    // The same assembler shape as the repo's F5 fixtures: kernel assembler + StandardsLib (the
    // admin procs call stock authority/pausable/ownable2step procs living there).
    let assembler = TransactionKernel::assembler()
        .with_dynamic_library(StandardsLib::default())
        .map_err(|e| anyhow::anyhow!("linking StandardsLib into the xreserve assembler: {e}"))?
        .with_warnings_as_errors(true);
    let library = assembler
        .assemble_library_from_dir(xusdc_encoding::xreserve_asm_dir(), "xreserve")
        .map_err(|e| anyhow::anyhow!("the shipped xreserve library failed to assemble: {e}"))?;
    let library = Arc::unwrap_or_clone(library);

    let empty = Word::empty();
    let (domain_w, identifier_w, source_domain_w, xrc_hi_w, xrc_lo_w) = match domain {
        None => (empty, empty, empty, empty, empty),
        Some(p) => {
            let packed = bytes32_to_packed_felts(&p.xreserve_contract);
            (
                Word::from([Felt::from(p.domain), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
                p.identifier_word(),
                Word::from([
                    Felt::from(p.source_domain),
                    Felt::ZERO,
                    Felt::ZERO,
                    Felt::ZERO,
                ]),
                Word::from([packed[0], packed[1], packed[2], packed[3]]),
                Word::from([packed[4], packed[5], packed[6], packed[7]]),
            )
        }
    };

    let slot = |label: &str, word: Word| -> Result<StorageSlot> {
        Ok(StorageSlot::with_value(
            StorageSlotName::new(label).with_context(|| format!("slot label '{label}'"))?,
            word,
        ))
    };

    AccountComponent::new(
        library,
        vec![
            slot(DOMAIN_CONFIG_SLOT_LABEL, domain_w)?,
            slot(IDENTIFIER_CONFIG_SLOT_LABEL, identifier_w)?,
            slot(SOURCE_DOMAIN_CONFIG_SLOT_LABEL, source_domain_w)?,
            slot(XRESERVE_CONTRACT_HI_SLOT_LABEL, xrc_hi_w)?,
            slot(XRESERVE_CONTRACT_LO_SLOT_LABEL, xrc_lo_w)?,
            StorageSlot::with_map(
                StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
                StorageMap::new(),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
                    .context("xReserveAttesters slot label")?,
                StorageMap::new(),
            ),
        ],
        AccountComponentMetadata::new("xusdc-production-faucet"),
    )
    .context("binding the xreserve library + all seven slots as a component")
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
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("USDCx").context("the USDCx token name")?)
        .symbol(TokenSymbol::new("USDCX").context("the USDCX token symbol")?)
        .decimals(USDCX_DECIMALS)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(0).context("zero token_supply")?)
        .is_max_supply_mutable(true)
        .build()
        .context("building the FungibleFaucet component")?;

    XReserveStablecoinBuilder::new(faucet, xreserve_component, owner, pauser, manager)
        .build_components()
        .map_err(|e| anyhow::anyhow!("composing the production faucet: {e}"))
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
    let xreserve_component = build_xreserve_component()?;
    let components = production_components(xreserve_component, owner, pauser, manager, max_supply)?;
    let auth = XReserveStablecoinBuilder::auth_component()
        .map_err(|e| anyhow::anyhow!("building the frozen AuthNetworkAccount component: {e}"))?;

    AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_auth_component(auth)
        .with_components(components)
        .build_with_schema_commitment()
        .context("building the deployable production faucet account")
}
