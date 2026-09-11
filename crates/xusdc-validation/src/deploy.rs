//! Builds accounts and components for the legacy local-node harness.

use std::sync::Arc;

use anyhow::{Context, Result};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account, AccountBuilder, AccountComponent, AccountId, AccountType, AssetCallbackFlag,
    StorageSlot, StorageSlotName,
};
use miden_protocol::assembly::{Linkage, Path as MasmPath};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::inspection::AccountBuilderSchemaCommitmentExt;
use miden_standards::StandardsLib;
use xusdc_encoding::account::xreserve::{
    XReserveFaucetExtension, XReserveStablecoinBuilder, IDENTIFIER_CONFIG_SLOT_LABEL, USDCX_DECIMALS,
};
use xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts;

use crate::config::DomainParams;

/// Creates the harness component with optional test configuration.
pub fn build_xreserve_component_seeded(domain: Option<&DomainParams>) -> Result<AccountComponent> {
    // The same assembler shape as the repo's F5 fixtures: kernel assembler + StandardsLib (the
    // admin procs call stock authority/pausable/ownable2step procs living there).
    // v16 assembler API: `with_dynamic_library(lib)` →
    // `with_package(Arc<Package>, Linkage::Dynamic)`, and `assemble_library_from_dir(dir, name)` →
    // `assemble_library_from_root(dir/mod.masm, Some(MasmPath))` (returns a `Box<Library>`).
    let assembler = TransactionKernel::assembler()
        .with_package(Arc::new(StandardsLib::default().into()), Linkage::Dynamic)
        .map_err(|e| anyhow::anyhow!("linking StandardsLib into the xreserve assembler: {e}"))?
        .with_warnings_as_errors(true);
    let library = *assembler
        .assemble_library_from_root(
            xusdc_encoding::xreserve_asm_dir().join("mod.masm"),
            Some(MasmPath::new("xreserve")),
        )
        .map_err(|e| anyhow::anyhow!("the shipped xreserve library failed to assemble: {e}"))?;

    let empty = Word::empty();
    let (domain_w, identifier_w, source_domain_w, xrc_hi_w, xrc_lo_w) = match domain {
        None => (empty, empty, empty, empty, empty),
        Some(p) => {
            let packed = bytes32_to_packed_felts(p.xreserve_contract.as_bytes());
            (
                Word::from([Felt::from(p.domain), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
                // The identifier ALWAYS ships EMPTY — the builder rejects a build-seeded identifier
                // (the account-id fixpoint; the identifier_init note is its only writer).
                empty,
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

    let slot = |name: &StorageSlotName, word: Word| StorageSlot::with_value(name.clone(), word);
    let identifier_name = StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)
        .context("the identifier slot label is a valid constant")?;

    AccountComponent::new(
        library,
        vec![
            slot(XReserveFaucetExtension::domain_config_slot(), domain_w),
            slot(&identifier_name, identifier_w),
            slot(
                XReserveFaucetExtension::source_domain_config_slot(),
                source_domain_w,
            ),
            slot(XReserveFaucetExtension::xreserve_contract_hi_slot(), xrc_hi_w),
            slot(XReserveFaucetExtension::xreserve_contract_lo_slot(), xrc_lo_w),
            StorageSlot::with_empty_map(XReserveFaucetExtension::used_nonces_slot().clone()),
            StorageSlot::with_empty_map(XReserveFaucetExtension::xreserve_attesters_slot().clone()),
        ],
        AccountComponentMetadata::new("xusdc-production-faucet"),
    )
    .context("binding the xreserve library + all seven slots as a component")
}

/// The deploy-path `xreserve` component: the shipped library + all seven slots EMPTY.
pub fn build_xreserve_component() -> Result<AccountComponent> {
    build_xreserve_component_seeded(None)
}

/// Builds faucet components with the supplied configuration and role holders.
pub fn production_components(
    xreserve_component: AccountComponent,
    owner: AccountId,
    pauser: AccountId,
    manager: AccountId,
    blk_manager: AccountId,
    max_supply: u64,
    domain: &DomainParams,
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

    XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        owner,
        pauser,
        manager,
        blk_manager,
    )
    .with_domain_config(
        domain.domain,
        domain.source_domain,
        domain.xreserve_contract,
    )
    .build_components()
    .map_err(|e| anyhow::anyhow!("composing the production faucet: {e}"))
}

/// Builds the deployable production faucet `Account` (new, nonce 0, seed embedded) under the
/// frozen `AuthNetworkAccount` auth component, using `init_seed` for the account-id derivation.
/// `domain` supplies the three build-seeded domain-config fields (see [`production_components`]);
/// the identifier slot ships EMPTY (the `identifier_init` note is its only writer).
/// The account id is created `AssetCallbackFlag::Enabled` (F4-reversal): the transfer blocklist is
/// wired as the active send + receive policy, so the kernel dispatches the policy callbacks on every
/// transfer — a REQUIREMENT that is an immutable property of the account id (building Disabled would
/// silently disable the callbacks, the audited foot-gun).
pub fn build_faucet_account(
    owner: AccountId,
    pauser: AccountId,
    manager: AccountId,
    blk_manager: AccountId,
    max_supply: u64,
    domain: &DomainParams,
    init_seed: [u8; 32],
) -> Result<Account> {
    let xreserve_component = build_xreserve_component()?;
    let components = production_components(
        xreserve_component,
        owner,
        pauser,
        manager,
        blk_manager,
        max_supply,
        domain,
    )?;
    let auth = XReserveStablecoinBuilder::auth_component()
        .map_err(|e| anyhow::anyhow!("building the frozen AuthNetworkAccount component: {e}"))?;

    AccountBuilder::new(init_seed)
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_auth_component(auth)
        .with_components(components)
        .build_with_schema_commitment()
        .context("building the deployable production faucet account")
}
