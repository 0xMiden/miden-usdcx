//! Faucet-account CONSTRUCTION: the assembled `xreserve` component type, the fixed-identity USDCx
//! faucet, the crate-root `Account` constructor, and [`XReserveStablecoinBuilder::build_account`].
//!
//! Split out of `builder/mod.rs` (which composes the component SET) so the two separable concerns —
//! composing the components vs. turning them into the deployable `Account` — live apart and each file
//! stays within the Rust file-size ceiling.

use std::sync::{Arc, LazyLock};

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account, AccountComponent, AccountId, AccountType, AssetCallbackFlag, StorageSlot,
    StorageSlotName,
};
use miden_protocol::assembly::{Linkage, Path as MasmPath};
use miden_protocol::asset::{AssetAmount, AssetCallbacks, TokenSymbol};
use miden_protocol::transaction::TransactionKernel;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::StandardsLib;

use super::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError, USDCX_DECIMALS, USDCX_TOKEN_SYMBOL,
};
use crate::xreserve::encoding::EthBytes32;

// CONSTANTS
// ================================================================================================

/// The metadata label the assembled `xreserve` component carries. It is a build-time label only —
/// the account's code commitment is over the procedure roots and its storage over the slot values,
/// neither of which depends on this string (the byte-identity suite proves it).
const XRESERVE_COMPONENT_LABEL: &str = "xusdc-xreserve";

static DOMAIN_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("xusdc::xreserve::domain_config::domain")
        .expect("storage slot name should be valid")
});
static SOURCE_DOMAIN_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("xusdc::xreserve::domain_config::source_domain")
        .expect("storage slot name should be valid")
});
static XRESERVE_CONTRACT_HI_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("xusdc::xreserve::domain_config::xreserve_contract_hi")
        .expect("storage slot name should be valid")
});
static XRESERVE_CONTRACT_LO_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("xusdc::xreserve::domain_config::xreserve_contract_lo")
        .expect("storage slot name should be valid")
});

/// The nonce registry the replay guard reads and the mint path writes.
static USED_NONCES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("xusdc::xreserve::nonce_registry::used_nonces")
        .expect("storage slot name should be valid")
});

/// The attester allowlist: the attestation check reads it and the `set_attester` admin path writes
/// it, so the two co-own the same slot.
static XRESERVE_ATTESTERS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("xusdc::xreserve::attester_admin::xreserve_attesters")
        .expect("storage slot name should be valid")
});

/// The shipped `xreserve` account component: the assembled MASM library bound to its six declared
/// storage slots. There is exactly ONE valid value — the shipped MASM — so it is a component TYPE the
/// builder produces itself rather than a parameter. Like the standards / agglayer component types, it
/// converts into an [`AccountComponent`] via `impl From<XReserveComponent> for AccountComponent`, so
/// account construction through `.with_component(XReserveComponent::assemble())` is traceable from the
/// library root.
pub struct XReserveComponent(AccountComponent);

impl XReserveComponent {
    /// Assembles the shipped `xreserve` MASM library and binds it with its six declared storage
    /// slots. The four domain-config value slots start zeroed (build-seeded from the domain-config
    /// parameters [`XReserveStablecoinBuilder::new`] takes) and the two registry maps start empty
    /// (`set_attester` and the mint path populate them). Assembly failures are invariants of the
    /// shipped source, so they panic rather than surfacing as a builder error (the same posture the
    /// admin-note script assembler takes).
    pub fn assemble() -> Self {
        let assembler = TransactionKernel::assembler()
            .with_package(Arc::new(StandardsLib::default().into()), Linkage::Dynamic)
            .expect("the standards library links into the xreserve assembler")
            .with_warnings_as_errors(true);
        let library = *assembler
            .assemble_library_from_root(
                crate::xreserve_asm_dir().join("mod.masm"),
                Some(MasmPath::new("xreserve")),
            )
            .expect("the shipped xreserve component library assembles");
        Self(
            AccountComponent::new(
                library,
                vec![
                    StorageSlot::with_empty_value(Self::domain_config_slot().clone()),
                    StorageSlot::with_empty_value(Self::source_domain_config_slot().clone()),
                    StorageSlot::with_empty_value(Self::xreserve_contract_hi_slot().clone()),
                    StorageSlot::with_empty_value(Self::xreserve_contract_lo_slot().clone()),
                    StorageSlot::with_empty_map(Self::used_nonces_slot().clone()),
                    StorageSlot::with_empty_map(Self::xreserve_attesters_slot().clone()),
                ],
                AccountComponentMetadata::new(XRESERVE_COMPONENT_LABEL),
            )
            .expect("the xreserve library binds with its six declared slots"),
        )
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`StorageSlotName`] holding the faucet's own Circle domain id.
    pub fn domain_config_slot() -> &'static StorageSlotName {
        &DOMAIN_CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] holding the source domain deposits are accepted from.
    pub fn source_domain_config_slot() -> &'static StorageSlotName {
        &SOURCE_DOMAIN_CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] holding the high half of the xReserve contract address.
    pub fn xreserve_contract_hi_slot() -> &'static StorageSlotName {
        &XRESERVE_CONTRACT_HI_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] holding the low half of the xReserve contract address.
    pub fn xreserve_contract_lo_slot() -> &'static StorageSlotName {
        &XRESERVE_CONTRACT_LO_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the consumed-nonce registry map.
    pub fn used_nonces_slot() -> &'static StorageSlotName {
        &USED_NONCES_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the attester allowlist map.
    pub fn xreserve_attesters_slot() -> &'static StorageSlotName {
        &XRESERVE_ATTESTERS_SLOT_NAME
    }
}

impl From<XReserveComponent> for AccountComponent {
    fn from(component: XReserveComponent) -> Self {
        component.0
    }
}

impl XReserveStablecoinBuilder {
    /// Builds the final composed faucet [`Account`] from `init_seed`: [`Self::build_components`] plus
    /// the production keyless-network `AuthNetworkAccount` auth component ([`Self::auth_component`]),
    /// assembled exactly as the network-deploy path does — `AccountType::Public`, and the asset
    /// callbacks enabled iff the composition installs the transfer-policy callback slots (it does:
    /// xUSDC is a policed asset).
    ///
    /// This is the crate-root faucet-account constructor: nothing outside the test harness previously
    /// turned the components into an `Account`, so account construction is now traceable from the
    /// library root. Composing the account through this entry is byte-identical to composing the
    /// components and the auth component by hand with the same seed (the byte-identity suite proves
    /// it against the pre-change composition).
    pub fn build_account(
        &self,
        init_seed: [u8; 32],
    ) -> Result<Account, XReserveStablecoinBuilderError> {
        let components = self.build_components()?;
        // xUSDC is a policed asset: the transfer blocklist is the active send + receive policy, so
        // the composition installs the two asset-callback slots and the account id must carry the
        // Enabled flag for the kernel to dispatch the callbacks. Derived from the composition rather
        // than hard-coded, so a composition that dropped the policy would flip the flag in lockstep.
        let has_callbacks = components.iter().any(|component| {
            component.storage_slots().iter().any(|slot| {
                slot.name() == AssetCallbacks::on_before_asset_added_to_note_slot()
                    || slot.name() == AssetCallbacks::on_before_asset_added_to_account_slot()
            })
        });
        let flag = if has_callbacks {
            AssetCallbackFlag::Enabled
        } else {
            AssetCallbackFlag::Disabled
        };
        let mut builder = Account::builder(init_seed)
            .account_type(AccountType::Public)
            .with_asset_callbacks(flag);
        for component in components {
            builder = builder.with_component(component);
        }
        builder = builder.with_components(
            Self::auth_component().map_err(XReserveStablecoinBuilderError::NetworkAuth)?,
        );
        builder
            .build()
            .map_err(XReserveStablecoinBuilderError::AccountComposition)
    }
}

/// Crate-root constructor for the final xUSDC faucet [`Account`]: builds the fixed-identity USDCx
/// faucet (`is_max_supply_mutable(true)` — the mutability invariant enforced BY CONSTRUCTION rather
/// than a runtime reject), then composes it into the attestation-gated keyless network account via
/// [`XReserveStablecoinBuilder`]. It is the single entry point that turns deploy parameters into the
/// deployable account, so account construction is traceable from the library root (the agglayer
/// `create_bridge_account` pattern). `init_seed` seeds the account id.
#[allow(clippy::too_many_arguments)]
pub fn build_faucet_account(
    init_seed: [u8; 32],
    max_supply: AssetAmount,
    token_supply: AssetAmount,
    owner: AccountId,
    pauser_holder: AccountId,
    manager_holder: AccountId,
    blocklist_manager_holder: AccountId,
    domain: u32,
    source_domain: u32,
    xreserve_contract: EthBytes32,
) -> Result<Account, XReserveStablecoinBuilderError> {
    XReserveStablecoinBuilder::new(
        max_supply,
        token_supply,
        owner,
        pauser_holder,
        manager_holder,
        blocklist_manager_holder,
        domain,
        source_domain,
        xreserve_contract,
    )?
    .build_account(init_seed)
}

/// Builds the fixed-identity USDCx [`FungibleFaucet`]: name `USDCx`, symbol [`USDCX_TOKEN_SYMBOL`],
/// [`USDCX_DECIMALS`] decimals, and `is_max_supply_mutable(true)` so the deployed `set_max_supply`
/// stays operable. The identity fields are constants (the `.expect`s are invariants); setting the
/// mutability flag here is what guarantees it by construction, replacing the removed runtime reject.
pub(super) fn build_usdcx_faucet(
    max_supply: AssetAmount,
    token_supply: AssetAmount,
) -> Result<FungibleFaucet, XReserveStablecoinBuilderError> {
    FungibleFaucet::builder()
        .name(TokenName::new("USDCx").expect("USDCx is a valid token name"))
        .symbol(TokenSymbol::new(USDCX_TOKEN_SYMBOL).expect("the USDCX symbol constant is valid"))
        .decimals(USDCX_DECIMALS)
        .max_supply(max_supply)
        .token_supply(token_supply)
        .is_max_supply_mutable(true)
        .build()
        .map_err(XReserveStablecoinBuilderError::FaucetComposition)
}
