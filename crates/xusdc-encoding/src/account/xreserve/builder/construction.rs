//! Faucet-account CONSTRUCTION: the assembled `xreserve` component type, the fixed-identity USDCx
//! faucet, the crate-root `Account` constructor, and [`XReserveStablecoinBuilder::build_account`].
//!
//! Split out of `builder/mod.rs` (which composes the component SET) so the two separable concerns —
//! composing the components vs. turning them into the deployable `Account` — live apart and each file
//! stays within the Rust file-size ceiling.

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    Account, AccountComponent, AccountId, AccountType, AssetCallbackFlag, StorageMap, StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, AssetCallbacks, TokenSymbol};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};

use crate::xreserve_lib::component_code;

use super::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError, DOMAIN_CONFIG_SLOT_LABEL,
    SOURCE_DOMAIN_CONFIG_SLOT_LABEL, USDCX_DECIMALS, USDCX_TOKEN_SYMBOL, USED_NONCES_SLOT_LABEL,
    XRESERVE_ATTESTERS_SLOT_LABEL, XRESERVE_CONTRACT_HI_SLOT_LABEL,
    XRESERVE_CONTRACT_LO_SLOT_LABEL,
};
use crate::xreserve::encoding::EthBytes32;

/// The metadata label the assembled `xreserve` component carries. It is a build-time label only —
/// the account's code commitment is over the procedure roots and its storage over the slot values,
/// neither of which depends on this string (the byte-identity suite proves it).
const XRESERVE_COMPONENT_LABEL: &str = "xusdc-xreserve";

/// The faucet's callable surface, assembled at build time from `asm/components/faucet/`. It exports
/// the two procedures the account answers to and nothing else; the rest of the xreserve library is
/// reachable only from inside them.
static FAUCET_COMPONENT_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    component_code(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/components/xreserve-faucet.masp"
    )))
});

/// The shipped `xreserve` account component: the assembled MASM library bound to its six declared
/// storage slots. There is exactly ONE valid value — the shipped MASM — so it is a component TYPE the
/// builder produces itself rather than a parameter. Like the standards / agglayer component types, it
/// converts into an [`AccountComponent`] via `impl From<XReserveComponent> for AccountComponent`, so
/// account construction through `.with_component(XReserveComponent::assemble())` is traceable from the
/// library root.
pub struct XReserveComponent(AccountComponent);

impl XReserveComponent {
    /// Binds the shipped faucet component code to its six declared storage slots. The four
    /// domain-config value slots start zeroed (build-seeded by
    /// [`XReserveStablecoinBuilder::with_domain_config`]) and the two registry maps start empty
    /// (`set_attester` and the mint path populate them). A binding failure is an invariant of the
    /// shipped MASM, so it panics rather than surfacing as a builder error.
    pub fn assemble() -> Self {
        let library = FAUCET_COMPONENT_CODE.clone();
        let empty = || Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
        let value_slot = |label: &str| {
            StorageSlot::with_value(
                StorageSlotName::new(label).expect("the xreserve slot labels are valid constants"),
                empty(),
            )
        };
        let map_slot = |label: &str| {
            StorageSlot::with_map(
                StorageSlotName::new(label).expect("the xreserve slot labels are valid constants"),
                StorageMap::new(),
            )
        };
        Self(
            AccountComponent::new(
                library,
                vec![
                    value_slot(DOMAIN_CONFIG_SLOT_LABEL),
                    value_slot(SOURCE_DOMAIN_CONFIG_SLOT_LABEL),
                    value_slot(XRESERVE_CONTRACT_HI_SLOT_LABEL),
                    value_slot(XRESERVE_CONTRACT_LO_SLOT_LABEL),
                    map_slot(USED_NONCES_SLOT_LABEL),
                    map_slot(XRESERVE_ATTESTERS_SLOT_LABEL),
                ],
                AccountComponentMetadata::new(XRESERVE_COMPONENT_LABEL),
            )
            .expect("the xreserve library binds with its six declared slots"),
        )
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
    )?
    .with_domain_config(domain, source_domain, xreserve_contract)
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
