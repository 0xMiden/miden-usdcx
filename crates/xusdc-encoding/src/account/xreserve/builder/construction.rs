//! Faucet-account CONSTRUCTION: the assembled `xreserve` component type and the fixed-identity
//! USDCx faucet.
//!
//! Split out of `builder/mod.rs` (which composes the component SET) so the two separable concerns —
//! composing the components vs. building the pieces they are composed from — live apart and each
//! file stays within the Rust file-size ceiling.

use std::sync::Arc;

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, StorageMap, StorageSlot, StorageSlotName};
use miden_protocol::assembly::{Linkage, Path as MasmPath};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::StandardsLib;

use super::{
    XReserveStablecoinBuilderError, DOMAIN_CONFIG_SLOT_LABEL, SOURCE_DOMAIN_CONFIG_SLOT_LABEL,
    USDCX_DECIMALS, USDCX_TOKEN_SYMBOL, USED_NONCES_SLOT_LABEL, XRESERVE_ATTESTERS_SLOT_LABEL,
    XRESERVE_CONTRACT_HI_SLOT_LABEL, XRESERVE_CONTRACT_LO_SLOT_LABEL,
};

/// The metadata label the assembled `xreserve` component carries. It is a build-time label only —
/// the account's code commitment is over the procedure roots and its storage over the slot values,
/// neither of which depends on this string (the byte-identity suite proves it).
const XRESERVE_COMPONENT_LABEL: &str = "xusdc-xreserve";

/// The shipped `xreserve` account component: the assembled MASM library bound to its six declared
/// storage slots. There is exactly ONE valid value — the shipped MASM — so it is a component TYPE the
/// builder produces itself rather than a parameter. Like the standards / agglayer component types, it
/// converts into an [`AccountComponent`] via `impl From<XReserveComponent> for AccountComponent`, so
/// account construction through `.with_component(XReserveComponent::assemble())` is traceable from the
/// library root.
pub struct XReserveComponent(AccountComponent);

impl XReserveComponent {
    /// Assembles the shipped `xreserve` MASM library and binds it with its six declared storage
    /// slots. The four domain-config value slots start zeroed (build-seeded by
    /// [`XReserveStablecoinBuilder::with_domain_config`]) and the two registry maps start empty
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
