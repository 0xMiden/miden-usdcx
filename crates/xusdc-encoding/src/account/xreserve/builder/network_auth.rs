//! The keyless network account's authorization surface: the note-script allowlist and the auth
//! component that carries the fee manager built from the network fee parameters.
//!
//! It lives beside the builder rather than inside it because the grouping is cohesive: the faucet
//! has no signing key, so this allowlist IS its authorization model, and nothing else decides which
//! notes the account will consume.

use std::collections::BTreeSet;

use miden_protocol::asset::AssetAmount;
use miden_protocol::block::FeeParameters;
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::TransactionFee;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::note::costs::NoteCost;
use miden_standards::note::{
    BurnNote, ConstantFeePolicyConfigNote, FaucetMetadataConfigNote, FeeSponsorshipNote, MintNote,
    PauseConfigNote, RbacConfigNote,
};
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_tx::{NetworkNotePricer, NotePricingError};

use super::{XReserveStablecoinBuilder, XReserveStablecoinBuilderError};

impl XReserveStablecoinBuilder {
    /// Returns the production faucet's note-script allowlist.
    ///
    /// The ten roots cover mint and burn, three faucet setters, pause and blocklist administration,
    /// role administration, constant-fee administration, and fee sponsorship. The general network
    /// account configuration note is excluded, so the note and transaction allowlists cannot be
    /// modified through an accepted note.
    pub fn allowed_note_scripts() -> BTreeSet<NoteScriptRoot> {
        BTreeSet::from([
            // Supply notes.
            MintNote::script_root(),
            BurnNote::script_root(),
            // Faucet administration notes.
            crate::note::xreserve_admin::XReserveSetAttesterNote::script_root(),
            crate::note::xreserve_admin::XReserveSetMinBurnSizeNote::script_root(),
            // Standard administration notes.
            FaucetMetadataConfigNote::script_root(),
            PauseConfigNote::script_root(),
            crate::note::xreserve_admin::XReserveBlocklistNote::script_root(),
            RbacConfigNote::script_root(),
            // Fee administration and sponsorship notes.
            ConstantFeePolicyConfigNote::script_root(),
            FeeSponsorshipNote::script_root(),
        ])
    }

    /// Builds the production `AuthNetworkAccount` component from the network fee parameters. It
    /// constructs the xUSDC fee schedule, uses [`Self::allowed_note_scripts`], admits only
    /// `ExpirationTransactionScript::script_root()` as a transaction script, and excludes the
    /// mutable `NetworkAccountConfigNote` entry point.
    pub fn auth_component(
        fee_parameters: FeeParameters,
    ) -> Result<AuthNetworkAccount, XReserveStablecoinBuilderError> {
        let fee_policy = Self::fee_policy(&fee_parameters)?;
        let fee_policy_manager = FeePolicyManager::builder()
            .fee_faucet_id(fee_parameters.fee_faucet_id())
            .active_fee_policy(fee_policy.into())
            .build();
        Ok(
            AuthNetworkAccount::custom(Self::allowed_note_scripts(), fee_policy_manager)?
                .with_allowed_tx_scripts(BTreeSet::from([
                    ExpirationTransactionScript::script_root(),
                ])),
        )
    }

    /// Constructs the xUSDC fee policy from the network fee parameters.
    pub(super) fn fee_policy(
        fee_parameters: &FeeParameters,
    ) -> Result<BasicConstantFeePolicy, XReserveStablecoinBuilderError> {
        let pricer = NetworkNotePricer::builder()
            .fee_parameters(fee_parameters.clone())
            .build();
        let mut policy = BasicConstantFeePolicy::new();
        for root in Self::allowed_note_scripts() {
            let price = if let Some(cost) = crate::note::costs::note_cost(root) {
                price_xusdc_note(&pricer, &cost)?
            } else {
                pricer.price(root)?
            };
            policy = policy.with_fee(root, price);
        }
        Ok(policy)
    }
}

/// Prices an xUSDC note from its measured consumption cost and any note it creates.
fn price_xusdc_note(
    pricer: &NetworkNotePricer,
    cost: &NoteCost,
) -> Result<AssetAmount, NotePricingError> {
    let fee_inputs = TransactionFee::new(cost.cycles()).map_err(NotePricingError::Fee)?;
    let mut total = pricer.fee(fee_inputs)?.as_u64();
    for &created_root in cost.created_notes() {
        total = total
            .checked_add(pricer.price(created_root)?.as_u64())
            .ok_or(NotePricingError::PriceOverflow)?;
    }
    AssetAmount::new(total).map_err(NotePricingError::PriceExceedsMaxAssetAmount)
}
