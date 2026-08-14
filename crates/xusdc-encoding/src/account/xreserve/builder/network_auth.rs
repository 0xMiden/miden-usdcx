//! The keyless network account's authorization surface: the note-script allowlist and the auth
//! component that carries the fee manager built from the caller-supplied fee faucet and concrete
//! constant-fee policy.
//!
//! It lives beside the builder rather than inside it because the grouping is cohesive: the faucet
//! has no signing key, so this allowlist IS its authorization model, and nothing else decides which
//! notes the account will consume.

use std::collections::BTreeSet;

use miden_protocol::account::AccountId;
use miden_protocol::note::NoteScriptRoot;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::note::{
    BurnNote, ConstantFeePolicyConfigNote, FeeSponsorshipNote, MintNote, PauseConfigNote,
    RbacConfigNote,
};
use miden_standards::tx_script::ExpirationTransactionScript;

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
            crate::note::xreserve_admin::XReserveSetMaxSupplyNote::script_root(),
            // Standard administration notes.
            PauseConfigNote::script_root(),
            crate::note::xreserve_admin::XReserveBlocklistNote::script_root(),
            RbacConfigNote::script_root(),
            // Fee administration and sponsorship notes.
            ConstantFeePolicyConfigNote::script_root(),
            FeeSponsorshipNote::script_root(),
        ])
    }

    /// Validates a [`BasicConstantFeePolicy`] against the accepted-note allowlist.
    pub(super) fn validate_fee_policy(
        fee_policy: &BasicConstantFeePolicy,
    ) -> Result<(), XReserveStablecoinBuilderError> {
        let allowed_note_scripts = Self::allowed_note_scripts();
        for root in &allowed_note_scripts {
            if !fee_policy.fee_schedule().contains_key(root) {
                return Err(XReserveStablecoinBuilderError::MissingFeeScheduleEntry(
                    *root,
                ));
            }
        }

        for root in fee_policy.fee_schedule().keys() {
            if !allowed_note_scripts.contains(root) {
                return Err(XReserveStablecoinBuilderError::UnexpectedFeeScheduleEntry(
                    *root,
                ));
            }
        }

        let config_note_fee = fee_policy
            .fee_schedule()
            .get(&ConstantFeePolicyConfigNote::script_root())
            .expect("the complete schedule contains the config note");
        if config_note_fee.as_u64() == 0 {
            return Err(XReserveStablecoinBuilderError::ZeroConstantFeePolicyConfigFee);
        }

        Ok(())
    }

    /// Builds the production `AuthNetworkAccount` component from the supplied fee faucet and basic
    /// constant-fee policy. It uses [`Self::allowed_note_scripts`], admits only
    /// `ExpirationTransactionScript::script_root()` as a transaction script, and excludes the
    /// mutable `NetworkAccountConfigNote` entry point.
    pub fn auth_component(
        fee_faucet_id: AccountId,
        fee_policy: BasicConstantFeePolicy,
    ) -> Result<AuthNetworkAccount, XReserveStablecoinBuilderError> {
        Self::validate_fee_policy(&fee_policy)?;
        let fee_policy_manager = FeePolicyManager::builder()
            .fee_faucet_id(fee_faucet_id)
            .active_fee_policy(fee_policy.into())
            .build();
        Ok(
            AuthNetworkAccount::custom(Self::allowed_note_scripts(), fee_policy_manager)?
                .with_allowed_tx_scripts(BTreeSet::from([
                    ExpirationTransactionScript::script_root(),
                ])),
        )
    }
}
