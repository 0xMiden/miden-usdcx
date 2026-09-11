//! Composes the faucet from standard token, policy, fee, and access-control components.
//! The custom mint policy verifies deposit attestations and records used nonces.
//!
//! The builder seeds domain configuration and role membership. Authorized role changes can
//! change membership and role administrators after deployment.

use bon::bon;
use miden_protocol::account::{AccountComponent, AccountId, RoleSymbol};
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::FeeParameters;
use miden_standards::account::access::{
    Pausable, PausableManager, RoleBasedAccessControl, RoleConfig,
};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::fees::ConstantFeeManager;
use miden_standards::account::policies::{
    BlocklistManager, BurnPolicy, MinBurnAmount, MintPolicy, TokenPolicyManager, TransferPolicy,
};

use crate::account::xreserve::XReserveAdminAuthority;

mod construction;
mod error;
mod network_auth;

use construction::build_usdcx_faucet;
pub use construction::{build_faucet_account, XReserveFaucetExtension};
pub use error::XReserveStablecoinBuilderError;

/// Role that authorizes pause through [`XReserveAdminAuthority`].
pub const DOM_PAUSER_ROLE: &str = "DOM_PAUSER";
/// Role that authorizes attester administration.
pub const ATTEST_ADMIN_ROLE: &str = "ATTEST_ADMIN";
/// Role that authorizes unpause.
pub const DOM_UNPAUSER_ROLE: &str = "DOM_UNPAUSER";

/// Role that authorizes [`BlocklistManager`] operations through [`XReserveAdminAuthority`].
/// The built-in `ADMIN` role manages its membership.
pub const BLK_MANAGER_ROLE: &str = "BLK_MANAGER";

/// Exported path of the attestation mint policy installed on the faucet.
pub const ATTESTATION_MINT_POLICY_PROC_PATH: &str =
    "xreserve::components::faucet_extension::check_policy";

/// Path of the attester setter exported by the shipped faucet extension.
pub const XRESERVE_SET_ATTESTER_PROC_PATH: &str =
    "xreserve::components::faucet_extension::set_attester";

/// Path of the procedure exported by the burn policy component.
pub const XRESERVE_BURN_POLICY_PROC_PATH: &str =
    "xreserve::components::faucet_burn_policy::check_burn_policy";

/// Minimum burn floor accepted by this builder and
/// [`XReserveMinBurnAmountNote`](crate::note::xreserve_admin::XReserveMinBurnAmountNote).
/// The standard policy setter itself accepts zero.
pub const MIN_BURN_SIZE_FLOOR: u64 = 1;

/// On-chain token symbol.
pub const USDCX_TOKEN_SYMBOL: &str = "USDCX";

/// Token decimals, matching the source USDC denomination.
pub const USDCX_DECIMALS: u8 = 6;

/// Composes the xUSDC faucet account: `FungibleFaucet` + the assembled `xreserve` library
/// component (attestation mint policy, admin procs) + a `TokenPolicyManager`
/// with the attestation mint policy and a burn policy that checks the required attachments
/// and the minimum amount stored by [`MinBurnAmount`], plus [`PausableManager`], [`BlocklistManager`], and
/// [`ConstantFeeManager`] components + a seeded `RoleBasedAccessControl` governed by
/// [`XReserveAdminAuthority`]'s `Authority::RbacControlled`.
///
/// Construct with the generated [`Self::builder`] (the faucet supply parameters, the `owner` and
/// role holders, the network fee parameters, and the build-seeded domain; the
/// min-burn floor is the one optional input), then call
/// [`XReserveStablecoinBuilder::build_components`] (or the crate-root `build_faucet_account` /
/// [`Self::build_account`] for the finished `Account`).
#[derive(Debug)]
pub struct XReserveStablecoinBuilder {
    faucet: FungibleFaucet,
    /// Initial member of the built-in `ADMIN` role.
    owner: AccountId,
    /// Initial member of the attester administration role.
    attest_admin_holder: AccountId,
    /// Initial pauser; must differ from the other role holders.
    pauser_holder: AccountId,
    /// Initial member of the unpause role.
    unpauser_holder: AccountId,
    /// Initial blocklist manager; must differ from the other role holders.
    blocklist_manager_holder: AccountId,
    /// Parameters used to price notes and identify the network fee asset.
    ///
    /// TODO: Use native fee faucet account construction when it is available.
    fee_parameters: FeeParameters,
    /// The minimum burn amount stored by [`MinBurnAmount`]. Defaults to [`MIN_BURN_SIZE_FLOOR`]
    /// and is validated at construction.
    min_burn_amount: AssetAmount,
    /// The faucet's own Circle domain id.
    domain: u32,
}

#[bon]
impl XReserveStablecoinBuilder {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a builder from the faucet supply parameters (`max_supply` / `token_supply`), the
    /// `owner` (the seeded `ADMIN` member that gates every unmapped authority-gated procedure), the
    /// `attest_admin_holder`, `pauser_holder` and `unpauser_holder` seeded as the sole members of
    /// `ATTEST_ADMIN`, `DOM_PAUSER` and `DOM_UNPAUSER`, and the
    /// `blocklist_manager_holder` seeded as the sole member of `BLK_MANAGER` (the external
    /// transfer-blocklist administrator), the network `fee_parameters`, plus the BUILD-SEEDED
    /// u32 `domain`. The domain is required because a faucet without it would ship a domain
    /// compare that reads an empty slot.
    ///
    /// The faucet is NOT a parameter: it has a fixed identity — name `USDCx`, symbol
    /// [`USDCX_TOKEN_SYMBOL`], [`USDCX_DECIMALS`] decimals, and `is_max_supply_mutable(true)` — so the
    /// builder BUILDS it here from `max_supply` / `token_supply`, and the mutability invariant, the
    /// decimals and the symbol are guaranteed BY CONSTRUCTION. There is no way to hand the
    /// builder an immutable or mis-configured faucet. The `xreserve` component is likewise not a
    /// parameter — there is exactly one valid value (the shipped MASM), so the builder assembles it
    /// via [`XReserveFaucetExtension`]. The active mint and burn policies are fixed by the
    /// composition. The burn policy reads `min_burn_amount` from [`MinBurnAmount`]; this builder
    /// input defaults to [`MIN_BURN_SIZE_FLOOR`].
    ///
    /// # Errors
    ///
    /// [`XReserveStablecoinBuilderError::FaucetComposition`] if the supply parameters do not form a
    /// valid `FungibleFaucet`;
    /// [`XReserveStablecoinBuilderError::MinBurnSizeBelowFloor`] if `min_burn_amount` is below
    /// [`MIN_BURN_SIZE_FLOOR`] (the zero-floor invariant).
    #[builder]
    pub fn new(
        max_supply: AssetAmount,
        token_supply: AssetAmount,
        owner: AccountId,
        attest_admin_holder: AccountId,
        pauser_holder: AccountId,
        unpauser_holder: AccountId,
        blocklist_manager_holder: AccountId,
        fee_parameters: FeeParameters,
        domain: u32,
        min_burn_amount: Option<AssetAmount>,
    ) -> Result<Self, XReserveStablecoinBuilderError> {
        let min_burn_amount = min_burn_amount.unwrap_or(
            AssetAmount::new(MIN_BURN_SIZE_FLOOR)
                .expect("the shipped burn floor is a valid asset amount"),
        );
        if min_burn_amount.as_u64() < MIN_BURN_SIZE_FLOOR {
            return Err(XReserveStablecoinBuilderError::MinBurnSizeBelowFloor(
                min_burn_amount.as_u64(),
            ));
        }
        Ok(Self {
            faucet: build_usdcx_faucet(max_supply, token_supply)?,
            owner,
            attest_admin_holder,
            pauser_holder,
            unpauser_holder,
            blocklist_manager_holder,
            fee_parameters,
            min_burn_amount,
            domain,
        })
    }
}

impl XReserveStablecoinBuilder {
    // BUILD / COMPOSE
    // --------------------------------------------------------------------------------------------

    /// Production composition: seeds the build-time domain,
    /// then composes the account components. The
    /// faucet's `max_supply` mutability is guaranteed by construction (the crate-root
    /// [`Self::build_account`] path builds the faucet `is_max_supply_mutable(true)`), so there is no
    /// runtime mutability reject. Public for the integration suite, which composes
    /// these components under a TEST auth account; [`Self::build_account`] is the production path.
    pub fn build_components(
        &self,
    ) -> Result<Vec<AccountComponent>, XReserveStablecoinBuilderError> {
        // BLK_MANAGER must not collide with any other role holder.
        if self.blocklist_manager_holder == self.owner {
            return Err(
                XReserveStablecoinBuilderError::BlocklistManagerNotIsolated {
                    collides_with: "ADMIN",
                },
            );
        }
        if self.blocklist_manager_holder == self.attest_admin_holder {
            return Err(
                XReserveStablecoinBuilderError::BlocklistManagerNotIsolated {
                    collides_with: "ATTEST_ADMIN",
                },
            );
        }
        if self.blocklist_manager_holder == self.pauser_holder {
            return Err(
                XReserveStablecoinBuilderError::BlocklistManagerNotIsolated {
                    collides_with: "DOM_PAUSER",
                },
            );
        }
        if self.blocklist_manager_holder == self.unpauser_holder {
            return Err(
                XReserveStablecoinBuilderError::BlocklistManagerNotIsolated {
                    collides_with: "DOM_UNPAUSER",
                },
            );
        }
        // DOM_PAUSER must not hold another role; BLK_MANAGER collisions were checked above.
        if self.pauser_holder == self.owner {
            return Err(XReserveStablecoinBuilderError::PauserNotIsolated {
                collides_with: "ADMIN",
            });
        }
        if self.pauser_holder == self.attest_admin_holder {
            return Err(XReserveStablecoinBuilderError::PauserNotIsolated {
                collides_with: "ATTEST_ADMIN",
            });
        }
        if self.pauser_holder == self.unpauser_holder {
            return Err(XReserveStablecoinBuilderError::PauserNotIsolated {
                collides_with: "DOM_UNPAUSER",
            });
        }
        // Seed domain config before the mint policy takes the component, so the manager
        // emits the installable copy.
        let xreserve_component = AccountComponent::from(XReserveFaucetExtension::new(self.domain));
        let burn_policy_component = Self::burn_policy_component();
        let burn_root = burn_policy_component
            .get_procedure_root_by_path(XRESERVE_BURN_POLICY_PROC_PATH)
            .ok_or(XReserveStablecoinBuilderError::BurnPolicyProcNotFound)?;

        let manager = TokenPolicyManager::builder()
            .active_mint_policy(
                MintPolicy::custom(
                    xreserve_component
                        .get_procedure_root_by_path(ATTESTATION_MINT_POLICY_PROC_PATH)
                        .ok_or(XReserveStablecoinBuilderError::AttestationPolicyProcNotFound)?,
                    [xreserve_component],
                )
                .map_err(XReserveStablecoinBuilderError::MintPolicy)?,
            )
            .active_burn_policy(BurnPolicy::custom(
                burn_root,
                [
                    burn_policy_component,
                    MinBurnAmount::new(self.min_burn_amount).into(),
                ],
            )?)
            .active_send_policy(TransferPolicy::empty_basic_blocklist())
            .active_receive_policy(TransferPolicy::empty_basic_blocklist())
            .build();

        let mut components = Vec::new();
        components.push(self.faucet.clone().into());
        components.push(Pausable::unpaused().into());
        components.extend(manager);
        components.push(PausableManager.into());
        components.push(BlocklistManager.into());
        components.push(ConstantFeeManager::for_basic_constant_fee_policy().into());
        components.push(seeded_dom_roles_rbac(
            self.owner,
            self.attest_admin_holder,
            self.pauser_holder,
            self.unpauser_holder,
            self.blocklist_manager_holder,
        ));
        components.push(XReserveAdminAuthority::new().into());
        Ok(components)
    }
}

/// Seeds all five roles with one member each and direct `ADMIN` administration.
fn seeded_dom_roles_rbac(
    owner: AccountId,
    attest_admin_holder: AccountId,
    pauser_holder: AccountId,
    unpauser_holder: AccountId,
    blocklist_manager_holder: AccountId,
) -> AccountComponent {
    let pauser =
        RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol (≤12)");
    let attest_admin = RoleSymbol::new(ATTEST_ADMIN_ROLE)
        .expect("ATTEST_ADMIN is a fixed valid role symbol (≤12)");
    let unpauser = RoleSymbol::new(DOM_UNPAUSER_ROLE)
        .expect("DOM_UNPAUSER is a fixed valid role symbol (≤12)");
    let blk_manager =
        RoleSymbol::new(BLK_MANAGER_ROLE).expect("BLK_MANAGER is a fixed valid role symbol (≤12)");
    let admin = RoleBasedAccessControl::admin_role();

    RoleBasedAccessControl::builder()
        .role(RoleConfig::new(pauser).with_member(pauser_holder))
        .role(RoleConfig::new(attest_admin).with_member(attest_admin_holder))
        .role(RoleConfig::new(unpauser).with_member(unpauser_holder))
        .role(RoleConfig::new(admin).with_member(owner))
        .role(RoleConfig::new(blk_manager).with_member(blocklist_manager_holder))
        .build()
        .expect("the seeded DOM-roles RBAC configuration should be valid")
        .into()
}
