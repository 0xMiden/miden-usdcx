//! `XReserveStablecoinBuilder` — the faucet account composition for the xUSDC faucet.
//! The mint path is the STOCK
//! `FungibleFaucet::mint_and_send` gated by the custom **attestation mint policy**
//! (`xreserve::mint_policy::check_policy` — the ENTIRE attestation pipeline lives in
//! the policy dispatch), so every supply increase passes the attestation gate — the
//! faucet's core mint-security invariant.
//!
//! Scope (cumulative): it composes the `FungibleFaucet`, the assembled `xreserve` library
//! component (carrying the attestation mint policy and the `set_attester` admin proc), a
//! `TokenPolicyManager` whose ACTIVE mint policy is the attestation
//! policy and whose ACTIVE burn policy is the STOCK [`MinBurnAmount`](miden_standards::account::policies::MinBurnAmount) (floor-seeded `>= 1`,
//! so zero-amount burns stay rejected by construction), the STOCK [`PausableManager`] and
//! [`BlocklistManager`] admin components, and the **role-gating admin foundation**
//! (a seeded `RoleBasedAccessControl` under the
//! [`XReserveAdminAuthority`]'s `Authority::RbacControlled`). The RBAC seed holds the two Circle
//! Domain role members (`DOM_PAUSER` / `DOM_MANAGER`) with `DOM_PAUSER` administration DELEGATED
//! to `DOM_MANAGER`, the stock `ADMIN` role on the administrator's account, and the external
//! `BLK_MANAGER` transfer-blocklist administrator. There is NO two-step ownership component: the
//! built-in `ADMIN` role is the account's only authority handle, and the standard role-action note
//! is what rotates it. That note also makes the delegation graph seeded here RUNTIME-MUTABLE — see
//! the allowlist doc in `network_auth`.
//!
//! Pause and blocklist administration are the STOCK managers gated per procedure: the authority's
//! role map assigns `pause`/`unpause` to `DOM_PAUSER` and `block_account`/`unblock_account` to
//! `BLK_MANAGER`, so neither capability reaches the administrator — Circle's distinct-role model, expressed
//! in the standard components rather than in hand-rolled wrappers. The managers install no storage
//! of their own: `is_paused` comes from the base `Pausable` component and `blocked_accounts` from
//! the `BasicBlocklist` companion, both of which were already installed.
//!
//! Domain config is entirely BUILD-SEEDED: `domain`, `source_domain`, and `xreserve_contract` are
//! required builder inputs written into the declared slots at composition time. The faucet
//! identifier is not among them and has no slot at all — it is the account's own id, which the
//! mint path derives on chain, so the composed faucet is mint-ready the moment it exists.

use bon::bon;
use miden_protocol::account::{AccountComponent, AccountId};
use miden_protocol::asset::AssetAmount;
use miden_standards::account::access::{Pausable, PausableManager};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::policies::{
    BlocklistManager, BurnPolicy, MintPolicy, TokenPolicyManager, TransferPolicy,
};

use crate::account::xreserve::XReserveAdminAuthority;
use crate::xreserve::encoding::EthBytes32;

mod construction;
mod error;
mod network_auth;
mod rbac_seed;

use construction::build_usdcx_faucet;
pub use construction::{build_faucet_account, XReserveFaucetExtension};
pub use error::XReserveStablecoinBuilderError;
use rbac_seed::seeded_dom_roles_rbac;

/// The two Circle Domain RoleSymbols this faucet seeds under the ratified Circle-faithful admin
/// model: `DOM_PAUSER` (pause/unpause) and `DOM_MANAGER` (rotation / role
/// management — the delegated admin of `DOM_PAUSER`). [`XReserveAdminAuthority`] is the single
/// place `DOM_PAUSER` gates a procedure — it assigns the symbol to the stock `PausableManager`'s
/// two roots, so no MASM mentions either symbol; role management consumes the STOCK rbac procs,
/// so no MASM references `DOM_MANAGER` either. The remaining setters are unassigned and so
/// resolve to `ADMIN`, whose sole seeded member is the bootstrap administrator.
pub const DOM_PAUSER_ROLE: &str = "DOM_PAUSER";
pub const DOM_MANAGER_ROLE: &str = "DOM_MANAGER";

/// The dedicated blocklist-administration RoleSymbol this faucet seeds under the ratified
/// transfer-blocklist decision: `BLK_MANAGER` is held by an EXTERNAL entity that
/// manages the transfer blocklist for Miden and has NO other admin capability (capability isolation
/// is two-way — the holder can ONLY block/unblock, and the administrator, lacking the role, cannot). The
/// stock `BlocklistManager`'s `block_account` / `unblock_account` roots are assigned this symbol by
/// [`XReserveAdminAuthority`], which is what keeps the capability off the administrator — the
/// owner-gated `BlocklistOwnerControlled` variant is the wrong identity and is not installed. Its
/// admin is left unset → resolves to the built-in `ADMIN`, so Miden rotates
/// or revokes the external entity through the allowlisted standard role-action note —
/// no new rotation machinery. `BLK_MANAGER` is seeded role id 4.
pub const BLK_MANAGER_ROLE: &str = "BLK_MANAGER";

/// Path of the attestation mint policy's `check_policy` procedure as the faucet component EXPORTS
/// it. The procedure is defined in the library's `mint_policy` module; the component re-exports it
/// under its own namespace, and it is that re-export the account installs and resolves by.
pub const ATTESTATION_MINT_POLICY_PROC_PATH: &str =
    "xreserve::components::faucet_extension::check_policy";

/// The smallest admissible `min_burn_amount` (the zero floor). The stock [`MinBurnAmount`](miden_standards::account::policies::MinBurnAmount) policy
/// asserts `min <= amount` ONLY (its authority-gated stock setter even accepts `0`), so the
/// zero-burn reject is preserved structurally: the builder rejects a floor below
/// this at construction, and the reworked `set_min_burn_size` admin note asserts `new_min >= 1`
/// BEFORE calling the stock setter — together the floor is `>= 1` at all times, which makes a
/// zero-amount burn (`0 < min`) unacceptable on every path.
pub const MIN_BURN_SIZE_FLOOR: u64 = 1;

/// The shipped on-chain `TokenSymbol` guard constant (token config). The token's identity is
/// **USDCx** — a DISTINCT identity from the "xUSDC" working label;
/// the two must not be confused.
pub const USDCX_TOKEN_SYMBOL: &str = "USDCX";

/// The spec-mandated token decimals (`token_config` decimals = 6; a Circle requirement of six
/// decimal places — the amount reducer scales to 6dp, so a mismatched faucet would silently
/// mis-scale every minted amount).
pub const USDCX_DECIMALS: u8 = 6;

/// Composes the xUSDC faucet account: `FungibleFaucet` + the assembled `xreserve` library
/// component (attestation mint policy, admin procs) + a `TokenPolicyManager`
/// with the attestation policy active on the mint side and the stock [`MinBurnAmount`](miden_standards::account::policies::MinBurnAmount) active on
/// the burn side + the STOCK [`PausableManager`] / [`BlocklistManager`] admin components + the
/// **role-gating admin foundation** (a seeded `RoleBasedAccessControl` +
/// [`XReserveAdminAuthority`]'s `Authority::RbacControlled`).
///
/// Construct with the generated [`Self::builder`] (the faucet supply parameters, the `owner` and
/// role holders, and the three build-seeded domain-config fields; the min-burn floor is the one
/// optional input), then call [`XReserveStablecoinBuilder::build_components`] (or the crate-root
/// `build_faucet_account` / [`Self::build_account`] for the finished `Account`).
#[derive(Debug)]
pub struct XReserveStablecoinBuilder {
    faucet: FungibleFaucet,
    /// The administrator: seeded as the sole member of the built-in `ADMIN` role, which is what
    /// gates every unmapped authority-gated procedure (`set_attester` / the
    /// stock `set_min_burn_amount` / stock `set_max_supply` / the policy setters) under
    /// `Authority::RbacControlled`. It is the account's ONLY authority handle; rotating it is a
    /// grant and a revoke of `ADMIN` through the standard role-action note.
    owner: AccountId,
    /// The seeded `DOM_PAUSER` role member — the holder the role map assigns the stock
    /// `PausableManager`'s pause and unpause procedures to.
    pauser_holder: AccountId,
    /// The seeded `DOM_MANAGER` role member (role management — the delegated admin of `DOM_PAUSER`).
    manager_holder: AccountId,
    /// The seeded `BLK_MANAGER` role member — the EXTERNAL entity that administers the transfer
    /// blocklist (block/unblock) and holds NO other admin capability. Its concrete
    /// account id is supplied at deploy time; the built-in `ADMIN` rotates/revokes it via
    /// the standard role-action note.
    blocklist_manager_holder: AccountId,
    /// The minimum burn amount (the burn-floor threshold) seeded into the stock [`MinBurnAmount`](miden_standards::account::policies::MinBurnAmount)
    /// companion's floor slot. Default [`MIN_BURN_SIZE_FLOOR`]; validated `>=` the floor at
    /// construction, so every held value keeps zero-amount burns rejected.
    min_burn_amount: AssetAmount,
    /// The faucet's own Circle domain id.
    domain: u32,
    /// The Circle domain deposits are accepted from, written into the declared `source_domain` slot
    /// at composition time as `[source_domain, 0, 0, 0]`.
    source_domain: u32,
    /// The xReserve contract's source-chain address.
    xreserve_contract: EthBytes32,
}

#[bon]
impl XReserveStablecoinBuilder {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a builder from the faucet supply parameters (`max_supply` / `token_supply`), the
    /// `owner` (the seeded `ADMIN` member that gates every unmapped authority-gated procedure), the
    /// `pauser_holder` / `manager_holder`
    /// seeded as the sole members of `DOM_PAUSER` / `DOM_MANAGER`, and the
    /// `blocklist_manager_holder` seeded as the sole member of `BLK_MANAGER` (the external
    /// transfer-blocklist administrator), plus the three BUILD-SEEDED domain-config fields: the u32
    /// `domain` and `source_domain` ids and the `xreserve_contract` remote address. The
    /// domain-config fields are required because a
    /// faucet without them would ship a domain compare that reads an empty slot — there is no way to
    /// leave them out.
    ///
    /// The faucet is NOT a parameter: it has a fixed identity — name `USDCx`, symbol
    /// [`USDCX_TOKEN_SYMBOL`], [`USDCX_DECIMALS`] decimals, and `is_max_supply_mutable(true)` — so the
    /// builder BUILDS it here from `max_supply` / `token_supply`, and the mutability invariant, the
    /// decimals and the symbol are guaranteed BY CONSTRUCTION. There is no way to hand the
    /// builder an immutable or mis-configured faucet. The `xreserve` component is likewise not a
    /// parameter — there is exactly one valid value (the shipped MASM), so the builder assembles it
    /// via [`XReserveFaucetExtension`]. The active mint policy is always the attestation policy,
    /// hard-wired at composition, and so is the stock
    /// [`MinBurnAmount`](miden_standards::account::policies::MinBurnAmount) on the burn side; only
    /// its floor, `min_burn_amount`, is a builder input, defaulting to [`MIN_BURN_SIZE_FLOOR`].
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
        pauser_holder: AccountId,
        manager_holder: AccountId,
        blocklist_manager_holder: AccountId,
        domain: u32,
        source_domain: u32,
        xreserve_contract: EthBytes32,
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
            pauser_holder,
            manager_holder,
            blocklist_manager_holder,
            min_burn_amount,
            domain,
            source_domain,
            xreserve_contract,
        })
    }
}

impl XReserveStablecoinBuilder {
    // BUILD / COMPOSE
    // --------------------------------------------------------------------------------------------

    /// Production composition: seeds the three build-time
    /// domain-config fields, then composes the account components. The
    /// faucet's `max_supply` mutability is guaranteed by construction (the crate-root
    /// [`Self::build_account`] path builds the faucet `is_max_supply_mutable(true)`), so there is no
    /// runtime mutability reject. Public for the integration suite, which composes
    /// these components under a TEST auth account; [`Self::build_account`] is the production path.
    pub fn build_components(
        &self,
    ) -> Result<Vec<AccountComponent>, XReserveStablecoinBuilderError> {
        // BLK_MANAGER must not collide with ADMIN / DOM_PAUSER / DOM_MANAGER.
        if self.blocklist_manager_holder == self.owner {
            return Err(
                XReserveStablecoinBuilderError::BlocklistManagerNotIsolated {
                    collides_with: "ADMIN",
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
        if self.blocklist_manager_holder == self.manager_holder {
            return Err(
                XReserveStablecoinBuilderError::BlocklistManagerNotIsolated {
                    collides_with: "DOM_MANAGER",
                },
            );
        }
        // Seed domain config before the mint policy takes the component, so the manager
        // emits the installable copy.
        let xreserve_component = AccountComponent::from(XReserveFaucetExtension::new(
            self.domain,
            self.source_domain,
            self.xreserve_contract,
        ));

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
            .active_burn_policy(BurnPolicy::min_burn_amount(self.min_burn_amount))
            .active_send_policy(TransferPolicy::empty_basic_blocklist())
            .active_receive_policy(TransferPolicy::empty_basic_blocklist())
            .build();

        let mut components = Vec::new();
        components.push(self.faucet.clone().into());
        components.push(Pausable::unpaused().into());
        components.extend(manager);
        components.push(PausableManager.into());
        components.push(BlocklistManager.into());
        components.push(seeded_dom_roles_rbac(
            self.owner,
            self.pauser_holder,
            self.manager_holder,
            self.blocklist_manager_holder,
        ));
        components.push(XReserveAdminAuthority::new().into());
        Ok(components)
    }
}
