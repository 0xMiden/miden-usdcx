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
//! Fee administration uses a standard
//! [`BasicConstantFeePolicy`](miden_standards::account::fees::BasicConstantFeePolicy) constructed
//! from the network fee parameters and the xUSDC note-cost table. The builder installs
//! [`ConstantFeeManager`], and `set_note_fee` is authorized through the account's `ADMIN` role.
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
//!
//! Packaging: the attestation policy is **runtime-assembled** MASM (no `.masl` asset /
//! `account_component_code!` here — that is a miden-standards-internal pipeline). The builder
//! assembles the shipped `xreserve` library into an `AccountComponent` itself (there is exactly one
//! valid component, so it is not a builder input); the policy procedure root is resolved from that
//! same installed code via [`AccountComponent::get_procedure_root_by_path`], so the `dynexec` root
//! the policy manager stores always equals the installed proc's MAST root. The final composed
//! [`Account`](miden_protocol::account::Account) is produced by
//! [`XReserveStablecoinBuilder::build_account`] / the crate-root
//! [`build_faucet_account`], so account construction is traceable from the library root.

use miden_protocol::account::{AccountComponent, AccountId, StorageSlot};
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::FeeParameters;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Pausable, PausableManager};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::fees::ConstantFeeManager;
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
pub use construction::{build_faucet_account, XReserveComponent};
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

/// Flat library path of the attestation mint policy's `check_policy` procedure within the
/// assembled `xreserve` library (namespace `xreserve`, module `mint_policy`).
pub const ATTESTATION_MINT_POLICY_PROC_PATH: &str = "xreserve::mint_policy::check_policy";

/// The smallest admissible `min_burn_size` (the zero floor). The stock [`MinBurnAmount`](miden_standards::account::policies::MinBurnAmount) policy
/// asserts `min <= amount` ONLY (its authority-gated stock setter even accepts `0`), so the
/// zero-burn reject is preserved structurally: the builder rejects a floor below
/// this at build time, and the reworked `set_min_burn_size` admin note asserts `new_min >= 1`
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

/// The three build-seeded domain-config fields (`domain`, `source_domain`, `xreserve_contract`).
#[derive(Debug, Clone, Copy)]
struct DomainConfigSeed {
    domain: u32,
    source_domain: u32,
    xreserve_contract: EthBytes32,
}

/// Composes the xUSDC faucet account: `FungibleFaucet` + the assembled `xreserve` library
/// component (attestation mint policy, admin procs) + a `TokenPolicyManager`
/// with the attestation policy active on the mint side and the stock [`MinBurnAmount`](miden_standards::account::policies::MinBurnAmount) active on
/// the burn side + the standard [`PausableManager`], [`BlocklistManager`], and
/// [`ConstantFeeManager`] components + a seeded `RoleBasedAccessControl` governed by
/// [`XReserveAdminAuthority`]'s `Authority::RbacControlled`.
///
/// Construct with [`XReserveStablecoinBuilder::new`] (the faucet supply parameters, the `owner` and
/// role holders, the network fee parameters, and the three build-seeded domain-config fields),
/// optionally override the min-burn floor, then call
/// [`XReserveStablecoinBuilder::build_components`] (or the crate-root `build_faucet_account` /
/// [`Self::build_account`] for the finished `Account`).
pub struct XReserveStablecoinBuilder {
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
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
    /// Parameters used to price notes and identify the network fee asset.
    ///
    /// TODO: Use native fee faucet account construction when it is available.
    fee_parameters: FeeParameters,
    /// The minimum burn size (the burn-floor threshold) seeded into the stock [`MinBurnAmount`](miden_standards::account::policies::MinBurnAmount)
    /// companion's floor slot. Default [`MIN_BURN_SIZE_FLOOR`] (= 1 — the zero floor: burns must
    /// move at least one unit, keeping zero-amount burns rejected); a value below the
    /// floor is rejected at build.
    min_burn_size: u64,
    /// The faucet's own Circle domain id.
    domain: u32,
    /// The Circle domain deposits are accepted from, written into the declared `source_domain` slot
    /// at composition time as `[source_domain, 0, 0, 0]`.
    source_domain: u32,
    /// The xReserve contract's source-chain address.
    xreserve_contract: EthBytes32,
}

impl XReserveStablecoinBuilder {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a builder from the faucet supply parameters (`max_supply` / `token_supply`), the
    /// `owner` (the seeded `ADMIN` member that gates every unmapped authority-gated procedure), the
    /// `pauser_holder` / `manager_holder`
    /// seeded as the sole members of `DOM_PAUSER` / `DOM_MANAGER`, and the
    /// `blocklist_manager_holder` seeded as the sole member of `BLK_MANAGER` (the external
    /// transfer-blocklist administrator), the network `fee_parameters`, plus the three BUILD-SEEDED
    /// domain-config fields: the u32 `domain` and
    /// `source_domain` ids and the `xreserve_contract` remote address. The
    /// domain-config fields are constructor parameters rather than optional modifiers because a
    /// faucet without them would ship a domain compare that reads an empty slot — there is no way to
    /// leave them out.
    ///
    /// The faucet is NOT a parameter: it has a fixed identity — name `USDCx`, symbol
    /// [`USDCX_TOKEN_SYMBOL`], [`USDCX_DECIMALS`] decimals, and `is_max_supply_mutable(true)` — so the
    /// builder BUILDS it here from `max_supply` / `token_supply`, and the mutability invariant, the
    /// decimals and the symbol are guaranteed BY CONSTRUCTION. There is no way to hand the
    /// builder an immutable or mis-configured faucet. The `xreserve` component is likewise not a
    /// parameter — there is exactly one valid value (the shipped MASM), so the builder assembles it
    /// via [`XReserveComponent`]. The active mint policy is always the attestation policy, hard-wired
    /// at composition, and so is the stock [`MinBurnAmount`](miden_standards::account::policies::MinBurnAmount) on the burn side; only its floor is a
    /// builder input, defaulting to [`MIN_BURN_SIZE_FLOOR`].
    ///
    /// # Errors
    ///
    /// [`XReserveStablecoinBuilderError::FaucetComposition`] if the supply parameters do not form a
    /// valid `FungibleFaucet`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_supply: AssetAmount,
        token_supply: AssetAmount,
        owner: AccountId,
        pauser_holder: AccountId,
        manager_holder: AccountId,
        blocklist_manager_holder: AccountId,
        fee_parameters: FeeParameters,
        domain: u32,
        source_domain: u32,
        xreserve_contract: EthBytes32,
    ) -> Result<Self, XReserveStablecoinBuilderError> {
        Ok(Self {
            faucet: build_usdcx_faucet(max_supply, token_supply)?,
            xreserve_component: XReserveComponent::assemble().into(),
            owner,
            pauser_holder,
            manager_holder,
            blocklist_manager_holder,
            fee_parameters,
            min_burn_size: MIN_BURN_SIZE_FLOOR,
            domain,
            source_domain,
            xreserve_contract,
        })
    }

    // MODIFIERS
    // --------------------------------------------------------------------------------------------

    /// Sets the minimum burn size seeded into the stock [`MinBurnAmount`](miden_standards::account::policies::MinBurnAmount) floor slot (default
    /// [`MIN_BURN_SIZE_FLOOR`] = 1). A value below the floor is rejected by
    /// [`Self::build_components`] with
    /// [`XReserveStablecoinBuilderError::MinBurnSizeBelowFloor`] (the zero-floor invariant);
    /// a value above [`AssetAmount::MAX`] with
    /// [`XReserveStablecoinBuilderError::MinBurnSizeExceedsMax`].
    pub fn min_burn_size(mut self, min_burn_size: u64) -> Self {
        self.min_burn_size = min_burn_size;
        self
    }

    // BUILD / COMPOSE
    // --------------------------------------------------------------------------------------------

    /// Production composition: validates the seeded burn floor, seeds the three build-time
    /// domain-config fields, then composes the account components. The
    /// faucet's `max_supply` mutability is guaranteed by construction (the crate-root
    /// [`Self::build_account`] path builds the faucet `is_max_supply_mutable(true)`), so there is no
    /// runtime mutability reject.
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
        if self.min_burn_size < MIN_BURN_SIZE_FLOOR {
            return Err(XReserveStablecoinBuilderError::MinBurnSizeBelowFloor(
                self.min_burn_size,
            ));
        }
        let min_burn = AssetAmount::new(self.min_burn_size).map_err(|_| {
            XReserveStablecoinBuilderError::MinBurnSizeExceedsMax(self.min_burn_size)
        })?;
        // Seed domain config before the mint policy takes the component, so the manager
        // emits the installable copy.
        let xreserve_component = self.xreserve_component_with_domain_seed(DomainConfigSeed {
            domain: self.domain,
            source_domain: self.source_domain,
            xreserve_contract: self.xreserve_contract,
        });
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
            .active_burn_policy(BurnPolicy::min_burn_amount(min_burn))
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
            self.pauser_holder,
            self.manager_holder,
            self.blocklist_manager_holder,
        ));
        components.push(XReserveAdminAuthority::new().into());
        Ok(components)
    }

    // The final-`Account` constructor ([`Self::build_account`]) and the crate-root
    // [`build_faucet_account`] / component assembly ([`XReserveComponent`]) live in the sibling
    // `construction` module (this file composes the component SET; that one turns it into an
    // `Account`).

    /// Reconstructs the supplied `xreserve` component with the three BUILD-SEEDED domain-config
    /// values written into their declared slots (`[domain, 0, 0, 0]`, `[source_domain, 0, 0, 0]`,
    /// and the packed `xreserve_contract` hi/lo
    /// words). The two registry maps are carried through as declared.
    fn xreserve_component_with_domain_seed(&self, seed: DomainConfigSeed) -> AccountComponent {
        let domain_name = XReserveComponent::domain_config_slot();
        let source_name = XReserveComponent::source_domain_config_slot();
        let hi_name = XReserveComponent::xreserve_contract_hi_slot();
        let lo_name = XReserveComponent::xreserve_contract_lo_slot();
        let scalar_word =
            |value: u32| Word::from([Felt::from(value), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
        let xrc = seed.xreserve_contract.to_packed_felts();
        let hi_word = Word::from([xrc[0], xrc[1], xrc[2], xrc[3]]);
        let lo_word = Word::from([xrc[4], xrc[5], xrc[6], xrc[7]]);
        let slots = self
            .xreserve_component
            .storage_slots()
            .iter()
            .map(|slot| {
                if slot.name() == domain_name {
                    StorageSlot::with_value(domain_name.clone(), scalar_word(seed.domain))
                } else if slot.name() == source_name {
                    StorageSlot::with_value(source_name.clone(), scalar_word(seed.source_domain))
                } else if slot.name() == hi_name {
                    StorageSlot::with_value(hi_name.clone(), hi_word)
                } else if slot.name() == lo_name {
                    StorageSlot::with_value(lo_name.clone(), lo_word)
                } else {
                    slot.clone()
                }
            })
            .collect();
        AccountComponent::new(
            self.xreserve_component.component_code().clone(),
            slots,
            self.xreserve_component.metadata().clone(),
        )
        .expect(
            "the xreserve component reseeded with the domain-config values keeps a valid slot set",
        )
    }
}
