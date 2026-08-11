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
//! policy and whose ACTIVE burn policy is the STOCK [`MinBurnAmount`] (floor-seeded `>= 1`,
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
//!
//! Packaging: the attestation policy is **runtime-assembled** MASM (no `.masl` asset /
//! `account_component_code!` here — that is a miden-standards-internal pipeline). The builder
//! assembles the shipped `xreserve` library into an `AccountComponent` itself (there is exactly one
//! valid component, so it is not a builder input); the policy procedure root is resolved from that
//! same installed code via [`AccountComponent::get_procedure_root_by_path`], so the `dynexec` root
//! the policy manager stores always equals the installed proc's MAST root. The final composed
//! [`Account`] is produced by [`XReserveStablecoinBuilder::build_account`] / the crate-root
//! [`build_faucet_account`], so account construction is traceable from the library root.

use miden_protocol::account::{
    AccountComponent, AccountId, AccountProcedureRoot, StorageSlot, StorageSlotName,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Pausable, PausableManager};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::policies::{
    BasicBlocklist, BlocklistManager, BurnPolicy, MinBurnAmount, MintPolicy, TokenPolicyManager,
    TransferPolicy,
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

/// The smallest admissible `min_burn_size` (the zero floor). The stock [`MinBurnAmount`] policy
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

/// Canonical Rust labels of the six caller-declared `xreserve` storage slots: the four
/// domain-config slots + the two registry maps. The four slots hold THREE build-seeded fields —
/// `xreserve_contract` is one bytes32 spread across its `hi`/`lo` pair — and none of the three
/// has a runtime writer.
pub const DOMAIN_CONFIG_SLOT_LABEL: &str = "xusdc::xreserve::domain_config::domain";
pub const SOURCE_DOMAIN_CONFIG_SLOT_LABEL: &str = "xusdc::xreserve::domain_config::source_domain";
pub const XRESERVE_CONTRACT_HI_SLOT_LABEL: &str =
    "xusdc::xreserve::domain_config::xreserve_contract_hi";
pub const XRESERVE_CONTRACT_LO_SLOT_LABEL: &str =
    "xusdc::xreserve::domain_config::xreserve_contract_lo";
pub const USED_NONCES_SLOT_LABEL: &str = "xusdc::xreserve::nonce_registry::used_nonces";
pub const XRESERVE_ATTESTER_KEYS_SLOT_LABEL: &str =
    "xusdc::xreserve::attestation::xreserve_attester_keys";

/// The SIX storage slots the supplied `xreserve` component must declare (the
/// validate-what-you-ship check): a missing slot would ship a faucet whose reads/writes of it trap
/// `ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME` at runtime;
/// [`XReserveStablecoinBuilder::build_components`] rejects at build time instead. The stock
/// [`MinBurnAmount`] floor slot is NOT in this set — it rides the policy companion component the
/// manager emits, not the `xreserve` component.
pub const REQUIRED_XRESERVE_SLOT_LABELS: [&str; 6] = [
    DOMAIN_CONFIG_SLOT_LABEL,
    SOURCE_DOMAIN_CONFIG_SLOT_LABEL,
    XRESERVE_CONTRACT_HI_SLOT_LABEL,
    XRESERVE_CONTRACT_LO_SLOT_LABEL,
    USED_NONCES_SLOT_LABEL,
    XRESERVE_ATTESTER_KEYS_SLOT_LABEL,
];

/// The three build-seeded domain-config fields (`domain`, `source_domain`, `xreserve_contract`).
#[derive(Debug, Clone, Copy)]
struct DomainConfigSeed {
    domain: u32,
    source_domain: u32,
    xreserve_contract: EthBytes32,
}

/// Reads the burn floor (element 0 of the value word) from a `BurnPolicy`'s stock [`MinBurnAmount`]
/// companion, or `None` if the descriptor carries no such companion. Used to reject a same-root
/// burn-policy override whose seeded floor disagrees with the builder-validated `min_burn_size`
/// (the same-root zero-floor bypass). Inspects a clone (the descriptor's components are private,
/// exposed only by its consuming `IntoIterator`).
fn min_burn_amount_floor_of(policy: &BurnPolicy) -> Option<u64> {
    policy.clone().into_iter().find_map(|component| {
        if component.component_code().as_package() != MinBurnAmount::code().as_package() {
            return None;
        }
        component
            .storage_slots()
            .iter()
            .find(|slot| slot.name() == MinBurnAmount::slot_name())
            .map(|slot| slot.value()[0].as_canonical_u64())
    })
}

/// Composes the xUSDC faucet account: `FungibleFaucet` + the assembled `xreserve` library
/// component (attestation mint policy, admin procs) + a `TokenPolicyManager`
/// with the attestation policy active on the mint side and the stock [`MinBurnAmount`] active on
/// the burn side + the STOCK [`PausableManager`] / [`BlocklistManager`] admin components + the
/// **role-gating admin foundation** (a seeded `RoleBasedAccessControl` +
/// [`XReserveAdminAuthority`]'s `Authority::RbacControlled`).
///
/// Construct with [`XReserveStablecoinBuilder::new`] (the faucet supply parameters plus the `owner`
/// and role holders — the faucet and the `xreserve` component are built internally, not passed in),
/// supply the three build-seeded domain-config fields via
/// [`XReserveStablecoinBuilder::with_domain_config`] (required — a build without them is rejected),
/// optionally override the active burn policy or the min-burn floor, then call
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
    /// Overridden active burn policy (default: the stock [`MinBurnAmount`] descriptor). A
    /// non-MinBurnAmount choice exercises the missing-burn-policy rejection.
    requested_active_burn_policy: Option<BurnPolicy>,
    /// The minimum burn size (the burn-floor threshold) seeded into the stock [`MinBurnAmount`]
    /// companion's floor slot. Default [`MIN_BURN_SIZE_FLOOR`] (= 1 — the zero floor: burns must
    /// move at least one unit, keeping zero-amount burns rejected); a value below the
    /// floor is rejected at build. The reworked `set_min_burn_size` admin note (which asserts
    /// the same floor) mutates the SAME slot at runtime.
    min_burn_size: u64,
    /// The three build-seeded domain-config fields — REQUIRED before
    /// [`Self::build_components`]; see [`Self::with_domain_config`].
    domain_config: Option<DomainConfigSeed>,
}

impl XReserveStablecoinBuilder {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a builder from the faucet supply parameters (`max_supply` / `token_supply`), the
    /// `owner` (the seeded `ADMIN` member that gates every unmapped authority-gated procedure), the
    /// `pauser_holder` / `manager_holder`
    /// seeded as the sole members of `DOM_PAUSER` / `DOM_MANAGER`, and the
    /// `blocklist_manager_holder` seeded as the sole member of `BLK_MANAGER` (the external
    /// transfer-blocklist administrator).
    ///
    /// The faucet is NOT a parameter: it has a fixed identity — name `USDCx`, symbol
    /// [`USDCX_TOKEN_SYMBOL`], [`USDCX_DECIMALS`] decimals, and `is_max_supply_mutable(true)` — so the
    /// builder BUILDS it here from `max_supply` / `token_supply`, and the mutability invariant, the
    /// decimals and the symbol are guaranteed BY CONSTRUCTION. There is no way to hand the
    /// builder an immutable or mis-configured faucet. The `xreserve` component is likewise not a
    /// parameter — there is exactly one valid value (the shipped MASM), so the builder assembles it
    /// via [`XReserveComponent`]. The active mint policy is always the attestation policy, hard-wired
    /// at composition. Defaults to the stock [`MinBurnAmount`] as the active burn policy and a
    /// min-burn floor of [`MIN_BURN_SIZE_FLOOR`].
    ///
    /// # Errors
    ///
    /// [`XReserveStablecoinBuilderError::FaucetComposition`] if the supply parameters do not form a
    /// valid `FungibleFaucet`.
    pub fn new(
        max_supply: AssetAmount,
        token_supply: AssetAmount,
        owner: AccountId,
        pauser_holder: AccountId,
        manager_holder: AccountId,
        blocklist_manager_holder: AccountId,
    ) -> Result<Self, XReserveStablecoinBuilderError> {
        Ok(Self {
            faucet: build_usdcx_faucet(max_supply, token_supply)?,
            xreserve_component: XReserveComponent::assemble().into(),
            owner,
            pauser_holder,
            manager_holder,
            blocklist_manager_holder,
            requested_active_burn_policy: None,
            min_burn_size: MIN_BURN_SIZE_FLOOR,
            domain_config: None,
        })
    }

    // MODIFIERS
    // --------------------------------------------------------------------------------------------

    /// Overrides the requested active burn policy (default: the stock [`MinBurnAmount`]).
    /// A non-MinBurnAmount choice (e.g. [`BurnPolicy::allow_all`]) is rejected by
    /// [`Self::build_components`] with
    /// [`XReserveStablecoinBuilderError::MissingMinBurnAmountPolicy`] — packaging cannot drop
    /// the burn floor predicate.
    pub fn with_active_burn_policy(mut self, policy: BurnPolicy) -> Self {
        self.requested_active_burn_policy = Some(policy);
        self
    }

    /// Sets the minimum burn size seeded into the stock [`MinBurnAmount`] floor slot (default
    /// [`MIN_BURN_SIZE_FLOOR`] = 1). A value below the floor is rejected by
    /// [`Self::build_components`] with
    /// [`XReserveStablecoinBuilderError::MinBurnSizeBelowFloor`] (the zero-floor invariant);
    /// a value above [`AssetAmount::MAX`] with
    /// [`XReserveStablecoinBuilderError::MinBurnSizeExceedsMax`].
    pub fn min_burn_size(mut self, min_burn_size: u64) -> Self {
        self.min_burn_size = min_burn_size;
        self
    }

    /// Supplies the three BUILD-SEEDED domain-config fields: the u32 `domain` and
    /// `source_domain` ids and the `xreserve_contract` remote address, typed as [`EthBytes32`] (the
    /// 32-byte source-chain address newtype) rather than a raw `[u8; 32]`. REQUIRED — a build without
    /// them is rejected with [`XReserveStablecoinBuilderError::MissingDomainConfig`]. The values are
    /// written into the declared `domain` / `source_domain` / `xreserve_contract_{hi,lo}` slots
    /// at composition time (`[domain, 0, 0, 0]` / `[source_domain, 0, 0, 0]` / the raw 8x
    /// u32-LE packed felts, hi = wire bytes 0..16, lo = bytes 16..32).
    pub fn with_domain_config(
        mut self,
        domain: u32,
        source_domain: u32,
        xreserve_contract: EthBytes32,
    ) -> Self {
        self.domain_config = Some(DomainConfigSeed {
            domain,
            source_domain,
            xreserve_contract,
        });
        self
    }

    // GETTERS
    // --------------------------------------------------------------------------------------------

    /// Resolves the attestation mint policy's procedure root from the installed `xreserve`
    /// component. The same root is registered as the active mint policy, so the policy manager's
    /// stored `dynexec` root equals the installed proc's MAST root.
    pub fn attestation_mint_policy_root(&self) -> Result<Word, XReserveStablecoinBuilderError> {
        self.xreserve_component
            .get_procedure_root_by_path(ATTESTATION_MINT_POLICY_PROC_PATH)
            .map(Word::from)
            .ok_or(XReserveStablecoinBuilderError::AttestationPolicyProcNotFound)
    }

    // BUILD / COMPOSE
    // --------------------------------------------------------------------------------------------

    /// Production composition: validates that the active burn policy is the stock [`MinBurnAmount`],
    /// seeds the three build-time domain-config fields, then composes the account components. The
    /// faucet's `max_supply` mutability is guaranteed by construction (the crate-root
    /// [`Self::build_account`] path builds the faucet `is_max_supply_mutable(true)`), so there is no
    /// runtime mutability reject.
    pub fn build_components(
        &self,
    ) -> Result<Vec<AccountComponent>, XReserveStablecoinBuilderError> {
        // Blocklist capability isolation: the BLK_MANAGER holder (transfer-blocklist administrator)
        // MUST be an external entity with no other faucet-admin capability. Reject at build time if it
        // collides with the administrator (ADMIN — would gain a direct block/unblock path), the DOM_PAUSER
        // holder, or the DOM_MANAGER holder — the two-way isolation the blocklist decision requires.
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
        let attestation_root = self.attestation_mint_policy_root()?;
        // The faucet ships exactly ONE mint policy: the attestation policy, hard-wired here from the
        // installed xreserve component (whose `has_procedure` check cannot fail — `attestation_root`
        // was just resolved FROM that component). There is no injectable override, so the active
        // mint policy resolves to the attestation root by construction and every supply increase
        // passes the attestation gate — a parameter with exactly one valid value is not a parameter.
        let active = MintPolicy::custom(
            AccountProcedureRoot::from_raw(attestation_root),
            [self.xreserve_component.clone()],
        )
        .map_err(XReserveStablecoinBuilderError::MintPolicy)?;
        // validate-what-you-ship: every required xreserve slot must be declared on the supplied
        // component — a missing slot would ship a faucet whose reads / writes of it trap
        // ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME at runtime. Presence-only for the two maps (the
        // per-slice fixtures legitimately pre-seed values); the three build-seeded fields are
        // overwritten below.
        for label in REQUIRED_XRESERVE_SLOT_LABELS {
            let name = StorageSlotName::new(label)
                .expect("the required xreserve slot labels are valid constants");
            if !self
                .xreserve_component
                .storage_slots()
                .iter()
                .any(|slot| slot.name() == &name)
            {
                return Err(XReserveStablecoinBuilderError::MissingXReserveSlot(label));
            }
        }
        // token-config exactness (decimals == 6, the amount reducer's scale; symbol == USDCX) is now
        // guaranteed BY CONSTRUCTION: the faucet is built by `build_usdcx_faucet`, which hard-wires
        // both, so there is nothing to validate here — the faucet cannot be handed in mis-configured.
        // The zero floor (zero-amount burns stay rejected): the seeded min-burn floor must be at least
        // MIN_BURN_SIZE_FLOOR (= 1) and a representable AssetAmount. The runtime twin is the
        // reworked set_min_burn_size note's `new_min >= 1` assert.
        if self.min_burn_size < MIN_BURN_SIZE_FLOOR {
            return Err(XReserveStablecoinBuilderError::MinBurnSizeBelowFloor(
                self.min_burn_size,
            ));
        }
        let min_burn = AssetAmount::new(self.min_burn_size).map_err(|_| {
            XReserveStablecoinBuilderError::MinBurnSizeExceedsMax(self.min_burn_size)
        })?;
        // Burn side: the ACTIVE burn policy the manager receives is ALWAYS the STOCK
        // MinBurnAmount seeded with the VALIDATED floor (`min_burn`, already `>= 1`). An explicit
        // override exists only to exercise the rejection paths and can NEVER lower the shipped
        // floor: a wrong-root override is rejected (MissingMinBurnAmountPolicy), and a same-root
        // override whose MinBurnAmount companion floor disagrees with the validated min_burn_size
        // is rejected (BurnPolicyFloorMismatch). This closes the same-root zero-floor bypass —
        // `with_active_burn_policy(BurnPolicy::min_burn_amount(0))` shares MinBurnAmount::root() and
        // would otherwise smuggle a zero-valued companion that restores zero-amount burns (the
        // stock predicate is `min <= amount`).
        if let Some(policy) = &self.requested_active_burn_policy {
            if policy.root() != MinBurnAmount::root() {
                return Err(XReserveStablecoinBuilderError::MissingMinBurnAmountPolicy);
            }
            let requested = min_burn_amount_floor_of(policy)
                .ok_or(XReserveStablecoinBuilderError::MissingMinBurnAmountPolicy)?;
            if requested != self.min_burn_size {
                return Err(XReserveStablecoinBuilderError::BurnPolicyFloorMismatch {
                    requested,
                    expected: self.min_burn_size,
                });
            }
        }
        let active_burn = BurnPolicy::min_burn_amount(min_burn);
        // Domain-config build seeding: the three domain-config fields are REQUIRED builder inputs
        // written into the declared slots.
        let domain_config = self
            .domain_config
            .ok_or(XReserveStablecoinBuilderError::MissingDomainConfig)?;
        let xreserve_component = self.xreserve_component_with_domain_seed(domain_config);
        // Transfer blocklist (a ratified decision — see the transfer-blocklist decision record
        // and the adversarially-audited integration research report under `docs/`). The stock
        // `BasicBlocklist` is wired as the ACTIVE policy for BOTH the send and receive kinds,
        // starting with an EMPTY blocklist. Both kinds reference the SAME descriptor root, so the
        // manager installs the `BasicBlocklist` companion (and its `blocked_accounts` slot)
        // exactly ONCE and dedups by root. Registering these policies makes the manager install
        // the two protocol asset-callback slots, which REQUIRES the account be built
        // `AssetCallbackFlag::Enabled`; xUSDC is a POLICED asset. No allow-all reserved alternate
        // is registered for ANY kind (the no-re-activation posture: the attestation gate, the
        // burn floor, and the blocklist can never be swapped out at runtime). The
        // `basic_asset_tripwire.rs` + `account_callable_surface.rs` tripwires enforce this wiring.
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(active)
            .active_burn_policy(active_burn)
            .active_send_policy(TransferPolicy::empty_basic_blocklist())
            .active_receive_policy(TransferPolicy::empty_basic_blocklist())
            .build();

        // The admin foundation, appended AFTER the early returns so a rejected build never reaches
        // here. `XReserveAdminAuthority` installs `Authority::RbacControlled` with a role assigned
        // to each of the four stock manager procedures; every other authority-gated procedure
        // (`set_attester`, the stock supply-cap / burn-floor / policy setters, the emergency
        // switch) is unassigned and so resolves to the `ADMIN` role, whose sole seeded member is the
        // bootstrap administrator — the same identity that gated them under the earlier owner-controlled mode. Mint
        // execution is `assert_authorized`-free (policy_manager.masm), so this leaves the
        // attestation-gate behavior unchanged. There is NO two-step ownership component, so the
        // built-in ADMIN role is the account's only authority handle and no owner slot exists to
        // drift from it. This mirrors `AccessControl::Rbac` (access/mod.rs) with the RBAC SEEDED
        // with the DOM role members + the external BLK_MANAGER, since the stock constructor cannot
        // express the `DOM_PAUSER → DOM_MANAGER` administration delegation the seed carries.
        let mut components = self.assemble_components(manager, xreserve_component)?;
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

    // The final-`Account` constructor ([`Self::build_account`]) and the crate-root
    // [`build_faucet_account`] / component assembly ([`XReserveComponent`]) live in the sibling
    // `construction` module (this file composes the component SET; that one turns it into an
    // `Account`).

    /// Reconstructs the supplied `xreserve` component with the three BUILD-SEEDED domain-config
    /// values written into their declared slots (`[domain, 0, 0, 0]`, `[source_domain, 0, 0, 0]`,
    /// and the packed `xreserve_contract` hi/lo
    /// words). The two registry maps are carried through as declared.
    fn xreserve_component_with_domain_seed(&self, seed: DomainConfigSeed) -> AccountComponent {
        let domain_name = StorageSlotName::new(DOMAIN_CONFIG_SLOT_LABEL)
            .expect("the domain slot label is a valid constant");
        let source_name = StorageSlotName::new(SOURCE_DOMAIN_CONFIG_SLOT_LABEL)
            .expect("the source_domain slot label is a valid constant");
        let hi_name = StorageSlotName::new(XRESERVE_CONTRACT_HI_SLOT_LABEL)
            .expect("the xreserve_contract_hi slot label is a valid constant");
        let lo_name = StorageSlotName::new(XRESERVE_CONTRACT_LO_SLOT_LABEL)
            .expect("the xreserve_contract_lo slot label is a valid constant");
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
                if slot.name() == &domain_name {
                    StorageSlot::with_value(domain_name.clone(), scalar_word(seed.domain))
                } else if slot.name() == &source_name {
                    StorageSlot::with_value(source_name.clone(), scalar_word(seed.source_domain))
                } else if slot.name() == &hi_name {
                    StorageSlot::with_value(hi_name.clone(), hi_word)
                } else if slot.name() == &lo_name {
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

    /// Assembles the final component list from the manager and the domain-seeded `xreserve`
    /// component.
    ///
    /// PAUSE PROVENANCE (Domain-Pauser-only): the stock `PausableManager` IS installed, and its
    /// `pause` / `unpause` roots are assigned `DOM_PAUSER` by [`XReserveAdminAuthority`], so the
    /// owner has no pause path — the capability is the Domain Pauser's alone. The `is_paused` slot
    /// every `assert_not_paused` halt-gate reads (`execute_mint_policy`/`execute_burn_policy`, the
    /// setters) is installed by the base `Pausable` component, not by the manager, which installs
    /// ZERO storage.
    ///
    /// POLICY-COMPANION SEAM: the
    /// policy descriptors carry their companion components, and the manager's iterator emits one
    /// companion copy per DISTINCT policy root after the manager component itself. With this
    /// policy set the remainder is EXACTLY THREE: ONE xreserve-component copy (the
    /// custom attestation mint policy), ONE stock [`MinBurnAmount`] companion (the burn policy —
    /// it carries the floor slot the policy reads and the stock setter writes), and ONE
    /// `BasicBlocklist` companion (the send + receive transfer policy, which share the descriptor
    /// root, so it appears once). The seam consumes the iterator, keeps its head (the manager
    /// component), asserts the remainder is exactly those three recognized companions, DROPS the
    /// redundant xreserve copy (the xreserve component is installed exactly ONCE, here), and
    /// INSTALLS the [`MinBurnAmount`] + `BasicBlocklist` companions emitted by the manager. Any
    /// other shape — a foreign companion, a missing floor/blocklist companion (which would ship a
    /// faucet whose slot accesses trap), or the wrong copy counts — is a loud
    /// [`XReserveStablecoinBuilderError::PolicyCompanionMismatch`], never a silent drop.
    fn assemble_components(
        &self,
        manager: TokenPolicyManager,
        xreserve_component: AccountComponent,
    ) -> Result<Vec<AccountComponent>, XReserveStablecoinBuilderError> {
        let xreserve_code = xreserve_component.component_code().clone();
        let mut manager_parts = manager.into_iter();
        let manager_component = manager_parts.next().expect(
            "the manager iterator yields the manager component first (manager.rs IntoIterator doc)",
        );
        let companions: Vec<AccountComponent> = manager_parts.collect();
        let expected_xreserve = 1;
        let expected_min_burn = 1;
        let expected_blocklist = 1;
        let xreserve_recognized = companions
            .iter()
            .filter(|c| c.component_code().as_package() == xreserve_code.as_package())
            .count();
        let mut min_burn_companion: Option<AccountComponent> = None;
        let mut min_burn_recognized = 0usize;
        let mut blocklist_companion: Option<AccountComponent> = None;
        let mut blocklist_recognized = 0usize;
        for companion in &companions {
            if companion.component_code().as_package() == MinBurnAmount::code().as_package() {
                min_burn_recognized += 1;
                min_burn_companion = Some(companion.clone());
            } else if companion.component_code().as_package() == BasicBlocklist::code().as_package()
            {
                blocklist_recognized += 1;
                blocklist_companion = Some(companion.clone());
            }
        }
        // `found` is the FULL remainder the manager emitted, so a smuggled foreign companion shows up
        // as `found > xreserve_recognized + min_burn_recognized + blocklist_recognized`, and a
        // missing/duplicated stock companion as its `*_recognized != expected_*`.
        if xreserve_recognized != expected_xreserve
            || min_burn_recognized != expected_min_burn
            || blocklist_recognized != expected_blocklist
            || companions.len() != expected_xreserve + expected_min_burn + expected_blocklist
        {
            return Err(XReserveStablecoinBuilderError::PolicyCompanionMismatch {
                expected_xreserve,
                expected_min_burn,
                expected_blocklist,
                found: companions.len(),
                xreserve_recognized,
                min_burn_recognized,
                blocklist_recognized,
            });
        }
        // the xreserve copy is the already-installed component: drop it and install the two
        // recognized stock companions (checked non-None by the guard above).
        let min_burn = min_burn_companion
            .expect("the guard above guarantees exactly one recognized MinBurnAmount companion");
        let blocklist = blocklist_companion
            .expect("the guard above guarantees exactly one recognized BasicBlocklist companion");
        Ok(vec![
            self.faucet.clone().into(),
            Pausable::unpaused().into(),
            xreserve_component,
            min_burn,
            blocklist,
            manager_component,
        ])
    }
}
