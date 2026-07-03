//! `XReserveStablecoinBuilder` — the faucet (01) account composition for the xUSDC faucet
//! (CMP-A15, spec §5.13). First increment (R-MINT-16): wires the **mint-deny guard** as the active
//! mint policy so the inherited stock `mint_and_send` traps and the custom `xreserve_mint` is the
//! provably sole supply-increasing surface (INV-MINT-SECURITY, §5.2).
//!
//! Scope (cumulative): it composes `FungibleFaucet` + the assembled `xreserve` library component
//! (carries `apply_mint_effects`, the deny-guard `check_policy`, the `set_attester` + `set_min_burn_size`
//! admin procs, the DOM_PAUSER custom `pause`/`unpause`) + a `TokenPolicyManager` whose active mint
//! policy is the deny guard + the **owner-gating admin foundation** (`Ownable2Step` + a seeded
//! `RoleBasedAccessControl` + `Authority::OwnerControlled`; DECISION-ADMIN-ROLE-MODEL,
//! the `AccessControl::Rbac{authority_role: None}` composition). The RBAC is SEEDED with the two Circle
//! Domain role members (`DOM_PAUSER` / `DOM_MANAGER`). Pause is Domain-Pauser-ONLY (Option 1,
//! CIRCLE-SPECIFICATION.md:121; IMPL-DEV-1 remediation): the stock `PausableManager` is NOT installed —
//! the only pause surface is the DOM_PAUSER-gated `xreserve::pause_admin` procs; the `is_paused` slot
//! the halt-gates read is installed by `FungibleFaucet` itself (see [`Self::assemble_components`]).
//! STILL DEFERRED to later slices: dynamic role management (`grant_role`/`revoke_role`/`set_role_admin`
//! consumers) and the full faucet assembly. The builder yields the validated component composition;
//! MockChain (tests) finalises it into a signed `Account`.
//!
//! Packaging: the deny guard is **runtime-assembled** MASM (no `.masl` asset / `account_component_code!`
//! here — that is a miden-standards-internal pipeline). The caller assembles the `xreserve` library
//! (namespace `xreserve`) into an `AccountComponent` and passes it in; the deny-guard procedure root
//! is resolved from that same installed code via [`AccountComponent::get_procedure_root_by_path`], so
//! the `dynexec` root the policy manager stores always equals the installed proc's MAST root.

use core::fmt;

use miden_protocol::account::{
    AccountComponent, AccountId, AccountType, RoleSymbol, StorageMap, StorageMapKey, StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step, RoleBasedAccessControl};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::policies::{
    BurnPolicyConfig, MintPolicyConfig, PolicyRegistration, TokenPolicyManager,
    TokenPolicyManagerError,
};

/// The two Circle Domain RoleSymbols this faucet seeds under the ratified Circle-faithful admin model
/// (DECISION-ADMIN-ROLE-MODEL): `DOM_PAUSER` (custom pause/unpause) and `DOM_MANAGER` (rotation / role
/// management). Both are valid `RoleSymbol`s (≤12 chars, `A`–`Z`/`_`; `DOMAIN_PAUSER`(13)/`DOMAIN_MANAGER`(14)
/// would be rejected). ORCHESTRATOR-FIXED — the builder only SEEDS the members here; their CONSUMERS
/// (the custom pause procs, grant/revoke/set_role_admin) are later slices. The setters are owner-gated
/// (`Authority::OwnerControlled`), not role-gated, so no MASM references these symbols in this slice.
pub const DOM_PAUSER_ROLE: &str = "DOM_PAUSER";
pub const DOM_MANAGER_ROLE: &str = "DOM_MANAGER";

/// Flat library path of the mint-deny guard's `check_policy` procedure within the assembled
/// `xreserve` library (namespace `xreserve`, module `mint_deny_guard`). This is the
/// no-leading-`::` form [`AccountComponent::get_procedure_root_by_path`] expects (matching the
/// `procedure_root!` macro and the protocol callback wiring).
pub const MINT_DENY_GUARD_PROC_PATH: &str = "xreserve::mint_deny_guard::check_policy";

/// Flat library path of the burn policy's `check_policy` procedure within the assembled `xreserve`
/// library (namespace `xreserve`, module `burn_policy`). The burn-slot twin of
/// [`MINT_DENY_GUARD_PROC_PATH`]; resolved via [`AccountComponent::get_procedure_root_by_path`] so the
/// `dynexec` root the policy manager stores equals the installed proc's MAST root (CMP-A10).
pub const BURN_POLICY_PROC_PATH: &str = "xreserve::burn_policy::check_policy";

/// Canonical Rust label of the `minBurnSize` value storage slot
/// (`xusdc::xreserve::attester_admin::min_burn_size`, §5.5 XReserveAttesterAdmin home, SPEC-OWNER
/// RATIFIED). The single Rust source of truth: `burn_policy.masm` declares a byte-identical
/// `word("…")` const (parity-enforced), the tests re-export this, and the future CMP-F2
/// `set_min_burn_size` setter co-owns the SAME slot. [`XReserveStablecoinBuilder::build_components`]
/// seeds it as `[min_burn_size, 0, 0, 0]`.
pub const MIN_BURN_SIZE_SLOT_LABEL: &str = "xusdc::xreserve::attester_admin::min_burn_size";

/// The storage slot the stock `FungibleFaucet` writes its mutability flags into (miden-standards
/// `token_metadata.rs`, pinned v0.15.3). `build_components` reads it to reject an immutable-`max_supply`
/// faucet — `FungibleFaucet` exposes no public accessor for the flag (it lives in private `metadata`).
const FAUCET_MUTABILITY_CONFIG_SLOT: &str = "miden::standards::faucets::mutability_config";

/// Index of `is_max_supply_mutable` within the faucet `mutability_config` word, whose layout is
/// `[is_desc_mutable, is_logo_mutable, is_extlink_mutable, is_max_supply_mutable]` (miden-standards
/// `token_metadata.rs`, pinned v0.15.3).
const MAX_SUPPLY_MUTABLE_WORD_INDEX: usize = 3;

/// Errors returned while composing the xUSDC faucet account.
#[derive(Debug)]
pub enum XReserveStablecoinBuilderError {
    /// The xUSDC faucet must be public (network-observable). A non-`Public` account type is rejected
    /// at build time so packaging cannot produce an unobservable faucet.
    NonPublicAccountType(AccountType),
    /// The active mint policy does not resolve to the deny guard — packaging cannot bypass the
    /// sole-supply-surface gate (INV-MINT-SECURITY, §5.2).
    MissingMintDenyGuard,
    /// The supplied faucet was not built with a mutable `max_supply`, so the stock `set_max_supply`
    /// admin function would be permanently dead on the deployed faucet (every call traps the runtime
    /// mutability gate). Rejected at build time so packaging cannot silently ship a faucet whose
    /// `set_max_supply` is inoperable — build the faucet with `.is_max_supply_mutable(true)`.
    ImmutableMaxSupply,
    /// The supplied `xreserve` component does not export the deny-guard procedure (assembly/path
    /// drift). Carries the expected path for diagnosis.
    DenyGuardProcNotFound,
    /// The active burn policy does not resolve to the installed `burn_policy::check_policy` — packaging
    /// cannot ship a faucet whose burns bypass the R-BURN-1/2 security predicate (CMP-A10). The burn-slot
    /// twin of [`Self::MissingMintDenyGuard`].
    MissingBurnPolicyGuard,
    /// The supplied `xreserve` component does not export the burn-policy procedure (assembly/path
    /// drift). The burn-slot twin of [`Self::DenyGuardProcNotFound`].
    BurnPolicyProcNotFound,
    /// The requested `min_burn_size` exceeds [`AssetAmount::MAX`] (`2^63 - 2^31`), so it is not a
    /// valid burn amount / field element and cannot be seeded into the `MIN_BURN_SIZE_SLOT`. Carries
    /// the offending value.
    MinBurnSizeExceedsMax(u64),
    /// The underlying `TokenPolicyManager` rejected the policy registration.
    PolicyManager(TokenPolicyManagerError),
}

impl fmt::Display for XReserveStablecoinBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonPublicAccountType(account_type) => {
                write!(
                    f,
                    "xusdc faucet must be AccountType::Public, got {account_type:?}"
                )
            }
            Self::MissingMintDenyGuard => write!(
                f,
                "active mint policy is not the mint-deny guard; packaging cannot bypass the \
                 sole-supply-surface gate"
            ),
            Self::ImmutableMaxSupply => write!(
                f,
                "xusdc faucet must be built with a mutable max supply \
                 (is_max_supply_mutable=true) so the deployed faucet's set_max_supply stays operable"
            ),
            Self::DenyGuardProcNotFound => write!(
                f,
                "the xreserve component does not export the mint-deny guard procedure \
                 '{MINT_DENY_GUARD_PROC_PATH}'"
            ),
            Self::MissingBurnPolicyGuard => write!(
                f,
                "active burn policy is not the xreserve burn policy; packaging cannot bypass the \
                 burn security predicate (R-BURN-1/2)"
            ),
            Self::BurnPolicyProcNotFound => write!(
                f,
                "the xreserve component does not export the burn policy procedure \
                 '{BURN_POLICY_PROC_PATH}'"
            ),
            Self::MinBurnSizeExceedsMax(value) => write!(
                f,
                "min_burn_size {value} exceeds the maximum representable asset amount \
                 (AssetAmount::MAX = 2^63 - 2^31)"
            ),
            Self::PolicyManager(_) => write!(f, "token policy manager composition failed"),
        }
    }
}

impl core::error::Error for XReserveStablecoinBuilderError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::PolicyManager(source) => Some(source),
            _ => None,
        }
    }
}

impl From<TokenPolicyManagerError> for XReserveStablecoinBuilderError {
    fn from(source: TokenPolicyManagerError) -> Self {
        Self::PolicyManager(source)
    }
}

/// Composes the xUSDC faucet account: `FungibleFaucet` + the assembled `xreserve` library component
/// + a `TokenPolicyManager` with the mint-deny guard active + the **owner-gating admin foundation**
/// (`Ownable2Step` + a seeded `RoleBasedAccessControl` + `Authority::OwnerControlled`;
/// DECISION-ADMIN-ROLE-MODEL). The foundation ships in this production builder so the deployed faucet
/// validates the real auth model: the setters (`set_attester` / `set_min_burn_size` / `set_max_supply`)
/// are gated on the Ownable2Step owner, and the `DOM_PAUSER` / `DOM_MANAGER` role members are seeded.
/// Pause is Domain-Pauser-ONLY: the stock `PausableManager` is deliberately NOT part of the
/// composition (Option 1, IMPL-DEV-1 remediation) — `xreserve::pause_admin::{pause,unpause}`
/// (DOM_PAUSER-gated) is the sole pause surface.
///
/// Construct with [`XReserveStablecoinBuilder::new`] (the `owner` and the `DOM_PAUSER` / `DOM_MANAGER`
/// holders are required), optionally override the account type (for the non-`Public` rejection test) or
/// the requested active mint policy (for the missing-guard rejection test), then call
/// [`XReserveStablecoinBuilder::build_components`].
pub struct XReserveStablecoinBuilder {
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
    /// Top-level authority (the `Ownable2Step` owner) — the sole authority for the owner-gated setters
    /// (`set_attester` / `set_min_burn_size` / stock `set_max_supply`) under `Authority::OwnerControlled`.
    owner: AccountId,
    /// The seeded `DOM_PAUSER` role member (its consumer — custom pause/unpause — is a later slice).
    pauser_holder: AccountId,
    /// The seeded `DOM_MANAGER` role member (its consumer — role management — is a later slice).
    manager_holder: AccountId,
    account_type: AccountType,
    requested_active_mint_policy: Option<MintPolicyConfig>,
    /// Overridden active burn policy (default: the installed `burn_policy::check_policy` as
    /// `Custom(burn_root)`). A non-burn-policy choice exercises the missing-burn-guard rejection.
    requested_active_burn_policy: Option<BurnPolicyConfig>,
    /// The `minBurnSize` (R-BURN-2 threshold) the builder seeds into the `MIN_BURN_SIZE_SLOT`
    /// (`xusdc::xreserve::attester_admin::min_burn_size`) value slot as `[min_burn_size, 0, 0, 0]`.
    /// Default `0` (no minimum); override via [`Self::min_burn_size`]. The deferred CMP-F2
    /// `set_min_burn_size` writes the SAME slot (plan §3.2).
    min_burn_size: u64,
}

impl XReserveStablecoinBuilder {
    /// Creates a builder from a built `FungibleFaucet` and the assembled `xreserve` library
    /// component (which must carry the deny-guard `check_policy`), the `owner` (top-level authority for
    /// the owner-gated setters), and the `pauser_holder` / `manager_holder` seeded as the sole members
    /// of `DOM_PAUSER` / `DOM_MANAGER`. Defaults to `AccountType::Public` and the deny guard as the
    /// active mint policy.
    pub fn new(
        faucet: FungibleFaucet,
        xreserve_component: AccountComponent,
        owner: AccountId,
        pauser_holder: AccountId,
        manager_holder: AccountId,
    ) -> Self {
        Self {
            faucet,
            xreserve_component,
            owner,
            pauser_holder,
            manager_holder,
            account_type: AccountType::Public,
            requested_active_mint_policy: None,
            requested_active_burn_policy: None,
            min_burn_size: 0,
        }
    }

    /// Overrides the account type (default `Public`). Used to exercise the non-`Public` rejection.
    pub fn account_type(mut self, account_type: AccountType) -> Self {
        self.account_type = account_type;
        self
    }

    /// Overrides the requested active mint policy (default: the deny guard). A non-deny choice is
    /// rejected by [`Self::build_components`] with [`XReserveStablecoinBuilderError::MissingMintDenyGuard`]
    /// — packaging cannot silently drop the deny guard.
    pub fn with_active_mint_policy(mut self, policy: MintPolicyConfig) -> Self {
        self.requested_active_mint_policy = Some(policy);
        self
    }

    /// Overrides the requested active burn policy (default: the installed `burn_policy::check_policy`).
    /// The burn-slot twin of [`Self::with_active_mint_policy`]; a non-burn-policy choice (e.g.
    /// [`BurnPolicyConfig::AllowAll`]) is rejected by [`Self::build_components`] with
    /// [`XReserveStablecoinBuilderError::MissingBurnPolicyGuard`] — packaging cannot drop the burn
    /// security predicate (CMP-A10, R-BURN-1/2).
    pub fn with_active_burn_policy(mut self, policy: BurnPolicyConfig) -> Self {
        self.requested_active_burn_policy = Some(policy);
        self
    }

    /// Sets the `minBurnSize` (the R-BURN-2 threshold) the builder seeds into the `MIN_BURN_SIZE_SLOT`
    /// value slot as `[min_burn_size, 0, 0, 0]` (default `0` — no minimum). The burn policy's R-BURN-2
    /// check reads element 0 of this slot.
    pub fn min_burn_size(mut self, min_burn_size: u64) -> Self {
        self.min_burn_size = min_burn_size;
        self
    }

    /// Resolves the deny-guard procedure root from the installed `xreserve` component. The same root
    /// is registered as the active mint policy, so the policy manager's stored `dynexec` root equals
    /// the installed proc's MAST root.
    pub fn mint_deny_guard_root(&self) -> Result<Word, XReserveStablecoinBuilderError> {
        self.xreserve_component
            .get_procedure_root_by_path(MINT_DENY_GUARD_PROC_PATH)
            .map(Word::from)
            .ok_or(XReserveStablecoinBuilderError::DenyGuardProcNotFound)
    }

    /// Resolves the burn-policy procedure root from the installed `xreserve` component. The same root
    /// is registered as the active burn policy, so the policy manager's stored `dynexec` root equals
    /// the installed proc's MAST root. The burn-slot twin of [`Self::mint_deny_guard_root`].
    pub fn burn_policy_root(&self) -> Result<Word, XReserveStablecoinBuilderError> {
        self.xreserve_component
            .get_procedure_root_by_path(BURN_POLICY_PROC_PATH)
            .map(Word::from)
            .ok_or(XReserveStablecoinBuilderError::BurnPolicyProcNotFound)
    }

    /// Reads the supplied faucet's `is_max_supply_mutable` flag from its assembled storage. The stock
    /// `FungibleFaucet` exposes no accessor for it (the flag lives in its private `metadata`), so the
    /// guard reads the `mutability_config` slot the faucet writes. Fail-closed: returns `true` ONLY
    /// when the slot is present and the flag felt is exactly `1`; a missing slot or any non-`1` felt
    /// yields `false`, so [`Self::build_components`] rejects the build rather than letting an immutable
    /// (or malformed) faucet pass silently.
    fn faucet_max_supply_is_mutable(&self) -> bool {
        let slot_name = StorageSlotName::new(FAUCET_MUTABILITY_CONFIG_SLOT)
            .expect("the faucet mutability_config slot name is a valid constant");
        self.faucet
            .clone()
            .into_storage_slots()
            .into_iter()
            .find(|slot| slot.name() == &slot_name)
            .map(|slot| slot.value()[MAX_SUPPLY_MUTABLE_WORD_INDEX] == Felt::from(1u32))
            .unwrap_or(false)
    }

    /// Production composition: validates `AccountType::Public` and that the active mint policy is the
    /// deny guard, then composes the account components with the deny guard as the **only** mint
    /// policy (no reserved allow-all — production carries no re-activation path for the denied stock
    /// mint).
    pub fn build_components(
        &self,
    ) -> Result<Vec<AccountComponent>, XReserveStablecoinBuilderError> {
        if self.account_type != AccountType::Public {
            return Err(XReserveStablecoinBuilderError::NonPublicAccountType(
                self.account_type,
            ));
        }
        let deny_root = self.mint_deny_guard_root()?;
        let active = self
            .requested_active_mint_policy
            .unwrap_or(MintPolicyConfig::Custom(deny_root));
        // INV-MINT-SECURITY (§5.2): the active mint policy MUST resolve to the deny guard.
        if active.root() != deny_root {
            return Err(XReserveStablecoinBuilderError::MissingMintDenyGuard);
        }
        // Validate-what-you-ship: the supplied faucet's max_supply must be mutable, else the stock
        // `set_max_supply` admin function ships permanently dead (it traps the runtime mutability gate
        // on every call). Placed AFTER the account-type / deny-guard rejections so those keep their
        // precedence. Reject — never mutate the supplied faucet.
        if !self.faucet_max_supply_is_mutable() {
            return Err(XReserveStablecoinBuilderError::ImmutableMaxSupply);
        }
        // CMP-A10 burn slot: wire the installed `burn_policy::check_policy` as the ACTIVE burn policy so
        // every `receive_and_burn` is gated on the R-BURN-1/2 predicate (the burn-slot twin of the
        // active mint deny guard above).
        let burn_root = self.burn_policy_root()?;
        let active_burn = self
            .requested_active_burn_policy
            .unwrap_or(BurnPolicyConfig::Custom(burn_root));
        // INV (CMP-A10): the active burn policy MUST resolve to the installed `burn_policy::check_policy`
        // — packaging cannot ship a faucet whose burns bypass the R-BURN-1/2 predicate (the burn-slot
        // twin of the mint deny-guard check above).
        if active_burn.root() != burn_root {
            return Err(XReserveStablecoinBuilderError::MissingBurnPolicyGuard);
        }
        let manager = TokenPolicyManager::new()
            .with_mint_policy(active, PolicyRegistration::Active)?
            .with_burn_policy(active_burn, PolicyRegistration::Active)?;

        // The owner-gating admin foundation (DECISION-ADMIN-ROLE-MODEL), appended AFTER the account-type
        // / deny-guard early returns so a rejected build never reaches here. `Authority::OwnerControlled`
        // gates the stock admin SETTERS (and `set_attester` / `set_min_burn_size`) on the Ownable2Step
        // owner; mint execution / the deny path is `assert_authorized`-free (policy_manager.masm:284-297),
        // so installing this leaves the R-MINT-16 deny behavior unchanged. This is exactly the
        // `AccessControl::Rbac { authority_role: None }` composition (Ownable2Step + RoleBasedAccessControl
        // + Authority::OwnerControlled, access/mod.rs:79) with the RBAC SEEDED with the two DOM role
        // members (whose consumers — custom pause, role management — are later slices).
        let xreserve_component = self.xreserve_component_with_min_burn_size()?;
        let mut components = self.assemble_components(manager, xreserve_component);
        components.push(Ownable2Step::new(self.owner).into());
        components.push(seeded_dom_roles_rbac(self.pauser_holder, self.manager_holder));
        components.push(Authority::OwnerControlled.into());
        Ok(components)
    }

    /// Reconstructs the supplied `xreserve` component with the `MIN_BURN_SIZE_SLOT` value slot
    /// appended (`[min_burn_size, 0, 0, 0]`) so the installed `burn_policy::check_policy` resolves its
    /// R-BURN-2 read on the deployed account. The caller supplies the component WITHOUT this slot (the
    /// builder owns seeding it); the future CMP-F2 `set_min_burn_size` mutates the SAME slot (plan
    /// §3.2). Uses the canonical `AssetAmount -> Felt` (no truncation); a `min_burn_size` exceeding
    /// [`AssetAmount::MAX`] is rejected with [`XReserveStablecoinBuilderError::MinBurnSizeExceedsMax`].
    fn xreserve_component_with_min_burn_size(
        &self,
    ) -> Result<AccountComponent, XReserveStablecoinBuilderError> {
        let min_burn = AssetAmount::new(self.min_burn_size)
            .map_err(|_| XReserveStablecoinBuilderError::MinBurnSizeExceedsMax(self.min_burn_size))?;
        let slot_name = StorageSlotName::new(MIN_BURN_SIZE_SLOT_LABEL)
            .expect("the min_burn_size slot label is a valid constant");
        let mut slots = self.xreserve_component.storage_slots().to_vec();
        slots.push(StorageSlot::with_value(
            slot_name,
            Word::from([Felt::from(min_burn), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        ));
        Ok(AccountComponent::new(
            self.xreserve_component.component_code().clone(),
            slots,
            self.xreserve_component.metadata().clone(),
        )
        .expect("the xreserve component augmented with the min_burn_size slot has < 256 slots"))
    }

    /// Assembles the final component list. Takes the `xreserve` component already augmented with the
    /// `MIN_BURN_SIZE_SLOT` (see [`Self::xreserve_component_with_min_burn_size`]).
    ///
    /// PAUSE PROVENANCE (Option 1, Domain-Pauser-only — IMPL-DEV-1 remediation): the stock
    /// `PausableManager` (owner-gated callable `pause`/`unpause`) is deliberately NOT installed; the
    /// only pause surface is the DOM_PAUSER-gated `xreserve::pause_admin` procs carried by the
    /// `xreserve` component. The `is_paused` slot every `assert_not_paused` halt-gate reads
    /// (`execute_mint_policy`/`execute_burn_policy`, the setters, `xreserve_mint.masm`) is installed
    /// by `FungibleFaucet::into_storage_slots` ITSELF at the pinned v0.15.3 (`fungible/mod.rs:397`) —
    /// `PausableManager` installs ZERO storage (`manager.rs:78`), so its removal cannot drop the slot.
    /// PIN-BUMP HAZARD: upstream v0.16 (#2944) moves the slot OUT of `FungibleFaucet` — at any pin
    /// bump the composition must add the base `Pausable` component (NOT `PausableManager`); the
    /// `production_components_carry_is_paused_slot` builder test is the loud tripwire. Do NOT add the
    /// base `Pausable` at THIS pin: the faucet already installs the identically-named slot and
    /// duplicate slot names hard-reject the build (`AccountError::DuplicateStorageSlotName`).
    fn assemble_components(
        &self,
        manager: TokenPolicyManager,
        xreserve_component: AccountComponent,
    ) -> Vec<AccountComponent> {
        let mut components = Vec::new();
        components.push(self.faucet.clone().into());
        components.push(xreserve_component);
        components.extend(manager); // [policy-manager component, MintAllowAll (when registered)]
        components
    }
}

/// Hand-builds the seeded `RoleBasedAccessControl` `AccountComponent` (Option A) with the TWO Circle
/// Domain role members — `DOM_PAUSER` (→ `pauser_holder`) and `DOM_MANAGER` (→ `manager_holder`). Both
/// stock RBAC maps are direct-seeded at build, consistent with `grant_role`'s post-state for a single
/// first grant per role — `role_membership[{0, <role>, holder.suffix, holder.prefix}] = [1,0,0,0]` AND
/// `role_config[{0,0,0,<role>}] = [member_count=1, admin_role=0, 0, 0]` (admin_role=0 = owner-administered;
/// `set_role_admin` is owner-only, rbac.masm:159). It reuses the stock RBAC code + slot names + component
/// metadata verbatim (NO custom RBAC logic); only the maps are non-empty (the stock
/// `From<RoleBasedAccessControl>` seeds them empty). The key encodings mirror the stock readers
/// (`miden-testing/tests/scripts/rbac.rs:57-63`). `grant_role` is NOT used (it would add a tx and is a
/// later dynamic-management slice). Seed correctness is locked by the `dom_roles_seeded_correctly` +
/// owner-ONLY tests, not by construction (`AccountComponent::new` does not validate slots against the
/// metadata schema). Construction failures are invariants, so this mirrors the stock `.expect()` pattern.
fn seeded_dom_roles_rbac(
    pauser_holder: AccountId,
    manager_holder: AccountId,
) -> AccountComponent {
    let pauser =
        RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol (≤12)");
    let manager =
        RoleSymbol::new(DOM_MANAGER_ROLE).expect("DOM_MANAGER is a fixed valid role symbol (≤12)");
    // [1,0,0,0]: role_config member_count = 1, and role_membership is_member = 1.
    let member_word = Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]);

    let role_config = StorageMap::with_entries([
        (
            StorageMapKey::new(Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(&pauser)])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(&manager)])),
            member_word,
        ),
    ])
    .expect("the two-role role_config seed is valid");

    let role_membership = StorageMap::with_entries([
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&pauser),
                pauser_holder.suffix(),
                pauser_holder.prefix().as_felt(),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&manager),
                manager_holder.suffix(),
                manager_holder.prefix().as_felt(),
            ])),
            member_word,
        ),
    ])
    .expect("the two-role role_membership seed is valid");

    AccountComponent::new(
        RoleBasedAccessControl::code().clone(),
        vec![
            StorageSlot::with_map(RoleBasedAccessControl::role_config_slot().clone(), role_config),
            StorageSlot::with_map(
                RoleBasedAccessControl::role_membership_slot().clone(),
                role_membership,
            ),
        ],
        RoleBasedAccessControl::component_metadata(),
    )
    .expect("the seeded DOM-roles RBAC component mirrors the stock From impl and is valid")
}
