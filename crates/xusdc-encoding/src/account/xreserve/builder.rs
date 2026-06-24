//! `XReserveStablecoinBuilder` — the faucet (01) account composition for the xUSDC faucet
//! (CMP-A15, spec §5.13). First increment (R-MINT-16): wires the **mint-deny guard** as the active
//! mint policy so the inherited stock `mint_and_send` traps and the custom `xreserve_mint` is the
//! provably sole supply-increasing surface (INV-MINT-SECURITY, §5.2).
//!
//! Scope (cumulative): it composes `FungibleFaucet` + the assembled `xreserve` library component
//! (carries `apply_mint_effects`, the deny-guard `check_policy`, AND the P5-01 `set_attester` admin
//! proc) + a `TokenPolicyManager` whose active mint policy is the deny guard + `PausableManager`
//! (required: `execute_mint_policy` runs `assert_not_paused`) + the **RBAC admin foundation**
//! (`Ownable2Step` + a seeded `RoleBasedAccessControl` + `Authority::RbacControlled` on
//! `ATTEST_ADMIN`; see below). STILL DEFERRED to later slices: dynamic role management
//! (`grant_role`/`revoke_role`/`set_role_admin`), other roles (DOMAIN_PAUSER / DOMAIN_MANAGER),
//! `set_max_supply`, domain init, and the burn policy. The builder yields the validated component
//! composition; MockChain (tests) finalises it into a signed `Account`.
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
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{
    Authority, Ownable2Step, PausableManager, RoleBasedAccessControl,
};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::policies::{
    MintPolicyConfig, PolicyRegistration, TokenPolicyManager, TokenPolicyManagerError,
};

/// The single RBAC role this faucet seeds and gates `set_attester` on: the deposit-attester
/// admin. 12 chars (`RoleSymbol`'s max; `ATTESTER_ADMIN` (14) would be rejected). The MASM gate
/// carries the same symbol via the installed `Authority::RbacControlled` slot — parity is asserted
/// in the builder tests.
pub const ATTEST_ADMIN_ROLE: &str = "ATTEST_ADMIN";

/// Flat library path of the mint-deny guard's `check_policy` procedure within the assembled
/// `xreserve` library (namespace `xreserve`, module `mint_deny_guard`). This is the
/// no-leading-`::` form [`AccountComponent::get_procedure_root_by_path`] expects (matching the
/// `procedure_root!` macro and the protocol callback wiring).
pub const MINT_DENY_GUARD_PROC_PATH: &str = "xreserve::mint_deny_guard::check_policy";

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
/// + a `TokenPolicyManager` with the mint-deny guard active + `PausableManager` + the **RBAC
/// admin foundation** (`Ownable2Step` + a seeded `RoleBasedAccessControl` + `Authority::RbacControlled`
/// gating on `ATTEST_ADMIN`). The RBAC foundation ships in this production builder so the deployed
/// faucet validates the real auth model: `set_attester` is gated on `ATTEST_ADMIN`.
///
/// Construct with [`XReserveStablecoinBuilder::new`] (the `owner` and the sole `ATTEST_ADMIN`
/// `admin_holder` are required), optionally override the account type (for the non-`Public`
/// rejection test) or the requested active mint policy (for the missing-guard rejection test), then
/// call [`XReserveStablecoinBuilder::build_components`].
pub struct XReserveStablecoinBuilder {
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
    /// Top-level RBAC authority (the `Ownable2Step` owner). Required by the stock RBAC component.
    owner: AccountId,
    /// The sole seeded member of `ATTEST_ADMIN` (the account allowed to send `set_attester` notes).
    admin_holder: AccountId,
    account_type: AccountType,
    requested_active_mint_policy: Option<MintPolicyConfig>,
}

impl XReserveStablecoinBuilder {
    /// Creates a builder from a built `FungibleFaucet` and the assembled `xreserve` library
    /// component (which must carry the deny-guard `check_policy`), the RBAC `owner` (top-level
    /// authority), and the `admin_holder` seeded as the sole `ATTEST_ADMIN` member. Defaults to
    /// `AccountType::Public` and the deny guard as the active mint policy.
    pub fn new(
        faucet: FungibleFaucet,
        xreserve_component: AccountComponent,
        owner: AccountId,
        admin_holder: AccountId,
    ) -> Self {
        Self {
            faucet,
            xreserve_component,
            owner,
            admin_holder,
            account_type: AccountType::Public,
            requested_active_mint_policy: None,
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

    /// Resolves the deny-guard procedure root from the installed `xreserve` component. The same root
    /// is registered as the active mint policy, so the policy manager's stored `dynexec` root equals
    /// the installed proc's MAST root.
    pub fn mint_deny_guard_root(&self) -> Result<Word, XReserveStablecoinBuilderError> {
        self.xreserve_component
            .get_procedure_root_by_path(MINT_DENY_GUARD_PROC_PATH)
            .map(Word::from)
            .ok_or(XReserveStablecoinBuilderError::DenyGuardProcNotFound)
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
        let manager =
            TokenPolicyManager::new().with_mint_policy(active, PolicyRegistration::Active)?;

        // The RBAC admin foundation, appended AFTER the account-type / deny-guard early returns so a
        // rejected build never reaches here. The single `Authority` slot gates the stock admin
        // SETTERS (and `set_attester`) on `ATTEST_ADMIN`; mint execution / the deny path is
        // `assert_authorized`-free (policy_manager.masm:284-297), so installing this leaves the
        // R-MINT-16 deny behavior unchanged. Dependency chain: `Ownable2Step` (top-level authority
        // the stock RBAC requires) -> seeded `RoleBasedAccessControl` -> `Authority::RbacControlled`
        // (links into `rbac::assert_sender_has_role`).
        let role = RoleSymbol::new(ATTEST_ADMIN_ROLE)
            .expect("ATTEST_ADMIN is a fixed valid 12-char role symbol");
        let mut components = self.assemble_components(manager);
        components.push(Ownable2Step::new(self.owner).into());
        components.push(seeded_attest_admin_rbac(self.admin_holder));
        components.push(Authority::RbacControlled { role }.into());
        Ok(components)
    }

    /// Assembles the final component list. `PausableManager` is mandatory: the stock
    /// `execute_mint_policy` runs `assert_not_paused` before dispatching the mint policy.
    fn assemble_components(&self, manager: TokenPolicyManager) -> Vec<AccountComponent> {
        let mut components = Vec::new();
        components.push(self.faucet.clone().into());
        components.push(self.xreserve_component.clone());
        components.extend(manager); // [policy-manager component, MintAllowAll (when registered)]
        components.push(PausableManager.into());
        components
    }
}

/// Hand-builds the seeded `RoleBasedAccessControl` `AccountComponent` (Option A): both stock RBAC
/// maps are direct-seeded at build, consistent with `grant_role`'s post-state for a single first
/// grant — `role_membership[{0, ATTEST_ADMIN, holder.suffix, holder.prefix}] = [1,0,0,0]` AND
/// `role_config[{0,0,0,ATTEST_ADMIN}] = [member_count=1, admin_role=0, 0, 0]`. It reuses the stock
/// RBAC code + slot names + component metadata verbatim (NO custom RBAC logic); only the maps are
/// non-empty (the stock `From<RoleBasedAccessControl>` seeds them empty). The key encodings mirror
/// the stock readers (`miden-testing/tests/scripts/rbac.rs:57-63`). `grant_role` is NOT used (it
/// would add a tx and is a later dynamic-management slice). Seed correctness is locked by the
/// `rbac_seed_parity` + role-gate tests, not by construction (`AccountComponent::new` does not
/// validate slots against the metadata schema). Construction failures are invariants, so this
/// mirrors the stock `From<RoleBasedAccessControl>` `.expect()` pattern.
fn seeded_attest_admin_rbac(admin_holder: AccountId) -> AccountComponent {
    let role = RoleSymbol::new(ATTEST_ADMIN_ROLE)
        .expect("ATTEST_ADMIN is a fixed valid 12-char role symbol");
    // [1,0,0,0]: role_config member_count = 1, and role_membership is_member = 1.
    let member_word = Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]);

    let role_config = StorageMap::with_entries([(
        StorageMapKey::new(Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(&role)])),
        member_word,
    )])
    .expect("the single-entry role_config seed is valid");

    let role_membership = StorageMap::with_entries([(
        StorageMapKey::new(Word::from([
            Felt::ZERO,
            Felt::from(&role),
            admin_holder.suffix(),
            admin_holder.prefix().as_felt(),
        ])),
        member_word,
    )])
    .expect("the single-entry role_membership seed is valid");

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
    .expect("the seeded RBAC component mirrors the stock From impl and is valid")
}
