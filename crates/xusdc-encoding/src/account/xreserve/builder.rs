//! `XReserveStablecoinBuilder` — the faucet (01) account composition for the xUSDC faucet
//! (CMP-A15, spec §5.13). First increment (R-MINT-16): wires the **mint-deny guard** as the active
//! mint policy so the inherited stock `mint_and_send` traps and the custom `xreserve_mint` is the
//! provably sole supply-increasing surface (INV-MINT-SECURITY, §5.2).
//!
//! Scope of THIS increment (the rest is named-deferred, not dropped — see the R-MINT-16 plan §2):
//! it composes `FungibleFaucet` + the assembled `xreserve` library component (carries
//! `apply_mint_effects` AND the deny-guard `check_policy`) + a `TokenPolicyManager` whose active mint
//! policy is the deny guard + `PausableManager` (required: `execute_mint_policy` runs
//! `assert_not_paused`). DEFERRED to later slices: `Authority`/`Ownable2Step`/`RBAC` admin + auth
//! finalisation into a signed `Account`, `XReserveDomainConfig`, `XReserveAttesterAdmin`,
//! `XReserveNonceRegistry` as a distinct component, and the burn policy. The builder yields the
//! validated component composition; MockChain (tests) and the future admin builder finalise it.
//!
//! Packaging: the deny guard is **runtime-assembled** MASM (no `.masl` asset / `account_component_code!`
//! here — that is a miden-standards-internal pipeline). The caller assembles the `xreserve` library
//! (namespace `xreserve`) into an `AccountComponent` and passes it in; the deny-guard procedure root
//! is resolved from that same installed code via [`AccountComponent::get_procedure_root_by_path`], so
//! the `dynexec` root the policy manager stores always equals the installed proc's MAST root.

use core::fmt;

use miden_protocol::account::{AccountComponent, AccountType};
use miden_protocol::Word;
use miden_standards::account::access::PausableManager;
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::policies::{
    MintPolicyConfig, PolicyRegistration, TokenPolicyManager, TokenPolicyManagerError,
};

/// Flat library path of the mint-deny guard's `check_policy` procedure within the assembled
/// `xreserve` library (namespace `xreserve`, module `mint_deny_guard`). This is the
/// no-leading-`::` form [`AccountComponent::get_procedure_root_by_path`] expects (matching the
/// `procedure_root!` macro and the protocol callback wiring).
pub const MINT_DENY_GUARD_PROC_PATH: &str = "xreserve::mint_deny_guard::check_policy";

/// Errors returned while composing the xUSDC faucet account.
#[derive(Debug)]
pub enum XReserveStablecoinBuilderError {
    /// The xUSDC faucet must be public (network-observable). A non-`Public` account type is rejected
    /// at build time so packaging cannot produce an unobservable faucet.
    NonPublicAccountType(AccountType),
    /// The active mint policy does not resolve to the deny guard — packaging cannot bypass the
    /// sole-supply-surface gate (INV-MINT-SECURITY, §5.2).
    MissingMintDenyGuard,
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
/// + a `TokenPolicyManager` with the mint-deny guard active + `PausableManager`.
///
/// Construct with [`XReserveStablecoinBuilder::new`], optionally override the account type (for the
/// non-`Public` rejection test) or the requested active mint policy (for the missing-guard rejection
/// test), then call [`XReserveStablecoinBuilder::build_components`].
pub struct XReserveStablecoinBuilder {
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
    account_type: AccountType,
    requested_active_mint_policy: Option<MintPolicyConfig>,
}

impl XReserveStablecoinBuilder {
    /// Creates a builder from a built `FungibleFaucet` and the assembled `xreserve` library
    /// component (which must carry the deny-guard `check_policy`). Defaults to `AccountType::Public`
    /// and the deny guard as the active mint policy.
    pub fn new(faucet: FungibleFaucet, xreserve_component: AccountComponent) -> Self {
        Self {
            faucet,
            xreserve_component,
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
        let manager =
            TokenPolicyManager::new().with_mint_policy(active, PolicyRegistration::Active)?;
        Ok(self.assemble_components(manager))
    }

    /// TEST-ORACLE seam (non-vacuity pair): composes the account with BOTH the deny guard and the
    /// stock allow-all registered, the `deny` arm Active and allow-all Reserved. Code-identical to
    /// [`Self::allow_all_oracle_components`] except for `active_mint_policy_proc_root`.
    ///
    /// Not for production: the deny arm of the load-bearing allow-vs-deny oracle. Production uses
    /// [`Self::build_components`] (deny only).
    #[doc(hidden)]
    pub fn deny_oracle_components(
        &self,
    ) -> Result<Vec<AccountComponent>, XReserveStablecoinBuilderError> {
        self.oracle_components(true)
    }

    /// TEST-ORACLE seam (non-vacuity pair): composes the account with BOTH policies registered, the
    /// stock allow-all Active and the deny guard Reserved. Code-identical to
    /// [`Self::deny_oracle_components`] except for `active_mint_policy_proc_root`. Used to prove the
    /// fixture reaches a *working* `mint_and_send` (so a deny trap is policy-caused, not a
    /// missing-slot / zero-root / proc-not-found artifact).
    #[doc(hidden)]
    pub fn allow_all_oracle_components(
        &self,
    ) -> Result<Vec<AccountComponent>, XReserveStablecoinBuilderError> {
        self.oracle_components(false)
    }

    /// Shared oracle composition. Both `MintPolicyConfig::AllowAll` and `Custom(deny_root)` are
    /// registered in every case (`AllowAll` contributes the `MintAllowAll` component whether Active
    /// or Reserved; `Custom` contributes none — the deny proc rides the `xreserve` component), so the
    /// component set is identical regardless of which is active; only the active root differs.
    fn oracle_components(
        &self,
        deny_active: bool,
    ) -> Result<Vec<AccountComponent>, XReserveStablecoinBuilderError> {
        if self.account_type != AccountType::Public {
            return Err(XReserveStablecoinBuilderError::NonPublicAccountType(
                self.account_type,
            ));
        }
        let deny = MintPolicyConfig::Custom(self.mint_deny_guard_root()?);
        let (active, reserved) = if deny_active {
            (deny, MintPolicyConfig::AllowAll)
        } else {
            (MintPolicyConfig::AllowAll, deny)
        };
        let manager = TokenPolicyManager::new()
            .with_mint_policy(active, PolicyRegistration::Active)?
            .with_mint_policy(reserved, PolicyRegistration::Reserved)?;
        Ok(self.assemble_components(manager))
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
