//! `XReserveStablecoinBuilder` — the faucet account composition for the xUSDC faucet
//! (CMP-A15). First increment (R-MINT-16): wires the **mint-deny guard** as the active
//! mint policy so the inherited stock `mint_and_send` traps and the custom `xreserve_mint` is the
//! provably sole supply-increasing surface (INV-MINT-SECURITY).
//!
//! Scope (cumulative): it composes `FungibleFaucet` + the assembled `xreserve` library component
//! (carries `apply_mint_effects`, the deny-guard `check_policy`, the `set_attester` + `set_min_burn_size`
//! admin procs, the DOM_PAUSER custom `pause`/`unpause`) + a `TokenPolicyManager` whose active mint
//! policy is the deny guard + the **owner-gating admin foundation** (`Ownable2Step` + a seeded
//! `RoleBasedAccessControl` + `Authority::OwnerControlled` composition). The RBAC is SEEDED with
//! the two Circle Domain role members (`DOM_PAUSER` / `DOM_MANAGER`), with `DOM_PAUSER`
//! administration DELEGATED to `DOM_MANAGER` (CMP-F5 — a Circle admin-model requirement that the
//! Domain Manager rotates the Pauser), plus — since the v16 migration (#3215 removed the owner's
//! implicit super-admin standing) — the stock `ADMIN` role seeded on the OWNER's account, which
//! keeps the owner-administers-roles model: the owner (as `ADMIN`) administers `DOM_MANAGER`, and
//! `DOM_MANAGER` administers `DOM_PAUSER` (the CMP-F5 delegation). NOTE the v16 consequence
//! (MIGRATION-V16-ALPHA2.md **S21**, HUMAN-RATIFIED): `set_role_admin(role)` is gated
//! on the ROLE's effective admin, so the `DOM_MANAGER` holder — not the owner — re-delegates
//! `DOM_PAUSER`; the owner reaches that power by first taking `DOM_MANAGER` (which it may, as the
//! `ADMIN` member). Pause
//! is Domain-Pauser-ONLY (IMPL-DEV-1 remediation): the stock `PausableManager` is NOT installed —
//! the only pause surface is the DOM_PAUSER-gated `xreserve::pause_admin` procs; the `is_paused`
//! slot the halt-gates read is installed by the base `Pausable` component (v16 — #2944 moved it
//! out of `FungibleFaucet`; see `Self::assemble_components`).
//! STILL DEFERRED to later slices: the full faucet assembly. The builder yields the validated
//! component composition; MockChain (tests) finalises it into a signed `Account`.
//!
//! Packaging: the deny guard is **runtime-assembled** MASM (no `.masl` asset / `account_component_code!`
//! here — that is a miden-standards-internal pipeline). The caller assembles the `xreserve` library
//! (namespace `xreserve`) into an `AccountComponent` and passes it in; the deny-guard procedure root
//! is resolved from that same installed code via [`AccountComponent::get_procedure_root_by_path`], so
//! the `dynexec` root the policy manager stores always equals the installed proc's MAST root.

use core::fmt;
use std::collections::BTreeSet;

use miden_protocol::account::{
    AccountComponent, AccountId, AccountProcedureRoot, AccountType, RoleSymbol, StorageMap,
    StorageMapKey, StorageSlot, StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step, Pausable, RoleBasedAccessControl};
use miden_standards::account::auth::{AuthNetworkAccount, NetworkAccountNoteAllowlistError};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::policies::{
    BurnPolicy, BurnPolicyError, MintPolicy, MintPolicyError, TokenPolicyManager,
};
use miden_standards::note::BurnNote;

use crate::note::xreserve_mint::XReserveMintNote;

/// The two Circle Domain RoleSymbols this faucet seeds under the ratified Circle-faithful admin
/// model: `DOM_PAUSER` (custom pause/unpause, CMP-F3) and `DOM_MANAGER` (rotation / role
/// management — the delegated admin of `DOM_PAUSER`, CMP-F5). Both are valid `RoleSymbol`s
/// (≤12 chars, `A`–`Z`/`_`; `DOMAIN_PAUSER`(13)/`DOMAIN_MANAGER`(14) would be rejected). The pause
/// gate hard-codes the `DOM_PAUSER` symbol in `pause_admin.masm` (parity-asserted); role
/// management consumes the STOCK rbac procs, so no MASM references `DOM_MANAGER`. The setters are
/// owner-gated (`Authority::OwnerControlled`), not role-gated.
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
/// (`xusdc::xreserve::attester_admin::min_burn_size`, the XReserveAttesterAdmin storage home).
/// The single Rust source of truth: `burn_policy.masm` declares a byte-identical
/// `word("…")` const (parity-enforced), the tests re-export this, and the future CMP-F2
/// `set_min_burn_size` setter co-owns the SAME slot. [`XReserveStablecoinBuilder::build_components`]
/// seeds it as `[min_burn_size, 0, 0, 0]`.
pub const MIN_BURN_SIZE_SLOT_LABEL: &str = "xusdc::xreserve::attester_admin::min_burn_size";

/// The shipped on-chain `TokenSymbol` guard constant (token config). The token's identity is
/// **USDCx** (human decision 2026-07-06) — a DISTINCT identity from the superseded "xUSDC" label;
/// the two must not be confused. The pinned `TokenSymbol` is uppercase-A–Z only (`token_symbol.rs`
/// `ShortCapitalString`), so the on-chain symbol is `USDCX`, the VM-forced uppercase form of
/// "USDCx"; the display `TokenName` keeps the mixed-case "USDCx".
/// [`XReserveStablecoinBuilder::build_components`] rejects any other symbol so the deployed symbol
/// is load-bearing.
pub const USDCX_TOKEN_SYMBOL: &str = "USDCX";

/// The spec-mandated token decimals (`token_config` decimals = 6; a Circle requirement of six
/// decimal places — the D5b reducer scales to 6dp, so a mismatched faucet would silently
/// mis-scale every minted amount).
pub const USDCX_DECIMALS: u8 = 6;

/// Canonical Rust labels of the seven caller-declared `xreserve` storage slots (the single Rust
/// source, the [`MIN_BURN_SIZE_SLOT_LABEL`] precedent: the tests re-export these and the
/// constant-parity suite pins them against the MASM `word("…")` consts). The five
/// domain-config slots + the two registry maps.
pub const DOMAIN_CONFIG_SLOT_LABEL: &str = "xusdc::xreserve::domain_config::domain";
pub const IDENTIFIER_CONFIG_SLOT_LABEL: &str = "xusdc::xreserve::domain_config::identifier";
pub const SOURCE_DOMAIN_CONFIG_SLOT_LABEL: &str = "xusdc::xreserve::domain_config::source_domain";
pub const XRESERVE_CONTRACT_HI_SLOT_LABEL: &str =
    "xusdc::xreserve::domain_config::xreserve_contract_hi";
pub const XRESERVE_CONTRACT_LO_SLOT_LABEL: &str =
    "xusdc::xreserve::domain_config::xreserve_contract_lo";
pub const USED_NONCES_SLOT_LABEL: &str = "xusdc::xreserve::nonce_registry::used_nonces";
pub const XRESERVE_ATTESTERS_SLOT_LABEL: &str =
    "xusdc::xreserve::attester_admin::xreserve_attesters";

/// The SEVEN storage slots the supplied `xreserve` component must declare (the
/// validate-what-you-ship check): a missing slot would ship a faucet whose reads/writes of it trap
/// `ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME` at runtime;
/// [`XReserveStablecoinBuilder::build_components`] rejects at build time instead (`min_burn_size`
/// is builder-seeded, not caller-declared — see [`XReserveStablecoinBuilder::min_burn_size`]).
pub const REQUIRED_XRESERVE_SLOT_LABELS: [&str; 7] = [
    DOMAIN_CONFIG_SLOT_LABEL,
    IDENTIFIER_CONFIG_SLOT_LABEL,
    SOURCE_DOMAIN_CONFIG_SLOT_LABEL,
    XRESERVE_CONTRACT_HI_SLOT_LABEL,
    XRESERVE_CONTRACT_LO_SLOT_LABEL,
    USED_NONCES_SLOT_LABEL,
    XRESERVE_ATTESTERS_SLOT_LABEL,
];

/// The storage slot the stock `FungibleFaucet` writes its mutability flags into (miden-standards
/// `token_metadata.rs` at the pinned `=0.16.0-alpha.2`; unlike `is_paused`, this slot did NOT move
/// out of the faucet). `build_components` reads it to reject an immutable-`max_supply`
/// faucet — `FungibleFaucet` exposes no public accessor for the flag (it lives in private `metadata`).
const FAUCET_MUTABILITY_CONFIG_SLOT: &str = "miden::standards::faucets::mutability_config";

/// Index of `is_max_supply_mutable` within the faucet `mutability_config` word, whose layout is
/// `[is_desc_mutable, is_logo_mutable, is_extlink_mutable, is_max_supply_mutable]` (miden-standards
/// `token_metadata.rs` at the pinned `=0.16.0-alpha.2`).
const MAX_SUPPLY_MUTABLE_WORD_INDEX: usize = 3;

/// Errors returned while composing the xUSDC faucet account.
#[derive(Debug)]
pub enum XReserveStablecoinBuilderError {
    /// The xUSDC faucet must be public (network-observable). A non-`Public` account type is rejected
    /// at build time so packaging cannot produce an unobservable faucet.
    NonPublicAccountType(AccountType),
    /// The active mint policy does not resolve to the deny guard — packaging cannot bypass the
    /// sole-supply-surface gate (INV-MINT-SECURITY).
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
    /// The supplied `xreserve` component does not declare a required storage slot (the
    /// validate-what-you-ship check, [`REQUIRED_XRESERVE_SLOT_LABELS`]: a missing slot would ship a
    /// faucet whose reads/writes of that slot trap at runtime). Carries the missing slot's label.
    MissingXReserveSlot(&'static str),
    /// The supplied faucet's `decimals` is not the spec-mandated [`USDCX_DECIMALS`] (= 6;
    /// `token_config` decimals = 6, a Circle requirement of six decimal places — the D5b reducer
    /// scales to 6dp, so a mismatched faucet silently mis-scales every amount). Carries the
    /// offending value.
    WrongDecimals(u8),
    /// The supplied faucet's `TokenSymbol` is not the shipped [`USDCX_TOKEN_SYMBOL`] guard
    /// constant. The token's identity is USDCx (human decision 2026-07-06, distinct from the
    /// superseded "xUSDC"); the pinned `TokenSymbol` is uppercase-A–Z only (`token_symbol.rs`),
    /// so the on-chain symbol is the VM-forced uppercase `USDCX`; this guard pins the shipped
    /// constant so the deployed symbol is load-bearing and a drift fails the build.
    WrongTokenSymbol,
    /// The mint-policy descriptor rejected its construction (v16 `MintPolicy::custom` validates
    /// the root against the supplied companion components).
    MintPolicy(MintPolicyError),
    /// The burn-policy descriptor rejected its construction — the burn-slot twin of
    /// [`Self::MintPolicy`].
    BurnPolicy(BurnPolicyError),
    /// The policy manager's companion components did not have the pinned shape at the
    /// composition seam (exactly the manager component first, then one xreserve-component copy
    /// per custom policy — MIGRATION-V16-ALPHA2.md S18). Never dropped silently. `found` is the
    /// FULL companion remainder the manager emitted and `recognized` how many of those were the
    /// already-installed xreserve component, so a smuggled foreign companion shows up as
    /// `found > recognized` instead of hiding behind a matching recognized count.
    PolicyCompanionMismatch {
        expected: usize,
        found: usize,
        recognized: usize,
    },
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
            Self::MissingXReserveSlot(label) => write!(
                f,
                "the xreserve component does not declare the required storage slot '{label}'"
            ),
            Self::WrongDecimals(decimals) => write!(
                f,
                "xusdc faucet decimals must be 6 (CIR-FEE-3; the reducer scales to 6dp), got \
                 {decimals}"
            ),
            Self::WrongTokenSymbol => write!(
                f,
                "xusdc faucet token symbol must be the shipped USDCX guard constant"
            ),
            Self::MintPolicy(_) => write!(f, "mint policy descriptor construction failed"),
            Self::BurnPolicy(_) => write!(f, "burn policy descriptor construction failed"),
            Self::PolicyCompanionMismatch {
                expected,
                found,
                recognized,
            } => write!(
                f,
                "token policy manager emitted an unexpected companion-component shape: expected \
                 exactly {expected} xreserve-component copies after the manager component; the \
                 remainder held {found} companions, {recognized} of them the installed xreserve \
                 component ({} foreign)",
                found.saturating_sub(*recognized)
            ),
        }
    }
}

impl core::error::Error for XReserveStablecoinBuilderError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::MintPolicy(source) => Some(source),
            Self::BurnPolicy(source) => Some(source),
            _ => None,
        }
    }
}

impl From<MintPolicyError> for XReserveStablecoinBuilderError {
    fn from(source: MintPolicyError) -> Self {
        Self::MintPolicy(source)
    }
}

impl From<BurnPolicyError> for XReserveStablecoinBuilderError {
    fn from(source: BurnPolicyError) -> Self {
        Self::BurnPolicy(source)
    }
}

/// Composes the xUSDC faucet account: `FungibleFaucet` + the assembled `xreserve` library
/// component + a `TokenPolicyManager` with the mint-deny guard active + the **owner-gating admin
/// foundation** (`Ownable2Step` + a seeded `RoleBasedAccessControl` + `Authority::OwnerControlled`).
/// The foundation ships in this production builder so the deployed faucet validates the real auth
/// model: the setters (`set_attester` / `set_min_burn_size` / `set_max_supply`) are gated on the
/// Ownable2Step owner, and the `DOM_PAUSER` / `DOM_MANAGER` role members are seeded. Pause is
/// Domain-Pauser-ONLY: the stock `PausableManager` is deliberately NOT part of the composition
/// (IMPL-DEV-1 remediation) — `xreserve::pause_admin::{pause,unpause}` (DOM_PAUSER-gated) is the
/// sole pause surface.
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
    requested_active_mint_policy: Option<MintPolicy>,
    /// Overridden active burn policy (default: the installed `burn_policy::check_policy` as a
    /// custom `BurnPolicy` descriptor). A non-burn-policy choice exercises the
    /// missing-burn-guard rejection.
    requested_active_burn_policy: Option<BurnPolicy>,
    /// The `minBurnSize` (R-BURN-2 threshold) the builder seeds into the `MIN_BURN_SIZE_SLOT`
    /// (`xusdc::xreserve::attester_admin::min_burn_size`) value slot as `[min_burn_size, 0, 0, 0]`.
    /// Default `0` (no minimum); override via [`Self::min_burn_size`]. The deferred CMP-F2
    /// `set_min_burn_size` writes the SAME slot.
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
    pub fn with_active_mint_policy(mut self, policy: MintPolicy) -> Self {
        self.requested_active_mint_policy = Some(policy);
        self
    }

    /// Overrides the requested active burn policy (default: the installed `burn_policy::check_policy`).
    /// The burn-slot twin of [`Self::with_active_mint_policy`]; a non-burn-policy choice (e.g.
    /// [`BurnPolicy::allow_all`]) is rejected by [`Self::build_components`] with
    /// [`XReserveStablecoinBuilderError::MissingBurnPolicyGuard`] — packaging cannot drop the burn
    /// security predicate (CMP-A10, R-BURN-1/2).
    pub fn with_active_burn_policy(mut self, policy: BurnPolicy) -> Self {
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

    /// The note-script allowlist for the production faucet's `AuthNetworkAccount` auth component
    /// (F5). It is the SINGLE SOURCE OF TRUTH — the production auth component (`Self::auth_component`)
    /// and the MockChain `Auth::NetworkAccount` fixture both consume it, and the allowlist tripwire
    /// asserts the built account's allowlist equals it exactly. The scheme-2 `NetworkAccountTarget`
    /// bind on the notes is routing-only, not a consume gate.
    ///
    /// COMPLETE — the frozen 13-root set: rows 1-2 (the supply-side mint + burn notes), row 3
    /// (`set_attester`, the reference op), and rows 4-13 (the remaining admin note scripts). The set
    /// is IMMUTABLE post-deploy (`AuthNetworkAccount` exports no mutator); `renounce_role` is
    /// deliberately OMITTED (human-ratified, grounded in Circle's xReserve EVM admin model, which has
    /// no role self-renounce). The materialized 13 pinned roots still require explicit HUMAN
    /// ratification before deploy.
    pub fn allowed_note_scripts() -> BTreeSet<NoteScriptRoot> {
        BTreeSet::from([
            // rows 1-2: the supply-side notes. The mint-note shim asserts exactly one scheme-1
            // attestation + one scheme-2 routing target (eq.2, dynamic commitment) — F5.
            XReserveMintNote::script_root(),
            BurnNote::script_root(),
            // row 3: set_attester admin note (reference op).
            crate::note::xreserve_admin::XReserveSetAttesterNote::script_root(),
            // row 13: domain_init admin note (owner-gated, init-once).
            crate::note::xreserve_admin::XReserveDomainInitNote::script_root(),
            // row 4: set_min_burn_size admin note (owner-gated).
            crate::note::xreserve_admin::XReserveSetMinBurnSizeNote::script_root(),
            // row 6: pause admin note (DOM_PAUSER-gated).
            crate::note::xreserve_admin::XReservePauseNote::script_root(),
            // row 7: unpause admin note (DOM_PAUSER-gated).
            crate::note::xreserve_admin::XReserveUnpauseNote::script_root(),
            // row 8: grant_role admin note (role-admin-gated, stock RBAC — v0.16 #3215/S2).
            crate::note::xreserve_admin::XReserveGrantRoleNote::script_root(),
            // row 5: set_max_supply admin note (owner-gated, stock FungibleFaucet).
            crate::note::xreserve_admin::XReserveSetMaxSupplyNote::script_root(),
            // row 9: revoke_role admin note (role-admin-gated, stock RBAC — v0.16 #3215/S2).
            crate::note::xreserve_admin::XReserveRevokeRoleNote::script_root(),
            // row 10: set_role_admin admin note (gated on the MANAGED role's effective admin,
            // stock RBAC — v0.16 #3215/S21, no longer owner-only).
            crate::note::xreserve_admin::XReserveSetRoleAdminNote::script_root(),
            // row 11: transfer_ownership admin note (current-owner-gated, stock Ownable2Step).
            crate::note::xreserve_admin::XReserveTransferOwnershipNote::script_root(),
            // row 12: accept_ownership admin note (nominated-owner-gated, stock Ownable2Step).
            crate::note::xreserve_admin::XReserveAcceptOwnershipNote::script_root(),
        ])
    }

    /// The stock `AuthNetworkAccount` production auth component, initialized with the frozen
    /// note-script allowlist (`Self::allowed_note_scripts`) and an EMPTY tx-script allowlist
    /// (sole-mint-surface / F1 — never `.with_allowed_tx_scripts`). Composed into the account's
    /// dedicated auth slot at finalization (deploy: `AccountBuilder::with_auth_component`; tests:
    /// `Auth::NetworkAccount`).
    pub fn auth_component() -> Result<AuthNetworkAccount, NetworkAccountNoteAllowlistError> {
        AuthNetworkAccount::with_allowed_notes(Self::allowed_note_scripts())
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
        // v16 (#2974): the policy descriptors are non-Copy and own their companion components —
        // clone the override, or construct the default custom descriptor from the installed
        // xreserve component (whose `has_procedure` check cannot fail here: `deny_root` was just
        // resolved FROM that component).
        let active = match &self.requested_active_mint_policy {
            Some(policy) => policy.clone(),
            None => MintPolicy::custom(
                AccountProcedureRoot::from_raw(deny_root),
                [self.xreserve_component.clone()],
            )
            .map_err(XReserveStablecoinBuilderError::MintPolicy)?,
        };
        // INV-MINT-SECURITY: the active mint policy MUST resolve to the deny guard.
        if Word::from(active.root()) != deny_root {
            return Err(XReserveStablecoinBuilderError::MissingMintDenyGuard);
        }
        // Validate-what-you-ship: the supplied faucet's max_supply must be mutable, else the stock
        // `set_max_supply` admin function ships permanently dead (it traps the runtime mutability gate
        // on every call). Placed AFTER the account-type / deny-guard rejections so those keep their
        // precedence. Reject — never mutate the supplied faucet.
        if !self.faucet_max_supply_is_mutable() {
            return Err(XReserveStablecoinBuilderError::ImmutableMaxSupply);
        }
        // validate-what-you-ship: every required xreserve slot must be declared on the supplied
        // component — a missing slot would ship a faucet whose reads / writes of it trap
        // ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME at runtime. Presence-only (the per-slice fixtures
        // legitimately pre-seed values; the E2E proves the empty->domain_init production path).
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
        // token-config exactness: decimals MUST be 6 (a Circle requirement; the D5b reducer scales
        // to 6dp) and the symbol MUST be the shipped USDCX guard constant (the USDCx identity's
        // VM-forced uppercase on-chain form — see USDCX_TOKEN_SYMBOL).
        if self.faucet.decimals() != USDCX_DECIMALS {
            return Err(XReserveStablecoinBuilderError::WrongDecimals(
                self.faucet.decimals(),
            ));
        }
        let expected_symbol = TokenSymbol::new(USDCX_TOKEN_SYMBOL)
            .expect("the shipped USDCX symbol guard constant is a valid TokenSymbol");
        if self.faucet.symbol() != &expected_symbol {
            return Err(XReserveStablecoinBuilderError::WrongTokenSymbol);
        }
        // CMP-A10 burn slot: wire the installed `burn_policy::check_policy` as the ACTIVE burn policy so
        // every `receive_and_burn` is gated on the R-BURN-1/2 predicate (the burn-slot twin of the
        // active mint deny guard above).
        let burn_root = self.burn_policy_root()?;
        let active_burn = match &self.requested_active_burn_policy {
            Some(policy) => policy.clone(),
            None => BurnPolicy::custom(
                AccountProcedureRoot::from_raw(burn_root),
                [self.xreserve_component.clone()],
            )
            .map_err(XReserveStablecoinBuilderError::BurnPolicy)?,
        };
        // INV (CMP-A10): the active burn policy MUST resolve to the installed `burn_policy::check_policy`
        // — packaging cannot ship a faucet whose burns bypass the R-BURN-1/2 predicate (the burn-slot
        // twin of the mint deny-guard check above).
        if Word::from(active_burn.root()) != burn_root {
            return Err(XReserveStablecoinBuilderError::MissingBurnPolicyGuard);
        }
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(active)
            .active_burn_policy(active_burn)
            .build();
        // xUSDC ships as a BASIC (transfer-free) fungible asset — DELIBERATELY no send/receive
        // transfer policy is registered here (human decision 2026-07-08, RATIFIED). With no transfer
        // policy the manager installs no asset-callback slots, so every minted xUSDC carries
        // `AssetCallbackFlag::Disabled` and holder-to-holder transfers are unpoliced — behaviourally
        // identical to Circle's reference `USDCx.sol`, which has no transfer logic.
        //
        // Do NOT add `.with_send_policy(...)` / `.with_receive_policy(...)` here. Registering ANY
        // transfer policy (even `TransferPolicy::AllowAll`, and even `Reserved`) stamps callbacks
        // Enabled and turns xUSDC into a "policed" asset: the kernel then `call`s this faucet's
        // policy proc on every send/receive, forcing every counterparty to attach this faucet as a
        // foreign account (FPI) on every transfer/consume. That breaks P2ID / basic-wallet / SWAP /
        // deposit-relayer composability supply-wide, for a capability Circle does NOT require —
        // xUSDC compliance lives at the bridge boundary (attestation-gated mint + pause + reserve
        // redemption), all already built. The "swap a custom policy in later" option is illusory:
        // `set_{send,receive}_policy` only accept a root already baked into the account + its
        // build-time allowed-roots map, both immutable post-deploy — any real change is a redeploy.
        //
        // Re-wiring is a conscious re-decision gated on Q-PRV-5 (Circle confirmation, OPEN) + a
        // faucet-v2 migration (IMPL-DEV-20). The `basic_asset_tripwire.rs` test enforces this
        // invariant (it goes RED on any wire).

        // The owner-gating admin foundation, appended AFTER the account-type / deny-guard early
        // returns so a rejected build never reaches here. `Authority::OwnerControlled` gates the
        // stock admin SETTERS (and `set_attester` / `set_min_burn_size`) on the Ownable2Step owner;
        // mint execution / the deny path is `assert_authorized`-free (policy_manager.masm), so
        // installing this leaves the R-MINT-16 deny behavior unchanged. This is exactly the
        // `AccessControl::Rbac { authority_role: None }` composition (Ownable2Step +
        // RoleBasedAccessControl + Authority::OwnerControlled, access/mod.rs) with the RBAC SEEDED
        // with the two DOM role members (whose consumers — custom pause, role management — are later
        // slices).
        let xreserve_component = self.xreserve_component_with_min_burn_size()?;
        let mut components = self.assemble_components(manager, xreserve_component)?;
        components.push(Ownable2Step::new(self.owner).into());
        components.push(seeded_dom_roles_rbac(
            self.owner,
            self.pauser_holder,
            self.manager_holder,
        ));
        components.push(Authority::OwnerControlled.into());
        Ok(components)
    }

    /// Reconstructs the supplied `xreserve` component with the `MIN_BURN_SIZE_SLOT` value slot
    /// appended (`[min_burn_size, 0, 0, 0]`) so the installed `burn_policy::check_policy` resolves its
    /// R-BURN-2 read on the deployed account. The caller supplies the component WITHOUT this slot (the
    /// builder owns seeding it); the future CMP-F2 `set_min_burn_size` mutates the SAME slot.
    /// Uses the canonical `AssetAmount -> Felt` (no truncation); a `min_burn_size` exceeding
    /// [`AssetAmount::MAX`] is rejected with [`XReserveStablecoinBuilderError::MinBurnSizeExceedsMax`].
    fn xreserve_component_with_min_burn_size(
        &self,
    ) -> Result<AccountComponent, XReserveStablecoinBuilderError> {
        let min_burn = AssetAmount::new(self.min_burn_size).map_err(|_| {
            XReserveStablecoinBuilderError::MinBurnSizeExceedsMax(self.min_burn_size)
        })?;
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
    /// PAUSE PROVENANCE (Domain-Pauser-only — IMPL-DEV-1 remediation): the stock `PausableManager`
    /// (owner-gated callable `pause`/`unpause`) is deliberately NOT installed; the only pause
    /// surface is the DOM_PAUSER-gated `xreserve::pause_admin` procs carried by the `xreserve`
    /// component. The `is_paused` slot every `assert_not_paused` halt-gate reads
    /// (`execute_mint_policy`/`execute_burn_policy`, the setters, `xreserve_mint.masm`) is
    /// installed by the base `Pausable` component — the v15 PIN-BUMP HAZARD resolved as predicted:
    /// upstream v0.16 (#2944) moved the slot OUT of `FungibleFaucet`, so `Pausable::unpaused()`
    /// now sits immediately after the faucet component (whose slot block carried it at v15; slots
    /// are name-addressed, so the position is auditability-only). `PausableManager` still installs
    /// ZERO storage. The `production_components_carry_is_paused_slot` tripwire pins the slot.
    ///
    /// POLICY-COMPANION SEAM (v16 — MIGRATION-V16-ALPHA2.md S18): the alpha.2 policy descriptors
    /// carry the xreserve component as their `custom()` companion, and the manager's iterator
    /// emits one companion copy per DISTINCT policy root (deny + burn = two copies) after the
    /// manager component itself. The xreserve component is installed exactly ONCE (here); the
    /// seam consumes the iterator, keeps its head (the manager component), asserts the remainder
    /// is exactly the two code-commitment-equal copies, and drops them — any other shape is a
    /// loud [`XReserveStablecoinBuilderError::PolicyCompanionMismatch`], never a silent drop.
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
        let expected = 2;
        let recognized = companions
            .iter()
            .filter(|c| c.component_code().as_library() == xreserve_code.as_library())
            .count();
        // `found` is the FULL remainder the manager emitted (not just the recognized copies), so a
        // smuggled foreign companion shows up as `found > recognized` instead of hiding behind a
        // matching recognized count.
        if recognized != expected || companions.len() != expected {
            return Err(XReserveStablecoinBuilderError::PolicyCompanionMismatch {
                expected,
                found: companions.len(),
                recognized,
            });
        }
        // both companions recognized as the already-installed xreserve component: drop them.
        Ok(vec![
            self.faucet.clone().into(),
            Pausable::unpaused().into(),
            xreserve_component,
            manager_component,
        ])
    }
}

/// Hand-builds the seeded `RoleBasedAccessControl` `AccountComponent` with the TWO Circle Domain
/// role members — `DOM_PAUSER` (→ `pauser_holder`) and `DOM_MANAGER` (→ `manager_holder`) — plus,
/// since the v16 migration (#3215 removed the Ownable2Step owner's implicit super-admin standing
/// over the role graph; MIGRATION-V16-ALPHA2.md S2, operator-approved 2026-07-13), the stock
/// `ADMIN` role seeded with the OWNER's account as its single member. `ADMIN` is the built-in
/// default admin role (`rbac.masm`): a role whose delegated admin is unset resolves to it, so
/// this seed preserves the ratified owner-administers-roles model — the owner-held account
/// administers `DOM_MANAGER` and every `set_role_admin`, now via its `ADMIN` membership rather
/// than owner status (NO new capability: `ADMIN` resolves to the same owner account). KNOWN
/// DIVERGENCE (documented, operator-approved): after `transfer_ownership`/`accept_ownership`,
/// `ADMIN` membership does not auto-follow — the rotation runbook grants `ADMIN` to the new
/// owner and revokes the old one via the existing grant/revoke admin notes.
///
/// Both stock RBAC maps are direct-seeded at build, consistent with the stock procs' post-state
/// for a single first grant per role — `role_membership[{0, <role>, holder.suffix,
/// holder.prefix}] = [1,0,0,0]` AND `role_config[{0,0,0,DOM_PAUSER}] = [member_count=1,
/// admin_role=DOM_MANAGER, 0, 0]` (the CMP-F5 delegation: the Domain Manager rotates the Pauser)
/// while `role_config[{0,0,0,DOM_MANAGER}] = [1, 0, 0, 0]` and `role_config[{0,0,0,ADMIN}] =
/// [1, 0, 0, 0]` (admin_role = 0 → resolves to the built-in `ADMIN`; `ADMIN` is thereby
/// self-administered). It reuses the stock RBAC code + slot names + component metadata verbatim
/// (NO custom RBAC logic); only the maps are non-empty (the stock `From<RoleBasedAccessControl>`
/// seeds them empty). The key encodings mirror the stock readers. `grant_role` is NOT used (it
/// would add a tx). Seed correctness is locked by the `shipped_delegation_reads_back` +
/// rotation-seam + ADMIN-gating tests, not by construction (`AccountComponent::new` does not
/// validate slots against the metadata schema). Construction failures are invariants, so this
/// mirrors the stock `.expect()` pattern.
fn seeded_dom_roles_rbac(
    owner: AccountId,
    pauser_holder: AccountId,
    manager_holder: AccountId,
) -> AccountComponent {
    let pauser =
        RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol (≤12)");
    let manager =
        RoleSymbol::new(DOM_MANAGER_ROLE).expect("DOM_MANAGER is a fixed valid role symbol (≤12)");
    let admin = RoleBasedAccessControl::admin_role();
    // [1,0,0,0]: role_config member_count = 1 (admin_role = 0 → the built-in ADMIN), and
    // role_membership is_member = 1.
    let member_word = Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    // [1, DOM_MANAGER, 0, 0]: member_count = 1 with administration delegated to DOM_MANAGER (CMP-F5).
    let delegated_config_word = Word::from([
        Felt::from(1u32),
        Felt::from(&manager),
        Felt::ZERO,
        Felt::ZERO,
    ]);

    let role_config = StorageMap::with_entries([
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&pauser),
            ])),
            delegated_config_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&manager),
            ])),
            member_word,
        ),
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO,
                Felt::from(&admin),
            ])),
            member_word,
        ),
    ])
    .expect("the three-role role_config seed is valid");

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
        (
            StorageMapKey::new(Word::from([
                Felt::ZERO,
                Felt::from(&admin),
                owner.suffix(),
                owner.prefix().as_felt(),
            ])),
            member_word,
        ),
    ])
    .expect("the three-role role_membership seed is valid");

    AccountComponent::new(
        RoleBasedAccessControl::code().clone(),
        vec![
            StorageSlot::with_map(
                RoleBasedAccessControl::role_config_slot().clone(),
                role_config,
            ),
            StorageSlot::with_map(
                RoleBasedAccessControl::role_membership_slot().clone(),
                role_membership,
            ),
        ],
        RoleBasedAccessControl::component_metadata(),
    )
    .expect("the seeded DOM-roles RBAC component mirrors the stock From impl and is valid")
}
