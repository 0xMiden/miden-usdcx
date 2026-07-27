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
//! `DOM_MANAGER` administers `DOM_PAUSER` (the CMP-F5 delegation). NOTE the S21 disposition flip
//! (human-ratified 2026-07-14): the runtime `set_role_admin` NOTE is REMOVED from the note-script
//! allowlist, so the delegation graph deploys FROZEN at this build seed — no sender can re-point
//! (or clear) any role's admin on-chain; role rotation is `grant_role`/`revoke_role` only
//! (CIR-ADMIN-3, matching Circle's fixed `DomainManageable.sol` graph). The stock
//! `rbac::set_role_admin` procedure stays composed but is present-but-unreachable
//! (`tests/account_callable_surface.rs`). Pause
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

use std::collections::BTreeSet;

use miden_protocol::account::{
    AccountComponent, AccountId, AccountProcedureRoot, AccountType, StorageSlot, StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Ownable2Step, Pausable};
use miden_standards::account::auth::{AuthNetworkAccount, NetworkAccountNoteAllowlistError};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::policies::{
    BasicBlocklist, BurnPolicy, MintPolicy, TokenPolicyManager, TransferPolicy,
};
use miden_standards::note::BurnNote;
use miden_standards::tx_script::ExpirationTransactionScript;

use crate::note::xreserve_mint::XReserveMintNote;

mod error;
mod rbac_seed;

pub use error::XReserveStablecoinBuilderError;
use rbac_seed::seeded_dom_roles_rbac;

/// The two Circle Domain RoleSymbols this faucet seeds under the ratified Circle-faithful admin
/// model: `DOM_PAUSER` (custom pause/unpause, CMP-F3) and `DOM_MANAGER` (rotation / role
/// management — the delegated admin of `DOM_PAUSER`, CMP-F5). Both are valid `RoleSymbol`s
/// (≤12 chars, `A`–`Z`/`_`; `DOMAIN_PAUSER`(13)/`DOMAIN_MANAGER`(14) would be rejected). The pause
/// gate hard-codes the `DOM_PAUSER` symbol in `pause_admin.masm` (parity-asserted); role
/// management consumes the STOCK rbac procs, so no MASM references `DOM_MANAGER`. The setters are
/// owner-gated (`Authority::OwnerControlled`), not role-gated.
pub const DOM_PAUSER_ROLE: &str = "DOM_PAUSER";
pub const DOM_MANAGER_ROLE: &str = "DOM_MANAGER";

/// The dedicated blocklist-administration RoleSymbol this faucet seeds under the F4-reversal
/// transfer-blocklist decision (Phil, 2026-07-23): `BLK_MANAGER` is held by an EXTERNAL entity that
/// manages the transfer blocklist for Miden and has NO other admin capability (capability isolation
/// is two-way — the holder can ONLY block/unblock, and the owner, lacking the role, cannot). The
/// stock `BlocklistOwnerControlled` is owner-gated (the wrong identity) and is deliberately NOT
/// installed; instead `xreserve::blocklist_admin::{block_account,unblock_account}` hard-code this
/// symbol (parity-asserted). `BLK_MANAGER` is a valid `RoleSymbol` (≤12 chars, `A`–`Z`/`_`). Its
/// admin is left unset → resolves to the built-in `ADMIN` (the owner-held account), so Miden rotates
/// or revokes the external entity through the EXISTING allowlisted `grant_role`/`revoke_role` notes —
/// no new rotation machinery. `BLK_MANAGER` is seeded role id 4.
pub const BLK_MANAGER_ROLE: &str = "BLK_MANAGER";

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
    /// The seeded `BLK_MANAGER` role member — the EXTERNAL entity that administers the transfer
    /// blocklist (block/unblock) and holds NO other admin capability (F4-reversal). Its concrete
    /// account id is supplied at deploy time; the built-in `ADMIN` (the owner) rotates/revokes it via
    /// the existing `grant_role`/`revoke_role` notes.
    blocklist_manager_holder: AccountId,
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
    /// the owner-gated setters), the `pauser_holder` / `manager_holder` seeded as the sole members of
    /// `DOM_PAUSER` / `DOM_MANAGER`, and the `blocklist_manager_holder` seeded as the sole member of
    /// `BLK_MANAGER` (the external transfer-blocklist administrator — F4-reversal). Defaults to
    /// `AccountType::Public` and the deny guard as the active mint policy.
    pub fn new(
        faucet: FungibleFaucet,
        xreserve_component: AccountComponent,
        owner: AccountId,
        pauser_holder: AccountId,
        manager_holder: AccountId,
        blocklist_manager_holder: AccountId,
    ) -> Self {
        Self {
            faucet,
            xreserve_component,
            owner,
            pauser_holder,
            manager_holder,
            blocklist_manager_holder,
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
    /// COMPLETE — the frozen 14-root set: rows 1-2 (the supply-side mint + burn notes), row 3
    /// (`set_attester`, the reference op), rows 4-12 (the remaining owner/role/pause admin note
    /// scripts), and rows 13-14 (the F4-reversal transfer-blocklist admin notes `block_account` /
    /// `unblock_account`, BLK_MANAGER-gated). The set is IMMUTABLE post-deploy (`AuthNetworkAccount`
    /// exports no mutator). The materialized 14 pinned roots require HUMAN ratification before deploy.
    /// Two capabilities are
    /// deliberately OMITTED (both human-ratified, grounded in Circle's xReserve EVM admin model):
    /// `renounce_role` (Circle has no role self-renounce) and — since the S21 disposition flip,
    /// 2026-07-14 — the runtime `set_role_admin` note (Circle's `DomainManageable.sol` has no
    /// function to change who administers a role; the delegation graph is BUILD-SEEDED by
    /// `seeded_dom_roles_rbac` (crate-private) and deploys frozen; rotation is `grant_role`/`revoke_role`,
    /// CIR-ADMIN-3 — see `DECISION-SETROLEADMIN-NOTE-REMOVAL.md`). The stock `rbac::set_role_admin`
    /// account procedure stays composed but is present-but-UNREACHABLE (enforced by
    /// `tests/account_callable_surface.rs`). The materialized 14 pinned roots still require explicit
    /// HUMAN ratification before deploy.
    pub fn allowed_note_scripts() -> BTreeSet<NoteScriptRoot> {
        // The "row N" labels below are the notes' STABLE allowlist identities (1-12, shared with
        // `note::xreserve_admin` and the tests), NOT positions in this initializer: the entries
        // are listed in historical insertion order, and the set is unordered anyway (BTreeSet
        // sorts by root). Renumbered 13→12 at the S21 flip, when the set_role_admin row was
        // removed (formerly row 10; transfer/accept/domain_init shifted down by one).
        BTreeSet::from([
            // rows 1-2: the supply-side notes. The mint-note shim asserts exactly one scheme-1
            // attestation + one scheme-2 routing target (eq.2, dynamic commitment) — F5.
            XReserveMintNote::script_root(),
            BurnNote::script_root(),
            // row 3: set_attester admin note (reference op).
            crate::note::xreserve_admin::XReserveSetAttesterNote::script_root(),
            // row 12: domain_init admin note (owner-gated, init-once).
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
            // NO set_role_admin row: REMOVED (S21 flip, 2026-07-14) — the role-admin graph is
            // frozen at the build seed; re-adding it violates the ratified decision and turns
            // the account_callable_surface enforcement tests RED.
            // row 10: transfer_ownership admin note (current-owner-gated, stock Ownable2Step).
            crate::note::xreserve_admin::XReserveTransferOwnershipNote::script_root(),
            // row 11: accept_ownership admin note (nominated-owner-gated, stock Ownable2Step).
            crate::note::xreserve_admin::XReserveAcceptOwnershipNote::script_root(),
            // row 13: block_account admin note (BLK_MANAGER-gated — F4-reversal transfer blocklist).
            crate::note::xreserve_admin::XReserveBlockAccountNote::script_root(),
            // row 14: unblock_account admin note (BLK_MANAGER-gated — F4-reversal transfer blocklist).
            crate::note::xreserve_admin::XReserveUnblockAccountNote::script_root(),
        ])
    }

    /// The stock `AuthNetworkAccount` production auth component, initialized with the frozen
    /// note-script allowlist (`Self::allowed_note_scripts`) and a tx-script allowlist containing
    /// EXACTLY the one canonical `ExpirationTransactionScript::script_root()` (S12, RATIFIED
    /// 2026-07-20). That single root is the protocol-standard expiration bounder a network account
    /// allowlists so the ntx-builder can bound how long a submitted tx stays valid; it is safe on
    /// an open network account because the submitter-controlled delta only bounds the inclusion
    /// window of the submitter's own transaction (kernel-capped at `0xFFFF` blocks) and can touch
    /// neither the account's nonce, state, nor assets. Every OTHER tx-script is still rejected
    /// (sole-mint-surface / F1 posture, now expressed as a one-root allowlist rather than an empty
    /// one). Composed into the account's dedicated auth slot at finalization (deploy:
    /// `AccountBuilder::with_auth_component`; tests: `Auth::NetworkAccount`).
    pub fn auth_component() -> Result<AuthNetworkAccount, NetworkAccountNoteAllowlistError> {
        Ok(
            AuthNetworkAccount::with_allowed_notes(Self::allowed_note_scripts())?
                .with_allowed_tx_scripts(BTreeSet::from([
                    ExpirationTransactionScript::script_root(),
                ])),
        )
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
        // F4-reversal capability isolation: the BLK_MANAGER holder (transfer-blocklist administrator)
        // MUST be an external entity with no other faucet-admin capability. Reject at build time if it
        // collides with the owner (also ADMIN — would gain a direct block/unblock path), the DOM_PAUSER
        // holder, or the DOM_MANAGER holder — the two-way isolation the reversal decision requires.
        if self.blocklist_manager_holder == self.owner {
            return Err(
                XReserveStablecoinBuilderError::BlocklistManagerNotIsolated {
                    collides_with: "owner",
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
        // F4 REVERSAL (transfer-blocklist decision, ratified 2026-07-23; supersedes the 2026-07-08
        // basic-asset decision in DECISION-F4-BASIC-ASSET-NO-TRANSFER-POLICY.md — see
        // DECISION-F4-REVERSAL-TRANSFER-BLOCKLIST.md and the adversarially-audited research report
        // RESEARCH-TRANSFER-BLOCKLIST-INTEGRATION.md). Miden head-of-product + Philipp concluded xUSDC
        // needs an ON-CHAIN transfer blocklist, so the stock `BasicBlocklist` is wired as the ACTIVE
        // policy for BOTH the send and receive kinds, starting with an EMPTY blocklist. Both kinds
        // reference the SAME descriptor root (`BasicBlocklist::root()`), so the manager installs the
        // `BasicBlocklist` companion (and its `blocked_accounts` slot) exactly ONCE and dedups by root
        // (`assemble_components` recognizes + installs that single companion).
        //
        // Consequences this DELIBERATELY accepts (the reversal of the F4 basic-asset posture):
        // registering these policies makes the manager install the two protocol asset-callback slots
        // (the fixed `invoke_send_policy`/`invoke_receive_policy` wrapper roots), which REQUIRES the
        // account be built `AssetCallbackFlag::Enabled` (a NEW account id ⇒ faucet v2, Circle
        // re-registration). xUSDC becomes a POLICED asset: the kernel `call`s this faucet's policy on
        // every send/receive, so every counterparty must attach this faucet as a foreign account (FPI)
        // on transfer/consume. A blocked account can neither send, receive, nor burn/redeem (a FULL
        // freeze incl. redemption); pause now halts ALL transfers while the policy is active. No
        // allow-all reserved alternate is registered (mirrors the F1 no-re-activation posture — the
        // blocklist can never be swapped out at runtime; `set_{send,receive}_policy` stay
        // composed-but-pointless, the only allowed root being the active blocklist one). The
        // `basic_asset_tripwire.rs` (now the policed-asset tripwire) + `account_callable_surface.rs`
        // (Enabled flag) tripwires enforce this wiring — they go RED on any un-wire.
        let manager = TokenPolicyManager::builder()
            .active_mint_policy(active)
            .active_burn_policy(active_burn)
            .active_send_policy(TransferPolicy::empty_basic_blocklist())
            .active_receive_policy(TransferPolicy::empty_basic_blocklist())
            .build();

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
            self.blocklist_manager_holder,
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
    /// POLICY-COMPANION SEAM (v16 — MIGRATION-V16-ALPHA2.md S18; F4-reversal rework): the alpha.2
    /// policy descriptors carry their `custom()` companion, and the manager's iterator emits one
    /// companion copy per DISTINCT policy root after the manager component itself. With the
    /// transfer blocklist wired the remainder is EXACTLY THREE: two xreserve-component copies (the
    /// custom mint deny-guard + burn policy) plus one `BasicBlocklist` companion (the send + receive
    /// transfer policy, which share the descriptor root, so it appears once). The seam consumes the
    /// iterator, keeps its head (the manager component), asserts the remainder is exactly those two
    /// recognized xreserve copies + one recognized `BasicBlocklist` companion, DROPS the redundant
    /// xreserve copies (the xreserve component is installed exactly ONCE, here), and INSTALLS the
    /// `BasicBlocklist` companion emitted by the manager (it carries the `blocked_accounts` storage
    /// the policy + `blocklist_admin` procs read/write). Any other shape — a foreign companion, a
    /// missing blocklist companion (which would ship a faucet whose `blocked_accounts` accesses
    /// trap), or the wrong copy counts — is a loud
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
        // the two custom-policy companions (mint deny-guard + burn policy) are both the installed
        // xreserve component; the one transfer-policy companion is the stock BasicBlocklist.
        let expected_xreserve = 2;
        let expected_blocklist = 1;
        let xreserve_recognized = companions
            .iter()
            .filter(|c| c.component_code().as_library() == xreserve_code.as_library())
            .count();
        let mut blocklist_companion: Option<AccountComponent> = None;
        let mut blocklist_recognized = 0usize;
        for companion in &companions {
            if companion.component_code().as_library() == BasicBlocklist::code().as_library() {
                blocklist_recognized += 1;
                blocklist_companion = Some(companion.clone());
            }
        }
        // `found` is the FULL remainder the manager emitted, so a smuggled foreign companion shows up
        // as `found > xreserve_recognized + blocklist_recognized`, and a missing/duplicated blocklist
        // companion as `blocklist_recognized != expected_blocklist`.
        if xreserve_recognized != expected_xreserve
            || blocklist_recognized != expected_blocklist
            || companions.len() != expected_xreserve + expected_blocklist
        {
            return Err(XReserveStablecoinBuilderError::PolicyCompanionMismatch {
                expected_xreserve,
                expected_blocklist,
                found: companions.len(),
                xreserve_recognized,
                blocklist_recognized,
            });
        }
        // the two xreserve copies are the already-installed component: drop them and install the
        // single recognized BasicBlocklist companion (checked non-None by the guard above).
        let blocklist = blocklist_companion
            .expect("the guard above guarantees exactly one recognized BasicBlocklist companion");
        Ok(vec![
            self.faucet.clone().into(),
            Pausable::unpaused().into(),
            xreserve_component,
            blocklist,
            manager_component,
        ])
    }
}
