//! `XReserveStablecoinBuilder` — the faucet account composition for the xUSDC faucet.
//! The mint path is the STOCK
//! `FungibleFaucet::mint_and_send` gated by the custom **attestation mint policy**
//! (`xreserve::mint_policy::check_policy` — the ENTIRE attestation pipeline lives in
//! the policy dispatch), so every supply increase passes the attestation gate — the
//! faucet's core mint-security invariant. There is NO separate mint-deny guard: the stock
//! path IS the gated path, so nothing needs trapping.
//!
//! Scope (cumulative): it composes the `FungibleFaucet`, the assembled `xreserve` library
//! component (carrying the attestation mint policy, the minimized `identifier_init`, the
//! `set_attester` admin proc, the DOM_PAUSER custom `pause`/`unpause`, and the BLK_MANAGER
//! `blocklist_admin`), a `TokenPolicyManager` whose ACTIVE mint policy is the attestation
//! policy and whose ACTIVE burn policy is the STOCK [`MinBurnAmount`] (floor-seeded `>= 1`,
//! so zero-amount burns stay rejected by construction), and the **owner-gating admin
//! foundation** (`Ownable2Step` with a seeded `RoleBasedAccessControl` under
//! `Authority::OwnerControlled`). The RBAC is SEEDED with the two Circle Domain role members
//! (`DOM_PAUSER` / `DOM_MANAGER`), with `DOM_PAUSER` administration DELEGATED to `DOM_MANAGER`,
//! plus the stock `ADMIN` role seeded on the OWNER's account, and the external
//! `BLK_MANAGER` transfer-blocklist administrator. NOTE the ratified role-graph freeze:
//! the runtime `set_role_admin` NOTE is deliberately absent from the
//! note-script allowlist, so the delegation graph deploys FROZEN at this build seed. Pause is
//! Domain-Pauser-ONLY: the stock `PausableManager` is NOT installed —
//! the only pause surface is the DOM_PAUSER-gated `xreserve::pause_admin` procs; the
//! `is_paused` slot the halt-gates read is installed by the base `Pausable` component.
//!
//! Domain config is BUILD-SEEDED except the identifier: `domain`, `source_domain`, and
//! `xreserve_contract` are required builder inputs written into the declared slots at
//! composition time; the `identifier` slot is a provable FIXPOINT of the account id (the id
//! derives from the initial storage commitment), so it ships EMPTY and is seeded post-deploy by
//! the ONE minimized `identifier_init` admin note (owner-gated, init-once).
//!
//! Packaging: the attestation policy is **runtime-assembled** MASM (no `.masl` asset /
//! `account_component_code!` here — that is a miden-standards-internal pipeline). The caller
//! assembles the `xreserve` library (namespace `xreserve`) into an `AccountComponent` and passes
//! it in; the policy procedure root is resolved from that same installed code via
//! [`AccountComponent::get_procedure_root_by_path`], so the `dynexec` root the policy manager
//! stores always equals the installed proc's MAST root.

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
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::account::policies::{
    BasicBlocklist, BurnPolicy, MinBurnAmount, MintPolicy, TokenPolicyManager, TransferPolicy,
};
use miden_standards::note::{BurnNote, MintNote};
use miden_standards::tx_script::ExpirationTransactionScript;

use crate::xreserve::encoding::bytes32_to_packed_felts;

mod error;
mod rbac_seed;

pub use error::XReserveStablecoinBuilderError;
use rbac_seed::seeded_dom_roles_rbac;

/// The two Circle Domain RoleSymbols this faucet seeds under the ratified Circle-faithful admin
/// model: `DOM_PAUSER` (custom pause/unpause) and `DOM_MANAGER` (rotation / role
/// management — the delegated admin of `DOM_PAUSER`). Both are valid `RoleSymbol`s
/// (≤12 chars, `A`–`Z`/`_`; `DOMAIN_PAUSER`(13)/`DOMAIN_MANAGER`(14) would be rejected). The pause
/// gate hard-codes the `DOM_PAUSER` symbol in `pause_admin.masm` (parity-asserted); role
/// management consumes the STOCK rbac procs, so no MASM references `DOM_MANAGER`. The setters are
/// owner-gated (`Authority::OwnerControlled`), not role-gated.
pub const DOM_PAUSER_ROLE: &str = "DOM_PAUSER";
pub const DOM_MANAGER_ROLE: &str = "DOM_MANAGER";

/// The dedicated blocklist-administration RoleSymbol this faucet seeds under the ratified
/// transfer-blocklist decision: `BLK_MANAGER` is held by an EXTERNAL entity that
/// manages the transfer blocklist for Miden and has NO other admin capability (capability isolation
/// is two-way — the holder can ONLY block/unblock, and the owner, lacking the role, cannot). The
/// stock `BlocklistOwnerControlled` is owner-gated (the wrong identity) and is deliberately NOT
/// installed; instead `xreserve::blocklist_admin::{block_account,unblock_account}` hard-code this
/// symbol (parity-asserted). `BLK_MANAGER` is a valid `RoleSymbol` (≤12 chars, `A`–`Z`/`_`). Its
/// admin is left unset → resolves to the built-in `ADMIN` (the owner-held account), so Miden rotates
/// or revokes the external entity through the EXISTING allowlisted `grant_role`/`revoke_role` notes —
/// no new rotation machinery. `BLK_MANAGER` is seeded role id 4.
pub const BLK_MANAGER_ROLE: &str = "BLK_MANAGER";

/// Flat library path of the attestation mint policy's `check_policy` procedure within the
/// assembled `xreserve` library (namespace `xreserve`, module `mint_policy`). This is the
/// no-leading-`::` form [`AccountComponent::get_procedure_root_by_path`] expects (matching the
/// `procedure_root!` macro and the protocol callback wiring).
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
/// the two must not be confused. The pinned `TokenSymbol` is uppercase-A–Z only (`token_symbol.rs`
/// `ShortCapitalString`), so the on-chain symbol is `USDCX`, the VM-forced uppercase form of
/// "USDCx"; the display `TokenName` keeps the mixed-case "USDCx".
/// [`XReserveStablecoinBuilder::build_components`] rejects any other symbol so the deployed symbol
/// is load-bearing.
pub const USDCX_TOKEN_SYMBOL: &str = "USDCX";

/// The spec-mandated token decimals (`token_config` decimals = 6; a Circle requirement of six
/// decimal places — the amount reducer scales to 6dp, so a mismatched faucet would silently
/// mis-scale every minted amount).
pub const USDCX_DECIMALS: u8 = 6;

/// Canonical Rust labels of the seven caller-declared `xreserve` storage slots (the single Rust
/// source: the tests re-export these and the constant-parity suite pins them against the MASM
/// `word("…")` consts where a MASM reader exists). The five domain-config slots + the two
/// registry maps. `domain` / `source_domain` / `xreserve_contract_{hi,lo}` are BUILD-SEEDED by
/// this builder (no runtime writer); `identifier` ships EMPTY (the `identifier_init` note is its
/// only writer).
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
/// [`XReserveStablecoinBuilder::build_components`] rejects at build time instead. The stock
/// [`MinBurnAmount`] floor slot is NOT in this set — it rides the policy companion component the
/// manager emits, not the `xreserve` component.
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
/// `token_metadata.rs` at the pinned `=0.16.0-alpha.2`; unlike `is_paused`, this slot lives on
/// the faucet itself). `build_components` reads it to reject an immutable-`max_supply`
/// faucet — `FungibleFaucet` exposes no public accessor for the flag (it lives in private `metadata`).
const FAUCET_MUTABILITY_CONFIG_SLOT: &str = "miden::standards::faucets::mutability_config";

/// Index of `is_max_supply_mutable` within the faucet `mutability_config` word, whose layout is
/// `[is_desc_mutable, is_logo_mutable, is_extlink_mutable, is_max_supply_mutable]` (miden-standards
/// `token_metadata.rs` at the pinned `=0.16.0-alpha.2`).
const MAX_SUPPLY_MUTABLE_WORD_INDEX: usize = 3;

/// The three build-seeded domain-config fields (`domain`, `source_domain`, `xreserve_contract`)
/// — every domain-config field EXCEPT the identifier fixpoint.
#[derive(Debug, Clone, Copy)]
struct DomainConfigSeed {
    domain: u32,
    source_domain: u32,
    xreserve_contract: [u8; 32],
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
/// component (attestation mint policy, identifier init, admin procs) + a `TokenPolicyManager`
/// with the attestation policy active on the mint side and the stock [`MinBurnAmount`] active on
/// the burn side + the **owner-gating admin foundation** (`Ownable2Step` + a seeded
/// `RoleBasedAccessControl` + `Authority::OwnerControlled`).
///
/// Construct with [`XReserveStablecoinBuilder::new`] (the `owner` and the role holders are
/// required), supply the three build-seeded domain-config fields via
/// [`XReserveStablecoinBuilder::with_domain_config`] (required — a build without them is
/// rejected), optionally override the account type / policies (for the rejection tests) or the
/// min-burn floor, then call [`XReserveStablecoinBuilder::build_components`].
pub struct XReserveStablecoinBuilder {
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
    /// Top-level authority (the `Ownable2Step` owner) — the sole authority for the owner-gated setters
    /// (`set_attester` / the stock `set_min_burn_amount` / stock `set_max_supply`) under
    /// `Authority::OwnerControlled`.
    owner: AccountId,
    /// The seeded `DOM_PAUSER` role member (the custom pause/unpause holder).
    pauser_holder: AccountId,
    /// The seeded `DOM_MANAGER` role member (role management — the delegated admin of `DOM_PAUSER`).
    manager_holder: AccountId,
    /// The seeded `BLK_MANAGER` role member — the EXTERNAL entity that administers the transfer
    /// blocklist (block/unblock) and holds NO other admin capability. Its concrete
    /// account id is supplied at deploy time; the built-in `ADMIN` (the owner) rotates/revokes it via
    /// the existing `grant_role`/`revoke_role` notes.
    blocklist_manager_holder: AccountId,
    account_type: AccountType,
    requested_active_mint_policy: Option<MintPolicy>,
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
    /// Creates a builder from a built `FungibleFaucet` and the assembled `xreserve` library
    /// component (which must carry the attestation mint policy `check_policy`), the `owner`
    /// (top-level authority for the owner-gated setters), the `pauser_holder` / `manager_holder`
    /// seeded as the sole members of `DOM_PAUSER` / `DOM_MANAGER`, and the
    /// `blocklist_manager_holder` seeded as the sole member of `BLK_MANAGER` (the external
    /// transfer-blocklist administrator). Defaults to `AccountType::Public`, the
    /// attestation policy as the active mint policy, the stock [`MinBurnAmount`] as the active
    /// burn policy, and a min-burn floor of [`MIN_BURN_SIZE_FLOOR`].
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
            min_burn_size: MIN_BURN_SIZE_FLOOR,
            domain_config: None,
        }
    }

    /// Overrides the account type (default `Public`). Used to exercise the non-`Public` rejection.
    pub fn account_type(mut self, account_type: AccountType) -> Self {
        self.account_type = account_type;
        self
    }

    /// Overrides the requested active mint policy (default: the attestation policy). A
    /// non-attestation choice is rejected by [`Self::build_components`] with
    /// [`XReserveStablecoinBuilderError::MissingAttestationMintPolicy`] — packaging cannot
    /// silently drop the attestation gate.
    pub fn with_active_mint_policy(mut self, policy: MintPolicy) -> Self {
        self.requested_active_mint_policy = Some(policy);
        self
    }

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
    /// `source_domain` ids and the `xreserve_contract` bytes32. REQUIRED — a build without them
    /// is rejected with [`XReserveStablecoinBuilderError::MissingDomainConfig`]. The values are
    /// written into the declared `domain` / `source_domain` / `xreserve_contract_{hi,lo}` slots
    /// at composition time (`[domain, 0, 0, 0]` / `[source_domain, 0, 0, 0]` / the raw 8x
    /// u32-LE packed felts, hi = wire bytes 0..16, lo = bytes 16..32); the `identifier` slot is
    /// NOT seeded (the account-id fixpoint — the `identifier_init` note is its only writer).
    pub fn with_domain_config(
        mut self,
        domain: u32,
        source_domain: u32,
        xreserve_contract: [u8; 32],
    ) -> Self {
        self.domain_config = Some(DomainConfigSeed {
            domain,
            source_domain,
            xreserve_contract,
        });
        self
    }

    /// Resolves the attestation mint policy's procedure root from the installed `xreserve`
    /// component. The same root is registered as the active mint policy, so the policy manager's
    /// stored `dynexec` root equals the installed proc's MAST root.
    pub fn attestation_mint_policy_root(&self) -> Result<Word, XReserveStablecoinBuilderError> {
        self.xreserve_component
            .get_procedure_root_by_path(ATTESTATION_MINT_POLICY_PROC_PATH)
            .map(Word::from)
            .ok_or(XReserveStablecoinBuilderError::AttestationPolicyProcNotFound)
    }

    /// The note-script allowlist for the production faucet's `AuthNetworkAccount` auth
    /// component. It is the SINGLE SOURCE OF TRUTH — the production auth component (`Self::auth_component`)
    /// consumes it (and the test fixtures compose through that same component), and the allowlist
    /// tripwire asserts the built account's allowlist equals it exactly. The scheme-2
    /// `NetworkAccountTarget` bind on the notes is routing-only, not a consume gate.
    ///
    /// COMPLETE — the frozen 14-root set: rows 1-2 (the supply-side STOCK `MintNote` + STOCK
    /// `BurnNote`), row 3 (`set_attester`, the reference op), rows 4-12 (the remaining
    /// owner/role/pause admin note scripts, with row 12 the minimized identifier-only
    /// `identifier_init` note), and rows 13-14 (the transfer-blocklist admin notes `block_account` /
    /// `unblock_account`, BLK_MANAGER-gated). The set is IMMUTABLE IN EFFECT post-deploy: the
    /// stock component does export allowlist mutators at this protocol version, but they are
    /// present-but-UNREACHABLE — no allowlisted note references them and the tx-script allowlist
    /// admits only the expiration bounder, which is a temporary and ratified state. The config
    /// note that could drive those mutators is deliberately NOT allowlisted.
    /// Two capabilities are deliberately OMITTED
    /// (both human-ratified, grounded in Circle's xReserve EVM admin model): `renounce_role`
    /// (Circle has no role self-renounce) and the
    /// runtime `set_role_admin` note (the delegation graph is BUILD-SEEDED by
    /// `seeded_dom_roles_rbac` and deploys frozen; rotation is `grant_role`/`revoke_role`, with
    /// the owner as the rotation backstop — see `DECISION-SETROLEADMIN-NOTE-REMOVAL.md`). The stock
    /// `rbac::set_role_admin` account procedure stays composed but is present-but-UNREACHABLE.
    /// The materialized 14 pinned roots require explicit HUMAN ratification before deploy.
    pub fn allowed_note_scripts() -> BTreeSet<NoteScriptRoot> {
        // The "row N" labels below are the notes' STABLE allowlist identities (1-14, shared with
        // `note::xreserve_admin` and the tests), NOT positions in this initializer: the entries
        // are listed in historical insertion order, and the set is unordered anyway (BTreeSet
        // sorts by root).
        BTreeSet::from([
            // rows 1-2: the supply-side notes — BOTH the STOCK standards scripts.
            // The mint row is the standards MintNote (attestation + intent ride as attachments;
            // the attestation mint policy is the gate); the burn row is the standards BurnNote.
            MintNote::script_root(),
            BurnNote::script_root(),
            // row 3: set_attester admin note (reference op).
            crate::note::xreserve_admin::XReserveSetAttesterNote::script_root(),
            // row 12: identifier_init admin note (owner-gated, init-once — identifier-only;
            // the other domain-config fields are build-seeded).
            crate::note::xreserve_admin::XReserveIdentifierInitNote::script_root(),
            // row 4: set_min_burn_size admin note (owner-gated; targets the STOCK
            // set_min_burn_amount with the note-side zero-floor guard).
            crate::note::xreserve_admin::XReserveSetMinBurnSizeNote::script_root(),
            // row 6: pause admin note (DOM_PAUSER-gated).
            crate::note::xreserve_admin::XReservePauseNote::script_root(),
            // row 7: unpause admin note (DOM_PAUSER-gated).
            crate::note::xreserve_admin::XReserveUnpauseNote::script_root(),
            // row 8: grant_role admin note (role-admin-gated, stock RBAC).
            crate::note::xreserve_admin::XReserveGrantRoleNote::script_root(),
            // row 5: set_max_supply admin note (owner-gated, stock FungibleFaucet).
            crate::note::xreserve_admin::XReserveSetMaxSupplyNote::script_root(),
            // row 9: revoke_role admin note (role-admin-gated, stock RBAC).
            crate::note::xreserve_admin::XReserveRevokeRoleNote::script_root(),
            // NO set_role_admin row (deliberately absent) — the role-admin graph is
            // frozen at the build seed; re-adding it violates the ratified decision and turns
            // the account_callable_surface enforcement tests RED.
            // row 10: transfer_ownership admin note (current-owner-gated, stock Ownable2Step).
            crate::note::xreserve_admin::XReserveTransferOwnershipNote::script_root(),
            // row 11: accept_ownership admin note (nominated-owner-gated, stock Ownable2Step).
            crate::note::xreserve_admin::XReserveAcceptOwnershipNote::script_root(),
            // row 13: block_account admin note (BLK_MANAGER-gated — transfer blocklist).
            crate::note::xreserve_admin::XReserveBlockAccountNote::script_root(),
            // row 14: unblock_account admin note (BLK_MANAGER-gated — transfer blocklist).
            crate::note::xreserve_admin::XReserveUnblockAccountNote::script_root(),
        ])
    }

    /// The PLACEHOLDER fee-faucet account id of the provisional fee configuration, as a hex
    /// literal (a valid public account id; parsed and validated where it is consumed).
    ///
    /// PROVISIONAL — deploy-time configuration replaces this value: fee economics for the keyless
    /// xReserve faucet are an OPEN Circle-owned decision (the real fee asset and policy are
    /// chosen by Circle before any deploy to a fee-charging chain), and the faucet's own id — the
    /// intended fee asset under the current thinking — cannot exist yet at composition time (the
    /// id derives from the very storage this value initializes). On MockChain, the only harness
    /// this workspace runs, the whole fee configuration is inert: the verification base fee is 0,
    /// so no fee note is ever created, and every allowlisted note is scheduled at an explicit
    /// zero fee. The exact materialized storage this value produces is pinned by a test.
    pub const TBD_DEPLOY_FEE_FAUCET_ID_HEX: &'static str = "0xaaaaaaaaaaaaaa112aaaaaaaaaaaaa";

    /// The PROVISIONAL zero-fee policy configuration every `AuthNetworkAccount` constructor at
    /// this protocol version requires (there is no none-variant): the stock
    /// `BasicConstantFeePolicy` scheduling an EXPLICIT ZERO fee for every allowlisted note script
    /// root, charging in the asset of the [`Self::TBD_DEPLOY_FEE_FAUCET_ID_HEX`] placeholder
    /// faucet.
    ///
    /// PROVISIONAL — the real fee economics are an open Circle-owned decision and replace this
    /// configuration before any deploy to a fee-charging chain; until then it is inert on
    /// MockChain (zero verification base fee, zero per-note fee). The zero fee is expressed as an
    /// explicit schedule entry per allowlisted root, not an empty schedule, because the auth
    /// procedure prices EVERY consumed note through the active policy and an unscheduled root
    /// aborts consumption.
    pub fn provisional_fee_policy_manager() -> FeePolicyManager {
        let fee_faucet_id = AccountId::from_hex(Self::TBD_DEPLOY_FEE_FAUCET_ID_HEX)
            .expect("the placeholder fee-faucet id hex is a valid account id");
        let mut policy = BasicConstantFeePolicy::new();
        for root in Self::allowed_note_scripts() {
            policy = policy.with_fee(root, AssetAmount::ZERO);
        }
        FeePolicyManager::builder()
            .fee_faucet_id(fee_faucet_id)
            .active_fee_policy(policy.into())
            .build()
    }

    /// The stock `AuthNetworkAccount` production auth component, initialized with the frozen
    /// note-script allowlist (`Self::allowed_note_scripts`), a tx-script allowlist containing
    /// EXACTLY the one canonical `ExpirationTransactionScript::script_root()` (a ratified
    /// decision), and the provisional zero-fee configuration
    /// ([`Self::provisional_fee_policy_manager`]). That single tx-script root is the
    /// protocol-standard expiration bounder a network account allowlists so the ntx-builder can
    /// bound how long a submitted tx stays valid; it is safe on an open network account because
    /// the submitter-controlled delta only bounds the inclusion window of the submitter's own
    /// transaction (kernel-capped at `0xFFFF` blocks) and can touch neither the account's nonce,
    /// state, nor assets. Every OTHER tx-script is still rejected (the sole-mint-surface
    /// posture, expressed as a one-root allowlist).
    ///
    /// Constructed via `AuthNetworkAccount::custom`, NEVER `new`: the default constructor
    /// force-inserts the config-note and fee-sponsorship script roots into the note allowlist,
    /// which would grow the frozen 14-root set and hand the (present-but-unreachable) allowlist
    /// mutators a runtime entry vector; `custom` inserts nothing, so the preserved allowlist
    /// stays exact, and a tripwire test fails if a config note ever appears in it. Composed at
    /// finalization; the value expands into the auth component plus its registered fee-policy
    /// components (`IntoIterator`), so callers install everything with one `with_components` /
    /// `extend`.
    pub fn auth_component() -> Result<AuthNetworkAccount, NetworkAccountNoteAllowlistError> {
        Ok(AuthNetworkAccount::custom(
            Self::allowed_note_scripts(),
            Self::provisional_fee_policy_manager(),
        )?
        .with_allowed_tx_scripts(BTreeSet::from([ExpirationTransactionScript::script_root()])))
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

    /// Production composition: validates `AccountType::Public`, that the active mint policy is the
    /// attestation policy and the active burn policy the stock [`MinBurnAmount`], seeds the three
    /// build-time domain-config fields, then composes the account components. No reserved
    /// alternate policies are registered — production carries no runtime path to a weaker mint or
    /// burn gate.
    pub fn build_components(
        &self,
    ) -> Result<Vec<AccountComponent>, XReserveStablecoinBuilderError> {
        if self.account_type != AccountType::Public {
            return Err(XReserveStablecoinBuilderError::NonPublicAccountType(
                self.account_type,
            ));
        }
        // Blocklist capability isolation: the BLK_MANAGER holder (transfer-blocklist administrator)
        // MUST be an external entity with no other faucet-admin capability. Reject at build time if it
        // collides with the owner (also ADMIN — would gain a direct block/unblock path), the DOM_PAUSER
        // holder, or the DOM_MANAGER holder — the two-way isolation the blocklist decision requires.
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
        let attestation_root = self.attestation_mint_policy_root()?;
        // The policy descriptors are non-Copy and own their companion components —
        // clone the override, or construct the default custom descriptor from the installed
        // xreserve component (whose `has_procedure` check cannot fail here: `attestation_root`
        // was just resolved FROM that component).
        let active = match &self.requested_active_mint_policy {
            Some(policy) => policy.clone(),
            None => MintPolicy::custom(
                AccountProcedureRoot::from_raw(attestation_root),
                [self.xreserve_component.clone()],
            )
            .map_err(XReserveStablecoinBuilderError::MintPolicy)?,
        };
        // The core mint-security invariant: the active mint policy MUST resolve to the attestation
        // policy — every supply increase passes the attestation gate.
        if Word::from(active.root()) != attestation_root {
            return Err(XReserveStablecoinBuilderError::MissingAttestationMintPolicy);
        }
        // Validate-what-you-ship: the supplied faucet's max_supply must be mutable, else the stock
        // `set_max_supply` admin function ships permanently dead (it traps the runtime mutability gate
        // on every call). Placed AFTER the account-type / policy rejections so those keep their
        // precedence. Reject — never mutate the supplied faucet.
        if !self.faucet_max_supply_is_mutable() {
            return Err(XReserveStablecoinBuilderError::ImmutableMaxSupply);
        }
        // validate-what-you-ship: every required xreserve slot must be declared on the supplied
        // component — a missing slot would ship a faucet whose reads / writes of it trap
        // ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME at runtime. Presence-only for the two maps (the
        // per-slice fixtures legitimately pre-seed values); the three build-seeded fields are
        // overwritten below and the identifier is checked EMPTY just after.
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
        // The identifier fixpoint (it can NEVER be build-seeded): the account id derives from the
        // initial storage commitment, and the identifier is (provisionally, pending Circle) the
        // faucet's own id as bytes32 — a fixpoint. A non-empty declared identifier would ship an
        // already-initialized, potentially misbound faucet AND make the init-once `identifier_init`
        // note trap as a reinitialization. Require the declared identifier value slot EMPTY at
        // composition; the `identifier_init` note (bound to the faucet id) is its only writer.
        let identifier_name = StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)
            .expect("the identifier slot label is a valid constant");
        let identifier_value = self
            .xreserve_component
            .storage_slots()
            .iter()
            .find(|slot| slot.name() == &identifier_name)
            .map(|slot| slot.value());
        if identifier_value != Some(Word::empty()) {
            return Err(XReserveStablecoinBuilderError::IdentifierNotEmpty);
        }
        // token-config exactness: decimals MUST be 6 (a Circle requirement; the amount reducer scales
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
        // Domain-config build seeding: the three non-identifier domain-config fields are REQUIRED
        // builder inputs written into the declared slots; the identifier slot stays as declared
        // (EMPTY in production — the identifier_init note is its only writer).
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

        // The owner-gating admin foundation, appended AFTER the early returns so a rejected build
        // never reaches here. `Authority::OwnerControlled` gates the stock admin SETTERS (and
        // `set_attester` / the stock `set_min_burn_amount`) on the Ownable2Step owner; mint
        // execution is `assert_authorized`-free (policy_manager.masm), so installing this leaves
        // the attestation-gate behavior unchanged. This is exactly the
        // `AccessControl::Rbac { authority_role: None }` composition (Ownable2Step +
        // RoleBasedAccessControl + Authority::OwnerControlled, access/mod.rs) with the RBAC SEEDED
        // with the DOM role members + the external BLK_MANAGER.
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

    /// Reconstructs the supplied `xreserve` component with the three BUILD-SEEDED domain-config
    /// values written into their declared slots (`[domain, 0, 0, 0]`, `[source_domain, 0, 0, 0]`,
    /// and the packed `xreserve_contract` hi/lo
    /// words). Every other slot — the identifier (the account-id fixpoint, seeded
    /// post-deploy by `identifier_init`) and the two registry maps — is carried through as
    /// declared.
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
        let xrc = bytes32_to_packed_felts(&seed.xreserve_contract);
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
    /// PAUSE PROVENANCE (Domain-Pauser-only): the stock `PausableManager`
    /// (owner-gated callable `pause`/`unpause`) is deliberately NOT installed; the only pause
    /// surface is the DOM_PAUSER-gated `xreserve::pause_admin` procs carried by the `xreserve`
    /// component. The `is_paused` slot every `assert_not_paused` halt-gate reads
    /// (`execute_mint_policy`/`execute_burn_policy`, the setters) is installed by the base
    /// `Pausable` component, not by the faucet. `PausableManager`
    /// still installs ZERO storage. The `production_components_carry_is_paused_slot` tripwire
    /// pins the slot.
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
