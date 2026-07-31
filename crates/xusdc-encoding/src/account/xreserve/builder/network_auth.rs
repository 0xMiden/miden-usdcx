//! The keyless network account's authorization surface: the note-script allowlist, the provisional
//! fee configuration every constructor at this protocol version requires, and the auth component
//! that carries both.
//!
//! It lives beside the builder rather than inside it because the grouping is cohesive: the faucet
//! has no signing key, so this allowlist IS its authorization model, and nothing else decides which
//! notes the account will consume.

use std::collections::BTreeSet;

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::NoteScriptRoot;
use miden_standards::account::auth::{AuthNetworkAccount, NetworkAccountNoteAllowlistError};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::note::{BlocklistConfigNote, BurnNote, MintNote, PauseActionNote};
use miden_standards::tx_script::ExpirationTransactionScript;

use super::XReserveStablecoinBuilder;

impl XReserveStablecoinBuilder {
    /// The note-script allowlist for the production faucet's `AuthNetworkAccount` auth
    /// component. It is the SINGLE SOURCE OF TRUTH — the production auth component (`Self::auth_component`)
    /// consumes it (and the test fixtures compose through that same component), and the allowlist
    /// tripwire asserts the built account's allowlist equals it exactly. The scheme-2
    /// `NetworkAccountTarget` bind on the notes is routing-only, not a consume gate.
    ///
    /// COMPLETE — the frozen 12-root set: rows 1-2 (the supply-side STOCK `MintNote` + STOCK
    /// `BurnNote`), row 3 (`set_attester`, the reference op), rows 4-5 and 8-12 (the remaining
    /// faucet-owned owner/role admin note scripts, with row 12 the minimized identifier-only
    /// `identifier_init` note), and rows 15-16 (the STOCK `PauseActionNote` and
    /// `BlocklistConfigNote`, each covering BOTH of its actions behind one script root). Pause and
    /// blocklist administration used to spend four rows on four faucet-owned notes (the former rows
    /// 6-7 and 13-14); adopting the standard config notes collapses those into two, which is where
    /// the 14 → 12 delta comes from. The set is IMMUTABLE IN EFFECT post-deploy: the
    /// stock component does export allowlist mutators at this protocol version, but they are
    /// present-but-UNREACHABLE — no allowlisted note references them and the tx-script allowlist
    /// admits only the expiration bounder, which is a temporary and ratified state. The config
    /// note that could drive those mutators is deliberately NOT allowlisted.
    /// Three capabilities are deliberately OMITTED
    /// (all human-ratified, grounded in Circle's xReserve EVM admin model): `renounce_role`
    /// (Circle has no role self-renounce); the
    /// runtime `set_role_admin` note (the delegation graph is BUILD-SEEDED by
    /// `seeded_dom_roles_rbac` and deploys frozen; rotation is `grant_role`/`revoke_role`, with
    /// the owner as the rotation backstop — see `DECISION-SETROLEADMIN-NOTE-REMOVAL.md`); and the
    /// stock `RbacActionNote`, whose single root would ALSO expose `SetRoleAdmin` and
    /// `RenounceRole` and so cannot be admitted while those two stay omitted — the faucet keeps its
    /// own single-purpose `grant_role` / `revoke_role` notes instead. The stock
    /// `rbac::set_role_admin` account procedure stays composed but is present-but-UNREACHABLE.
    /// The materialized 12 pinned roots require explicit HUMAN ratification before deploy.
    pub fn allowed_note_scripts() -> BTreeSet<NoteScriptRoot> {
        // The "row N" labels below are the notes' STABLE allowlist identities (shared with
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
            // row 4: set_min_burn_size admin note (ADMIN-gated; targets the STOCK
            // set_min_burn_amount with the note-side zero-floor guard).
            crate::note::xreserve_admin::XReserveSetMinBurnSizeNote::script_root(),
            // row 15: the STOCK pause-action note — pause AND unpause behind one root,
            // calling PausableManager, gated on DOM_PAUSER by the procedure-role map.
            PauseActionNote::script_root(),
            // row 8: grant_role admin note (role-admin-gated, stock RBAC).
            crate::note::xreserve_admin::XReserveGrantRoleNote::script_root(),
            // row 5: set_max_supply admin note (ADMIN-gated, stock FungibleFaucet).
            crate::note::xreserve_admin::XReserveSetMaxSupplyNote::script_root(),
            // row 9: revoke_role admin note (role-admin-gated, stock RBAC).
            crate::note::xreserve_admin::XReserveRevokeRoleNote::script_root(),
            // NO set_role_admin row and NO RbacActionNote row (both deliberately absent) — the
            // role-admin graph is frozen at the build seed; re-adding either violates the
            // ratified decision and turns the account_callable_surface enforcement tests RED.
            // row 10: transfer_ownership admin note (current-owner-gated, stock Ownable2Step).
            crate::note::xreserve_admin::XReserveTransferOwnershipNote::script_root(),
            // row 11: accept_ownership admin note (nominated-owner-gated, stock Ownable2Step).
            crate::note::xreserve_admin::XReserveAcceptOwnershipNote::script_root(),
            // row 16: the STOCK blocklist-config note — block AND unblock behind one root,
            // calling BlocklistManager, gated on BLK_MANAGER by the procedure-role map.
            BlocklistConfigNote::script_root(),
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
    /// which would grow the frozen 12-root set and hand the (present-but-unreachable) allowlist
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
}
