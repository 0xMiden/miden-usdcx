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
use miden_standards::note::{
    BlocklistConfigNote, BurnNote, MintNote, PauseActionNote, RbacActionNote,
};
use miden_standards::tx_script::ExpirationTransactionScript;

use super::XReserveStablecoinBuilder;

impl XReserveStablecoinBuilder {
    /// The note-script allowlist for the production faucet's `AuthNetworkAccount` auth
    /// component. It is the SINGLE SOURCE OF TRUTH — the production auth component (`Self::auth_component`)
    /// consumes it, and the allowlist
    /// tripwire asserts the built account's allowlist equals it exactly. The scheme-2
    /// `NetworkAccountTarget` bind on the notes is routing-only, not a consume gate.
    ///
    /// COMPLETE — the 8-root set: the two supply-side STOCK notes (`MintNote` + `BurnNote`), the
    /// three faucet-owned `ADMIN`-gated setters (`set_attester`, `set_min_burn_size` and
    /// `set_max_supply`), and the three STOCK
    /// admin notes (`PauseActionNote`, `BlocklistConfigNote` and `RbacActionNote`), each covering
    /// EVERY one of its actions behind one script root. The set is IMMUTABLE IN EFFECT post-deploy:
    /// the stock component does export allowlist mutators at this protocol version, but they are
    /// present-but-UNREACHABLE — no allowlisted note references them and the tx-script allowlist
    /// admits only the expiration bounder, which is a temporary and ratified state. The config
    /// note that could drive those mutators is deliberately NOT allowlisted.
    ///
    /// Two capability decisions are recorded in this set, both human-ratified.
    ///
    /// There is no IDENTIFIER-INIT note, because there is no identifier to seed: the mint path
    /// derives the faucet's identifier from its own account id, so the faucet is mint-ready from
    /// deploy and no post-deploy write — nor the window in front of it — exists to allowlist.
    ///
    /// There is no OWNERSHIP note, because the faucet installs no two-step ownership component: the
    /// account has a single authority handle, the built-in `ADMIN` role, and rotating it is a grant
    /// and a revoke of that role. The handover is single-step — there is no nominate-then-accept
    /// confirmation to protect against naming the wrong successor.
    ///
    /// Role management is the STOCK `RbacActionNote`, one script root carrying FOUR actions:
    /// grant, revoke, set-role-admin and renounce. Allowlisting is per root, so admitting it admits
    /// all four, and two capabilities follow that the faucet did not previously have. The
    /// role-admin graph `seeded_dom_roles_rbac` builds is runtime-MUTABLE: a role's effective
    /// admin may re-point that role at another role, and because delegation is exclusive, `ADMIN`
    /// has no authority over a role that was delegated away (`DOM_MANAGER`, not `ADMIN`, governs
    /// `DOM_PAUSER`). And a role holder may RENOUNCE its own membership, ungated, which can leave a
    /// role empty until its admin grants it again. Both are accepted; the alternative was keeping
    /// two bespoke note scripts to withhold them.
    ///
    /// The materialized 8 pinned roots require explicit HUMAN ratification before deploy.
    pub fn allowed_note_scripts() -> BTreeSet<NoteScriptRoot> {
        BTreeSet::from([
            // the supply-side notes — BOTH the STOCK standards scripts. The mint row is the
            // standards MintNote (attestation + intent ride as attachments; the attestation mint
            // policy is the gate); the burn row is the standards BurnNote.
            MintNote::script_root(),
            BurnNote::script_root(),
            // set_attester admin note (reference op).
            crate::note::xreserve_admin::XReserveSetAttesterNote::script_root(),
            // set_min_burn_size admin note (ADMIN-gated; targets the STOCK set_min_burn_amount
            // with the note-side zero-floor guard).
            crate::note::xreserve_admin::XReserveSetMinBurnSizeNote::script_root(),
            // set_max_supply admin note (ADMIN-gated, stock FungibleFaucet).
            crate::note::xreserve_admin::XReserveSetMaxSupplyNote::script_root(),
            // the STOCK pause-action note — pause AND unpause behind one root, calling
            // PausableManager, gated on DOM_PAUSER by the procedure-role map.
            PauseActionNote::script_root(),
            // the STOCK blocklist-config note — block AND unblock behind one root, calling
            // BlocklistManager, gated on BLK_MANAGER by the procedure-role map.
            BlocklistConfigNote::script_root(),
            // the STOCK role-action note — grant, revoke, set-role-admin AND renounce behind one
            // root, calling the stock role component, which gates every action on the note sender.
            RbacActionNote::script_root(),
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

    /// The stock `AuthNetworkAccount` production auth component, initialized with the
    /// note-script allowlist (`Self::allowed_note_scripts`), a tx-script allowlist containing
    /// EXACTLY the one canonical `ExpirationTransactionScript::script_root()` (a ratified
    /// decision), and the provisional zero-fee configuration
    /// ([`Self::provisional_fee_policy_manager`]).
    pub fn auth_component() -> Result<AuthNetworkAccount, NetworkAccountNoteAllowlistError> {
        Ok(AuthNetworkAccount::custom(
            Self::allowed_note_scripts(),
            Self::provisional_fee_policy_manager(),
        )?
        .with_allowed_tx_scripts(BTreeSet::from([ExpirationTransactionScript::script_root()])))
    }
}
