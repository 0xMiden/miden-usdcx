//! MIGRATION PINS — the note-script allowlist, the mint-policy root, and the account storage-slot
//! set, pinned as frozen literals so a protocol bump that moves any of them is FORCED into review
//! instead of being absorbed silently.
//!
//! Why these three: a stock dependency bump can move a compiled MAST root under us (a note script
//! whose callee's root moved), move the security-core `check_policy` root, or add a storage slot.
//! The pre-existing tripwires already DETECT such a move — `typing_builder_byte_identity` pins the
//! account's code commitment and a digest over its storage slots, and both went red at the rc.3
//! bump — but they detect it only in AGGREGATE: they say something underneath moved, never WHICH
//! root or WHICH slot. What these pins add is ATTRIBUTION, not detection. When a pin goes red, the
//! movement is real and must be re-derived, its upstream cause identified, and the new value
//! ratified by a human at PR assembly before the pin is treated as accepted — never hand-edited to
//! match.
//!
//! HISTORY: the pinned VALUES here were measured GREEN at the PRE-BUMP base (protocol at the
//! `4971ec4b38…` git rev), then went RED at the v0.16.0-rc.3 bump — five of the eight allowlist
//! roots and the `check_policy` root moved, and one storage slot was added — which is exactly the
//! movement these pins exist to catch.
//!
//! RATIFIED — human decision (Philipp Keinberger, 2026-08-11). All eleven moved MAST roots — the
//! five allowlist roots and the six callable-surface roots (`check_policy` among them) — are
//! ratified as correctly re-derived, with the upstream/shim causes documented in this file and in
//! the migration handoff. The installed rc.3 root literals below are the ACCEPTED values.
//! `check_policy` remains shim-contaminated (its callee `attestation_verify` carries the fail-closed
//! signature stand-in) and is EXPECTED to move again when the real signature path is rebuilt; it is
//! ratified at its current rc.3 value for this slice, and that later movement is expected, not a
//! regression.
//!
//! NOT RATIFIED — one root moved AFTER that ratification and is therefore NOT covered by it. The
//! ratification above was measured against the pre-refresh base; refreshing this branch onto
//! `implementation` brought in #112, which binds the `SET_ATTESTER` note to its target faucet and
//! moves that note's script root. `XReserveSetAttesterNote` below carries its NEW, MEASURED value
//! and is flagged NOT RATIFIED in place: a human must re-ratify it at PR assembly. The other ten
//! ratified roots were re-measured on the refreshed tree and all HELD. (The refresh also moved the
//! `typing_builder_byte_identity` account id, storage digest and state commitment — via #112's
//! allowlist-slot change and #120's commitment-bound id derivation — which are flagged NOT RATIFIED
//! in that file.)
//!
//! Word values are pinned in their stable `Debug` rendering (decimal limbs), matching the
//! convention `typing_builder_byte_identity` already uses for the account commitment — comparing the
//! rendered string sidesteps any felt-repr ambiguity.

mod support;

use std::collections::BTreeSet;

use miden_protocol::note::NoteScriptRoot;
use miden_protocol::Word;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

const MAX_SUPPLY: u64 = 1_000_000;

// ── FROZEN VALUES (the rc.3 re-materialization, RATIFIED — except the one root the post-rc.3 ─────
// ── refresh moved, which is measured and NOT RATIFIED; see the module note) ──────────────────────

/// The 8 note-script roots of the production faucet's allowlist, as their stable `Debug` renderings.
/// Per-root movement and cause — at the rc.3 bump for the five stock roots, and repo-side for the
/// one of ours that moved afterwards. The upstream causes below were CORRECTED against upstream
/// ground truth: both revisions were built and every common export root compared directly. An
/// earlier revision of this block named several causes that do not survive that check; each
/// correction is called out inline so the wrong mechanism is not reused as a model.
/// - MintNote (stock): MOVED. Its own script is textually unchanged; the mover is its callee
///   `policy_manager::execute_mint_policy`, whose dispatch changed from `dynexec` to `dyncall`.
///   (CORRECTED: the earlier text credited `fungible::mint`, which exists at NEITHER revision, and
///   a "fungible mint stack-handling rewrite"; `mint_and_send`'s body is byte-identical.)
/// - BurnNote (stock): MOVED because ITS OWN SCRIPT was rewritten upstream (`notes/burn.masm`,
///   about +53 lines — the change that made BURN notes store and validate the asset passed to
///   `receive_and_burn`). (CORRECTED: the earlier text filed this as a callee-root consequence with
///   an unchanged script, the mirror image of the MintNote error.)
/// - PauseConfigNote, RbacConfigNote, BlocklistConfigNote (stock): MOVED, with two real movers —
///   they now ENFORCE a `NetworkAccountTarget` binding on the consuming account, and their error
///   STRINGS changed, which compile to different error-code felts. (CORRECTED: a rename cannot move
///   a MAST root, so the earlier "the notes were renamed" mechanism was no mechanism. And
///   `BlocklistConfigNote` was never renamed — it already existed under this name pre-bump.)
/// - The three custom xUSDC admin setters: did NOT move at the rc.3 bump. Their upstream callees
///   `min_burn_amount::set_min_burn_amount` and `fungible::set_max_supply` are byte-identical across
///   the two revisions, confirmed by DIRECT root comparison with their call closures resolved to a
///   fixpoint. (CORRECTED: the earlier text inferred callee stability FROM caller stability. That
///   inference is unsound — upstream `P2idNote`'s root moved at this same bump while `p2id.masm`
///   stayed blob-identical, because a callee's `@locals` changed. Rely on the direct comparison.)
/// - XReserveSetAttesterNote (ours): MOVED AFTER the rc.3 bump, and NOT from upstream. #112 added
///   the `NetworkAccountTarget` consume gate to its own script — the same binding the three stock
///   config notes gained — so its root moved when this branch was refreshed onto `implementation`.
///   Measured, NOT RATIFIED (see the module note); deleting just that binding reproduces the
///   pre-#112 value exactly, which is what identifies #112 as the sole cause.
const ALLOWLIST_ROOTS: [&str; 8] = [
    // MintNote (stock) — MOVED (callee `execute_mint_policy`: dynexec to dyncall)
    "Word([11109209218350460709, 3213691629472996675, 2255365811080514867, 18088254706611776118])",
    // BurnNote (stock) — MOVED (its OWN script was rewritten upstream)
    "Word([12122422334946346513, 10122401082904778272, 6707120545647545940, 3821787119724495246])",
    // PauseConfigNote (stock) — MOVED (enforced target binding + error-string change)
    "Word([6364434116874213150, 4164134719637857369, 7386558776359450689, 1580380303471260809])",
    // BlocklistConfigNote (stock) — MOVED (enforced target binding + error-string change; NOT renamed)
    "Word([16590673221306893276, 933664217937136407, 6546816079571360662, 9137981551125041524])",
    // RbacConfigNote (stock) — MOVED (enforced target binding + error-string change)
    "Word([12288918691266617685, 8762671118025779749, 10130882319008906523, 11642151975824730339])",
    // XReserveSetAttesterNote (ours) — MOVED post-refresh by #112's target binding. NOT RATIFIED.
    "Word([10621302505952483781, 4639415540999186121, 10534906880494260490, 1124375946573662446])",
    // XReserveSetMaxSupplyNote (ours) — unmoved
    "Word([10709095122753693795, 8423686110443497664, 7806138698224003758, 10344805623532725753])",
    // XReserveSetMinBurnSizeNote (ours) — unmoved
    "Word([12829454892963408916, 16929175846341868860, 13019495347172580774, 3827466316585659635])",
];

/// The `xreserve::mint_policy::check_policy` root, the account's active mint policy — the
/// security-core procedure the whole attestation pipeline lives behind. MOVED at the rc.3 bump.
/// CAUSE: `check_policy` invokes `attestation_verify::verify_attestation`, and this migration
/// replaces the deleted upstream prehash-ECDSA primitive with a fail-closed stand-in INSIDE
/// `verify_attestation` (whose crypto callees also moved under miden-vm 0.29). That moves
/// `verify_attestation`'s root and therefore `check_policy`'s, which embeds its callee's root. This
/// is NOT a caller-side dispatch change (a caller cannot move a callee's root). SHIM-CONTAMINATED:
/// the signature-rebuild work rewrites `verify_attestation` again, so this root moves a second time.
/// SECOND, INDEPENDENT CAUSE, added on correction: `check_policy` also embeds `p2id::prepare_note`,
/// whose root moved at this same bump for an unrelated upstream reason — `wallets::basic::
/// move_note_assets_to_account` changed its `@locals` count, which moved the `p2id`, `p2ide`, `swap`
/// and `tx_fee` script roots with it. So this root has TWO movers, not one, and the shim accounts
/// for only part of the movement. Do not treat removing the shim as necessarily restoring the
/// pre-bump value.
const CHECK_POLICY_ROOT: &str =
    "Word([8626271302954437360, 8610777333073226278, 15617565890196817113, 8361425840678887082])";

/// The production faucet's 55 storage-slot names. The rc.3 bump added exactly one
/// (`…network_account::sponsor_at_most_collected_fees`) over the pre-bump 54, with zero renames and
/// zero removals.
const SLOT_NAMES: [&str; 55] = [
    "miden::protocol::faucet::callback::on_before_asset_added_to_account",
    "miden::protocol::faucet::callback::on_before_asset_added_to_note",
    "miden::standards::access::authority::authority_config",
    "miden::standards::access::authority::procedure_roles",
    "miden::standards::access::pausable::is_paused",
    "miden::standards::access::rbac::role_config",
    "miden::standards::access::rbac::role_membership",
    "miden::standards::auth::network_account::active_fee_policy_proc_root",
    "miden::standards::auth::network_account::allowed_fee_policy_proc_roots",
    "miden::standards::auth::network_account::allowed_note_scripts",
    "miden::standards::auth::network_account::allowed_tx_scripts",
    "miden::standards::auth::network_account::fee_asset_id",
    // ADDED at rc.3 (the one slot the bump introduced):
    "miden::standards::auth::network_account::sponsor_at_most_collected_fees",
    "miden::standards::faucets::external_link_0",
    "miden::standards::faucets::external_link_1",
    "miden::standards::faucets::external_link_2",
    "miden::standards::faucets::external_link_3",
    "miden::standards::faucets::external_link_4",
    "miden::standards::faucets::external_link_5",
    "miden::standards::faucets::external_link_6",
    "miden::standards::faucets::fungible::token_config",
    "miden::standards::faucets::logo_uri_0",
    "miden::standards::faucets::logo_uri_1",
    "miden::standards::faucets::logo_uri_2",
    "miden::standards::faucets::logo_uri_3",
    "miden::standards::faucets::logo_uri_4",
    "miden::standards::faucets::logo_uri_5",
    "miden::standards::faucets::logo_uri_6",
    "miden::standards::faucets::mutability_config",
    "miden::standards::faucets::policies::burn::min_burn_amount::min_burn_amount",
    "miden::standards::faucets::policies::policy_manager::active_burn_policy_proc_root",
    "miden::standards::faucets::policies::policy_manager::active_mint_policy_proc_root",
    "miden::standards::faucets::policies::policy_manager::active_receive_policy_proc_root",
    "miden::standards::faucets::policies::policy_manager::active_send_policy_proc_root",
    "miden::standards::faucets::policies::policy_manager::allowed_burn_policy_proc_roots",
    "miden::standards::faucets::policies::policy_manager::allowed_mint_policy_proc_roots",
    "miden::standards::faucets::policies::policy_manager::allowed_receive_policy_proc_roots",
    "miden::standards::faucets::policies::policy_manager::allowed_send_policy_proc_roots",
    "miden::standards::faucets::policies::transfer::blocklist::blocked_accounts",
    "miden::standards::faucets::token_description_0",
    "miden::standards::faucets::token_description_1",
    "miden::standards::faucets::token_description_2",
    "miden::standards::faucets::token_description_3",
    "miden::standards::faucets::token_description_4",
    "miden::standards::faucets::token_description_5",
    "miden::standards::faucets::token_description_6",
    "miden::standards::faucets::token_name_0",
    "miden::standards::faucets::token_name_1",
    "miden::standards::fees::policies::basic_constant_fee::fee_schedule",
    "xusdc::xreserve::attester_admin::xreserve_attesters",
    "xusdc::xreserve::domain_config::domain",
    "xusdc::xreserve::domain_config::source_domain",
    "xusdc::xreserve::domain_config::xreserve_contract_hi",
    "xusdc::xreserve::domain_config::xreserve_contract_lo",
    "xusdc::xreserve::nonce_registry::used_nonces",
];

// ── THE THREE PINS ──────────────────────────────────────────────────────────────────────────────

/// PIN 1 — the note-script allowlist, as a frozen SET of roots plus its count. Asserts set equality
/// (every expected root present, no unexpected root) AND the count, over the single-source-of-truth
/// `allowed_note_scripts()` the production auth component is built from.
#[test]
fn note_script_allowlist_set_and_count_are_pinned() {
    let allowlist: BTreeSet<NoteScriptRoot> = XReserveStablecoinBuilder::allowed_note_scripts();
    assert_eq!(
        allowlist.len(),
        ALLOWLIST_ROOTS.len(),
        "the note-script allowlist count moved (a note was added or removed)",
    );
    let got: BTreeSet<String> = allowlist
        .iter()
        .map(|root| format!("{:?}", Word::from(*root)))
        .collect();
    let expected: BTreeSet<String> = ALLOWLIST_ROOTS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        got, expected,
        "the note-script allowlist ROOT SET moved — a compiled note-script MAST root changed. \
         Re-derive the moved roots, identify the upstream cause, and get the new values ratified \
         before re-materializing this pin. Do NOT hand-edit to match.",
    );
}

/// PIN 2 — the `check_policy` (attestation mint policy) root, the security-core procedure. Widened
/// from the allowlist pin's shape to the single most important account procedure root. The pinned
/// value is SHIM-CONTAMINATED (see the module note) and will move again when the signature path is
/// rebuilt.
#[test]
fn attestation_mint_policy_root_is_pinned() {
    // measured through the SHARED production builder (`support::production_builder`), the same one
    // the production fixtures compose — a local copy of its arguments here would keep this pin
    // green after the shipped builder's inputs moved.
    let root = production_builder(MAX_SUPPLY, 0, TEST_DOMAIN)
        .expect("the production faucet builder must construct")
        .attestation_mint_policy_root()
        .expect("the attestation mint policy root must resolve");
    assert_eq!(
        format!("{root:?}"),
        CHECK_POLICY_ROOT,
        "the xreserve::mint_policy::check_policy root moved. It embeds the root of \
         attestation_verify::verify_attestation, which this migration edits (the fail-closed \
         signature stand-in) and which 0.29 also touched; the value here is shim-contaminated and \
         provisional — re-derive, identify the cause, ratify, then re-materialize.",
    );
}

/// PIN 3 — the account storage-slot NAME SET plus its count. Catches a slot addition, removal or
/// rename independently of any slot value.
#[test]
fn account_storage_slot_name_set_and_count_are_pinned() {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_, _| Vec::new())
        .expect("the production faucet must build");
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .expect("the production faucet must be committed")
        .clone();
    let got: BTreeSet<String> = account
        .storage()
        .slots()
        .iter()
        .map(|slot| format!("{}", slot.name()))
        .collect();
    assert_eq!(
        got.len(),
        SLOT_NAMES.len(),
        "the account storage-slot COUNT moved (a slot was added or removed)",
    );
    let expected: BTreeSet<String> = SLOT_NAMES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        got, expected,
        "the account storage-slot NAME SET moved. The rc.3 bump added exactly one slot \
         (…network_account::sponsor_at_most_collected_fees); any further move must be re-derived.",
    );
}
