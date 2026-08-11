//! MIGRATION PINS — the note-script allowlist, the mint-policy root, and the account storage-slot
//! set, pinned as frozen literals so a protocol bump that moves any of them is FORCED into review
//! instead of being absorbed silently.
//!
//! Why these three: a stock dependency bump can move a compiled MAST root under us (a note script
//! whose callee's root moved), move the security-core `check_policy` root, or add a storage slot —
//! and none of the pre-existing membership/reachability tripwires records the literal VALUE, so such
//! a move used to be invisible. These pins record the value. When a pin goes red, the movement is
//! real and must be re-derived, its upstream cause identified, and the new value ratified by a human
//! at PR assembly before the pin is treated as accepted — never hand-edited to match.
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
//! SHIM-CONTAMINATED (moves again): `check_policy` is measured against the temporary fail-closed
//! signature-verify stand-in this migration installs; the later signature-rebuild work both deletes
//! that stand-in and rewrites `check_policy`, so this root — and the account initial commitment that
//! covers it (pinned by `typing_builder_byte_identity`) — MOVE AGAIN and must be re-materialized a
//! second time then.
//!
//! Word values are pinned in their stable `Debug` rendering (decimal limbs), matching the
//! convention `typing_builder_byte_identity` already uses for the account commitment — comparing the
//! rendered string sidesteps any felt-repr ambiguity.

mod support;

use std::collections::BTreeSet;

use miden_protocol::asset::AssetAmount;
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::Word;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::xreserve::encoding::EthBytes32;

const MAX_SUPPLY: u64 = 1_000_000;

// ── FROZEN rc.3 VALUES (re-materialized from the pre-bump set; PROVISIONAL, awaiting ratification) ─

/// The 8 note-script roots of the production faucet's allowlist, as their stable `Debug` renderings.
/// Per-root movement and cause at the rc.3 bump:
/// - MintNote, BurnNote (stock): MOVED — a callee-root consequence. Their scripts are textually
///   unchanged, but each embeds its callee's MAST root (`fungible::mint` / `fungible::receive_and_burn`),
///   and the upstream fungible mint/burn stack-handling rewrite moved those callees.
/// - PauseConfigNote, BlocklistConfigNote, RbacConfigNote (stock): MOVED — the upstream config-note
///   rework changed the compiled note SCRIPTS themselves (the notes were renamed and now carry and
///   ENFORCE a `NetworkAccountTarget` binding on the consuming account).
/// - The three custom xUSDC admin setters: did NOT move — which proves their upstream callees
///   (`min_burn_amount::set_min_burn_amount`, `fungible::set_max_supply`) did not move.
const ALLOWLIST_ROOTS: [&str; 8] = [
    // MintNote (stock) — MOVED (callee-root consequence)
    "Word([11109209218350460709, 3213691629472996675, 2255365811080514867, 18088254706611776118])",
    // BurnNote (stock) — MOVED (callee-root consequence)
    "Word([12122422334946346513, 10122401082904778272, 6707120545647545940, 3821787119724495246])",
    // PauseConfigNote (stock) — MOVED (config-note rework: rename + enforced target binding)
    "Word([6364434116874213150, 4164134719637857369, 7386558776359450689, 1580380303471260809])",
    // BlocklistConfigNote (stock) — MOVED (config-note rework)
    "Word([16590673221306893276, 933664217937136407, 6546816079571360662, 9137981551125041524])",
    // RbacConfigNote (stock) — MOVED (config-note rework)
    "Word([12288918691266617685, 8762671118025779749, 10130882319008906523, 11642151975824730339])",
    // XReserveSetAttesterNote (ours) — unmoved
    "Word([1014266409661146010, 13413563347990402434, 3353735645470309830, 6697281211075163595])",
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

// ── HELPERS ───────────────────────────────────────────────────────────────────────────────────

fn production_builder() -> XReserveStablecoinBuilder {
    XReserveStablecoinBuilder::new(
        AssetAmount::new(MAX_SUPPLY).expect("max supply is a valid asset amount"),
        AssetAmount::new(0).expect("token supply is a valid asset amount"),
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
    )
    .expect("the production faucet builder must construct")
    .with_domain_config(
        TEST_DOMAIN,
        TEST_SOURCE_DOMAIN,
        EthBytes32::new(test_xreserve_contract()),
    )
}

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
    let root = production_builder()
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
