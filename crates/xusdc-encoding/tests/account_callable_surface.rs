//! FULL-ACCOUNT CALLABLE-SURFACE PIN (S12, human-ratified 2026-07-13).
//!
//! `mint_root_surface.rs` freezes the 17 callable roots of the **xreserve** component. This file
//! freezes the **whole composed account** — the xreserve 17 PLUS every callable procedure the STOCK
//! components contribute (`Authority` incl. the v0.16 `freeze`/`unfreeze`, `RoleBasedAccessControl`,
//! `Ownable2Step`, `FungibleFaucet` incl. the v0.16 `has_procedure` re-export, `TokenPolicyManager`,
//! `Pausable`, and the `AuthNetworkAccount` auth procedure). It exists because a stock dependency
//! bump can hand this faucet a NEW callable capability silently: at the v0.16 migration
//! `Authority::OwnerControlled` began bundling owner-gated `freeze`/`unfreeze` procedures
//! (upstream #3102/#3209) that no v0.15 composition had. That must never be inherited quietly again
//! — so the composed account's callable set is pinned to a FROZEN literal list here, and any stock
//! bump that adds (or drops) a callable procedure fails LOUDLY in
//! `production_account_callable_surface_is_frozen`. (Building this pin caught THREE v0.16 stock
//! additions beyond freeze/unfreeze that no v0.15 composition had — `authority::get_authority` and
//! the #3047 `policy_manager::invoke_send_policy`/`invoke_receive_policy` transfer-policy dispatch
//! wrappers. They are human-ratified in their OWN map row S24 (NOT under S12); the wrappers are
//! callable but INERT here: F4 registers no transfer policy, so `AssetCallbackFlag::Disabled` and
//! the kernel never invokes them on a transfer, and with no active send/receive policy the stock
//! `invoke_transfer_policy` returns ASSET_VALUE unchanged and skips the pause check — no zero-root
//! trap. `invoke_wrappers_are_inert_and_the_asset_stays_basic` re-confirms F4 at v16.)
//!
//! S12 DISPOSITION — `freeze`/`unfreeze` are PRESENT but OPERATIONALLY UNREACHABLE, and this file
//! proves it rather than asserting it: the faucet is a keyless network account whose
//! `AuthNetworkAccount` admits ONLY the immutable 13-root note-script allowlist and an EMPTY
//! tx-script allowlist (F5). `freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note`
//! scans the MAST of all 13 allowlisted note scripts and shows not one of them references the
//! freeze/unfreeze roots; `freeze_and_unfreeze_are_not_admissible_via_either_allowlist` shows the
//! roots are not among the 13 note-script roots; and `the_auth_component_rejects_a_non_allowlisted_note`
//! / `the_auth_component_rejects_any_tx_script_via_the_empty_allowlist` EXECUTE the two (and only
//! two) entry vectors and watch the auth component reject them. (The allowlist is an epilogue
//! `@auth_script`, checked AFTER note/tx-script execution, so a note that itself calls `freeze`
//! would trap on freeze's own owner-gate before the allowlist check — the allowlist's decision on
//! such a note is the root-membership one, which is why the freeze-specific proof is membership,
//! not a self-trapping execution.) So `freeze` can never be invoked, `is_frozen` is never set, and
//! `ERR_AUTHORITY_FROZEN` never fires: the mechanism is inert — the same disposition as the
//! ratified `renounce_role`.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::AssetCallbackFlag;
use miden_protocol::account::{Account, AccountComponent};
use miden_protocol::assembly::mast::MastNodeExt;
use miden_protocol::asset::AssetCallbacks;
use miden_protocol::note::{NoteScript, NoteScriptRoot};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Authority;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::note::BurnNote;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::note::xreserve_admin::{
    XReserveAcceptOwnershipNote, XReserveDomainInitNote, XReserveGrantRoleNote, XReservePauseNote,
    XReserveRevokeRoleNote, XReserveSetAttesterNote, XReserveSetMaxSupplyNote,
    XReserveSetMinBurnSizeNote, XReserveSetRoleAdminNote, XReserveTransferOwnershipNote,
    XReserveUnpauseNote,
};
use xusdc_encoding::note::xreserve_mint::XReserveMintNote;

const MAX_SUPPLY: u64 = 1_000_000;

/// The FROZEN callable surface of the composed production faucet ACCOUNT: every procedure a
/// transaction may `call` on it, by fully-qualified path. This is a LITERAL list on purpose — it is
/// NOT derived from the components, so a stock bump that adds a callable procedure grows the
/// account's real surface without growing this list, and the set-equality below goes RED.
///
/// Membership is ratified, not incidental (paths are the component-wrapper form the exports carry):
/// - the 17 `::xreserve::…` roots are the F1-frozen set (`mint_root_surface.rs` pins them separately);
/// - the 45 stock rows are what the composition's components export at `=0.16.0-alpha.2`;
/// - `authority::freeze` / `authority::unfreeze` are the v0.16 additions (#3102) — PRESENT but
///   UNREACHABLE (S12; the tests below), never silently inherited; `authority::get_authority` is the
///   v0.16 view accessor;
/// - `policy_manager::invoke_send_policy` / `invoke_receive_policy` are the #3047 transfer-policy
///   dispatch wrappers — callable but INERT (F4 registers no transfer policy → no callback slots
///   installed → the kernel never dispatches them on a transfer; with no active send/receive
///   policy the stock `invoke_transfer_policy` returns ASSET_VALUE unchanged and skips the pause
///   check — S24, human-ratified);
/// - `fungible_faucet::has_procedure` is the v0.16 `FungibleFaucet` re-export (#3222) the stock BURN
///   note's faucet-kind reflection requires.
const FROZEN_ACCOUNT_SURFACE: [&str; 62] = [
    // --- the 17 xreserve component roots (their IDENTITIES are also pinned in
    //     mint_root_surface.rs::FROZEN_CALLABLE_ROOTS; here they complete the whole account) ---
    "::xreserve::attestation_verify::verify_attestation",
    "::xreserve::attester_admin::set_attester",
    "::xreserve::burn_policy::check_policy",
    "::xreserve::deposit_intent_parser::assert_deposit_intent",
    "::xreserve::deposit_intent_parser::assert_mint_amounts",
    "::xreserve::deposit_intent_parser::assert_nonce_unused",
    "::xreserve::domain_config::domain_init",
    "::xreserve::encoding::bytes32_to_key",
    "::xreserve::encoding::parse_deposit_intent",
    "::xreserve::encoding::pubkey_commitment",
    "::xreserve::encoding::uint256_to_asset_amount",
    "::xreserve::min_burn_admin::set_min_burn_size",
    "::xreserve::mint_deny_guard::check_policy",
    "::xreserve::pause_admin::pause",
    "::xreserve::pause_admin::unpause",
    "::xreserve::xreserve_mint::mint",
    "::xreserve::xreserve_mint_note_entry::receive_and_mint",
    // --- the 45 stock-component roots ---
    "::miden::standards::components::access::authority::freeze",
    "::miden::standards::components::access::authority::get_authority",
    "::miden::standards::components::access::authority::unfreeze",
    "::miden::standards::components::access::ownable2step::accept_ownership",
    "::miden::standards::components::access::ownable2step::get_nominated_owner",
    "::miden::standards::components::access::ownable2step::get_owner",
    "::miden::standards::components::access::ownable2step::renounce_ownership",
    "::miden::standards::components::access::ownable2step::transfer_ownership",
    "::miden::standards::components::access::pausable::is_paused",
    "::miden::standards::components::access::rbac::get_role_admin",
    "::miden::standards::components::access::rbac::get_role_member_count",
    "::miden::standards::components::access::rbac::grant_role",
    "::miden::standards::components::access::rbac::has_role",
    "::miden::standards::components::access::rbac::renounce_role",
    "::miden::standards::components::access::rbac::revoke_role",
    "::miden::standards::components::access::rbac::set_role_admin",
    "::miden::standards::components::auth::network_account::auth_network_transaction",
    "::miden::standards::components::faucets::fungible_faucet::get_decimals",
    "::miden::standards::components::faucets::fungible_faucet::get_max_supply",
    "::miden::standards::components::faucets::fungible_faucet::get_mutability_config",
    "::miden::standards::components::faucets::fungible_faucet::get_name",
    "::miden::standards::components::faucets::fungible_faucet::get_token_config",
    "::miden::standards::components::faucets::fungible_faucet::get_token_supply",
    "::miden::standards::components::faucets::fungible_faucet::get_token_symbol",
    "::miden::standards::components::faucets::fungible_faucet::has_procedure",
    "::miden::standards::components::faucets::fungible_faucet::is_description_mutable",
    "::miden::standards::components::faucets::fungible_faucet::is_external_link_mutable",
    "::miden::standards::components::faucets::fungible_faucet::is_logo_uri_mutable",
    "::miden::standards::components::faucets::fungible_faucet::is_max_supply_mutable",
    "::miden::standards::components::faucets::fungible_faucet::mint_and_send",
    "::miden::standards::components::faucets::fungible_faucet::receive_and_burn",
    "::miden::standards::components::faucets::fungible_faucet::set_description",
    "::miden::standards::components::faucets::fungible_faucet::set_external_link",
    "::miden::standards::components::faucets::fungible_faucet::set_logo_uri",
    "::miden::standards::components::faucets::fungible_faucet::set_max_supply",
    "::miden::standards::components::faucets::policies::policy_manager::get_burn_policy",
    "::miden::standards::components::faucets::policies::policy_manager::get_mint_policy",
    "::miden::standards::components::faucets::policies::policy_manager::get_receive_policy",
    "::miden::standards::components::faucets::policies::policy_manager::get_send_policy",
    "::miden::standards::components::faucets::policies::policy_manager::invoke_receive_policy",
    "::miden::standards::components::faucets::policies::policy_manager::invoke_send_policy",
    "::miden::standards::components::faucets::policies::policy_manager::set_burn_policy",
    "::miden::standards::components::faucets::policies::policy_manager::set_mint_policy",
    "::miden::standards::components::faucets::policies::policy_manager::set_receive_policy",
    "::miden::standards::components::faucets::policies::policy_manager::set_send_policy",
];

/// The production composition, component by component: the SHIPPED component set
/// (`support::production_component_set` → `XReserveStablecoinBuilder::build_components()`) PLUS the
/// `AuthNetworkAccount` auth component the MockChain fixture installs — both single-sourced from
/// `XReserveStablecoinBuilder`, so this cannot drift from what ships.
fn production_components() -> Result<Vec<AccountComponent>> {
    let mut components =
        production_component_set(MAX_SUPPLY, 0).context("the production composition must build")?;
    components.push(
        XReserveStablecoinBuilder::auth_component()
            .context("the production auth component must build")?
            .into(),
    );
    Ok(components)
}

/// Every callable procedure of the composed account, as `(path, root)` — read from each component's
/// FILTERED interface (the `@account_procedure` / `@auth_script` exports; v0.16 #3171).
fn component_surface(components: &[AccountComponent]) -> Vec<(String, Word)> {
    let mut surface = Vec::new();
    for component in components {
        let code = component.component_code();
        for export in code.exports() {
            let path = export.path.to_string();
            let root = code
                .get_procedure_root_by_path(export.path.as_ref())
                .unwrap_or_else(|| panic!("the exported path {path} must resolve to a root"));
            surface.push((path, Word::from(root)));
        }
    }
    surface
}

/// The committed production faucet ACCOUNT (the real composed, auth-carrying account the network
/// executes against).
fn production_account() -> Result<Account> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("the production faucet must be committed")?
        .clone();
    Ok(account)
}

/// The 13 allowlisted note SCRIPTS (not just their roots): the two supply notes + the 11 admin
/// notes. Single-sourced from the same factories the allowlist itself is built from, so a note that
/// enters the allowlist necessarily enters this sweep too.
fn allowlisted_note_scripts() -> Vec<(&'static str, NoteScript)> {
    vec![
        ("xreserve_mint_note", XReserveMintNote::script()),
        ("stock_burn_note", BurnNote::script()),
        ("set_attester", XReserveSetAttesterNote::script()),
        ("domain_init", XReserveDomainInitNote::script()),
        ("set_min_burn_size", XReserveSetMinBurnSizeNote::script()),
        ("pause", XReservePauseNote::script()),
        ("unpause", XReserveUnpauseNote::script()),
        ("grant_role", XReserveGrantRoleNote::script()),
        ("revoke_role", XReserveRevokeRoleNote::script()),
        ("set_role_admin", XReserveSetRoleAdminNote::script()),
        ("set_max_supply", XReserveSetMaxSupplyNote::script()),
        (
            "transfer_ownership",
            XReserveTransferOwnershipNote::script(),
        ),
        ("accept_ownership", XReserveAcceptOwnershipNote::script()),
    ]
}

// THE FROZEN SURFACE
// ================================================================================================

/// SET-EQUALITY, both layers: the FROZEN literal surface above == the composition's real callable
/// procedures (by path) == the committed ACCOUNT's callable procedure roots (on-chain). A stock bump
/// that adds a callable procedure grows the account but not the frozen list — RED. One that drops a
/// procedure the faucet relies on — likewise RED. Nothing is inherited silently.
#[test]
fn production_account_callable_surface_is_frozen() -> Result<()> {
    let components = production_components()?;
    let surface = component_surface(&components);

    // Layer 1 (source): the component-exported paths equal the frozen 62-root list EXACTLY (17
    // xreserve + 45 stock, in one literal set — a stock bump that adds or removes any callable
    // procedure fails HERE).
    let mut paths: Vec<String> = surface.iter().map(|(path, _)| path.clone()).collect();
    paths.sort();
    let mut expected: Vec<String> = FROZEN_ACCOUNT_SURFACE
        .iter()
        .map(|p| (*p).to_string())
        .collect();
    expected.sort();
    assert_eq!(
        paths, expected,
        "the composed account's callable surface drifted from the frozen 62-root set — a stock \
         bump added or removed a callable procedure (or the xreserve surface changed). This is NOT \
         a mechanical conformance change: every such delta must be SURFACED for ratification \
         (MIGRATION-V16-ALPHA2.md §4a stock-surface discipline + STOP condition 5), exactly as the \
         v0.16 freeze/unfreeze (S12) and get_authority/invoke_* (S24) additions were."
    );

    // Layer 2 (on-chain): the committed account's callable roots == the roots of that same surface.
    let account = production_account()?;
    let account_roots: BTreeSet<Word> = account
        .code()
        .procedures()
        .iter()
        .map(|root| Word::from(*root))
        .collect();
    let expected_roots: BTreeSet<Word> = surface.iter().map(|(_, root)| *root).collect();
    assert_eq!(
        account_roots, expected_roots,
        "the committed account's callable root set must equal EXACTLY the roots of the frozen \
         surface (no procedure appears on-chain that the frozen list does not name)"
    );
    assert_eq!(
        account_roots.len(),
        FROZEN_ACCOUNT_SURFACE.len(),
        "the account's callable procedure COUNT must equal the frozen 62-root surface"
    );
    Ok(())
}

// S12 — FREEZE / UNFREEZE: PRESENT, AND PROVABLY UNREACHABLE
// ================================================================================================

/// PRESENT: the v0.16 `Authority` freeze/unfreeze procedures ARE callable roots of the composed
/// account (this is the fact S12 ratifies, stated explicitly rather than left implicit in a count).
#[test]
fn authority_freeze_and_unfreeze_are_present_on_the_account() -> Result<()> {
    let account = production_account()?;
    let roots: BTreeSet<Word> = account
        .code()
        .procedures()
        .iter()
        .map(|root| Word::from(*root))
        .collect();
    for (name, root) in [
        ("freeze", Word::from(Authority::freeze_root())),
        ("unfreeze", Word::from(Authority::unfreeze_root())),
    ] {
        assert!(
            roots.contains(&root),
            "the v0.16 stock Authority component contributes `{name}` to the account's callable \
             surface (S12) — if this ever stops being true, the S12 disposition must be re-ratified"
        );
    }
    Ok(())
}

/// UNREACHABLE, leg 1 (static, exhaustive over the allowlist): NOT ONE of the 13 allowlisted note
/// scripts references the freeze or unfreeze root ANYWHERE in its MAST — so no admissible note can
/// invoke them. Scanning every MAST node digest (not just the entrypoint) catches a call by root, a
/// call by path, and any nested/external reference alike.
#[test]
fn freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    assert_eq!(
        scripts.len(),
        13,
        "the unreachability sweep must cover all 13 allowlisted note scripts"
    );
    // The scripts swept ARE the allowlist (no script can dodge the sweep by not being listed here).
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 13-root note-script allowlist"
    );

    let forbidden = [
        ("freeze", Word::from(Authority::freeze_root())),
        ("unfreeze", Word::from(Authority::unfreeze_root())),
    ];
    for (label, script) in &scripts {
        let forest = script.mast();
        for node in forest.nodes() {
            let digest = node.digest();
            for (name, root) in &forbidden {
                assert_ne!(
                    digest, *root,
                    "allowlisted note script `{label}` references the Authority `{name}` root — \
                     the S12 unreachability guarantee is BROKEN (a note that can invoke freeze \
                     would make the account-self-freeze operationally reachable)"
                );
            }
        }
    }
    Ok(())
}

/// UNREACHABLE, cross-reference (freeze-specific): the freeze/unfreeze roots are not ADMISSIBLE via
/// either entry vector. `AuthNetworkAccount` admits an input note only if its script root is one of
/// the 13 allowlisted roots, and admits a tx script only if its root is in the tx-script allowlist —
/// which is EMPTY. There is no freeze/unfreeze NOTE FACTORY at all (the 13 are the two supply notes
/// + the 11 admin notes; none carries freeze), so no freeze-bearing note root can be among the 13,
/// and the empty tx-script allowlist admits nothing. Combined with the MAST sweep above (no
/// allowlisted note even references the roots) both entry vectors are provably closed.
#[test]
fn freeze_and_unfreeze_are_not_admissible_via_either_allowlist() -> Result<()> {
    let note_allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    for (name, root) in [
        ("freeze", Authority::freeze_root()),
        ("unfreeze", Authority::unfreeze_root()),
    ] {
        let as_note_root = NoteScriptRoot::from_raw(Word::from(root));
        assert!(
            !note_allowlist.contains(&as_note_root),
            "the `{name}` root must NOT be a member of the 13-root note-script allowlist \
             (there is no freeze note factory; a freeze-bearing note is inadmissible)"
        );
    }
    // The tx-script entry vector is closed by the EMPTY tx-script allowlist — pinned + executed by
    // `the_auth_component_rejects_any_tx_script_via_the_empty_allowlist` below (and the canonical
    // `f5_network_account_auth::production_faucet_tx_script_allowlist_is_exactly_empty`). Together
    // with the note-root non-membership above, no freeze/unfreeze call is admissible via either
    // entry vector.
    Ok(())
}

/// UNREACHABLE, executing (entry vector 1 — INPUT NOTES): the auth component rejects any input note
/// whose script root is not one of the 13 (a clean, non-self-trapping probe note so the AUTH gate is
/// unambiguously the rejector — the note-script allowlist is an epilogue `@auth_script`, checked
/// after note execution, so a note that itself calls `freeze` would trap on freeze's own gate before
/// this check; the allowlist's decision on such a note is the ROOT-membership one asserted above).
#[tokio::test]
async fn the_auth_component_rejects_a_non_allowlisted_note() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let script = CodeBuilder::new()
        .compile_note_script("@note_script\npub proc main\n    dropw\nend")
        .context("compiling the non-allowlisted probe note script")?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(9u32),
        Felt::from(9u32),
        Felt::from(9u32),
        Felt::from(9u32),
    ]));
    let note = NoteBuilder::new(pf.producer_id, &mut rng)
        .script(script)
        .build()
        .context("building the non-allowlisted probe note")?;
    let result = pf
        .mock_chain
        .build_tx_context(pf.faucet_id, &[], core::slice::from_ref(&note))
        .context("non-allowlisted note tx context")?
        .build()
        .context("non-allowlisted note tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);
    Ok(())
}

/// UNREACHABLE, executing (entry vector 2 — TX SCRIPT): the auth component rejects any transaction
/// script against the EMPTY tx-script allowlist (a clean, non-self-trapping probe script, same
/// reasoning as the note vector). With both entry vectors closed — every note must be one of the 13
/// (none touches freeze) and every tx script must be in an allowlist that is empty — `freeze` is
/// operationally unreachable on this faucet, `is_frozen` is never set, and `ERR_AUTHORITY_FROZEN`
/// never fires: the mechanism is INERT (S12, the ratified `renounce_role` disposition).
#[tokio::test]
async fn the_auth_component_rejects_any_tx_script_via_the_empty_allowlist() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;
    let tx_script = CodeBuilder::new()
        .compile_tx_script("@transaction_script\npub proc main\n    nop\nend\n")
        .context("compiling the probe tx script")?;
    let result = pf
        .mock_chain
        .build_tx_context(pf.faucet_id, &[], &[])
        .context("tx-script tx context")?
        .tx_script(tx_script)
        .build()
        .context("tx-script tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(result, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);
    Ok(())
}

// S24 — the invoke_* wrappers are INERT: F4 (no transfer policy) and the callback flag are UNAFFECTED
// ================================================================================================

/// CONDITION 3 (round-9 S24 ratification): the mere PRESENCE of the #3047
/// `invoke_send_policy`/`invoke_receive_policy` wrappers on the account's callable surface did NOT
/// register a transfer policy or flip the asset-callback flag — F4 holds unchanged at v16. Asserts,
/// directly on the shipped composition + account: (1) NEITHER asset-callback slot is installed (no
/// send/receive transfer policy was wired — the wrappers are callable but the kernel has no callback
/// slot to dispatch them from), and (2) the faucet account id carries `AssetCallbackFlag::Disabled`
/// (every minted xUSDC is a basic, unpoliced asset — #3167). Complements the standing
/// `basic_asset_tripwire` (F4) and `mint_root_surface::production_supply_raising_root_set_is_exactly_mint`
/// (F1), both green: the invoke_* presence changed neither.
#[test]
fn invoke_wrappers_are_inert_and_the_asset_stays_basic() -> Result<()> {
    let components =
        production_component_set(MAX_SUPPLY, 0).context("the production composition must build")?;

    // (1) no transfer policy → NEITHER reserved asset-callback slot is installed.
    for slot in [
        AssetCallbacks::on_before_asset_added_to_note_slot(),
        AssetCallbacks::on_before_asset_added_to_account_slot(),
    ] {
        assert!(
            !components
                .iter()
                .flat_map(|c| c.storage_slots().iter())
                .any(|s| s.name() == slot),
            "an asset-callback slot ({slot}) is installed — a transfer policy was wired, so the \
             invoke_* wrappers would be LIVE. F4 requires xUSDC stay unpoliced (no transfer policy)."
        );
    }

    // (2) the committed faucet account id carries the Disabled callback flag (basic asset).
    let account = production_account()?;
    assert_eq!(
        account.id().asset_callback_flag(),
        AssetCallbackFlag::Disabled,
        "the faucet account id must carry AssetCallbackFlag::Disabled (every minted xUSDC is a \
         basic, unpoliced asset — the invoke_* wrappers' presence must NOT flip this)"
    );
    Ok(())
}
