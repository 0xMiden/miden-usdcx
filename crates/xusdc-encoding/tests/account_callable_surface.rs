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
//! `AuthNetworkAccount` admits ONLY the immutable 12-root note-script allowlist and a tx-script
//! allowlist of EXACTLY the one canonical `ExpirationTransactionScript` (S12, RATIFIED 2026-07-20 —
//! F5). `freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note`
//! scans the MAST of all 12 allowlisted note scripts and shows not one of them references the
//! freeze/unfreeze roots; `freeze_and_unfreeze_are_not_admissible_via_either_allowlist` shows the
//! roots are not among the 12 note-script roots; and `the_auth_component_rejects_a_non_allowlisted_note`
//! / `the_auth_component_rejects_non_expiration_tx_scripts_and_admits_expiration` EXECUTE the two
//! (and only two) entry vectors and watch the auth component reject every non-admitted script (the
//! sole admitted tx-script — the expiration bounder — cannot reach freeze). (The allowlist is an epilogue
//! `@auth_script`, checked AFTER note/tx-script execution, so a note that itself calls `freeze`
//! would trap on freeze's own owner-gate before the allowlist check — the allowlist's decision on
//! such a note is the root-membership one, which is why the freeze-specific proof is membership,
//! not a self-trapping execution.) So `freeze` can never be invoked, `is_frozen` is never set, and
//! `ERR_AUTHORITY_FROZEN` never fires: the mechanism is inert — the same disposition as the
//! ratified `renounce_role`.
//!
//! S21 DISPOSITION (flip, human-ratified 2026-07-14) — `rbac::set_role_admin` gets the SAME
//! treatment: the runtime `set_role_admin` admin note was REMOVED from the allowlist (13 → 12
//! roots), so the account procedure stays a callable root of the composed account (stock RBAC,
//! row 62-of-62 unchanged) but is OPERATIONALLY UNREACHABLE — no allowlisted note references its
//! root and the tx-script allowlist admits only the canonical expiration bounder (which cannot reach
//! it). The role-admin graph the faucet deploys with is the
//! BUILD-TIME seed (`role_config[DOM_PAUSER].admin_role = DOM_MANAGER`, byte-identical to an
//! owner-sent `set_role_admin(DOM_PAUSER, DOM_MANAGER)`), and role rotation is
//! `grant_role`/`revoke_role` (CIR-ADMIN-3) — Circle's EVM reference (`DomainManageable.sol`) has
//! no function to change who administers a role, so freezing the graph is MORE Circle-faithful.
//! Removal makes owner self-lockout (re-pointing `DOM_MANAGER.admin_role` off `ADMIN`) and the v16
//! #3215 Manager re-delegation of DOM_PAUSER structurally unreachable.
//! `rbac_set_role_admin_is_present_on_the_account`,
//! `set_role_admin_is_unreachable_from_every_allowlisted_note`, and
//! `set_role_admin_former_note_root_is_not_admissible_via_either_allowlist` are the proofs; the
//! executing rejection legs live in `f5_admin_notes.rs` (the preserved former note is consumed and
//! rejected by the auth component).

mod support;

use core::num::NonZeroU16;
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
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::note::xreserve_admin::{
    XReserveAcceptOwnershipNote, XReserveDomainInitNote, XReserveGrantRoleNote, XReservePauseNote,
    XReserveRevokeRoleNote, XReserveSetAttesterNote, XReserveSetMaxSupplyNote,
    XReserveSetMinBurnSizeNote, XReserveTransferOwnershipNote, XReserveUnpauseNote,
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
/// - `rbac::set_role_admin` is stock RBAC and STAYS a callable root, but is PRESENT-and-UNREACHABLE
///   since the S21 disposition flip (2026-07-14): its runtime note was removed from the allowlist,
///   so the role-admin graph is frozen at the build seed (the tests below prove unreachability);
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

/// The 12 allowlisted note SCRIPTS (not just their roots): the two supply notes + the 10 admin
/// notes. Single-sourced from the same factories the allowlist itself is built from, so a note that
/// enters the allowlist necessarily enters this sweep too. There is deliberately NO `set_role_admin`
/// entry: the runtime `set_role_admin` note was REMOVED from the allowlist (S21 disposition flip,
/// human-ratified 2026-07-14) — the role-admin graph is BUILD-SEEDED and frozen; rotation is
/// `grant_role`/`revoke_role` (CIR-ADMIN-3).
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

/// UNREACHABLE, leg 1 (static, exhaustive over the allowlist): NOT ONE of the 12 allowlisted note
/// scripts references the freeze or unfreeze root ANYWHERE in its MAST — so no admissible note can
/// invoke them. Scanning every MAST node digest (not just the entrypoint) catches a call by root, a
/// call by path, and any nested/external reference alike.
#[test]
fn freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    assert_eq!(
        scripts.len(),
        12,
        "the unreachability sweep must cover all 12 allowlisted note scripts"
    );
    // The scripts swept ARE the allowlist (no script can dodge the sweep by not being listed here).
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 12-root note-script allowlist"
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
/// the 12 allowlisted roots, and admits a tx script only if its root is in the tx-script allowlist —
/// which admits EXACTLY the one canonical `ExpirationTransactionScript` (S12), never freeze/unfreeze.
/// There is no freeze/unfreeze NOTE FACTORY at all (the 12 are the two supply notes + the 10 admin
/// notes; none carries freeze), so no freeze-bearing note root can be among the 12, and the one-root
/// tx-script allowlist admits only the expiration bounder (not freeze). Combined with the MAST sweep
/// above (no allowlisted note even references the roots) both entry vectors are provably closed.
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
            "the `{name}` root must NOT be a member of the 12-root note-script allowlist \
             (there is no freeze note factory; a freeze-bearing note is inadmissible)"
        );
    }
    // The tx-script entry vector is closed to freeze by the one-root tx-script allowlist (it admits
    // ONLY the canonical expiration bounder, not freeze) — pinned + executed by
    // `the_auth_component_rejects_non_expiration_tx_scripts_and_admits_expiration` below (and the
    // canonical `f5_network_account_auth::production_faucet_tx_script_allowlist_is_exactly_the_expiration_root`).
    // Together with the note-root non-membership above, no freeze/unfreeze call is admissible via
    // either entry vector.
    Ok(())
}

/// UNREACHABLE, executing (entry vector 1 — INPUT NOTES): the auth component rejects any input note
/// whose script root is not one of the 12 (a clean, non-self-trapping probe note so the AUTH gate is
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
/// script EXCEPT the one canonical `ExpirationTransactionScript` (S12, RATIFIED 2026-07-20) against
/// the one-root tx-script allowlist (a clean, non-self-trapping probe script, same reasoning as the
/// note vector). With both entry vectors closed — every note must be one of the 12 (none touches
/// freeze) and every tx script must be the single allowlisted expiration bounder (which cannot touch
/// nonce/state/assets) — `freeze` is operationally unreachable on this faucet, `is_frozen` is never
/// set, and `ERR_AUTHORITY_FROZEN` never fires: the mechanism is INERT (S12, the ratified
/// `renounce_role` disposition).
#[tokio::test]
async fn the_auth_component_rejects_non_expiration_tx_scripts_and_admits_expiration() -> Result<()>
{
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production network-auth faucet")?;

    // NEGATIVE — a non-expiration (nop) tx script is rejected by the one-root allowlist.
    let bogus = CodeBuilder::new()
        .compile_tx_script("@transaction_script\npub proc main\n    nop\nend\n")
        .context("compiling the probe tx script")?;
    let rejected = pf
        .mock_chain
        .build_tx_context(pf.faucet_id, &[], &[])
        .context("tx-script tx context")?
        .tx_script(bogus)
        .build()
        .context("tx-script tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(rejected, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    // POSITIVE — the canonical expiration script CLEARS the allowlist gate. An expiration-only tx
    // changes no account state and consumes no notes, so the kernel then rejects it with the empty-tx
    // epilogue assertion — downstream of, and orthogonal to, the allowlist gate. The precise S12
    // invariant: the expiration script is NOT rejected by the tx-script allowlist (a mutation
    // dropping the expiration root flips this back to the allowlist error — RED — caught here).
    let expiration = ExpirationTransactionScript::new(NonZeroU16::new(64).expect("64 is non-zero"));
    let admitted = pf
        .mock_chain
        .build_tx_context(pf.faucet_id, &[], &[])
        .context("expiration tx-script tx context")?
        .tx_script(expiration.into())
        .tx_script_args(expiration.tx_script_args())
        .build()
        .context("expiration tx-script tx build")?
        .execute()
        .await;
    match admitted {
        Ok(_) => {}
        Err(TransactionExecutorError::TransactionProgramExecutionFailed(actual)) => assert!(
            !ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED.matches_execution_error(&actual),
            "the canonical ExpirationTransactionScript must be ADMITTED by the S12 allowlist, but \
             it was rejected by the tx-script allowlist: {actual}",
        ),
        Err(other) => {
            panic!("the expiration tx failed with an unexpected non-execution error: {other}")
        }
    }
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

// S21 — SET_ROLE_ADMIN: PRESENT, AND PROVABLY UNREACHABLE (the frozen role-admin graph)
// ================================================================================================

/// The fully-qualified path of the stock RBAC `set_role_admin` account procedure (a member of the
/// frozen 62-root surface above — the proc STAYS; only its runtime note was removed).
const RBAC_SET_ROLE_ADMIN_PROC_PATH: &str =
    "::miden::standards::components::access::rbac::set_role_admin";

/// The pinned root of the REMOVED runtime `set_role_admin` note script (formerly
/// `XRESERVE_SET_ROLE_ADMIN_NOTE_SCRIPT_ROOT_HEX`, allowlist row 10 of the old 13-root set).
/// Preserved so its non-membership stays machine-checked: re-adding the note to the allowlist
/// turns `set_role_admin_former_note_root_is_not_admissible_via_either_allowlist` RED.
const FORMER_SET_ROLE_ADMIN_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x0c69fe1a19ee27196780be8d7815920e6a5da49e05ee10b9a615c4ee7a778648";

/// Resolves the `rbac::set_role_admin` account-procedure root from the shipped composition (by
/// path, so a stock re-key cannot silently blunt the MAST sweep below).
fn rbac_set_role_admin_proc_root() -> Result<Word> {
    let components = production_components()?;
    component_surface(&components)
        .into_iter()
        .find(|(path, _)| path == RBAC_SET_ROLE_ADMIN_PROC_PATH)
        .map(|(_, root)| root)
        .context(
            "the composed account must expose rbac::set_role_admin (present-but-unreachable, S21)",
        )
}

/// PRESENT: the stock RBAC `set_role_admin` procedure IS a callable root of the composed account —
/// the S21 disposition keeps the stock component intact (the 62-root surface is unchanged); ONLY
/// the runtime note that could reach it was removed.
#[test]
fn rbac_set_role_admin_is_present_on_the_account() -> Result<()> {
    let root = rbac_set_role_admin_proc_root()?;
    let account = production_account()?;
    let roots: BTreeSet<Word> = account
        .code()
        .procedures()
        .iter()
        .map(|r| Word::from(*r))
        .collect();
    assert!(
        roots.contains(&root),
        "the stock RBAC component contributes `set_role_admin` to the account's callable surface \
         (S21: present-but-unreachable) — if this ever stops being true, the S21 disposition must \
         be re-ratified"
    );
    Ok(())
}

/// UNREACHABLE, leg 1 (static, exhaustive over the allowlist): NOT ONE of the 12 allowlisted note
/// scripts references the `rbac::set_role_admin` root ANYWHERE in its MAST — so no admissible note
/// can re-point (or clear) any role's admin delegation. The swept set is asserted equal to the
/// allowlist first, so a re-added 13th note cannot dodge the sweep: the set-equality itself goes
/// RED (this is the machine-enforced conformance-manifest row for the S21 removal).
#[test]
fn set_role_admin_is_unreachable_from_every_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 12-root note-script allowlist — an extra root \
         (e.g. a re-added set_role_admin note) breaks the ratified S21 removal \
         (DECISION-SETROLEADMIN-NOTE-REMOVAL: the role-admin graph is build-frozen)"
    );

    let forbidden = rbac_set_role_admin_proc_root()?;
    for (label, script) in &scripts {
        let forest = script.mast();
        for node in forest.nodes() {
            assert_ne!(
                node.digest(),
                forbidden,
                "allowlisted note script `{label}` references the rbac::set_role_admin root — the \
                 S21 unreachability guarantee is BROKEN (the role-admin graph would be \
                 runtime-mutable again: owner self-lockout and Manager re-delegation become \
                 reachable)"
            );
        }
    }
    Ok(())
}

/// UNREACHABLE, cross-reference (set_role_admin-specific): neither entry vector admits the removed
/// capability. The FORMER pinned `set_role_admin` note root is NOT a member of the 12-root
/// note-script allowlist (re-adding it turns this test RED), and the tx-script allowlist admits ONLY
/// the canonical expiration bounder — never `set_role_admin` (pinned + executed by
/// `the_auth_component_rejects_non_expiration_tx_scripts_and_admits_expiration`).
/// The executing leg — the preserved former note is consumed and REJECTED by the auth component —
/// lives in `f5_admin_notes.rs::set_role_admin_note_is_rejected_as_non_allowlisted`.
#[test]
fn set_role_admin_former_note_root_is_not_admissible_via_either_allowlist() -> Result<()> {
    let former = NoteScriptRoot::from_raw(
        Word::parse(FORMER_SET_ROLE_ADMIN_NOTE_SCRIPT_ROOT_HEX)
            .expect("the former set_role_admin note-script root hex is a valid word"),
    );
    assert!(
        !XReserveStablecoinBuilder::allowed_note_scripts().contains(&former),
        "the former set_role_admin note root must NOT be a member of the 12-root note-script \
         allowlist — the runtime set_role_admin note was REMOVED (S21 flip, human-ratified \
         2026-07-14; rotation is grant_role/revoke_role, the delegation graph is build-seeded); \
         re-adding it violates the ratified DECISION-SETROLEADMIN-NOTE-REMOVAL disposition"
    );
    Ok(())
}

// S13/S24 — GET_AUTHORITY IS READ-ONLY (executed bounding, not documentation)
// ================================================================================================

/// The v0.16 `authority::get_authority` view accessor is READ-ONLY in execution, not just by
/// documentation (S13/S24 bounding): a note that `call`s it by root on the production-composed
/// account executes successfully and leaves storage AND vault byte-identical (only the fixture's
/// nonce-increment auth runs). Uses the permissive-auth production composition (the same
/// `GuardSelection::ProductionDeny` fixture the role-gating suites use) because on the
/// network-auth faucet the epilogue allowlist would reject the probe note before its effects could
/// be observed.
#[tokio::test]
async fn get_authority_is_read_only_on_the_account() -> Result<()> {
    let components = production_components()?;
    let get_authority_root = component_surface(&components)
        .into_iter()
        .find(|(path, _)| {
            path == "::miden::standards::components::access::authority::get_authority"
        })
        .map(|(_, root)| root)
        .context("the composed account must expose authority::get_authority (S24)")?;

    let driver = mint_composition_driver_src(&[Felt::from(0u32)], 60, 6);
    let probe = composition_supply_probe_src(0);
    let gm = setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        MAX_SUPPLY,
        0,
        Word::from([7u32, 0, 0, 0]),
        Word::from([11u32, 12, 13, 14]),
        None,
        None,
        &driver,
        &probe,
        true,
    )?;
    let account = faucet_account(&gm.harness);
    let storage_before = account.storage().to_commitment();
    let vault_before = account.vault().root();

    // A probe note that calls get_authority by ROOT (resolved above from the shipped composition)
    // and drops the returned discriminator: [pad(16)] in, [authority, pad(15)] out.
    let src = format!(
        "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20dropw\n\
         \x20\x20\x20\x20call.{}\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
        get_authority_root.to_hex(),
    );
    let script = CodeBuilder::new()
        .compile_note_script(src)
        .context("compiling the get_authority probe note script")?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(13u32),
        Felt::from(24u32),
        Felt::from(13u32),
        Felt::from(24u32),
    ]));
    let note = NoteBuilder::new(test_account_id(9), &mut rng)
        .script(script)
        .build()
        .context("building the get_authority probe note")?;

    let tx = gm
        .harness
        .mock_chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .context("get_authority probe tx context")?
        .build()
        .context("get_authority probe tx build")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("the get_authority probe note must execute cleanly: {e}"))?;

    let mut evolved = account.clone();
    evolved.apply_patch(tx.account_patch())?;
    assert_eq!(
        evolved.storage().to_commitment(),
        storage_before,
        "get_authority must not mutate ANY account storage (S13/S24: read-only, executed proof)"
    );
    assert_eq!(
        evolved.vault().root(),
        vault_before,
        "get_authority must not mutate the vault / issued supply (S13/S24: read-only, executed \
         proof)"
    );
    Ok(())
}
