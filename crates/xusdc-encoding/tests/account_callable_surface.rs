//! FULL-ACCOUNT CALLABLE-SURFACE PIN (S12, human-ratified 2026-07-13).
//!
//! `mint_root_surface.rs` freezes the 2 callable roots of the **xreserve** component. This file
//! freezes the **whole composed account** — the xreserve 2 PLUS every callable procedure the STOCK
//! components contribute (`Authority` incl. the v0.16 `freeze`/`unfreeze`, `RoleBasedAccessControl`,
//! `FungibleFaucet` incl. the v0.16 `has_procedure` re-export, `TokenPolicyManager`,
//! `MinBurnAmount` (the Wave-1 S1 stock burn policy), `Pausable`, and the `AuthNetworkAccount`
//! auth procedure). It exists because a stock dependency
//! bump can hand this faucet a NEW callable capability silently: at the v0.16 migration
//! the stock `Authority` component began bundling authority-gated `freeze`/`unfreeze` procedures
//! (upstream #3102/#3209) that no v0.15 composition had. That must never be inherited quietly again
//! — so the composed account's callable set is pinned to a FROZEN literal list here, and any stock
//! bump that adds (or drops) a callable procedure fails LOUDLY in
//! `production_account_callable_surface_is_frozen`. (Building this pin caught THREE v0.16 stock
//! additions beyond freeze/unfreeze that no v0.15 composition had — `authority::get_authority` and
//! the #3047 `policy_manager::invoke_send_policy`/`invoke_receive_policy` transfer-policy dispatch
//! wrappers. They are human-ratified in their OWN map row S24 (NOT under S12). SINCE THE F4 REVERSAL
//! (2026-07-23) the wrappers are LIVE, not inert: the stock `BasicBlocklist` is wired as the active
//! send + receive policy, so `AssetCallbackFlag::Enabled` and the kernel `dyncall`s the wrappers on
//! every policed-asset transfer, which run the account-wide pause check + `basic_blocklist::check_policy`.
//! `invoke_wrappers_are_live_and_the_asset_is_policed` re-confirms the reversal at v16.)
//!
//! S12 DISPOSITION — `freeze`/`unfreeze` are PRESENT but OPERATIONALLY UNREACHABLE, and this file
//! proves it rather than asserting it: the faucet is a keyless network account whose
//! `AuthNetworkAccount` admits ONLY the immutable 8-root note-script allowlist and a tx-script
//! allowlist of EXACTLY the one canonical `ExpirationTransactionScript` (S12, RATIFIED 2026-07-20 —
//! F5). `freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note`
//! scans the MAST of all 8 allowlisted note scripts and shows not one of them references the
//! freeze/unfreeze roots; `freeze_and_unfreeze_are_not_admissible_via_either_allowlist` shows the
//! roots are not among the 8 note-script roots; and `the_auth_component_rejects_a_non_allowlisted_note`
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
//! ROLE MANAGEMENT — REACHABLE, and deliberately so. The standard role-action note is allowlisted,
//! and its single script root carries `grant_role`, `revoke_role`, `set_role_admin` and
//! `renounce_role` alike, so all four are reachable on this account. That is a human-ratified
//! capability decision, not an oversight: the role-admin graph the build seeds
//! (`role_config[DOM_PAUSER].admin_role = DOM_MANAGER`) is runtime-mutable, each role's effective
//! admin governs the role it administers exclusively, and a holder may drop its own membership.
//! `w2admin_surface_finalization.rs` drives all four actions against the real faucet.

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
use miden_standards::account::policies::TokenPolicyManager;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::note::{
    BlocklistConfigNote, BurnNote, MintNote, PauseActionNote, RbacActionNote,
};
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::note::xreserve_admin::{
    XReserveSetAttesterNote, XReserveSetMaxSupplyNote, XReserveSetMinBurnSizeNote,
};

const MAX_SUPPLY: u64 = 1_000_000;

/// The FROZEN callable surface of the composed production faucet ACCOUNT: every procedure a
/// transaction may `call` on it, by fully-qualified path. This is a LITERAL list on purpose — it is
/// NOT derived from the components, so a stock bump that adds a callable procedure grows the
/// account's real surface without growing this list, and the set-equality below goes RED.
///
/// Membership is ratified, not incidental (paths are the component-wrapper form the exports carry):
/// - the 2 `::xreserve::…` roots are the genuine xreserve entry points (`mint_root_surface.rs`
///   pins them separately) — the one `set_attester` admin wrapper and the attestation
///   `mint_policy::check_policy` (the ACTIVE mint policy); the shared-encoding codecs, the
///   deposit-intent parser and the attestation verifier are `exec`-only helpers off the account
///   interface, and pause and blocklist administration are STOCK now (the manager rows below);
/// - the 59 stock rows are what the composition's components export at the frozen
///   protocol-`next` rev, including
///   the F4-reversal `basic_blocklist::check_policy` transfer-policy predicate (S24-policed) and
///   the three Wave-1 S1 `burn::min_burn_amount` rows (`check_policy` / `set_min_burn_amount` /
///   `get_min_burn_amount`) of the stock `MinBurnAmount` component wired as the ACTIVE burn policy
///   (replacing the deleted custom `burn_policy` / `min_burn_admin` modules);
/// - `authority::freeze` / `authority::unfreeze` are the v0.16 additions (#3102) — PRESENT but
///   UNREACHABLE (S12; the tests below), never silently inherited; `authority::get_authority` is the
///   v0.16 view accessor;
/// - `rbac::set_role_admin` is stock RBAC and is REACHABLE through the allowlisted standard
///   role-action note, whose one script root carries it alongside grant, revoke and renounce — the
///   ratified capability decision recorded in the header;
/// - `policy_manager::invoke_send_policy` / `invoke_receive_policy` are the #3047 transfer-policy
///   dispatch wrappers — callable and LIVE since the F4 reversal (the `BasicBlocklist` is the active
///   send + receive policy → both callback slots installed → the kernel dispatches them on every
///   policed-asset transfer, running the pause check + `basic_blocklist::check_policy` — S24,
///   human-ratified);
/// - `fungible_faucet::has_procedure` is the v0.16 `FungibleFaucet` re-export (#3222) the stock BURN
///   note's faucet-kind reflection requires.
const FROZEN_ACCOUNT_SURFACE: [&str; 61] = [
    // --- the 2 xreserve component roots (their IDENTITIES are also pinned in
    //     mint_root_surface.rs::FROZEN_CALLABLE_ROOTS; here they complete the whole account) ---
    "::xreserve::attester_admin::set_attester",
    "::xreserve::mint_policy::check_policy",
    // --- the 59 stock-component roots ---
    // The pause and blocklist admin procedures are STOCK now: the four custom xreserve wrappers
    // above gave way to the stock managers, each of whose procedures the account's procedure-role
    // map gates on the same role the wrapper hard-coded (pause / unpause on the Domain pauser,
    // block / unblock on the external blocklist administrator). Four custom xreserve wrappers out,
    // four stock manager procs in; separately, the mint-path de-export drops
    // `encoding::pubkey_commitment` from the callable surface (it is `exec`-only now), the
    // deposit-intent parser's three assertion procs and the shared `encoding::parse_deposit_intent`
    // collapsed into the `exec`-only `deposit_intent_parser::{parse,validate}` pair, the
    // two-step ownership component is gone, which is where the five missing access rows went, and
    // the three remaining `exec`-only xreserve helpers (`encoding::bytes32_to_key`,
    // `encoding::verify_uint256_to_asset_amount` and `attestation_verify::verify_attestation`) no
    // longer carry `@account_procedure`, and `identifier_init::init_identifier` left with the
    // stored identifier the mint path no longer reads — so
    // the whole account surface is 61 (2 xreserve + 59 stock).
    "::miden::standards::components::access::pausable::manager::pause",
    "::miden::standards::components::access::pausable::manager::unpause",
    "::miden::standards::components::faucets::policies::transfer::blocklist::manager::block_account",
    "::miden::standards::components::faucets::policies::transfer::blocklist::manager::unblock_account",
    "::miden::standards::components::access::authority::freeze",
    "::miden::standards::components::access::authority::get_authority",
    "::miden::standards::components::access::authority::unfreeze",
    "::miden::standards::components::access::pausable::is_paused",
    "::miden::standards::components::access::rbac::get_role_admin",
    "::miden::standards::components::access::rbac::get_role_member_count",
    "::miden::standards::components::access::rbac::grant_role",
    "::miden::standards::components::access::rbac::has_role",
    "::miden::standards::components::access::rbac::renounce_role",
    "::miden::standards::components::access::rbac::revoke_role",
    "::miden::standards::components::access::rbac::set_role_admin",
    // V16-NOW temporary growth (ratified, TWO reachability tiers, reverted at V16-FINAL): the
    // protocol-`next` stock AuthNetworkAccount unconditionally exports the four allowlist
    // mutators (Tier A — truly unreachable, the S12 disposition) and six fee procedures
    // (Tier B — no external entry point; the fee-estimation path runs INTERNALLY on every input
    // note via the auth procedure, computing the scheduled zero fee — internally active but
    // inert) alongside the auth procedure. The note/tx-script allowlists stay
    // membership-identical and exact; `account_surface_unreachable.rs` proves each tier's
    // posture.
    "::miden::standards::components::auth::network_account::add_allowed_fee_policy",
    "::miden::standards::components::auth::network_account::add_allowed_note_script",
    "::miden::standards::components::auth::network_account::add_allowed_tx_script",
    "::miden::standards::components::auth::network_account::auth_network_transaction",
    "::miden::standards::components::auth::network_account::estimate_note_fee",
    "::miden::standards::components::auth::network_account::get_fee_asset_id",
    "::miden::standards::components::auth::network_account::get_fee_policy",
    "::miden::standards::components::auth::network_account::remove_allowed_fee_policy",
    "::miden::standards::components::auth::network_account::remove_allowed_note_script",
    "::miden::standards::components::auth::network_account::remove_allowed_tx_script",
    "::miden::standards::components::auth::network_account::set_fee_policy",
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
    // Wave-1 S1: the stock MinBurnAmount burn-policy component (the ACTIVE burn policy since the
    // recomposition — its check_policy is dispatched by the policy manager on every burn, its
    // set_min_burn_amount is the ADMIN-role-gated floor setter the reworked admin note calls).
    "::miden::standards::components::faucets::policies::burn::min_burn_amount::check_policy",
    "::miden::standards::components::faucets::policies::burn::min_burn_amount::get_min_burn_amount",
    "::miden::standards::components::faucets::policies::burn::min_burn_amount::set_min_burn_amount",
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
    // F4-reversal: the stock BasicBlocklist transfer-policy predicate (active send + receive
    // policy). Callable, and now LIVE (S24-policed) — the kernel dispatches it via the
    // invoke_send_policy/invoke_receive_policy wrappers on every policed-asset transfer.
    "::miden::standards::components::faucets::policies::transfer::basic_blocklist::check_policy",
    // V16-NOW temporary growth (ratified, Tier B like the fee rows above): the mandatory
    // provisional fee policy's dispatch target. No external entry point; the auth procedure
    // dyncalls it internally on every input note, where it computes the scheduled zero fee.
    "::miden::standards::components::fees::policies::basic_constant_fee::compute_note_fee",
];

/// The production composition, component by component: the SHIPPED component set
/// (`support::production_component_set` → `XReserveStablecoinBuilder::build_components()`) PLUS the
/// `AuthNetworkAccount` auth component the MockChain fixture installs — both single-sourced from
/// `XReserveStablecoinBuilder`, so this cannot drift from what ships.
fn production_components() -> Result<Vec<AccountComponent>> {
    let mut components =
        production_component_set(MAX_SUPPLY, 0).context("the production composition must build")?;
    components.extend(
        XReserveStablecoinBuilder::auth_component()
            .context("the production auth component must build")?,
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
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("the production faucet must be committed")?
        .clone();
    Ok(account)
}

/// The 8 allowlisted note SCRIPTS (not just their roots): the two STOCK supply notes (the Wave-1
/// S1 `MintNote` transport + the `BurnNote`) and six admin/config notes — the three
/// `ADMIN`-role-gated setters (`set_attester`, `set_min_burn_size`, `set_max_supply`) plus the
/// three stock admin notes:
/// `PauseActionNote` (pause+unpause), `BlocklistConfigNote` (block+unblock) and `RbacActionNote`
/// (grant+revoke+set_role_admin+renounce). Single-sourced from the
/// same factories the allowlist itself is built from, so a note that enters the allowlist necessarily
/// enters this sweep too. There are no ownership notes: the faucet installs no ownership component,
/// and rotating the administrator is a grant and a revoke of the `ADMIN` role.
fn allowlisted_note_scripts() -> Vec<(&'static str, NoteScript)> {
    vec![
        ("stock_mint_note", MintNote::script()),
        ("stock_burn_note", BurnNote::script()),
        ("set_attester", XReserveSetAttesterNote::script()),
        ("set_min_burn_size", XReserveSetMinBurnSizeNote::script()),
        ("stock_pause_action_note", PauseActionNote::script()),
        ("set_max_supply", XReserveSetMaxSupplyNote::script()),
        ("stock_blocklist_config_note", BlocklistConfigNote::script()),
        ("stock_rbac_action_note", RbacActionNote::script()),
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

    // Layer 1 (source): the component-exported paths equal the frozen 61-root list EXACTLY (2
    // xreserve + 59 stock, in one literal set — a stock bump that adds or removes any callable
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
        "the composed account's callable surface drifted from the frozen 61-root set — a stock \
         bump added or removed a callable procedure (or the xreserve surface changed). This is NOT \
         a mechanical conformance change: every such delta must be SURFACED for ratification \
         exactly as the \
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
        "the account's callable procedure COUNT must equal the frozen 61-root surface"
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

/// UNREACHABLE, leg 1 (static, exhaustive over the allowlist): NOT ONE of the 8 allowlisted note
/// scripts references the freeze or unfreeze root ANYWHERE in its MAST — so no admissible note can
/// invoke them. Scanning every MAST node digest (not just the entrypoint) catches a call by root, a
/// call by path, and any nested/external reference alike.
#[test]
fn freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    assert_eq!(
        scripts.len(),
        8,
        "the unreachability sweep must cover all 8 allowlisted note scripts"
    );
    // The scripts swept ARE the allowlist (no script can dodge the sweep by not being listed here).
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 8-root note-script allowlist"
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
/// the 8 allowlisted roots, and admits a tx script only if its root is in the tx-script allowlist —
/// which admits EXACTLY the one canonical `ExpirationTransactionScript` (S12), never freeze/unfreeze.
/// There is no freeze/unfreeze NOTE FACTORY at all (the 8 are the two supply notes + the six admin
/// notes; none carries freeze), so no freeze-bearing note root can be among the 8, and the one-root
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
            "the `{name}` root must NOT be a member of the 8-root note-script allowlist \
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
/// whose script root is not one of the 8 (a clean, non-self-trapping probe note so the AUTH gate is
/// unambiguously the rejector — the note-script allowlist is an epilogue `@auth_script`, checked
/// after note execution, so a note that itself calls `freeze` would trap on freeze's own gate before
/// this check; the allowlist's decision on such a note is the ROOT-membership one asserted above).
#[tokio::test]
async fn the_auth_component_rejects_a_non_allowlisted_note() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_, _faucet_id| Vec::new())
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
        .build_transaction(pf.faucet_id)
        .unauthenticated_input_note(note.clone())
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
/// note vector). With both entry vectors closed — every note must be one of the 8 (none touches
/// freeze) and every tx script must be the single allowlisted expiration bounder (which cannot touch
/// nonce/state/assets) — `freeze` is operationally unreachable on this faucet, `is_frozen` is never
/// set, and `ERR_AUTHORITY_FROZEN` never fires: the mechanism is INERT (S12).
#[tokio::test]
async fn the_auth_component_rejects_non_expiration_tx_scripts_and_admits_expiration() -> Result<()>
{
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;

    // NEGATIVE — a non-expiration (nop) tx script is rejected by the one-root allowlist.
    let bogus = CodeBuilder::new()
        .compile_tx_script("@transaction_script\npub proc main\n    nop\nend\n")
        .context("compiling the probe tx script")?;
    let rejected = pf
        .mock_chain
        .build_transaction(pf.faucet_id)
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
        .build_transaction(pf.faucet_id)
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

// S24 (F4-REVERSAL) — the invoke_* wrappers are LIVE: the transfer blocklist is policed and the
// callback flag is Enabled
// ================================================================================================

/// F4-REVERSAL policed counterpart of the former `invoke_wrappers_are_inert_and_the_asset_stays_basic`
/// (which asserted the OPPOSITE — no callback slots, `AssetCallbackFlag::Disabled` — under the
/// basic-asset F4). The transfer blocklist is now wired as the active send + receive policy, so the
/// #3047 `invoke_send_policy`/`invoke_receive_policy` wrappers are LIVE. Asserts, directly on the
/// shipped composition + account: (1) BOTH protocol asset-callback slots ARE installed and hold the
/// fixed `invoke_*_policy` wrapper roots (the kernel dispatches them on every policed-asset
/// transfer), and (2) the committed faucet account id carries `AssetCallbackFlag::Enabled` (every
/// minted xUSDC is a POLICED asset — the silent-foot-gun tripwire: a fixture built Disabled with the
/// policy wired would make the callbacks never fire, and this assertion catches it — mutation check
/// (b)). Complements the policed `basic_asset_tripwire` (F4-reversal).
#[test]
fn invoke_wrappers_are_live_and_the_asset_is_policed() -> Result<()> {
    let components =
        production_component_set(MAX_SUPPLY, 0).context("the production composition must build")?;

    // (1) the transfer blocklist is wired → BOTH asset-callback slots are installed, holding the
    // fixed invoke_*_policy wrapper roots.
    let expected_callbacks = [
        (
            AssetCallbacks::on_before_asset_added_to_note_slot(),
            TokenPolicyManager::invoke_send_policy_root().as_word(),
        ),
        (
            AssetCallbacks::on_before_asset_added_to_account_slot(),
            TokenPolicyManager::invoke_receive_policy_root().as_word(),
        ),
    ];
    for (slot, wrapper_root) in expected_callbacks {
        let installed = components
            .iter()
            .flat_map(|c| c.storage_slots().iter())
            .find(|s| s.name() == slot)
            .unwrap_or_else(|| {
                panic!(
                    "the asset-callback slot ({slot}) must be installed — the transfer blocklist is \
                     wired as the active send/receive policy (F4-reversal), so the invoke_* wrappers \
                     are LIVE"
                )
            });
        assert_eq!(
            installed.value(),
            wrapper_root,
            "the asset-callback slot ({slot}) must hold the fixed invoke_*_policy wrapper root"
        );
    }

    // (2) the committed faucet account id carries the Enabled callback flag (policed asset). A
    // Disabled flag with the policy wired would silently never fire the callbacks — the audited
    // foot-gun. This assertion makes that impossible to miss (mutation check (b)).
    let account = production_account()?;
    assert_eq!(
        account.id().asset_callback_flag(),
        AssetCallbackFlag::Enabled,
        "the faucet account id must carry AssetCallbackFlag::Enabled (every minted xUSDC is a \
         POLICED asset — the transfer blocklist callbacks only fire when the id flag is Enabled)"
    );
    Ok(())
}
