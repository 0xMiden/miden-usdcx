//! The PRESENT-BUT-UNREACHABLE and READ-ONLY halves of the FULL-ACCOUNT CALLABLE-SURFACE pin,
//! split out of `account_callable_surface.rs` to respect the file-size
//! ceiling. `account_callable_surface.rs` holds the frozen-surface equality pin + the
//! freeze/unfreeze disposition + the asset-callback (transfer-blocklist-live) proof; THIS file
//! holds:
//!   * `rbac::set_role_admin` is a callable root but OPERATIONALLY UNREACHABLE (its runtime
//!     note was removed from the allowlist; the role-admin graph is
//!     build-seeded and frozen — rotation is grant_role/revoke_role only);
//!   * `authority::get_authority` is READ-ONLY in execution (executed bounding, not
//!     documentation);
//!   * temporary v0.16 growth — the 11 mutator/fee procedures the protocol-`next` stock
//!     components add, in TWO ratified reachability tiers: Tier A (the 4 allowlist mutators)
//!     truly unreachable, the same disposition as freeze/unfreeze and set_role_admin; Tier B
//!     (the 6 fee procedures + the
//!     `compute_note_fee` callback) direct-entry-unreachable — no external entry point — while
//!     the fee-estimation path runs INTERNALLY on every input note, computing the scheduled
//!     zero fee (internally active but inert). TEMPORARY — a later slice reverts this growth
//!     together with the provisional fee configuration.
//!
//! The small conformance helpers (`production_components`/`component_surface`/`production_account`/
//! `allowlisted_note_scripts`) are duplicated here so this module is
//! self-contained; both copies are single-sourced from `XReserveStablecoinBuilder`, so neither can
//! drift from what ships.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountComponent, StorageSlotContent};
use miden_protocol::assembly::mast::MastNodeExt;
use miden_protocol::note::{NoteScript, NoteScriptRoot};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{BlocklistConfigNote, BurnNote, MintNote, PauseActionNote};
use miden_standards::testing::note::NoteBuilder;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::note::xreserve_admin::{
    XReserveAcceptOwnershipNote, XReserveGrantRoleNote, XReserveIdentifierInitNote,
    XReserveRevokeRoleNote, XReserveSetAttesterNote, XReserveSetMaxSupplyNote,
    XReserveSetMinBurnSizeNote, XReserveTransferOwnershipNote,
};

const MAX_SUPPLY: u64 = 1_000_000;

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
/// FILTERED interface (the `@account_procedure` / `@auth_script` exports).
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

/// The 14 allowlisted note SCRIPTS (not just their roots): the two STOCK supply notes (the stock
/// `MintNote` transport + the `BurnNote`) + the 12 admin notes (10 owner/role/pause — with the
/// identifier-only `identifier_init` — + the 2
/// transfer-blocklist notes). Single-sourced from the
/// same factories the allowlist itself is built from, so a note that enters the allowlist necessarily
/// enters this sweep too. There is deliberately NO `set_role_admin` entry: the runtime
/// `set_role_admin` note was REMOVED from the
/// allowlist — the role-admin graph is BUILD-SEEDED and frozen; rotation is
/// `grant_role`/`revoke_role` (the Domain Manager rotates the Pauser, the owner is the backstop).
fn allowlisted_note_scripts() -> Vec<(&'static str, NoteScript)> {
    vec![
        ("stock_mint_note", MintNote::script()),
        ("stock_burn_note", BurnNote::script()),
        ("set_attester", XReserveSetAttesterNote::script()),
        ("identifier_init", XReserveIdentifierInitNote::script()),
        ("set_min_burn_size", XReserveSetMinBurnSizeNote::script()),
        ("stock_pause_action_note", PauseActionNote::script()),
        ("grant_role", XReserveGrantRoleNote::script()),
        ("revoke_role", XReserveRevokeRoleNote::script()),
        ("set_max_supply", XReserveSetMaxSupplyNote::script()),
        (
            "transfer_ownership",
            XReserveTransferOwnershipNote::script(),
        ),
        ("accept_ownership", XReserveAcceptOwnershipNote::script()),
        ("stock_blocklist_config_note", BlocklistConfigNote::script()),
    ]
}

// SET_ROLE_ADMIN: PRESENT, AND PROVABLY UNREACHABLE (the frozen role-admin graph)
// ================================================================================================

/// The fully-qualified path of the stock RBAC `set_role_admin` account procedure (a member of the
/// frozen 75-root surface — the proc STAYS; only its runtime note was removed).
const RBAC_SET_ROLE_ADMIN_PROC_PATH: &str =
    "::miden::standards::components::access::rbac::set_role_admin";

/// The pinned root of the REMOVED runtime `set_role_admin` note script.
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
/// the ratified disposition keeps the stock component intact (the frozen surface membership is
/// otherwise unchanged); ONLY
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

/// UNREACHABLE, leg 1 (static, exhaustive over the allowlist): NOT ONE of the 14 allowlisted note
/// scripts references the `rbac::set_role_admin` root ANYWHERE in its MAST — so no admissible note
/// can re-point (or clear) any role's admin delegation. The swept set is asserted equal to the
/// allowlist first, so a re-added note cannot dodge the sweep: the set-equality itself goes
/// RED (this is the machine-enforced check that the note's removal holds).
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

// GET_AUTHORITY IS READ-ONLY (executed bounding, not documentation)
// ================================================================================================

/// The v0.16 `authority::get_authority` view accessor is READ-ONLY in execution, not just by
/// documentation: a note that `call`s it by root on the production-composed
/// account executes successfully and leaves storage AND vault byte-identical (only the fixture's
/// nonce-increment auth runs). Uses the permissive-auth production composition (the same
/// `GuardSelection::ProductionAttestation` fixture the role-gating suites use) because on the
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

    // a no-op driver: the guarded-mint harness requires at least one driver component, but the
    // probe below calls `get_authority` by root through its own note, never this driver.
    let driver = "#! A no-op driver — the get_authority probe fires a standalone note, not this\n\
                  #! driver; the guarded-mint harness merely requires one driver component.\n\
                  #!\n\
                  #! Inputs:  [pad(16)]\n\
                  #! Outputs: [pad(16)]\n\
                  #!\n\
                  #! Invocation: call\n\
                  @account_procedure\n\
                  pub proc drive\n\
                  \x20\x20\x20\x20push.0 drop\n\
                  end\n"
        .to_string();
    let probe = composition_supply_probe_src(0);
    let gm = setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
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
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
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

// TEMPORARY V16 GROWTH — THE RATIFIED FEE/MUTATOR ROWS: TWO REACHABILITY TIERS
// ================================================================================================
//
// The 11 forced additions fall in two reachability tiers (ratified wording, verified
// against the protocol source at the pin):
//
// Tier A — truly unreachable: the 4 stock admin allowlist mutators. No note or tx can reach them
// under the frozen 12-root note-script allowlist + 1-root tx-script allowlist (the same
// disposition as the freeze/unfreeze + set_role_admin precedents).
//
// Tier B — internally-active-but-inert, direct-entry-unreachable: the 6 stock fee procedures +
// the `compute_note_fee` policy callback. None is a new externally-authorized entry point (none
// in the note/tx-script allowlist, so no outside caller reaches them directly). BUT the
// fee-estimation path IS executed internally on every input note during
// `auth_network_transaction` (`collect_sponsored_fees` -> `estimate_note_fee_internal` -> dyncall
// to `compute_note_fee`). With `BasicConstantFeePolicy` scheduling an explicit ZERO fee for all
// 14 allowlisted roots, that execution computes a zero fee and is functionally inert (doubly so
// on the zero-base-fee MockChain). The 12-root schedule is required precisely because this path
// runs on every note.
//
// Both tiers are TEMPORARY: a later slice reverts the growth together with the provisional fee
// configuration.

/// Tier A — the four stock allowlist mutators: truly unreachable (the same disposition as
/// freeze/unfreeze and set_role_admin).
const TIER_A_MUTATOR_ROWS: [&str; 4] = [
    "::miden::standards::components::auth::network_account::add_allowed_note_script",
    "::miden::standards::components::auth::network_account::remove_allowed_note_script",
    "::miden::standards::components::auth::network_account::add_allowed_tx_script",
    "::miden::standards::components::auth::network_account::remove_allowed_tx_script",
];

/// Tier B — the six stock fee procedures + the fee-policy callback: no external entry point
/// (not in either allowlist), while the estimation path (`estimate_note_fee_internal` -> dyncall
/// `compute_note_fee`) runs INTERNALLY on every input note, computing the scheduled zero fee.
const TIER_B_FEE_ROWS: [&str; 7] = [
    "::miden::standards::components::auth::network_account::estimate_note_fee",
    "::miden::standards::components::auth::network_account::get_fee_asset_id",
    "::miden::standards::components::auth::network_account::get_fee_policy",
    "::miden::standards::components::auth::network_account::set_fee_policy",
    "::miden::standards::components::auth::network_account::add_allowed_fee_policy",
    "::miden::standards::components::auth::network_account::remove_allowed_fee_policy",
    "::miden::standards::components::fees::policies::basic_constant_fee::compute_note_fee",
];

/// Resolves the given growth rows' account-procedure roots from the shipped composition (by
/// path, so a stock re-key cannot silently blunt the sweeps below).
fn growth_row_roots(paths: &[&'static str]) -> Result<Vec<(&'static str, Word)>> {
    let components = production_components()?;
    let surface = component_surface(&components);
    paths
        .iter()
        .map(|path| {
            surface
                .iter()
                .find(|(p, _)| p == path)
                .map(|(_, root)| (*path, *root))
                .with_context(|| {
                    format!("the composed account must expose {path} (ratified temporary growth)")
                })
        })
        .collect()
}

/// All 11 ratified growth rows (Tier A + Tier B), for the asserts that span both tiers.
fn ratified_growth_row_roots() -> Result<Vec<(&'static str, Word)>> {
    let mut rows = growth_row_roots(&TIER_A_MUTATOR_ROWS)?;
    rows.extend(growth_row_roots(&TIER_B_FEE_ROWS)?);
    Ok(rows)
}

/// PRESENT: each of the 11 ratified growth rows IS a callable root of the composed account — the
/// fact the ratification covers, stated explicitly rather than left implicit in the 75-root count.
/// If any row disappears, the temporary-growth ratification must be re-visited (the revert slice
/// expects to remove exactly these).
#[test]
fn ratified_growth_rows_are_present_on_the_account() -> Result<()> {
    let rows = ratified_growth_row_roots()?;
    let account = production_account()?;
    let roots: BTreeSet<Word> = account
        .code()
        .procedures()
        .iter()
        .map(|r| Word::from(*r))
        .collect();
    for (path, root) in rows {
        assert!(
            roots.contains(&root),
            "the composed account must carry `{path}` on-chain (ratified temporary growth)"
        );
    }
    Ok(())
}

/// Tier A, UNREACHABLE, leg 1 (static, exhaustive over the allowlist): NOT ONE of the 14
/// allowlisted note scripts references ANY of the 4 mutator roots ANYWHERE in its MAST — so no
/// admissible note can mutate the allowlists. The swept set is asserted equal to the allowlist
/// first, so a new note cannot dodge the sweep.
#[test]
fn tier_a_mutators_are_unreachable_from_every_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 12-root note-script allowlist"
    );

    let rows = growth_row_roots(&TIER_A_MUTATOR_ROWS)?;
    for (label, script) in &scripts {
        let forest = script.mast();
        for node in forest.nodes() {
            for (path, root) in &rows {
                assert_ne!(
                    node.digest(),
                    *root,
                    "allowlisted note script `{label}` references the Tier-A mutator root \
                     `{path}` — the unreachability guarantee is BROKEN (an admissible note could \
                     mutate the frozen allowlists)"
                );
            }
        }
    }
    Ok(())
}

/// Tier B, NO DIRECT REFERENCE (static, exhaustive over the allowlist): NOT ONE of the 14
/// allowlisted note scripts references ANY of the 7 fee-tier roots ANYWHERE in its MAST — no
/// admissible note calls the fee machinery ITSELF. This is deliberately NOT an unreachability
/// claim: the fee-estimation path runs INTERNALLY on every input note (the auth procedure's
/// `collect_sponsored_fees` -> `estimate_note_fee_internal` -> dyncall `compute_note_fee`),
/// computing the scheduled zero fee — internally active but inert. What this sweep proves is
/// that the only executor is that internal dispatch, never an admissible script.
#[test]
fn tier_b_fee_rows_are_not_referenced_by_any_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 12-root note-script allowlist"
    );

    let rows = growth_row_roots(&TIER_B_FEE_ROWS)?;
    for (label, script) in &scripts {
        let forest = script.mast();
        for node in forest.nodes() {
            for (path, root) in &rows {
                assert_ne!(
                    node.digest(),
                    *root,
                    "allowlisted note script `{label}` references the Tier-B fee root `{path}` \
                     directly — the fee machinery must only ever run via the auth procedure's \
                     internal dispatch, never from an admissible script"
                );
            }
        }
    }
    Ok(())
}

/// NO EXTERNAL ENTRY POINT (both tiers): no growth root is a member of EITHER allowlist — the
/// 12-root note-script allowlist or the tx-script allowlist (read directly from the production
/// auth component's slot; it holds EXACTLY the one canonical expiration root, as the
/// expiration-allowlist tests pin).
/// For Tier A this closes both entry vectors outright (with the MAST sweep above: truly
/// unreachable). For Tier B it establishes exactly the ratified posture: no outside caller
/// reaches the fee procedures directly; their only execution is the auth procedure's internal
/// zero-fee dispatch.
#[test]
fn ratified_growth_rows_are_not_admissible_via_either_allowlist() -> Result<()> {
    let note_allowlist = XReserveStablecoinBuilder::allowed_note_scripts();

    // the production auth component's materialized tx-script allowlist keys (non-empty values
    // mark membership, matching the MASM `word::eqz` check — the s12 view).
    let auth_component: AccountComponent = XReserveStablecoinBuilder::auth_component()
        .map_err(|e| anyhow::anyhow!("auth_component() must build: {e}"))?
        .into_iter()
        .next()
        .expect("the auth component is yielded first");
    let tx_slot = auth_component
        .storage_slots()
        .iter()
        .find(|s| s.name() == AuthNetworkAccount::allowed_tx_scripts_slot())
        .expect("the auth component must carry the tx-script allowlist slot");
    let StorageSlotContent::Map(tx_map) = tx_slot.content() else {
        panic!("the tx-script allowlist slot must be a MAP slot");
    };
    let tx_allowlist: BTreeSet<Word> = tx_map
        .entries()
        .filter(|(_key, value)| **value != Word::empty())
        .map(|(key, _value)| key.as_word())
        .collect();

    for (path, root) in ratified_growth_row_roots()? {
        let as_note_root = NoteScriptRoot::from_raw(root);
        assert!(
            !note_allowlist.contains(&as_note_root),
            "the `{path}` root must NOT be a member of the 12-root note-script allowlist"
        );
        assert!(
            !tx_allowlist.contains(&root),
            "the `{path}` root must NOT be a member of the tx-script allowlist"
        );
    }
    Ok(())
}
