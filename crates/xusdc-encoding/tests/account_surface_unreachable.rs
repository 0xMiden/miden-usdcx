//! S21 + S13/S24 dispositions of the FULL-ACCOUNT CALLABLE SURFACE — the PRESENT-BUT-UNREACHABLE
//! and READ-ONLY halves of the pin, split out of `account_callable_surface.rs` for the G3 file-size
//! ceiling. `account_callable_surface.rs` holds the frozen-surface equality pin + the S12
//! freeze/unfreeze disposition + the S24 asset-callback (transfer-blocklist-live) proof; THIS file
//! holds:
//!   * S21 — `rbac::set_role_admin` is a callable root but OPERATIONALLY UNREACHABLE (its runtime
//!     note was removed from the allowlist, human-ratified 2026-07-14; the role-admin graph is
//!     build-seeded and frozen — rotation is grant_role/revoke_role only, CIR-ADMIN-3);
//!   * S13/S24 — `authority::get_authority` is READ-ONLY in execution (executed bounding, not
//!     documentation).
//!
//! The small conformance helpers (`production_components`/`component_surface`/`production_account`/
//! `allowlisted_note_scripts`) are duplicated here (as in the round-5 test splits) so this module is
//! self-contained; both copies are single-sourced from `XReserveStablecoinBuilder`, so neither can
//! drift from what ships.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountComponent};
use miden_protocol::assembly::mast::MastNodeExt;
use miden_protocol::note::{NoteScript, NoteScriptRoot};
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::BurnNote;
use miden_standards::testing::note::NoteBuilder;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::note::xreserve_admin::{
    XReserveAcceptOwnershipNote, XReserveBlockAccountNote, XReserveDomainInitNote,
    XReserveGrantRoleNote, XReservePauseNote, XReserveRevokeRoleNote, XReserveSetAttesterNote,
    XReserveSetMaxSupplyNote, XReserveSetMinBurnSizeNote, XReserveTransferOwnershipNote,
    XReserveUnblockAccountNote, XReserveUnpauseNote,
};
use xusdc_encoding::note::xreserve_mint::XReserveMintNote;

const MAX_SUPPLY: u64 = 1_000_000;

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

/// The 14 allowlisted note SCRIPTS (not just their roots): the two supply notes + the 12 admin
/// notes (10 owner/role/pause + the 2 F4-reversal transfer-blocklist notes). Single-sourced from the
/// same factories the allowlist itself is built from, so a note that enters the allowlist necessarily
/// enters this sweep too. There is deliberately NO `set_role_admin` entry: the runtime
/// `set_role_admin` note was REMOVED from the allowlist (S21 disposition flip, human-ratified
/// 2026-07-14) — the role-admin graph is BUILD-SEEDED and frozen; rotation is
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
        ("block_account", XReserveBlockAccountNote::script()),
        ("unblock_account", XReserveUnblockAccountNote::script()),
    ]
}

// S21 — SET_ROLE_ADMIN: PRESENT, AND PROVABLY UNREACHABLE (the frozen role-admin graph)
// ================================================================================================

/// The fully-qualified path of the stock RBAC `set_role_admin` account procedure (a member of the
/// frozen 65-root surface above — the proc STAYS; only its runtime note was removed).
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
/// the S21 disposition keeps the stock component intact (the 65-root surface is unchanged); ONLY
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
/// RED (this is the machine-enforced conformance-manifest row for the S21 removal).
#[test]
fn set_role_admin_is_unreachable_from_every_allowlisted_note() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let scripts = allowlisted_note_scripts();
    let swept: BTreeSet<_> = scripts.iter().map(|(_, s)| s.root()).collect();
    assert_eq!(
        swept, allowlist,
        "the swept note scripts must be EXACTLY the 14-root note-script allowlist — an extra root \
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
/// capability. The FORMER pinned `set_role_admin` note root is NOT a member of the 14-root
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
        "the former set_role_admin note root must NOT be a member of the 14-root note-script \
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
