//! The config-note ABSENCE pin: the stock `NetworkAccountConfigNote` script root (and its
//! companion default, the `FeeSponsorshipNote` root) must be ABSENT from the faucet's note-script
//! allowlist — at the builder source, at the auth component's storage, and on the built account.
//!
//! Why this file exists: at protocol-`next`, `AuthNetworkAccount::new()` force-inserts BOTH roots
//! into whatever allowlist it is given (the config note so a deployed account's allowlists can be
//! reconfigured post-deploy; the sponsorship note so prepaid fees can be collected). The xReserve
//! faucet's entire authorization model is the FROZEN 14-root note allowlist — admitting the
//! config note would hand the (present-but-unreachable) allowlist mutators a runtime entry
//! vector, and the faucet collects no sponsored fees. The production composition therefore goes
//! through `AuthNetworkAccount::custom()`, which inserts NOTHING: the absence asserted here is
//! STRUCTURAL (no code path adds the roots), and this file is the executable tripwire that keeps
//! it that way. Re-adding either root — by switching back to `new()`, by composing through the
//! `miden-testing` `Auth::NetworkAccount` fixture (which routes through `new()`), or by listing a
//! root explicitly — turns this file RED.
//!
//! The allowlist-mutator PROCEDURES the same upstream change added to the account's callable
//! surface are a separate, ratified matter: they are present-but-unreachable rows, pinned in
//! `account_callable_surface.rs` / `account_surface_unreachable.rs`. This file guards the entry
//! vector those rows would need: the note-script allowlist stays the exact 14 ratified roots.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::account::{AccountComponent, StorageSlotContent, StorageSlotName};
use miden_protocol::Word;
use miden_standards::account::auth::{AuthNetworkAccount, NetworkAccountNoteAllowlist};
use miden_standards::note::{FeeSponsorshipNote, NetworkAccountConfigNote};
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

/// The faucet max supply used by the production-faucet fixture (mirrors the sibling suites).
const MAX_SUPPLY: u64 = 1_000_000;

/// The two roots `AuthNetworkAccount::new()` force-inserts and `custom()` must keep out.
fn forbidden_roots() -> [(&'static str, Word); 2] {
    [
        (
            "NetworkAccountConfigNote",
            NetworkAccountConfigNote::script_root().as_word(),
        ),
        (
            "FeeSponsorshipNote",
            FeeSponsorshipNote::script_root().as_word(),
        ),
    ]
}

/// Reads the non-empty keys of the named MAP storage slot out of an `AccountComponent` (the same
/// view `s12_expiration_tx_script_allowlist.rs` uses — only non-empty values mark an allowlisted
/// key, matching the MASM `word::eqz` check).
fn allowlisted_keys(component: &AccountComponent, slot: &StorageSlotName) -> BTreeSet<Word> {
    let content = component
        .storage_slots()
        .iter()
        .find(|s| s.name() == slot)
        .unwrap_or_else(|| panic!("the auth component must carry the {slot} slot"))
        .content();
    let StorageSlotContent::Map(map) = content else {
        panic!("the {slot} slot must be a MAP slot");
    };
    map.entries()
        .filter(|(_key, value)| **value != Word::empty())
        .map(|(key, _value)| key.as_word())
        .collect()
}

/// Source layer: the builder's single-source 14-root set does not name either forbidden root
/// (the set is a literal, so this is the source-drift tripwire).
#[test]
fn config_note_root_is_not_in_the_builder_allowlist() {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    for (name, root) in forbidden_roots() {
        assert!(
            !allowlist.iter().any(|r| r.as_word() == root),
            "the {name} script root must NOT be a member of the builder's 14-root note-script \
             allowlist"
        );
    }
}

/// Component layer: the auth component `auth_component()` composes carries neither forbidden root
/// in its allowlist slot, and the slot holds EXACTLY 14 keys — the composition went through
/// `custom()`, which inserts nothing. RED whenever the composition routes through `new()` (which
/// force-inserts both roots).
#[test]
fn config_note_root_is_not_in_the_auth_components_allowlist() -> Result<()> {
    let component: AccountComponent = XReserveStablecoinBuilder::auth_component()
        .map_err(|e| anyhow::anyhow!("auth_component() must build: {e}"))?
        .into_iter()
        .next()
        .expect("the auth component is yielded first");

    let note_keys = allowlisted_keys(&component, AuthNetworkAccount::allowed_note_scripts_slot());
    assert_eq!(
        note_keys.len(),
        14,
        "the auth component's note-script allowlist must hold EXACTLY the 14 ratified roots; \
         found {} (a 15th/16th key means a force-inserting constructor was used)",
        note_keys.len(),
    );
    for (name, root) in forbidden_roots() {
        assert!(
            !note_keys.contains(&root),
            "the {name} script root must NOT be a key of the auth component's note-script \
             allowlist slot (the production composition must construct via custom(), which \
             inserts nothing)"
        );
    }
    Ok(())
}

/// On-chain layer: the BUILT production faucet's materialized allowlist storage holds exactly 14
/// roots and neither forbidden root. This is the layer the kernel enforces at runtime, and the
/// layer the test-support composition must preserve (composing through the `miden-testing`
/// `Auth::NetworkAccount` fixture would violate it — the fixture routes through `new()`).
#[test]
fn config_note_root_is_absent_from_the_built_accounts_allowlist() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("the production faucet must be committed")?
        .clone();

    let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
        .map_err(|e| anyhow::anyhow!("the faucet must carry the allowlist slot: {e}"))?;
    let roots: BTreeSet<Word> = allowlist
        .allowed_script_roots()
        .iter()
        .map(|r| r.as_word())
        .collect();

    assert_eq!(
        roots.len(),
        14,
        "the built faucet's on-chain note-script allowlist must hold EXACTLY the 14 ratified \
         roots; found {}",
        roots.len(),
    );
    for (name, root) in forbidden_roots() {
        assert!(
            !roots.contains(&root),
            "the {name} script root must NOT be in the built faucet's on-chain note-script \
             allowlist (structural absence via custom(); the new()/fixture path would violate it)"
        );
    }
    Ok(())
}
