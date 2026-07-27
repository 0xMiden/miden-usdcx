//! S12 (RATIFIED 2026-07-20) — the faucet's production auth component allowlists EXACTLY the one
//! canonical `ExpirationTransactionScript` in its tx-script allowlist, and NOTHING else.
//!
//! This is the dedicated RED-then-GREEN proof for the S12 change: it exercises the SOURCE of the
//! change — `XReserveStablecoinBuilder::auth_component()` — directly (component storage), an angle
//! distinct from the finalized-account view in `f5_network_account_auth.rs`, plus the on-chain
//! enforcement (execute-level admit/reject). It fails RED against the pre-S12 EMPTY tx-script
//! allowlist and passes GREEN once `auth_component()` allowlists the single expiration root.
//!
//! Invariant (three checks):
//! - the auth component's tx-script allowlist slot carries EXACTLY `{ script_root() }` (the "only"
//!   property — extra or missing = RED);
//! - the note-script allowlist slot is UNCHANGED by S12 — 14 non-empty roots (S12 must not touch it);
//! - on-chain enforcement: the canonical expiration script is ADMITTED and executes, while an
//!   arbitrary (nop) tx-script is REJECTED with `ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED`.

mod support;

use core::num::NonZeroU16;
use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::account::{AccountComponent, StorageSlotContent, StorageSlotName};
use miden_protocol::Word;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

/// The faucet max supply used by the production-faucet fixture (mirrors the sibling suites).
const MAX_SUPPLY: u64 = 1_000_000;

/// Reads the non-empty keys of the named MAP storage slot out of an `AccountComponent`. Only
/// non-empty values mark an allowlisted key (matching the MASM `word::eqz` check), so this view
/// agrees with on-chain enforcement.
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

/// DIRECT test of the changed function: `auth_component()`'s tx-script allowlist slot must carry
/// EXACTLY the one canonical `ExpirationTransactionScript::script_root()` — nothing more, nothing
/// less. RED before S12 (the slot is empty), GREEN after.
#[test]
fn auth_component_tx_script_allowlist_is_exactly_the_expiration_root() -> Result<()> {
    let component: AccountComponent = XReserveStablecoinBuilder::auth_component()
        .map_err(|e| anyhow::anyhow!("auth_component() must build: {e}"))?
        .into();

    let tx_keys = allowlisted_keys(&component, AuthNetworkAccount::allowed_tx_scripts_slot());
    let expected = BTreeSet::from([ExpirationTransactionScript::script_root().as_word()]);
    assert_eq!(
        tx_keys,
        expected,
        "auth_component()'s tx-script allowlist must equal EXACTLY {{ script_root() }} (S12); \
         found {} key(s)",
        tx_keys.len(),
    );
    Ok(())
}

/// S12 must NOT touch the note-script allowlist: the note slot still carries the frozen 14 roots
/// (12 owner/role/pause + the 2 F4-reversal transfer-blocklist notes).
#[test]
fn auth_component_note_script_allowlist_is_untouched_by_s12() -> Result<()> {
    let component: AccountComponent = XReserveStablecoinBuilder::auth_component()
        .map_err(|e| anyhow::anyhow!("auth_component() must build: {e}"))?
        .into();

    let note_keys = allowlisted_keys(&component, AuthNetworkAccount::allowed_note_scripts_slot());
    assert_eq!(
        note_keys.len(),
        14,
        "S12 must leave the note-script allowlist at EXACTLY the frozen 14 roots; found {}",
        note_keys.len(),
    );
    // The exact-14-root set (source + on-chain) is pinned by f5; here we only prove S12 did not
    // add/remove a note root while flipping the tx-script allowlist.
    Ok(())
}

/// On-chain enforcement: the canonical expiration script is ADMITTED (clears the allowlist gate and
/// executes) while an arbitrary nop tx-script is REJECTED. RED before S12 (both rejected).
#[tokio::test]
async fn expiration_is_admitted_and_every_other_tx_script_is_rejected() -> Result<()> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_, _faucet_id| Vec::new())
        .context("building the production network-auth faucet")?;

    // NEGATIVE — a nop tx script is not the expiration root, so the one-root allowlist rejects it.
    let bogus = CodeBuilder::new()
        .compile_tx_script("@transaction_script\npub proc main\n    nop\nend\n")
        .context("compiling the nop probe tx script")?;
    let rejected = pf
        .mock_chain
        .build_tx_context(pf.faucet_id, &[], &[])
        .context("nop tx-script context")?
        .tx_script(bogus)
        .build()
        .context("nop tx-script build")?
        .execute()
        .await;
    assert_transaction_executor_error!(rejected, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);

    // POSITIVE — the canonical expiration script IS allowlisted, so it CLEARS the allowlist gate.
    // An expiration-only tx changes no account state and consumes no notes, so the kernel then
    // rejects it with the empty-tx epilogue assertion — which is DOWNSTREAM of, and orthogonal to,
    // the S12 tx-script allowlist gate. The precise S12 invariant is that the expiration script is
    // NOT rejected by the tx-script allowlist; a mutation dropping the expiration root flips this
    // back to `ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED` (the RED state), which this catches.
    let expiration = ExpirationTransactionScript::new(NonZeroU16::new(64).expect("64 is non-zero"));
    let admitted = pf
        .mock_chain
        .build_tx_context(pf.faucet_id, &[], &[])
        .context("expiration tx-script context")?
        .tx_script(expiration.into())
        .tx_script_args(expiration.tx_script_args())
        .build()
        .context("expiration tx-script build")?
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
