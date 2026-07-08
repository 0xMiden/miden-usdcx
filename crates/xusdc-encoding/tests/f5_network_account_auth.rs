//! F5 — production transaction auth: the faucet is a Miden NETWORK ACCOUNT (executing-red suite,
//! committed BEFORE any green implementation).
//!
//! Human decision (2026-07-08, RATIFIED): the xUSDC/xReserve faucet ships composing the stock
//! `AuthNetworkAccount` as its ONE production auth component — keyless, a frozen note-script
//! allowlist, an EMPTY tx-script allowlist. Basis:
//! `circle-integration/07-implementation-readiness/F5-PRODUCTION-AUTH-RESEARCH-AND-RECOMMENDATION.md`;
//! plan: `~/.claude/plans/model-soft-crescent.md` (Round-P PASS + §4 allowlist ratified).
//!
//! RED-FOR-THE-RIGHT-REASON. Every test below references only APIs that already exist and asserts
//! the F5 END STATE. At this commit the production faucet is still finalized under the permissive
//! `Auth::IncrNonce` (`support::setup_production_faucet`) and the notes still carry their pre-F5
//! attachment sets, so each test RUNS and fails BEHAVIOURALLY — nothing here is a compile error and
//! no production code is touched by this commit. The green loop makes them pass by (a) composing
//! `AuthNetworkAccount` with `builder.allowed_note_scripts()` (which re-bases `setup_production_faucet`
//! onto `Auth::NetworkAccount`), and (b) adding the scheme-2 `NetworkAccountTarget` routing
//! attachment to the mint + burn notes (reconciling the mint shim `eq.1`→`eq.2`).
//!
//! Scope of THIS red file (the MockChain-provable core of proofs #1, #2, #3, #5, #6). The admin
//! layered-auth E2E (#4), the scheme-aware mint negatives, and the exact-13-root allowlist assertion
//! land alongside green because they require the not-yet-shipped admin note scripts / the reconciled
//! 2-attachment constructor to even construct their fixtures.

mod support;

use core::slice;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::note::NoteType;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{
    AuthNetworkAccount, NetworkAccount, NetworkAccountNoteAllowlist,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED,
    ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED,
};
use miden_standards::note::BurnNote;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, assert_transaction_executor_error};
use support::*;
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::note::xreserve_mint::{MintAttestation, XReserveMintNote};
use xusdc_encoding::xreserve::encoding::XReserveBurnItems;

const MAX_SUPPLY: u64 = 1_000_000;

// HELPERS
// ================================================================================================

/// A deterministic standalone note rng (only the serial number depends on it, never the gate).
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// A sample DC-7 burn payload (round-trippable; only the amount is material here).
fn sample_burn_items(amount: u64) -> XReserveBurnItems {
    XReserveBurnItems {
        amount: miden_protocol::asset::AssetAmount::new(amount).expect("amount within bounds"),
        dest_domain: 9,
        dest_recipient: [0xABu8; 32],
        salt: [0xCDu8; 32],
    }
}

/// A valid deposit-intent payload (any accepted vector; the recipient encoded inside is immaterial
/// to the note's attachment set).
fn accept_deposit_intent_payload() -> Vec<u8> {
    let v = xusdc_encoding::vectors::load();
    v.families
        .di
        .iter()
        .find(|d| d.kind == "accept")
        .expect("at least one accepted deposit-intent vector")
        .bytes()
}

/// Builds the current PRODUCTION faucet and returns the committed faucet account object.
fn production_faucet_account() -> Result<(MockChain, miden_protocol::account::Account)> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .context("building the production faucet")?;
    let account = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("fetching the committed faucet account")?
        .clone();
    Ok((pf.mock_chain, account))
}

// PROOF #6 — the production faucet IS a network account (closes CHARTER-03's no-auth finding)
// ================================================================================================

/// The production build's dedicated auth component must be `AuthNetworkAccount`: a public account
/// carrying the standardized note-script allowlist slot, which `NetworkAccount::new` verifies.
/// RED now: the faucet is finalized under `Auth::IncrNonce`, which installs no allowlist slot, so
/// `NetworkAccount::new` returns `Err(SlotNotFound)`.
#[test]
fn production_faucet_is_a_network_account() -> Result<()> {
    let (_chain, account) = production_faucet_account()?;
    let result = NetworkAccount::new(account);
    assert!(
        result.is_ok(),
        "the production faucet is not a network account (no AuthNetworkAccount / no allowlist \
         slot); F5 must compose AuthNetworkAccount as the sole auth component. Got: {:?}",
        result.err()
    );
    Ok(())
}

// PROOF #5 — the frozen note-script allowlist + an EMPTY tx-script allowlist
// ================================================================================================

/// The built account's note-script allowlist must exist and contain the canonical mint + burn
/// roots (the full ratified 13-root assertion lands with the admin scripts in green), and the
/// tx-script allowlist slot must be present and EMPTY. RED now: no allowlist slots exist under
/// `Auth::IncrNonce`.
#[test]
fn production_faucet_allowlist_carries_mint_and_burn_and_empty_tx_allowlist() -> Result<()> {
    let (_chain, account) = production_faucet_account()?;

    let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
        .map_err(|e| anyhow::anyhow!("the faucet must carry a note-script allowlist slot: {e}"))?;
    let roots = allowlist.allowed_script_roots();
    assert!(
        roots.contains(&XReserveMintNote::script_root()),
        "the frozen allowlist must contain the XReserveMintNote script root",
    );
    assert!(
        roots.contains(&BurnNote::script_root()),
        "the frozen allowlist must contain the stock BurnNote script root",
    );

    // The tx-script allowlist slot must be present and empty (sole-mint-surface; reinforces F1).
    let tx_slot = account.storage().get(AuthNetworkAccount::allowed_tx_scripts_slot());
    assert!(
        tx_slot.is_some(),
        "the tx-script allowlist slot must be installed (AuthNetworkAccount) — and must be EMPTY",
    );
    Ok(())
}

// PROOF #1 — the auth boundary is real (non-allowlisted note + any tx script rejected)
// ================================================================================================

/// Consuming a note whose script root is NOT in the allowlist must be rejected by the network-auth
/// component with the exact allowlist error. RED now: under `Auth::IncrNonce` the no-op note is
/// consumed successfully (or fails for an unrelated reason), never the allowlist error.
#[tokio::test]
async fn non_allowlisted_note_is_rejected_by_auth() -> Result<()> {
    let (chain, account) = production_faucet_account()?;
    let bogus_script = CodeBuilder::new()
        .compile_note_script("@note_script\npub proc main\n    dropw\nend")
        .context("compiling the non-allowlisted probe note script")?;
    let bogus = NoteBuilder::new(test_account_id(9), &mut note_rng(99))
        .note_type(NoteType::Public)
        .script(bogus_script)
        .build()
        .context("building the non-allowlisted probe note")?;

    let result = chain
        .build_tx_context(account.id(), &[], slice::from_ref(&bogus))
        .context("building the consume tx context")?
        .build()
        .context("building the consume tx")?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);
    Ok(())
}

/// Any transaction script must be rejected by the EMPTY tx-script allowlist. RED now: under
/// `Auth::IncrNonce` there is no tx-script allowlist, so a trivial tx script is not rejected with
/// the allowlist error.
#[tokio::test]
async fn any_tx_script_is_rejected_by_empty_tx_allowlist() -> Result<()> {
    let (chain, account) = production_faucet_account()?;
    let tx_script = CodeBuilder::new()
        .compile_tx_script("begin nop end")
        .context("compiling the probe tx script")?;

    let result = chain
        .build_tx_context(account.id(), &[], &[])
        .context("building the tx-script tx context")?
        .tx_script(tx_script)
        .build()
        .context("building the tx-script tx")?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED);
    Ok(())
}

// PROOF #2 / #3 — the routing-attachment wire form (mint carries 2, burn carries 1)
// ================================================================================================

/// The mint note must carry BOTH the scheme-1 attestation attachment AND the scheme-2
/// `NetworkAccountTarget` routing attachment. RED now: the constructor builds only the attestation
/// (1 attachment).
#[test]
fn mint_note_carries_attestation_and_target_attachments() -> Result<()> {
    let payload = accept_deposit_intent_payload();
    let att = gen_attester(1, &payload);
    let note = XReserveMintNote::create(
        test_account_id(3),
        test_account_id(1),
        &payload,
        &MintAttestation::new(att.sig_bytes, att.pubkey_bytes),
        &mut note_rng(1),
    )
    .map_err(|e| anyhow::anyhow!("constructing the mint note: {e}"))?;

    assert_eq!(
        note.attachments().num_attachments(),
        2,
        "the mint note must carry the scheme-1 attestation + the scheme-2 NetworkAccountTarget \
         routing attachment (F5 routing reconciliation)",
    );
    Ok(())
}

/// The burn note must carry the scheme-2 `NetworkAccountTarget` routing attachment. RED now: the
/// burn note carries zero attachments.
#[test]
fn burn_note_carries_network_account_target_attachment() -> Result<()> {
    let note = XReserveBurnNote::create(
        test_account_id(3),
        test_account_id(1),
        sample_burn_items(5_000),
        &mut note_rng(2),
    )
    .map_err(|e| anyhow::anyhow!("constructing the burn note: {e}"))?;

    assert_eq!(
        note.attachments().num_attachments(),
        1,
        "the burn note must carry the scheme-2 NetworkAccountTarget routing attachment (was 0 \
         attachments pre-F5; changes the shared burn-note wire form [] -> [2])",
    );
    Ok(())
}
