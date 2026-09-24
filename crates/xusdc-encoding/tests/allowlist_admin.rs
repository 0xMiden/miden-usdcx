//! Allowlist administration on the production faucet: `ADMIN` widens and narrows the note-script
//! allowlist through the `miden-standards` network-account configuration note, and a change
//! applies from the next transaction.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::{Note, NoteScriptRoot, NoteType};
use miden_standards::account::auth::NetworkAccountNoteAllowlist;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED;
use miden_standards::note::config::{ConstantFeePolicyConfigNote, NetworkAccountConfig};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::assert_transaction_executor_error;
use support::w2admin::*;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::note::xreserve_admin::XReserveMinBurnAmountNote;

/// A public no-op note whose script the builder does not allowlist, sent by `sender`.
fn probe_note(sender: AccountId) -> Result<Note> {
    let script = CodeBuilder::new()
        .compile_note_script("@note_script\npub proc main\n    dropw\nend")
        .context("compiling the probe note script")?;
    NoteBuilder::new(sender, &mut support::w2admin::note_rng(7))
        .note_type(NoteType::Public)
        .script(script)
        .build()
        .context("building the probe note")
}

/// The constant-fee configuration note that prices `root` at zero on `faucet_id`.
fn zero_fee_note(sender: AccountId, faucet_id: AccountId, root: NoteScriptRoot) -> Result<Note> {
    let note = ConstantFeePolicyConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .note_script_root(root)
        .fee_asset(FungibleAsset::new(test_fee_faucet_id(), 0)?)
        .serial_number(support::w2admin::serial(11))
        .build()?;
    Ok(Note::from(note))
}

/// The note-script allowlist a committed faucet stores.
fn committed_allowlist(account: &Account) -> Result<BTreeSet<NoteScriptRoot>> {
    Ok(NetworkAccountNoteAllowlist::try_from(account.storage())
        .map_err(|e| anyhow::anyhow!("the faucet must carry a note-script allowlist slot: {e}"))?
        .into_allowed_script_roots())
}

/// `ADMIN` admits a new note root. Once the configuration note and a fee-schedule entry for the
/// root are committed, a note with that root is consumed.
#[tokio::test]
async fn admin_widens_the_note_allowlist_and_the_admitted_note_is_consumed() -> Result<()> {
    let probe = probe_note(admin_holder())?;
    let probe_root = probe.script().root();
    let mut pf = admin_faucet(|faucet_id| {
        vec![
            network_account_config_note(
                admin_holder(),
                faucet_id,
                NetworkAccountConfig::AddAllowedNoteScript {
                    script_root: probe_root,
                },
                1,
            )
            .expect("the add note builds"),
            zero_fee_note(admin_holder(), faucet_id, probe_root).expect("the fee note builds"),
            probe,
        ]
    })?;
    let add = pf.seeded_notes[0].clone();
    let fee = pf.seeded_notes[1].clone();
    let probe = pf.seeded_notes[2].clone();

    let account = consume_and_commit(&mut pf, &add, "admitting the probe root").await?;
    let mut expected = XReserveStablecoinBuilder::allowed_note_scripts();
    expected.insert(probe_root);
    assert_eq!(
        committed_allowlist(&account)?,
        expected,
        "the committed allowlist must gain the probe root"
    );

    consume_and_commit(&mut pf, &fee, "pricing the probe root").await?;
    consume(&pf, &probe)
        .await
        .map_err(|e| anyhow::anyhow!("the admitted probe note must be consumed: {e}"))?;
    Ok(())
}

/// `ADMIN` removes an allowlisted root. Once the configuration note is committed, the allowlist
/// gate rejects a note with that root.
#[tokio::test]
async fn admin_narrows_the_note_allowlist_and_the_removed_note_is_rejected() -> Result<()> {
    let min_burn_root = XReserveMinBurnAmountNote::script_root();
    let mut pf = admin_faucet(|faucet_id| {
        vec![
            network_account_config_note(
                admin_holder(),
                faucet_id,
                NetworkAccountConfig::RemoveAllowedNoteScript {
                    script_root: min_burn_root,
                },
                2,
            )
            .expect("the remove note builds"),
            stock_min_burn_note(admin_holder(), faucet_id, 5_000, 3)
                .expect("the min-burn note builds"),
        ]
    })?;
    let remove = pf.seeded_notes[0].clone();
    let min_burn = pf.seeded_notes[1].clone();

    let account = consume_and_commit(&mut pf, &remove, "removing the min-burn root").await?;
    let mut expected = XReserveStablecoinBuilder::allowed_note_scripts();
    expected.remove(&min_burn_root);
    assert_eq!(
        committed_allowlist(&account)?,
        expected,
        "the committed allowlist must lose the min-burn root"
    );

    let result = consume(&pf, &min_burn).await;
    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED);
    Ok(())
}

/// A role holder outside `ADMIN` cannot change the allowlist: the configuration note's actions
/// resolve to `ADMIN` through the authority fallback.
#[tokio::test]
async fn a_role_holder_without_admin_cannot_change_the_allowlist() -> Result<()> {
    let probe_root = probe_note(pauser_holder())?.script().root();
    let pf = admin_faucet(|faucet_id| {
        vec![network_account_config_note(
            pauser_holder(),
            faucet_id,
            NetworkAccountConfig::AddAllowedNoteScript {
                script_root: probe_root,
            },
            4,
        )
        .expect("the add note builds")]
    })?;
    let add = pf.seeded_notes[0].clone();

    let result = consume(&pf, &add).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}
