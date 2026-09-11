//! Checks deployment and configuration observations fetched from the node.

use std::collections::BTreeSet;

use anyhow::{bail, ensure, Context, Result};
use miden_protocol::account::{Account, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{
    NetworkAccountNoteAllowlist, NetworkAccountTxScriptAllowlist,
};
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_standards::tx_script::ExpirationTransactionScript;
use xusdc_encoding::account::xreserve::{
    XReserveFaucetExtension, XReserveStablecoinBuilder, IDENTIFIER_CONFIG_SLOT_LABEL,
};
use xusdc_encoding::note::xreserve_admin::XReserveIdentifierInitNote;
use xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts;

use crate::config::DomainParams;
use crate::observations::RowsAbObservations;

/// The exact error string `identifier_init::init_identifier`'s init-once gate traps with
/// (`ERR_XRESERVE_IDENTIFIER_REINIT` in `asm/standards/xreserve/identifier_init.masm` — the
/// Wave-1 S1 replacement of the former `domain_config` reinit gate); the reinit rejection must
/// carry THIS error — any other failure is not the init-once gate.
pub const ERR_IDENTIFIER_REINIT_TEXT: &str = "identifier has already been initialized";

/// Reads a named value slot from a fetched account's storage.
fn storage_word(account: &Account, name: &StorageSlotName) -> Result<Word> {
    account
        .storage()
        .get_item(name)
        .with_context(|| format!("the deployed faucet does not carry the '{name}' slot"))
}

/// **Row A — deploy + recognize.**
///
/// - `GetAccount` returned the faucet (the node recognizes the deployed account).
/// - The returned account id matches the harness-built id and is PUBLIC (full on-chain state).
/// - The nonce is exactly 1 (the single deploy transaction; `AuthNetworkAccount` bumped 0 → 1).
/// - The standardized network-account note-script allowlist slot is present and NON-EMPTY, and
///   equals EXACTLY the frozen 12-root production set (`allowed_note_scripts()` — extra or
///   missing roots are a composition defect; the runtime `set_role_admin` note was removed,
///   S21 flip 2026-07-14).
/// - The tx-script allowlist slot is present and equals EXACTLY the frozen v16 production set — the
///   one canonical `ExpirationTransactionScript::script_root()` (S12, RATIFIED). v16 no longer
///   ships an EMPTY tx-script allowlist: `XReserveStablecoinBuilder::auth_component()` allowlists
///   exactly the expiration root, so the sole-mint-surface / F1 invariant is now "exactly the
///   expiration root", not "exactly empty".
pub fn assert_row_a(obs: &RowsAbObservations) -> Result<()> {
    let account = obs.deployed.as_ref().context(
        "row A: GetAccount returned no account — the node does not recognize the deployed faucet",
    )?;

    ensure!(
        account.id() == obs.faucet_id,
        "row A: GetAccount returned a different account id (got {}, deployed {})",
        account.id(),
        obs.faucet_id,
    );
    ensure!(
        account.id().is_public(),
        "row A: the faucet account must be PUBLIC (full state on-chain), got a private id",
    );
    ensure!(
        account.nonce() == Felt::from(1u32),
        "row A: the deployed faucet's nonce must be exactly 1 after the deploy transaction, got {}",
        account.nonce(),
    );

    // The standardized allowlist slot — presence of this slot is what makes the node treat the
    // account as a network account; row A requires it present + non-empty.
    let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage()).map_err(|e| {
        anyhow::anyhow!(
            "row A: the on-chain account carries no readable network-account note allowlist \
             slot: {e}"
        )
    })?;
    ensure!(
        !allowlist.allowed_script_roots().is_empty(),
        "row A: the network-account note-script allowlist must be non-empty on-chain",
    );
    let expected = XReserveStablecoinBuilder::allowed_note_scripts();
    ensure!(
        allowlist.allowed_script_roots() == &expected,
        "row A: the on-chain note-script allowlist must equal EXACTLY the frozen {}-root \
         production set (got {} roots)",
        expected.len(),
        allowlist.allowed_script_roots().len(),
    );

    // The tx-script allowlist must exist and equal EXACTLY the frozen v16 production set — the one
    // canonical ExpirationTransactionScript root. Extra or missing roots are a
    // composition defect.
    let tx_allowlist =
        NetworkAccountTxScriptAllowlist::try_from(account.storage()).map_err(|e| {
            anyhow::anyhow!(
                "row A: the on-chain account carries no readable tx-script allowlist slot: {e}"
            )
        })?;
    let expected_tx = BTreeSet::from([ExpirationTransactionScript::script_root()]);
    ensure!(
        tx_allowlist.allowed_script_roots() == &expected_tx,
        "row A: the on-chain tx-script allowlist must equal EXACTLY the frozen {}-root production \
         set (the S12 expiration script), found {} root(s)",
        expected_tx.len(),
        tx_allowlist.allowed_script_roots().len(),
    );

    Ok(())
}

/// Asserts the five domain-config slots of `account` are correct: the three BUILD-SEEDED fields hold
/// `params`' values, and the `identifier_init`-committed identifier holds the OWN-ID fixpoint key
/// `identifier_for(account.id())` (derived from the faucet id, NOT from `params` — R2 binding fix).
fn assert_domain_config_slots(account: &Account, params: &DomainParams, ctx: &str) -> Result<()> {
    let domain = storage_word(account, XReserveFaucetExtension::domain_config_slot())?;
    ensure!(
        domain
            == Word::from([
                Felt::from(params.domain),
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO
            ]),
        "{ctx}: domain slot read-back mismatch (got {domain:?}, expected [{}, 0, 0, 0])",
        params.domain,
    );

    // The identifier is BOUND to the faucet identity: the `identifier_init` note derives it from the
    // faucet's OWN id (`identifier_for(faucet_id)` = `bytes32_to_storage_map_key(EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32())`,
    // the own-id fixpoint), NOT from any caller-chosen `params` value (the R2 identifier-binding fix;
    // the deployed-faucet re-check in `sanity` enforces the SAME key). So the expected identifier is
    // derived from `account.id()`, not `params.identifier_word()`.
    let identifier_name = StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)
        .context("the identifier slot label is a valid constant")?;
    let identifier = storage_word(account, &identifier_name)?;
    let expected_identifier = XReserveIdentifierInitNote::identifier_for(account.id());
    ensure!(
        identifier == expected_identifier,
        "{ctx}: identifier slot read-back mismatch (got {identifier:?}, expected the own-id key \
         {expected_identifier:?})",
    );
    ensure!(
        identifier != Word::empty(),
        "{ctx}: the stored identifier must be non-empty (it is the init-once sentinel)",
    );

    let source_domain = storage_word(account, XReserveFaucetExtension::source_domain_config_slot())?;
    ensure!(
        source_domain
            == Word::from([
                Felt::from(params.source_domain),
                Felt::ZERO,
                Felt::ZERO,
                Felt::ZERO
            ]),
        "{ctx}: source_domain slot read-back mismatch (got {source_domain:?}, expected [{}, 0, 0, \
         0])",
        params.source_domain,
    );

    let packed = bytes32_to_packed_felts(params.xreserve_contract.as_bytes());
    let xrc_hi = storage_word(account, XReserveFaucetExtension::xreserve_contract_hi_slot())?;
    let xrc_lo = storage_word(account, XReserveFaucetExtension::xreserve_contract_lo_slot())?;
    ensure!(
        xrc_hi == Word::from([packed[0], packed[1], packed[2], packed[3]]),
        "{ctx}: xreserve_contract_hi slot read-back mismatch",
    );
    ensure!(
        xrc_lo == Word::from([packed[4], packed[5], packed[6], packed[7]]),
        "{ctx}: xreserve_contract_lo slot read-back mismatch",
    );
    Ok(())
}

/// **Row B — identifier_init init-once** (the Wave-1 S1 retarget: the row proves the SAME
/// init-once invariant, whose surviving runtime subject is the minimized `identifier_init` note —
/// the other three domain-config fields are build-seeded and have NO runtime writer at all).
///
/// - The owner-sent first `identifier_init` initialized the identifier to the OWN-ID fixpoint key
///   (`identifier_for(faucet_id)`), and the build seed carried the other three fields: all five
///   domain-config slots read back from ON-CHAIN storage (`domain`, `identifier` — the spec's named
///   read-backs — plus `source_domain` and the two `xreserve_contract` limbs).
/// - The SECOND `identifier_init` was REJECTED by the init-once gate: the consumption attempt
///   failed with EXACTLY the `ERR_XRESERVE_IDENTIFIER_REINIT` error (the second note derives the
///   SAME own-id key, so it traps as a reinit regardless of value).
/// - The rejection changed NOTHING: the re-fetched account still carries the own-id identifier +
///   build seed, the nonce is unchanged, and the second note was never consumed on-chain.
pub fn assert_row_b(obs: &RowsAbObservations) -> Result<()> {
    let account = obs
        .deployed
        .as_ref()
        .context("row B: no deployed account to read the domain config back from")?;

    // Init happened: the five slots hold the run params (build seed + first note's identifier).
    assert_domain_config_slots(account, &obs.domain_params, "row B (post-init read-back)")?;

    // Init-once: the second consumption attempt trapped with EXACTLY the reinit error.
    let err = obs.reinit_error.as_ref().context(
        "row B: the SECOND identifier_init consumption attempt did not fail — the init-once gate \
         did not hold",
    )?;
    ensure!(
        err.contains(ERR_IDENTIFIER_REINIT_TEXT),
        "row B: the second identifier_init failed, but not with the init-once gate error \
         ('{ERR_IDENTIFIER_REINIT_TEXT}'); got: {err}",
    );

    // Nothing changed: the post-attempt state still carries the FIRST params + nonce 1.
    let after = obs.after_reinit.as_ref().context(
        "row B: no post-reinit-attempt account fetched — cannot prove the rejection left state \
         unchanged",
    )?;
    ensure!(
        after.nonce() == Felt::from(1u32),
        "row B: the faucet nonce changed after the rejected reinit attempt (got {}, expected 1) \
         — something executed against the faucet",
        after.nonce(),
    );
    assert_domain_config_slots(after, &obs.domain_params, "row B (post-reinit-attempt)")?;

    // The post-attempt read-back above already re-asserts the identifier is STILL the own-id key
    // (unchanged by the rejected reinit). There is no distinct "second identifier" to detect: the
    // second `identifier_init` derives the SAME own-id key from the SAME faucet_id (the R2
    // identifier-binding fix), so the init-once proof rests on the trap error, the unchanged nonce,
    // this unchanged read-back, and the note never being consumed on-chain (below) — not on a value
    // mismatch between two notes.

    if obs.second_note_consumed {
        bail!(
            "row B: the SECOND identifier_init note was consumed on-chain — the init-once gate \
             did not hold (note {})",
            obs.second_note_id,
        );
    }

    Ok(())
}
