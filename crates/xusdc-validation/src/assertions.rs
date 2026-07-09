//! Row-A + row-B assertion suite (written test-first, before the drivers).
//!
//! Matrix rows (authoritative spec, `TASK-P5-01-PHASE4-LOCAL-NODE-VALIDATION-PLAN-BUILDER.md`):
//! - **A. Deploy + recognize** — the production faucet (post-F5 composition) deploys to the local
//!   node; `GetAccount` returns it; the network-account allowlist slot is present + non-empty
//!   on-chain; the account is PUBLIC.
//! - **B. domain_init** — the owner-sent first admin note initializes the domain config; a SECOND
//!   `domain_init` is REJECTED (init-once); `domain` + `identifier` read back from on-chain
//!   storage.
//!
//! Every check reads the NODE-fetched state carried by [`RowsAbObservations`] — a green here is a
//! statement about the real chain, not about the client's local store.

use anyhow::{bail, ensure, Context, Result};
use miden_protocol::account::{Account, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{
    NetworkAccountNoteAllowlist, NetworkAccountTxScriptAllowlist,
};
use xusdc_encoding::account::xreserve::{
    XReserveStablecoinBuilder, DOMAIN_CONFIG_SLOT_LABEL, IDENTIFIER_CONFIG_SLOT_LABEL,
    SOURCE_DOMAIN_CONFIG_SLOT_LABEL, XRESERVE_CONTRACT_HI_SLOT_LABEL,
    XRESERVE_CONTRACT_LO_SLOT_LABEL,
};
use xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts;

use crate::config::DomainParams;
use crate::observations::RowsAbObservations;

/// The exact error string `domain_config::domain_init`'s init-once gate traps with
/// (`ERR_XRESERVE_DOMAIN_REINIT` in `asm/standards/xreserve/domain_config.masm`); the reinit
/// rejection must carry THIS error — any other failure is not the init-once gate.
pub const ERR_DOMAIN_REINIT_TEXT: &str = "domain config has already been initialized";

/// Reads a named value slot from a fetched account's storage.
fn storage_word(account: &Account, label: &str) -> Result<Word> {
    let name = StorageSlotName::new(label)
        .with_context(|| format!("'{label}' is not a valid storage slot name"))?;
    account
        .storage()
        .get_item(&name)
        .with_context(|| format!("the deployed faucet does not carry the '{label}' slot"))
}

/// **Row A — deploy + recognize.**
///
/// - `GetAccount` returned the faucet (the node recognizes the deployed account).
/// - The returned account id matches the harness-built id and is PUBLIC (full on-chain state).
/// - The nonce is exactly 1 (the single deploy transaction; `AuthNetworkAccount` bumped 0 → 1).
/// - The standardized network-account note-script allowlist slot is present and NON-EMPTY, and
///   equals EXACTLY the frozen 13-root production set (`allowed_note_scripts()` — extra or
///   missing roots are a composition defect).
/// - The tx-script allowlist slot is present and EXACTLY empty (sole-mint-surface / F1).
pub fn assert_row_a(obs: &RowsAbObservations) -> Result<()> {
    let account = obs
        .deployed
        .as_ref()
        .context("row A: GetAccount returned no account — the node does not recognize the deployed faucet")?;

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

    // The tx-script allowlist must exist and be EXACTLY empty (sole-mint-surface / F1).
    let tx_allowlist =
        NetworkAccountTxScriptAllowlist::try_from(account.storage()).map_err(|e| {
            anyhow::anyhow!(
                "row A: the on-chain account carries no readable tx-script allowlist slot: {e}"
            )
        })?;
    ensure!(
        tx_allowlist.allowed_script_roots().is_empty(),
        "row A: the tx-script allowlist must be EXACTLY empty on-chain, found {} root(s)",
        tx_allowlist.allowed_script_roots().len(),
    );

    Ok(())
}

/// Asserts the five §5.9 domain-config slots of `account` hold exactly `params`' values.
fn assert_domain_config_slots(account: &Account, params: &DomainParams, ctx: &str) -> Result<()> {
    let domain = storage_word(account, DOMAIN_CONFIG_SLOT_LABEL)?;
    ensure!(
        domain == Word::from([Felt::from(params.domain), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        "{ctx}: domain slot read-back mismatch (got {domain:?}, expected [{}, 0, 0, 0])",
        params.domain,
    );

    let identifier = storage_word(account, IDENTIFIER_CONFIG_SLOT_LABEL)?;
    let expected_identifier = params.identifier_word();
    ensure!(
        identifier == expected_identifier,
        "{ctx}: identifier slot read-back mismatch (got {identifier:?}, expected \
         {expected_identifier:?})",
    );
    ensure!(
        identifier != Word::empty(),
        "{ctx}: the stored identifier must be non-empty (it is the init-once sentinel)",
    );

    let source_domain = storage_word(account, SOURCE_DOMAIN_CONFIG_SLOT_LABEL)?;
    ensure!(
        source_domain
            == Word::from([Felt::from(params.source_domain), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        "{ctx}: source_domain slot read-back mismatch (got {source_domain:?}, expected [{}, 0, 0, \
         0])",
        params.source_domain,
    );

    let packed = bytes32_to_packed_felts(&params.xreserve_contract);
    let xrc_hi = storage_word(account, XRESERVE_CONTRACT_HI_SLOT_LABEL)?;
    let xrc_lo = storage_word(account, XRESERVE_CONTRACT_LO_SLOT_LABEL)?;
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

/// **Row B — domain_init init-once.**
///
/// - The owner-sent first `domain_init` initialized the domain config: all five §5.9 slots read
///   back from ON-CHAIN storage at exactly the creator-committed params (`domain`, `identifier`
///   — the spec's named read-backs — plus `source_domain` and the two `xreserve_contract` limbs).
/// - The SECOND `domain_init` was REJECTED by the init-once gate: the consumption attempt failed
///   with EXACTLY the `ERR_XRESERVE_DOMAIN_REINIT` error.
/// - The rejection changed NOTHING: the re-fetched account still carries the FIRST params (never
///   the second note's), the nonce is unchanged, and the second note was never consumed on-chain.
pub fn assert_row_b(obs: &RowsAbObservations) -> Result<()> {
    let account = obs
        .deployed
        .as_ref()
        .context("row B: no deployed account to read the domain config back from")?;

    // Init happened: the five slots hold the FIRST note's params.
    assert_domain_config_slots(account, &obs.domain_params, "row B (post-init read-back)")?;

    // Init-once: the second consumption attempt trapped with EXACTLY the reinit error.
    let err = obs.reinit_error.as_ref().context(
        "row B: the SECOND domain_init consumption attempt did not fail — the init-once gate did \
         not hold",
    )?;
    ensure!(
        err.contains(ERR_DOMAIN_REINIT_TEXT),
        "row B: the second domain_init failed, but not with the init-once gate error \
         ('{ERR_DOMAIN_REINIT_TEXT}'); got: {err}",
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

    // Belt-and-braces: had the second note's params been written, the first-params compare above
    // would already have failed; make the negative explicit anyway when the two sets differ.
    if obs.reinit_params.domain != obs.domain_params.domain {
        let domain = storage_word(after, DOMAIN_CONFIG_SLOT_LABEL)?;
        ensure!(
            domain
                != Word::from([
                    Felt::from(obs.reinit_params.domain),
                    Felt::ZERO,
                    Felt::ZERO,
                    Felt::ZERO
                ]),
            "row B: the SECOND domain_init's domain value appeared in storage — the init-once \
             gate did not hold",
        );
    }

    if obs.second_note_consumed {
        bail!(
            "row B: the SECOND domain_init note was consumed on-chain — the init-once gate did \
             not hold (note {})",
            obs.second_note_id,
        );
    }

    Ok(())
}
