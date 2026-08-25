//! Row-A assertion suite (written test-first, before the drivers).
//!
//! Matrix row:
//! - **A. Deploy + recognize** — the production faucet deploys to the local node; `GetAccount`
//!   returns it; the network-account allowlists are present and equal the frozen production sets
//!   on-chain; the account is PUBLIC; and the four build-seeded domain-config slots read back from
//!   ON-CHAIN storage.
//!
//! Every check reads the NODE-fetched state carried by [`RowsAbObservations`] — a green here is a
//! statement about the real chain, not about the client's local store.

use std::collections::BTreeSet;

use anyhow::{ensure, Context, Result};
use miden_protocol::account::{Account, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{
    NetworkAccountNoteAllowlist, NetworkAccountTxScriptAllowlist,
};
use miden_standards::tx_script::ExpirationTransactionScript;
use xusdc_encoding::account::xreserve::{XReserveFaucetExtension, XReserveStablecoinBuilder};
use xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts;

use crate::config::DomainParams;
use crate::observations::RowsAbObservations;

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
///   equals EXACTLY the frozen production set (`allowed_note_scripts()`) — extra or missing roots
///   are a composition defect.
/// - The tx-script allowlist slot is present and equals EXACTLY the frozen production set — the one
///   canonical `ExpirationTransactionScript::script_root()` (S12, RATIFIED). The sole-mint-surface /
///   F1 invariant is "exactly the expiration root".
/// - The four BUILD-SEEDED domain-config slots read back from ON-CHAIN storage.
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

    assert_domain_config_slots(account, &obs.domain_params, "row A (build-seed read-back)")?;

    Ok(())
}

/// Asserts the four domain-config slots of `account` hold `params`' values. All four are BUILD-SEEDED
/// at composition time and have no runtime writer, so this is a read-back of the deploy seed.
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

    let source_domain = storage_word(
        account,
        XReserveFaucetExtension::source_domain_config_slot(),
    )?;
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
    let xrc_hi = storage_word(
        account,
        XReserveFaucetExtension::xreserve_contract_hi_slot(),
    )?;
    let xrc_lo = storage_word(
        account,
        XReserveFaucetExtension::xreserve_contract_lo_slot(),
    )?;
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
