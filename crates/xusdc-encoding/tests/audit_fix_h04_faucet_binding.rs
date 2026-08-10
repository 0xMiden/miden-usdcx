//! Regression test for audit finding H-04 — after binding the `set_attester` admin note to its
//! target faucet, a foreign account can no longer consume a note routed to another faucet.
//!
//! Two production faucets share a chain (same administrator, distinct ids). A `set_attester` note
//! is built for `faucet_a`; `faucet_b` attempting to consume it now TRAPS at the note script's
//! faucet-binding check, while `faucet_a` consumes it and applies the write. Before the fix,
//! `faucet_b` consumed it and nullified the note (the H-04 PoC on `audit/pocs`).

mod support;

use anyhow::{Context as _, Result};
use miden_protocol::account::AccountComponent;
use miden_protocol::asset::AssetAmount;
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_testing::{assert_transaction_executor_error, MockChain};
use support::mint_transport::*;
use support::*;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;
use xusdc_encoding::xreserve::encoding::EthBytes32;

fn production_components() -> Result<Vec<AccountComponent>> {
    XReserveStablecoinBuilder::new(
        AssetAmount::new(MAX_SUPPLY).context("max_supply")?,
        AssetAmount::new(0).context("token_supply")?,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
    )
    .map_err(|e| anyhow::anyhow!("building faucet: {e}"))?
    .with_domain_config(
        TEST_DOMAIN,
        TEST_SOURCE_DOMAIN,
        EthBytes32::new(test_xreserve_contract()),
    )
    .build_components()
    .map_err(|e| anyhow::anyhow!("composing faucet: {e}"))
}

#[tokio::test]
async fn a_foreign_faucet_cannot_consume_a_bound_admin_note() -> Result<()> {
    let mut mc = MockChain::builder();
    let faucet_a =
        add_network_faucet_account(&mut mc, production_components()?).context("adding faucet_a")?;
    let faucet_b =
        add_network_faucet_account(&mut mc, production_components()?).context("adding faucet_b")?;

    let k = gen_attester(9, b"attester-K-h04-fix").commitment;
    let note: Note =
        XReserveSetAttesterNote::create(administrator(), faucet_a.id(), k, 1, &mut note_rng(4001))
            .context("building the set_attester note bound to faucet_a")?;
    mc.add_output_note(RawOutputNote::Full(note.clone()));
    let mut chain = mc.build().context("building the chain")?;

    // faucet_b — NOT the bound faucet — now TRAPS at the note's faucet-binding check.
    let wrong_faucet =
        MasmError::from_static_str("set_attester note is not bound to the consuming faucet");
    let denied = chain
        .build_transaction(faucet_b.id())
        .authenticated_input_note(note.id())
        .build()
        .context("faucet_b consume tx build")?
        .execute()
        .await;
    assert_transaction_executor_error!(denied, wrong_faucet);

    // faucet_a — the bound faucet — consumes it and applies the write. The note was never
    // nullified by faucet_b, so the intended admin action still lands.
    let tx = consume_note(&chain, faucet_a.id(), note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the bound faucet must still consume its own note: {e}"))?;
    commit(&mut chain, &tx)?;
    let fa = committed(&chain, faucet_a.id())?;
    assert_eq!(
        read_map_word(&fa, XRESERVE_ATTESTERS_SLOT_LABEL, k)?,
        marker(),
        "H-04 fix: the bound faucet applies the admin write the note carried"
    );

    Ok(())
}
