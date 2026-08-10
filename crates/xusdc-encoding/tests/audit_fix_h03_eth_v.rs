//! Regression test for audit finding H-03 — after normalizing the recovery byte in
//! `signature_felts`, a Circle attestation carrying an Ethereum-style `v` (27/28) mints
//! successfully through the real production factory.
//!
//! Before the fix this aborts with `invalid value: Invalid recovery ID` inside the on-chain ECDSA
//! verify precompile (see the H-03 PoC on `audit/pocs`). The note is built via
//! `XUsdcMintNote::create`, which packs the signature through `Signature::to_felts` →
//! `signature_felts`, so this exercises the exact production path the fix touches.

mod support;

use anyhow::{Context as _, Result};
use support::mint_transport::*;
use support::*;
use xusdc_encoding::note::xreserve_mint::{MintAttestation, XUsdcMintNote};

#[tokio::test]
async fn eth_style_v_mints_through_the_production_factory() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;

    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 51);
    let attester = gen_attester(1, &payload);

    // Re-encode the SAME signature with an Ethereum-style recovery byte: byte 64 is the k256
    // recovery id (0 or 1); Circle's EVM signer would carry it as 27 + id.
    let mut eth_sig = attester.sig_bytes;
    let recovery_id = eth_sig[64];
    assert!(recovery_id <= 1, "k256 recovery id is 0 or 1");
    eth_sig[64] = 27 + recovery_id;

    // Build through the production factory (packs via signature_felts → the normalized recovery id).
    let note = XUsdcMintNote::create(
        pf.producer_id,
        pf.faucet_id,
        &payload,
        &MintAttestation::new(eth_sig, attester.pubkey_bytes),
        &mut note_rng(51),
    )
    .map_err(|e| anyhow::anyhow!("the factory must build the mint note: {e}"))?;

    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .context("H-03 fix: an Ethereum-style-v attestation must mint after normalization")?;

    assert_eq!(
        tx.output_notes().num_notes(),
        1,
        "the mint emits the attested output note"
    );
    Ok(())
}
