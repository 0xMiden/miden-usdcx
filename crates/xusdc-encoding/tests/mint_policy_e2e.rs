//! ATTESTATION MINT POLICY E2E — the VERIFY-CHAIN + CAP/ADMIN half of the recomposed
//! mint-semantics matrix (Wave-1 S1): REAL stock `MintNote`s (DepositIntent scheme-4 +
//! attestation scheme-5 + `NetworkAccountTarget` scheme-2 attachments) consumed by the
//! PRODUCTION-composed faucet, whose stock `mint_and_send` dispatches
//! `xreserve::mint_policy::check_policy` as the ACTIVE mint policy.
//!
//! This file carries the relocated D5a–D5d verify-stage negatives (attester allowlist +
//! REMOVE/rotation, forged signature, wrong domain / wrong identifier, amount-below-maxFee) and
//! the stock cap discipline (over-cap, plus the `set_max_supply` x mint admin interplay:
//! lower-then-reject, at-cap boundary accept, raise-then-accept). The ASSERT-MATCH binding,
//! recipient-extraction, transport-shape, pause, F1-restatement, and routing legs live in
//! `mint_policy_binding_e2e.rs` (one G3-sized module per concern); the shared
//! production-transport harness (tamper engine + fixtures + drivers) is
//! `support::mint_transport`, consumed by reference. Every negative asserts its EXACT error
//! (never `is_err()`), and the security-critical rejects prove fail-closure (no nonce burned,
//! no supply raised).

mod support;

use anyhow::Result;
use miden_protocol::Felt;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::note::xreserve_admin::{XReserveSetAttesterNote, XReserveSetMaxSupplyNote};

// D5d — ATTESTER ALLOWLIST + SIGNATURE (through the new transport)
// ================================================================================================

/// A NON-allowlisted attester's (valid) attestation rejects: R-MINT-13 through the policy.
#[tokio::test]
async fn mint_rejects_a_non_allowlisted_attester() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 11);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        2, // a DIFFERENT keypair — its commitment is not allowlisted
        None,
        &AttachmentPlan::default(),
        81,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT"),
    )
    .await
}

/// The ALLOWLISTED attester's key with a signature over DIFFERENT bytes rejects: R-MINT-14.
#[tokio::test]
async fn mint_rejects_a_forged_signature() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 12);
    let other = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 13);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        Some(&other), // allowlisted key, signature over the WRONG payload
        &AttachmentPlan::default(),
        82,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_SIG_INVALID"),
    )
    .await
}

/// A REMOVED attester's attestation rejects: the bring-up allowlists attester 1, then a THIRD
/// owner `set_attester` note REMOVES it (`enabled = 0` writes the EMPTY word back). The mint
/// attested by the removed key then trips the same R-MINT-13 allowlist gate, fail-closed —
/// proving the disable write actually clears the allowlist marker through the new transport.
#[tokio::test]
async fn mint_rejects_a_removed_attester() -> Result<()> {
    let mut pf = fixture_with(MAX_SUPPLY, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, faucet_id, MINT_AMOUNT, 0)).commitment;
        vec![
            XReserveSetAttesterNote::create(owner(), faucet_id, commitment, 0, &mut note_rng(954))
                .expect("building the owner remove-attester note"),
        ]
    })?;
    bring_up(&mut pf, 3).await?; // identifier_init + set_attester(enable) + set_attester(REMOVE)
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 30);
    let note = honest_note(&pf, &payload, 99)?; // attested by the (now removed) attester 1
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT"),
    )
    .await
}

/// Attester ROTATION: attester 1 is rotated OUT (removed) and attester 2 rotated IN. A mint
/// attested by the rotated-out key rejects (fail-closed), then a mint attested by the NEW key
/// lands on the SAME chain — the allowlist reflects exactly the rotated state.
#[tokio::test]
async fn mint_rotation_rejects_the_old_attester_and_accepts_the_new() -> Result<()> {
    let mut pf = fixture_with(MAX_SUPPLY, |recipient, faucet_id| {
        let base = payload_for(recipient, faucet_id, MINT_AMOUNT, 0);
        vec![
            XReserveSetAttesterNote::create(
                owner(),
                faucet_id,
                gen_attester(1, &base).commitment,
                0,
                &mut note_rng(955),
            )
            .expect("building the rotate-out note"),
            XReserveSetAttesterNote::create(
                owner(),
                faucet_id,
                gen_attester(2, &base).commitment,
                1,
                &mut note_rng(956),
            )
            .expect("building the rotate-in note"),
        ]
    })?;
    bring_up(&mut pf, 4).await?; // init + enable(1) + remove(1) + enable(2)

    // the ROTATED-OUT key rejects (exact error + no nonce burned + no supply raised)
    let payload_old = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 31);
    let note_old = tampered_mint_note(
        &pf,
        &payload_old,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1, // the rotated-out keypair
        None,
        &AttachmentPlan::default(),
        100,
    )?;
    expect_reject(
        &mut pf,
        note_old,
        &payload_old,
        shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT"),
    )
    .await?;

    // the ROTATED-IN key mints on the same chain
    let payload_new = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 32);
    let note_new = tampered_mint_note(
        &pf,
        &payload_new,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        2, // the rotated-in keypair
        None,
        &AttachmentPlan::default(),
        101,
    )?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note_new).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note_new.id())
        .await
        .map_err(|e| anyhow::anyhow!("the rotated-in attester's mint must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(MINT_AMOUNT)?,
        "the rotated-in attester's mint raises supply by the attested amount"
    );
    Ok(())
}

// D5a — DOMAIN / IDENTIFIER COMPARES (build-seeded domain; note-seeded identifier)
// ================================================================================================

/// A deposit intent addressed to a DIFFERENT remote domain rejects: R-MINT-6 against the
/// BUILD-SEEDED domain config (DEC-4).
#[tokio::test]
async fn mint_rejects_a_wrong_domain() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 14);
    payload[REMOTE_DOMAIN_BYTE_OFF..REMOTE_DOMAIN_BYTE_OFF + 4]
        .copy_from_slice(&TEST_WRONG_DOMAIN.to_be_bytes());
    let note = honest_note(&pf, &payload, 83)?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_WRONG_DOMAIN"),
    )
    .await
}

/// A deposit intent whose remoteToken is not THIS faucet's identifier rejects: R-MINT-7 against
/// the identifier the minimized init note seeded.
#[tokio::test]
async fn mint_rejects_a_wrong_identifier() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 15);
    payload[REMOTE_TOKEN_BYTE_OFF] ^= 0xff;
    let note = honest_note(&pf, &payload, 84)?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_WRONG_IDENTIFIER"),
    )
    .await
}

// D5b — AMOUNT/FEE BOUNDS (relocated into the policy dispatch)
// ================================================================================================

/// An attested amount STRICTLY BELOW the attested maxFee rejects: R-MINT-10 through the policy's
/// relocated D5b stage (`assert_mint_amounts` — the fee could never be covered).
#[tokio::test]
async fn mint_rejects_an_amount_below_max_fee() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 33);
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(MINT_AMOUNT + 1)); // maxFee = amount + 1 -> amount < maxFee
    let note = honest_note(&pf, &payload, 102)?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_AMOUNT_BELOW_FEE"),
    )
    .await
}

// SUPPLY CAP — the STOCK mint_and_send discipline (the policy carries no supply arithmetic)
// ================================================================================================

/// An attested amount above the remaining supply headroom rejects in the STOCK `mint_and_send`
/// cap discipline (the R-MINT-15 semantics, now stock-owned), fail-closed.
#[tokio::test]
async fn mint_rejects_an_over_cap_amount() -> Result<()> {
    let mut pf = fixture_with(MINT_AMOUNT - 1, |_, _| vec![])?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 16);
    let note = honest_note(&pf, &payload, 85)?;
    expect_reject(&mut pf, note, &payload, &err_stock_over_cap()).await
}

// ADMIN INTERPLAY — set_max_supply x mint through the recomposed transport (the runtime cap and
// the attested mint interact exactly as the stock discipline dictates)
// ================================================================================================

/// LOWER-then-over-cap: the owner's `set_max_supply` note LOWERS the cap below the attested
/// amount BEFORE the mint; the attested mint then rejects in the stock cap discipline,
/// fail-closed (no nonce burned, no supply raised).
#[tokio::test]
async fn mint_rejects_after_the_owner_lowers_max_supply_below_the_amount() -> Result<()> {
    let mut pf = fixture_with(MAX_SUPPLY, |_, faucet_id| {
        vec![XReserveSetMaxSupplyNote::create(
            owner(),
            faucet_id,
            MINT_AMOUNT - 1,
            &mut note_rng(957),
        )
        .expect("building the owner lower-cap note")]
    })?;
    bring_up(&mut pf, 3).await?; // identifier_init + set_attester + set_max_supply(lower)
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 34);
    let note = honest_note(&pf, &payload, 103)?;
    expect_reject(&mut pf, note, &payload, &err_stock_over_cap()).await
}

/// AT-CAP boundary: from a build cap BELOW the attested amount, the owner's note RAISES the cap
/// to EXACTLY that amount; the mint then lands with `token_supply == max_supply` — the boundary
/// ACCEPTS (the cap is `<=`, not `<`), and the acceptance is attributable to the admin note.
#[tokio::test]
async fn mint_accepts_at_the_exact_raised_cap_boundary() -> Result<()> {
    let mut pf = fixture_with(MINT_AMOUNT - 1, |_, faucet_id| {
        vec![
            XReserveSetMaxSupplyNote::create(owner(), faucet_id, MINT_AMOUNT, &mut note_rng(958))
                .expect("building the owner raise-to-boundary note"),
        ]
    })?;
    bring_up(&mut pf, 3).await?; // identifier_init + set_attester + set_max_supply(= amount)
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 35);
    let note = honest_note(&pf, &payload, 104)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the at-cap boundary mint must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(MINT_AMOUNT)?,
        "the boundary mint fills the raised cap exactly (supply == max_supply)"
    );
    Ok(())
}

/// RAISE-then-accepts: under the too-low build cap the attested mint REJECTS over-cap (the low
/// cap binds); after the owner's raise note lands, a fresh-nonce mint of the SAME amount
/// succeeds — the runtime raise is what unlocks the mint.
#[tokio::test]
async fn mint_accepts_after_the_owner_raises_max_supply() -> Result<()> {
    let mut pf = fixture_with(MINT_AMOUNT - 1, |_, faucet_id| {
        vec![
            XReserveSetMaxSupplyNote::create(owner(), faucet_id, MAX_SUPPLY, &mut note_rng(959))
                .expect("building the owner raise-cap note"),
        ]
    })?;
    bring_up(&mut pf, 2).await?; // identifier_init + set_attester — the raise stays unconsumed

    // under the low build cap the attested amount rejects (the cap binds pre-raise)
    let payload_low = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 36);
    let note_low = honest_note(&pf, &payload_low, 105)?;
    expect_reject(&mut pf, note_low, &payload_low, &err_stock_over_cap()).await?;

    // the owner's raise lands, then a fresh-nonce mint of the same amount succeeds
    consume_seeded_admin_note(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 37);
    let note = honest_note(&pf, &payload, 106)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the post-raise mint must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(MINT_AMOUNT)?,
        "the post-raise mint raises supply by the attested amount"
    );
    Ok(())
}
