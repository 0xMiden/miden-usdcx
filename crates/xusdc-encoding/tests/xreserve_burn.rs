//! `XReserveBurnNote` suite (component CMP-B2, payload codec DC-7): the Circle-facing public
//! burn-event note.
//!
//! A FRESH note (the `P2idNote` idiom) that REUSES the stock
//! burn consume script (`receive_and_burn` → CMP-A10), mandates `NoteType::Public`, bears the fixed
//! xUSDC burn tag, and writes the DC-7 `(amount, destDomain, destRecipient, salt)` payload into
//! `NoteStorage.items` via the shared encoding codec (consumed by reference).
//!
//! The load-bearing proof is OBSERVABILITY NON-VACUITY: `note_type` AND the exact `tag`
//! are asserted DIRECTLY against an independent constant, never inferred from the payload — a wrong
//! tag or a `Private` note must fail a named test. The create→consume seam proves the real note is
//! consumable by the faucet (running CMP-A10) and decrements `token_supply` by exactly the amount.
//! `burn_note_emitted_items_match_codec_vectors` is vector-driven EMITTED-note parity (TV-DUAL-4):
//! the items as they land on-chain equal both the codec encode AND the golden vector felts.

mod support;

use core::slice;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::LocalTransactionProver;
use support::*;
use xusdc_encoding::note::xreserve_burn::{XReserveBurnNote, FIXED_XUSDC_BURN_TAG};
use xusdc_encoding::vectors::load;
use xusdc_encoding::xreserve::encoding::{
    decode_burn_note_items, encode_burn_note_items, XReserveBurnItems,
};

// HARNESS
// ================================================================================================

/// A deterministic standalone note rng (only the serial number depends on it; never the schema/tag).
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// A sample DC-7 payload with an arbitrary (round-trippable) destination + salt.
fn sample_items(amount: u64) -> XReserveBurnItems {
    XReserveBurnItems {
        amount: AssetAmount::new(amount).expect("amount within AssetAmount bounds"),
        dest_domain: 9,
        dest_recipient: [0xABu8; 32],
        salt: [0xCDu8; 32],
    }
}

/// Emits a real `XReserveBurnNote` carrying `items` through a minimal MockChain (basic faucet + a
/// user seeded at `AssetAmount::MAX` so every accept-vector amount moves) and returns the EMITTED
/// output note's `NoteStorage.items` — the on-chain truth the TV-DUAL-4 parity test asserts.
async fn emitted_items_for(items: &XReserveBurnItems) -> anyhow::Result<Vec<Felt>> {
    let cap = u64::from(AssetAmount::MAX);
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "USDCX",
        cap,
        Some(cap),
    )?;
    let seed_asset = FungibleAsset::new(faucet.id(), cap)?;
    // The user EMITS the burn note, so it carries the emit helper (v0.16 #3204: note creation runs
    // in account context — MIGRATION-V16-ALPHA2.md S22).
    let user = add_emitting_wallet(&mut builder, Auth::IncrNonce, [seed_asset.into()])?;

    let note = XReserveBurnNote::create(user.id(), faucet.id(), items.clone(), builder.rng_mut())?;
    // The asset the emit moves equals the note's own NoteAssets asset (single-sourced from the amount).
    let note_asset = FungibleAsset::new(faucet.id(), u64::from(items.amount))?;
    let chain = builder.build()?;

    let tx0 = try_emit_burn_note(&chain, &note, &note_asset, faucet.id(), user.id())
        .await
        .map_err(|e| anyhow::anyhow!("emit tx0 failed: {e:?}"))?;
    let emitted = tx0.output_notes().get_note(0);
    let recipient = emitted
        .recipient()
        .expect("public output note carries its full recipient");
    Ok(recipient.storage().items().to_vec())
}

// 1 — OBSERVABILITY NON-VACUITY: Public + the exact fixed tag, asserted DIRECTLY
// ================================================================================================

#[test]
fn burn_note_is_public_with_fixed_tag() {
    let sender = test_account_id(3);
    let faucet = test_faucet_id(1);
    let note = XReserveBurnNote::create(sender, faucet, sample_items(5_000), &mut note_rng(1))
        .expect("constructing the burn note");

    // Direct (NOT payload-inferred) assertions — a wrong tag or a Private note fails HERE.
    assert_eq!(
        note.metadata().note_type(),
        NoteType::Public,
        "burn note must be Public"
    );
    assert_eq!(
        note.metadata().tag().as_u32(),
        FIXED_XUSDC_BURN_TAG,
        "burn note must bear the fixed full-32-bit xUSDC burn tag",
    );
    // The fixed enumerated tag is structurally NOT the stock account-target tag.
    assert_ne!(
        note.metadata().tag(),
        NoteTag::with_account_target(faucet),
        "the fixed xUSDC burn tag must differ from the stock account-target tag",
    );
}

// 2 — DC-7 PAYLOAD SCHEMA: items in NoteStorage (NOT metadata); assets + sender
// ================================================================================================

#[test]
fn burn_note_payload_schema() {
    let sender = test_account_id(3);
    let faucet = test_faucet_id(1);
    let items = sample_items(5_000);
    let note = XReserveBurnNote::create(sender, faucet, items.clone(), &mut note_rng(2))
        .expect("constructing the burn note");

    // Payload lives in NoteStorage.items, in the exact DC-7 order/width (decode round-trips).
    let storage_items = note.recipient().storage().items();
    assert_eq!(storage_items.len(), 18, "DC-7 is exactly 18 felts");
    let decoded = decode_burn_note_items(storage_items).expect("decoding DC-7 items");
    assert_eq!(
        decoded, items,
        "NoteStorage.items decode == input items (DC-7 order)"
    );

    // NoteAssets carries the burned xUSDC FungibleAsset (amount single-sourced from items.amount).
    let asset = note
        .assets()
        .iter_fungible()
        .next()
        .expect("note carries one fungible asset");
    assert_eq!(asset.faucet_id(), faucet, "asset issued by the faucet");
    assert_eq!(
        asset.amount(),
        items.amount,
        "NoteAssets amount == items.amount"
    );

    // metadata exposes ONLY the depositor as sender (destination fields are in NoteStorage; anti-ASG-13).
    assert_eq!(
        note.metadata().sender(),
        sender,
        "metadata.sender == depositor"
    );
}

// 3 — R-BURN-6 PRODUCING SIDE: the constructor always yields Public (no note_type parameter)
// ================================================================================================

#[test]
fn burn_note_is_never_private() {
    let faucet = test_faucet_id(1);
    for seed in [1u64, 2, 3] {
        let note = XReserveBurnNote::create(
            test_account_id(3),
            faucet,
            sample_items(1_000),
            &mut note_rng(seed),
        )
        .expect("constructing the burn note");
        assert_eq!(
            note.metadata().note_type(),
            NoteType::Public,
            "R-BURN-6: always Public"
        );
        assert_ne!(
            note.metadata().note_type(),
            NoteType::Private,
            "R-BURN-6: never Private"
        );
    }
}

// 4 — TV-DUAL-4 (vector-driven EMITTED-note parity): emitted items == codec encode == golden felts
// ================================================================================================

#[tokio::test]
async fn burn_note_emitted_items_match_codec_vectors() -> anyhow::Result<()> {
    let accept: Vec<_> = load()
        .families
        .bn
        .iter()
        .filter(|v| v.kind == "accept")
        .collect();
    assert!(!accept.is_empty(), "BN accept vectors present");
    for vec in accept {
        let items = vec.expected_struct();
        let expected = encode_burn_note_items(&items);
        let got = emitted_items_for(&items).await?;
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "vector {}: emitted NoteStorage.items == encode_burn_note_items",
            vec.id,
        );
        assert_eq!(
            got.as_slice(),
            vec.items_values().as_slice(),
            "vector {}: emitted NoteStorage.items == golden §7 felts",
            vec.id,
        );
    }
    Ok(())
}

// 5 — CREATE→CONSUME SEAM: faucet consumes the real note (CMP-A10) → token_supply -= amount
// ================================================================================================

#[tokio::test]
async fn burn_note_consumed_by_faucet_decrements() -> anyhow::Result<()> {
    const MAX_SUPPLY: u64 = 1_000_000;
    const TOKEN_SUPPLY: u64 = 100_000;
    const MIN_BURN_SIZE: u64 = 1_000;
    const AMOUNT: u64 = 5_000; // >= MIN_BURN_SIZE and <= TOKEN_SUPPLY

    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        AMOUNT,
    )?;

    // The REAL XReserveBurnNote with the same faucet + user + amount as the harness asset.
    let items = XReserveBurnItems {
        amount: AssetAmount::new(AMOUNT)?,
        dest_domain: 9,
        dest_recipient: [0xABu8; 32],
        salt: [0xCDu8; 32],
    };
    let note = XReserveBurnNote::create(h.user_id, h.faucet_id, items, &mut note_rng(42))?;

    let mut chain = h.chain;
    assert_eq!(
        committed_token_supply(&chain, h.faucet_id)?,
        AssetAmount::new(TOKEN_SUPPLY)?
    );

    // Emit at block N, faucet consumes at N+1 (runs receive_and_burn → execute_burn_policy → CMP-A10).
    let tx1 = run_burn_consume(&mut chain, &note, &h.asset, h.faucet_id, h.user_id)
        .await
        .expect("faucet consumes the XReserveBurnNote via receive_and_burn → CMP-A10");
    chain.add_pending_executed_transaction(&tx1)?;
    chain.prove_next_block()?;

    assert_eq!(
        committed_token_supply(&chain, h.faucet_id)?,
        AssetAmount::new(TOKEN_SUPPLY - AMOUNT)?,
        "committed token_supply -= AMOUNT exactly",
    );
    Ok(())
}

// 6 — R-BURN-5: insufficient holder balance fails the create-tx (the asset can't move into NoteAssets)
// ================================================================================================

#[tokio::test]
async fn burn_note_insufficient_balance_rejects_create() -> anyhow::Result<()> {
    const MAX_SUPPLY: u64 = 1_000_000;
    const TOKEN_SUPPLY: u64 = 100_000;
    const MIN_BURN_SIZE: u64 = 1_000;
    const HELD: u64 = 5_000;

    // The user is seeded with exactly HELD of the asset.
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        HELD,
    )?;

    // A note demanding MORE than the holder's balance.
    let over = HELD + 1;
    let items = XReserveBurnItems {
        amount: AssetAmount::new(over)?,
        dest_domain: 9,
        dest_recipient: [0xABu8; 32],
        salt: [0xCDu8; 32],
    };
    let note = XReserveBurnNote::create(h.user_id, h.faucet_id, items, &mut note_rng(7))?;
    let over_asset = FungibleAsset::new(h.faucet_id, over)?;

    let result = try_emit_burn_note(&h.chain, &note, &over_asset, h.faucet_id, h.user_id).await;
    assert!(
        result.is_err(),
        "R-BURN-5: creating a burn note for more than the holder's balance must fail the create-tx",
    );
    Ok(())
}

// 7 — R-BURN-5 `==balance` ACCEPT boundary: the recipient burns 100% of holdings
// ================================================================================================

/// The `== balance` ACCEPT side of R-BURN-5, pinned EXPLICITLY: the holder burns their ENTIRE
/// holding — the emit succeeds, the holder's vault is EMPTY afterwards, and `token_supply`
/// decrements by exactly the full amount. Honest framing: the seam test above already burns == the
/// seeded balance de facto (the harness seeds the user with exactly `burn_amount`), but nothing
/// ASSERTED the boundary — this pin adds the vault-empty and exact-decrement assertions so a
/// fixture-constant drift cannot silently unpin the accept boundary.
#[tokio::test]
async fn recipient_burns_full_balance() -> anyhow::Result<()> {
    const MAX_SUPPLY: u64 = 1_000_000;
    const TOKEN_SUPPLY: u64 = 100_000;
    const MIN_BURN_SIZE: u64 = 1_000;
    const HELD: u64 = 5_000; // the holder's ENTIRE seeded balance — burned in full

    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        HELD,
    )?;
    let items = sample_items(HELD);
    let note = XReserveBurnNote::create(h.user_id, h.faucet_id, items, &mut note_rng(21))?;

    let mut chain = h.chain;
    let tx1 = run_burn_consume(&mut chain, &note, &h.asset, h.faucet_id, h.user_id)
        .await
        .expect("a burn of the holder's ENTIRE balance (the == boundary of R-BURN-5) must succeed");
    chain.add_pending_executed_transaction(&tx1)?;
    chain.prove_next_block()?;

    assert_eq!(
        chain
            .committed_account(h.user_id)?
            .vault()
            .get_balance(h.asset.id())?,
        AssetAmount::new(0)?,
        "the full-balance emit leaves the holder's vault EMPTY"
    );
    assert_eq!(
        committed_token_supply(&chain, h.faucet_id)?,
        AssetAmount::new(TOKEN_SUPPLY - HELD)?,
        "committed token_supply -= the full holding exactly"
    );
    Ok(())
}

// 8 — same-block erasure with the PRODUCTION note (the canary erasure mechanism)
// ================================================================================================

/// R-BURN-4 with the PRODUCTION `XReserveBurnNote` on the PRODUCTION burn-policy
/// composition (the burn canary proved this mechanism with the STOCK `BurnNote` on a canary
/// fixture): the user emits the note and the faucet consumes it UNAUTHENTICATED in the SAME block
/// — the note is erased (absent from the block's output notes, not retrievable, not committed, no
/// nullifier), yet tx1's account delta COMMITS, so `token_supply` still drops by the burned
/// amount. Pins the exact semantics the canary observed, now on the production note + policy.
#[tokio::test]
async fn production_burn_note_same_block_consume_is_erased() -> anyhow::Result<()> {
    const MAX_SUPPLY: u64 = 1_000_000;
    const TOKEN_SUPPLY: u64 = 100_000;
    const MIN_BURN_SIZE: u64 = 1_000;
    const AMOUNT: u64 = 5_000;

    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        AMOUNT,
    )?;
    let items = sample_items(AMOUNT);
    let note = XReserveBurnNote::create(h.user_id, h.faucet_id, items, &mut note_rng(22))?;
    let mut chain = h.chain;

    // tx0: the user emit-tx creates the production note in-block (executed, then dummy-proven —
    // the canary idiom; the create_*_proven_tx helpers are private to miden-testing).
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_library(&emit_helper_component()?.component_code().clone())?
        .compile_tx_script(send_burn_note_script(&note, &h.asset, h.faucet_id))?;
    let tx0 = chain
        .build_tx_context(h.user_id, &[], &[])?
        .tx_script(tx_script)
        // F5: the routing-target attachment content (keyed by commitment) for `add_attachment`.
        .extend_advice_inputs(attachment_advice(&note))
        .extend_expected_output_notes(vec![RawOutputNote::Full(note.clone())])
        .build()?
        .execute()
        .await?;
    assert_eq!(
        tx0.output_notes().get_note(0).id(),
        note.id(),
        "tx0 emits the production XReserveBurnNote"
    );
    let tx0p = LocalTransactionProver::default().prove_dummy(tx0)?;

    // tx1: the faucet consumes the note UNAUTHENTICATED (not yet committed) — running the real
    // `receive_and_burn` behind the PRODUCTION burn policy.
    let tx1 = chain
        .build_tx_context(h.faucet_id, &[], slice::from_ref(&note))?
        .build()?
        .execute()
        .await?;
    let tx1p = LocalTransactionProver::default().prove_dummy(tx1)?;

    // Create BEFORE consume, then ONE block — the same-block erase shape.
    chain.add_pending_proven_transaction(tx0p);
    chain.add_pending_proven_transaction(tx1p);
    let block = chain.prove_next_block()?;

    // The canary erasure quad, on the production note.
    assert!(
        block
            .body()
            .output_notes()
            .all(|(_, on)| on.id() != note.id()),
        "the production burn note is erased from the block's output notes"
    );
    assert!(
        chain.get_public_note(&note.id()).is_none(),
        "the erased note is not retrievable"
    );
    assert!(
        !chain.is_note_committed(&note.id()),
        "the erased note is not committed"
    );
    assert!(
        !chain.is_note_consumed(&note.nullifier()),
        "no nullifier is created for the erased note"
    );

    // Erasure removes the NOTE, not tx1's account delta: the burn still lands on the ledger.
    assert_eq!(
        committed_token_supply(&chain, h.faucet_id)?,
        AssetAmount::new(TOKEN_SUPPLY - AMOUNT)?,
        "token_supply -= AMOUNT even under same-block erasure"
    );
    Ok(())
}
