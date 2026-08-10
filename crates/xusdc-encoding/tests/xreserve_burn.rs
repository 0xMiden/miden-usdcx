//! `XReserveBurnNote` suite: the public note a holder emits to withdraw, and the evidence Circle
//! reads to release the corresponding native USDC on the source chain.
//!
//! The note is built fresh per burn, following the same shape as the standard pay-to-id note, but
//! it is consumed by the faucet's stock `receive_and_burn` script rather than by a wallet. It is
//! always `NoteType::Public`, always carries the fixed xUSDC burn tag, and writes its
//! `(amount, destDomain, destRecipient, salt)` withdrawal payload into `NoteStorage.items` using
//! the shared encoding codec, so on-chain bytes and off-chain decode never drift.
//!
//! Public and tagged is the whole point: the off-chain listener finds these notes by tag, and
//! Circle's withdrawal only happens because the burn is externally observable. So the tests assert
//! the note type and the exact tag value DIRECTLY against an independent constant rather than
//! inferring either from the payload — a note that turned Private, or drifted to another tag,
//! must fail a test named for that fact, not pass quietly.
//!
//! Two further seams are covered. Emitting the note and consuming it through the faucet must
//! actually reduce `token_supply` by exactly the burned amount — a burn that does not shrink
//! supply would break the 1:1 backing. And the items as they land on-chain must equal both what
//! the Rust codec encodes and what the golden vectors pin, so the listener decoding a real note
//! sees the same fields the producer intended.

mod support;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::note::{NoteAttachmentScheme, NoteTag, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::LocalTransactionProver;
use support::*;
use xusdc_encoding::note::xreserve_burn::{
    XReserveBurnNote, FIXED_XUSDC_BURN_TAG, XUSDC_BURN_EVIDENCE_ATTACHMENT_SCHEME,
};
use xusdc_encoding::vectors::load;
use xusdc_encoding::xreserve::encoding::XReserveBurnItems;

// HARNESS
// ================================================================================================

/// A fixed-seed rng for standalone note construction, so runs are reproducible. It feeds only the
/// note's serial number — the payload layout and the tag are constants and never depend on it.
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// A representative withdrawal payload: the given amount plus an arbitrary destination domain,
/// destination recipient, and salt. The non-amount fields are only there to be carried and read
/// back unchanged, so their values are arbitrary as long as they round-trip.
fn sample_items(amount: u64) -> XReserveBurnItems {
    XReserveBurnItems {
        amount: AssetAmount::new(amount).expect("amount within AssetAmount bounds"),
        dest_domain: 9,
        dest_recipient: [0xABu8; 32],
        salt: [0xCDu8; 32],
    }
}

/// Emits a real `XReserveBurnNote` on a MockChain and returns the evidence-attachment payload of
/// the note as it actually landed on-chain.
///
/// The chain is deliberately minimal: a basic faucet and one user holding the maximum asset
/// amount, so any amount a vector asks for can actually be moved. What comes back is the on-chain
/// truth the parity test compares the codec's output against — not a re-encode of the same Rust
/// call, which would prove nothing.
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
    // The user account emits the note itself, so it needs the emit helper installed: note creation
    // runs in account context, not in the transaction script.
    let user = add_emitting_wallet(&mut builder, Auth::IncrNonce, [seed_asset.into()])?;

    let note = XReserveBurnNote::create(user.id(), faucet.id(), items.clone(), builder.rng_mut())?;
    // The asset the emit moves equals the note's own NoteAssets asset (single-sourced from the amount).
    let note_asset = FungibleAsset::new(faucet.id(), u64::from(items.amount))?;
    let chain = builder.build()?;

    let tx0 = try_emit_burn_note(&chain, &note, &note_asset, faucet.id(), user.id())
        .await
        .map_err(|e| anyhow::anyhow!("emit tx0 failed: {e:?}"))?;
    let emitted = tx0.output_notes().get_note(0);
    let scheme = NoteAttachmentScheme::new(XUSDC_BURN_EVIDENCE_ATTACHMENT_SCHEME)
        .expect("the evidence attachment scheme is valid");
    let attachment = emitted
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == scheme)
        .expect("the emitted burn note carries the evidence attachment");
    Ok(attachment.as_elements()[..XReserveBurnNote::EVIDENCE_PAYLOAD_FELTS].to_vec())
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

// 2 — PAYLOAD SCHEMA: the withdrawal fields live in NoteStorage, not in metadata
// ================================================================================================

#[test]
fn burn_note_payload_schema() {
    let sender = test_account_id(3);
    let faucet = test_faucet_id(1);
    let items = sample_items(5_000);
    let note = XReserveBurnNote::create(sender, faucet, items.clone(), &mut note_rng(2))
        .expect("constructing the burn note");

    // The payload sits in the evidence attachment in the codec's field order and widths, so
    // decoding it returns exactly what was encoded.
    let evidence = XReserveBurnNote::evidence_items(&note)
        .expect("the burn note carries the evidence attachment");
    assert_eq!(evidence.len(), 18, "DC-7 is exactly 18 felts");
    let decoded = XReserveBurnItems::decode(&evidence).expect("decoding DC-7 items");
    assert_eq!(
        decoded, items,
        "the evidence-attachment decode == input items (DC-7 order)"
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

    // Note metadata exposes only the burner as sender. The destination domain and recipient stay
    // in NoteStorage, so they are read from the payload the listener decodes rather than inferred
    // from a metadata field that means something else.
    assert_eq!(
        note.metadata().sender(),
        sender,
        "metadata.sender == depositor"
    );
}

// 3 — PRODUCING SIDE: the constructor can only make Public notes (it takes no note-type argument)
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

// 4 — PARITY: the items on the emitted note equal the codec's encoding and the golden vectors
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
        let expected = items.encode();
        let got = emitted_items_for(&items).await?;
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "vector {}: emitted NoteStorage.items == XReserveBurnItems::encode",
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

// 5 — CREATE-THEN-CONSUME SEAM: the faucet consumes a real note and its supply falls by the amount
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

    // The note is emitted in one block and consumed in the next — a burn note consumed in its own
    // block is erased instead (covered at the end of this file). Consuming runs the stock
    // `receive_and_burn`, which applies the faucet's minimum-burn policy before destroying the asset.
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

// 6 — a holder cannot burn more than they hold: the asset never moves into the note
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

// 7 — the accept side of that boundary: burning exactly the full balance is allowed
// ================================================================================================

/// Burning an amount equal to the holder's entire balance succeeds.
///
/// This is the accepting edge of the insufficient-balance check above: at exactly the balance the
/// emit must go through, the holder's vault must end up empty, and `token_supply` must fall by the
/// full amount. The seam test further up happens to burn the whole seeded balance too, but it
/// never asserts that fact, so a change to its fixture constants would quietly stop covering this
/// edge. Asserting the empty vault and the exact decrement here keeps the boundary pinned.
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

// 8 — a burn note created and consumed inside one block is erased
// ================================================================================================

/// A same-block create-and-consume destroys the evidence, which is why a burn takes two blocks.
///
/// The user emits the note and the faucet consumes it unauthenticated in the SAME block. The
/// protocol then erases the note: it is absent from the block's output notes, not retrievable, not
/// committed, and produces no nullifier. The burn itself still happens — the emitting
/// transaction's account delta commits and `token_supply` drops by the burned amount — so the
/// tokens are gone with nothing on-chain for the off-chain listener to find or for Circle to be
/// shown. That asymmetry is the reason the withdrawal flow requires the consume to land in a later
/// block than the creation, and this test pins the erasure semantics on the real note and the real
/// burn policy rather than on a stand-in.
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
        .with_dynamically_linked_package(emit_helper_component()?.component_code().clone())?
        .compile_tx_script(send_burn_note_script(&note, &h.asset, h.faucet_id))?;
    let tx0 = chain
        .build_transaction(h.user_id)
        .tx_script(tx_script)
        // the routing-target attachment's content, keyed by its commitment for `add_attachment`.
        .extend_advice_inputs(attachment_advice(&note))
        .expected_output_note(RawOutputNote::Full(note.clone()))
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
        .build_transaction(h.faucet_id)
        .unauthenticated_input_note(note.clone())
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
