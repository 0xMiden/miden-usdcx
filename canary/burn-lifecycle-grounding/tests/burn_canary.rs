//! P5-01 burn-mechanics grounding canary — MockChain gate.
//!
//! Proves, with RUNNING code (not assembly), the STOCK fungible-faucet BURN primitives the later
//! real burn slices build on, using the stock allow-all `BurnAllowAll` placeholder policy that
//! `add_existing_basic_faucet` wires (chain_builder.rs:402) — no real burn policy/schema:
//!
//!   - C1 (next-block lifecycle): a USER creates an asset-bearing `BurnNote` in-block via a send
//!     tx-script (asset moves user-vault -> NoteAssets), the note is retrievable via
//!     `get_public_note` at block N, the faucet consumes it (authenticated) at block N+1, and
//!     `token_supply -= amount`. Public note stays discoverable after consumption (MockChain
//!     retains consumed notes; see report caveat).
//!   - C2 (same-block erasure): the user-create tx and the faucet UNAUTHENTICATED-consume tx land
//!     in ONE block -> the note is erased (absent from block output notes, not committed, no
//!     nullifier), yet the supply still decrements (per-tx account deltas survive erasure).
//!   - B (exactly-one-asset trap): a 0-asset note consumed via the burn script traps with the
//!     stock `ERR_FUNGIBLE_BURN_WRONG_NUMBER_OF_ASSETS`.
//!
//! What this canary does NOT prove (the real-slice boundary): the real burn policy
//! (amount/min/pause, R-BURN-1/2/3), the real burn-note schema/tag/payload (DC-7), set_min_burn,
//! R-BURN-5, burn composition, DEV-2. It uses STOCK components + the allow-all placeholder only.

use core::slice;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountId, StorageSlotDelta, StorageSlotName};
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::note::{
    Note, NoteAssets, NoteRecipient, NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::transaction::{InputNote, RawOutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FAUCET_BURN_AMOUNT_EXCEEDS_TOKEN_SUPPLY, ERR_FUNGIBLE_BURN_WRONG_NUMBER_OF_ASSETS,
};
use miden_standards::note::BurnNote;
use miden_testing::{assert_transaction_executor_error, Auth, MockChain};
use miden_tx::LocalTransactionProver;

use xusdc_canary_burn_lifecycle::{BURN_NOTE_SCRIPT, TOKEN_CONFIG_SLOT_LABEL};

// PLACEHOLDER amounts (the canary asserts mechanics, not magnitudes).
const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
const AMOUNT: u64 = 5_000;

// HARNESS
// ================================================================================================

/// Builds the user send tx-script that emits `burn_note` exactly: it pushes `burn_note`'s recipient
/// digest + metadata (Public, faucet-target tag — matching `BurnNote::create`) into
/// `output_note::create`, then `call`s the BasicWallet `move_asset_to_note` to draw `fungible_asset`
/// from the executing user's vault into that note. The executing account is the user, so the
/// emitted note's metadata sender == user.id() — required for NoteId parity (NoteId commits to
/// details AND metadata).
fn send_burn_note_script(
    burn_note: &Note,
    fungible_asset: &FungibleAsset,
    faucet_id: AccountId,
) -> String {
    let recipient = burn_note.recipient().digest();
    let note_type = Felt::from(NoteType::Public);
    let tag = Felt::from(NoteTag::with_account_target(faucet_id));
    let asset_key = fungible_asset.to_key_word();
    let asset_value = fungible_asset.to_value_word();
    format!(
        r#"
use miden::protocol::output_note
use miden::standards::wallets::basic->wallet

begin
    # create the burn note (empty) carrying burn_note's recipient + metadata.
    push.{recipient}
    push.{note_type}
    push.{tag}
    exec.output_note::create
    # => [note_idx]

    # move the user's single fungible asset from the vault into the note.
    push.{asset_value}
    push.{asset_key}
    # => [ASSET_KEY, ASSET_VALUE, note_idx]
    call.wallet::move_asset_to_note
    # => [pad(16)]

    exec.::miden::core::sys::truncate_stack
end
"#
    )
}

/// Reads the faucet's committed `token_supply` from its `token_config` slot post-block.
fn committed_token_supply(chain: &MockChain, faucet_id: AccountId) -> anyhow::Result<AssetAmount> {
    let storage = chain.committed_account(faucet_id)?.storage();
    Ok(FungibleFaucet::try_from(storage)?.token_supply())
}

/// Asserts the retrieved public note's FULL details match the canonical `burn_note` — id, assets,
/// recipient digest, and metadata (sender/type/tag) — via `InputNote::note()`. This makes the
/// public-note observability the withdrawal flow needs explicit, not just an id / `Some` check.
fn assert_full_burn_note_details(
    retrieved: &InputNote,
    burn_note: &Note,
    user_id: AccountId,
    faucet_id: AccountId,
) {
    let r = retrieved.note();
    assert_eq!(r.id(), burn_note.id(), "retrieved note id");
    assert_eq!(r.assets(), burn_note.assets(), "retrieved note assets");
    assert_eq!(
        r.recipient().digest(),
        burn_note.recipient().digest(),
        "retrieved recipient digest"
    );
    assert_eq!(r.metadata().sender(), user_id, "retrieved metadata sender");
    assert_eq!(
        r.metadata().note_type(),
        NoteType::Public,
        "retrieved note type"
    );
    assert_eq!(
        r.metadata().tag(),
        NoteTag::with_account_target(faucet_id),
        "retrieved metadata tag"
    );
}

// C1 — NEXT-BLOCK LIFECYCLE (user create -> retrieve -> authenticated consume -> supply decrement)
// ================================================================================================

#[tokio::test]
async fn c1_next_block_user_create_retrieve_consume() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "XUSDC",
        MAX_SUPPLY,
        Some(TOKEN_SUPPLY),
    )?;
    let fungible_asset = FungibleAsset::new(faucet.id(), AMOUNT)?;
    let user = builder.add_existing_wallet_with_assets(Auth::IncrNonce, [fungible_asset.into()])?;

    // The canonical burn note (random serial) — the reference we reproduce in-block and consume.
    let burn_note = BurnNote::create(
        user.id(),
        faucet.id(),
        fungible_asset.into(),
        Default::default(),
        builder.rng_mut(),
    )?;

    let mut chain = builder.build()?;

    // Pre-state supply.
    assert_eq!(
        committed_token_supply(&chain, faucet.id())?,
        AssetAmount::new(TOKEN_SUPPLY)?
    );

    // tx0: the user emits `burn_note` in-block (NOT genesis seeding).
    let tx_script = CodeBuilder::new().compile_tx_script(send_burn_note_script(
        &burn_note,
        &fungible_asset,
        faucet.id(),
    ))?;
    let tx0 = chain
        .build_tx_context(user.id(), &[], &[])?
        .tx_script(tx_script)
        // Register the full note details (script/serial/inputs) so the kernel's
        // `before_created` event can resolve the PUBLIC note's details when tx0 creates it.
        .extend_expected_output_notes(vec![RawOutputNote::Full(burn_note.clone())])
        .build()?
        .execute()
        .await?;

    // Assert tx0 emitted a note matching `burn_note` — metadata parity FIRST, then id
    // (NoteId commits to details AND metadata, so both must match).
    assert_eq!(
        tx0.output_notes().num_notes(),
        1,
        "tx0 emits exactly one note"
    );
    let n = tx0.output_notes().get_note(0);
    assert_eq!(
        n.metadata().sender(),
        user.id(),
        "emitted note sender metadata"
    );
    assert_eq!(
        n.metadata().note_type(),
        NoteType::Public,
        "emitted note type"
    );
    assert_eq!(
        n.metadata().tag(),
        NoteTag::with_account_target(faucet.id()),
        "emitted note tag"
    );
    assert_eq!(
        n.recipient_digest(),
        burn_note.recipient().digest(),
        "emitted note recipient digest"
    );
    let emitted_asset = n
        .assets()
        .iter_fungible()
        .next()
        .expect("emitted note carries a fungible asset");
    assert_eq!(
        emitted_asset.faucet_id(),
        faucet.id(),
        "emitted asset faucet id"
    );
    assert_eq!(
        emitted_asset.amount(),
        AssetAmount::new(AMOUNT)?,
        "emitted asset amount"
    );
    assert_eq!(
        n.id(),
        burn_note.id(),
        "emitted note id == BurnNote::create id"
    );

    // Commit block N.
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // tx0 really moved the asset out of the user vault.
    assert_eq!(
        chain
            .committed_account(user.id())?
            .vault()
            .get_balance(fungible_asset.vault_key())?,
        AssetAmount::new(0)?,
        "user vault depleted after tx0"
    );

    // Retrievable at block N (public-note discoverability).
    assert!(
        chain.is_note_committed(&burn_note.id()),
        "burn note committed at block N"
    );
    let retrieved = chain
        .get_public_note(&burn_note.id())
        .expect("public burn note retrievable at block N");
    assert_full_burn_note_details(&retrieved, &burn_note, user.id(), faucet.id());
    assert!(
        chain.is_note_unspent(&burn_note.nullifier()),
        "nullifier unspent before consume"
    );

    // Block N+1: the faucet consumes the now-authenticated note by id (runs receive_and_burn).
    let tx1 = chain
        .build_tx_context(faucet.id(), &[burn_note.id()], &[])?
        .build()?
        .execute()
        .await?;

    // tx-level proof: token_config Value-slot delta reflects the decremented supply.
    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotDelta::Value(cfg) = tx1
        .account_delta()
        .storage()
        .get(&cfg_slot)
        .expect("token_config slot must carry a delta after the burn")
    else {
        panic!("token_config must be a Value slot delta");
    };
    assert_eq!(
        cfg[0],
        Felt::from((TOKEN_SUPPLY - AMOUNT) as u32),
        "token_config word[0] == token_supply - AMOUNT"
    );

    chain.add_pending_executed_transaction(&tx1)?;
    chain.prove_next_block()?;

    // Committed supply decremented by exactly AMOUNT (the burn analog of the proven mint increment).
    assert_eq!(
        committed_token_supply(&chain, faucet.id())?,
        AssetAmount::new(TOKEN_SUPPLY - AMOUNT)?,
        "committed token_supply -= AMOUNT"
    );
    assert!(
        chain.is_note_consumed(&burn_note.nullifier()),
        "nullifier consumed after burn"
    );

    // Public note still discoverable AFTER consumption — assert the FULL details still match.
    // NOTE: this holds because MockChain marks the nullifier spent but does not yet prune
    // committed_notes (chain.rs:920-928 TODO) — a harness behavior, not a protocol guarantee. The
    // durable burn-event observability is a local-node / withdrawal-attester concern (see
    // BURN-MECHANICS-GROUNDING-REPORT.md).
    let retrieved_after = chain
        .get_public_note(&burn_note.id())
        .expect("public note retained post-consume (MockChain TODO)");
    assert_full_burn_note_details(&retrieved_after, &burn_note, user.id(), faucet.id());

    println!(
        "[burn-canary][C1] user created BurnNote in-block; retrievable at N; faucet burned at N+1."
    );
    println!(
        "[burn-canary][C1] token_supply {} -> {} (-= {}).",
        TOKEN_SUPPLY,
        TOKEN_SUPPLY - AMOUNT,
        AMOUNT
    );
    Ok(())
}

// C2 — SAME-BLOCK ERASURE (unauthenticated consume; R-BURN-4)
// ================================================================================================

#[tokio::test]
async fn c2_same_block_erasure_unauthenticated_consume() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "XUSDC",
        MAX_SUPPLY,
        Some(TOKEN_SUPPLY),
    )?;
    let fungible_asset = FungibleAsset::new(faucet.id(), AMOUNT)?;
    let user = builder.add_existing_wallet_with_assets(Auth::IncrNonce, [fungible_asset.into()])?;
    let burn_note = BurnNote::create(
        user.id(),
        faucet.id(),
        fungible_asset.into(),
        Default::default(),
        builder.rng_mut(),
    )?;
    let mut chain = builder.build()?;

    // tx0: user send-tx emits burn_note in-block; executed then dummy-proven (exact — the
    // create_*_proven_tx helpers live in a private module, so we inline execute + prove_dummy).
    let tx_script = CodeBuilder::new().compile_tx_script(send_burn_note_script(
        &burn_note,
        &fungible_asset,
        faucet.id(),
    ))?;
    let tx0 = chain
        .build_tx_context(user.id(), &[], &[])?
        .tx_script(tx_script)
        // Register the full note details (script/serial/inputs) so the kernel's
        // `before_created` event can resolve the PUBLIC note's details when tx0 creates it.
        .extend_expected_output_notes(vec![RawOutputNote::Full(burn_note.clone())])
        .build()?
        .execute()
        .await?;
    assert_eq!(
        tx0.output_notes().get_note(0).id(),
        burn_note.id(),
        "tx0 emits burn_note"
    );
    let tx0p = LocalTransactionProver::default().prove_dummy(tx0.clone())?;

    // tx1: the faucet consumes burn_note UNAUTHENTICATED — &[] authenticated ids, &[burn_note]
    // unauthenticated note values (the note is not committed yet). This is the inlined body of
    // create_unauthenticated_notes_proven_tx(faucet.id(), slice::from_ref(&burn_note)).
    let tx1 = chain
        .build_tx_context(faucet.id(), &[], slice::from_ref(&burn_note))?
        .build()?
        .execute()
        .await?;
    let tx1p = LocalTransactionProver::default().prove_dummy(tx1.clone())?;

    // Push create BEFORE consume (ordering: NoteConsumedBeforeCreated otherwise), then ONE block.
    chain.add_pending_proven_transaction(tx0p);
    chain.add_pending_proven_transaction(tx1p);
    let block = chain.prove_next_block()?;

    // Erasure: the same-block create+consume note is gone.
    assert!(
        block
            .body()
            .output_notes()
            .all(|(_, on)| on.id() != burn_note.id()),
        "burn note erased from block output notes"
    );
    assert!(
        chain.get_public_note(&burn_note.id()).is_none(),
        "erased note not retrievable"
    );
    assert!(
        !chain.is_note_committed(&burn_note.id()),
        "erased note not committed"
    );
    assert!(
        !chain.is_note_consumed(&burn_note.nullifier()),
        "no nullifier created for erased note"
    );

    // tx0 actually ran (the send-tx analog of "spawn note consumed"): user vault depleted.
    assert_eq!(
        chain
            .committed_account(user.id())?
            .vault()
            .get_balance(fungible_asset.vault_key())?,
        AssetAmount::new(0)?,
        "tx0 moved the asset out of the user vault"
    );

    // Audit-bait, asserted EMPIRICALLY: erasure removes the note, not tx1's account-state delta —
    // so the faucet's committed token_supply still drops by AMOUNT.
    assert_eq!(
        committed_token_supply(&chain, faucet.id())?,
        AssetAmount::new(TOKEN_SUPPLY - AMOUNT)?,
        "token_supply -= AMOUNT even under same-block erasure"
    );

    println!("[burn-canary][C2] same-block create+consume: note erased; no nullifier; supply still -= {}.", AMOUNT);
    Ok(())
}

// B — EXACTLY-ONE-ASSET TRAP (0-asset note)
// ================================================================================================

#[tokio::test]
async fn b_zero_asset_note_traps_wrong_number_of_assets() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "XUSDC",
        MAX_SUPPLY,
        Some(TOKEN_SUPPLY),
    )?;
    let sender = builder.add_existing_wallet(Auth::IncrNonce)?;

    // A note with the stock burn script but ZERO assets -> receive_and_burn's exactly-one-asset
    // assert must trip. (This negative case is independent of the user-create lifecycle, so a
    // committed note is fine here.)
    let note_script = CodeBuilder::default().compile_note_script(BURN_NOTE_SCRIPT)?;
    let serial_num = Word::from([9u32, 9, 9, 9]);
    let vault = NoteAssets::new(vec![])?;
    let metadata = PartialNoteMetadata::new(sender.id(), NoteType::Public)
        .with_tag(NoteTag::with_account_target(faucet.id()));
    let inputs = NoteStorage::new(vec![])?;
    let recipient = NoteRecipient::new(serial_num, note_script, inputs);
    let zero_asset_note = Note::new(vault, metadata, recipient);

    builder.add_output_note(RawOutputNote::Full(zero_asset_note.clone()));
    let chain = builder.build()?;

    let tx = chain
        .build_tx_context(faucet.id(), &[zero_asset_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(tx, ERR_FUNGIBLE_BURN_WRONG_NUMBER_OF_ASSETS);

    println!(
        "[burn-canary][B] 0-asset burn note trapped ERR_FUNGIBLE_BURN_WRONG_NUMBER_OF_ASSETS."
    );
    Ok(())
}

// B2 — EXCEEDS-SUPPLY TRAP (burn amount > token_supply)
// ================================================================================================

#[tokio::test]
async fn b_exceeds_supply_traps_amount_exceeds_token_supply() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_existing_basic_faucet(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        "XUSDC",
        MAX_SUPPLY,
        Some(TOKEN_SUPPLY),
    )?;
    let sender = builder.add_existing_wallet(Auth::IncrNonce)?;

    // A single-asset burn note carrying MORE than the faucet's current token_supply -> stock
    // receive_and_burn's `amount <= token_supply` guard (fungible.masm:432-433) must trip. Mirrors
    // the stock `faucet_burn_fungible_asset_fails_amount_exceeds_token_supply` test. Negative case,
    // so a committed note is fine.
    let over_amount = TOKEN_SUPPLY + 1;
    let fungible_asset = FungibleAsset::new(faucet.id(), over_amount)?;
    let note_script = CodeBuilder::default().compile_note_script(BURN_NOTE_SCRIPT)?;
    let serial_num = Word::from([7u32, 7, 7, 7]);
    let vault = NoteAssets::new(vec![fungible_asset.into()])?;
    let metadata = PartialNoteMetadata::new(sender.id(), NoteType::Public)
        .with_tag(NoteTag::with_account_target(faucet.id()));
    let inputs = NoteStorage::new(vec![])?;
    let recipient = NoteRecipient::new(serial_num, note_script, inputs);
    let over_note = Note::new(vault, metadata, recipient);

    builder.add_output_note(RawOutputNote::Full(over_note.clone()));
    let chain = builder.build()?;

    let tx = chain
        .build_tx_context(faucet.id(), &[over_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(tx, ERR_FAUCET_BURN_AMOUNT_EXCEEDS_TOKEN_SUPPLY);

    println!(
        "[burn-canary][B2] burn {} > token_supply {} trapped ERR_FAUCET_BURN_AMOUNT_EXCEEDS_TOKEN_SUPPLY.",
        over_amount, TOKEN_SUPPLY
    );
    Ok(())
}
