//! P5-01 D5e mint-effects grounding canary — MockChain gate.
//!
//! Proves, with RUNNING code (not assembly), the faucet write-side kernel primitives that D5e's
//! `apply_mint_effects` will consume, on a `FungibleFaucet` account that ALSO carries a custom
//! component:
//!   - the `token_config` value-slot read/modify/write (`active_account::get_item` +
//!     `native_account::set_item`) — `bump_token_supply`,
//!   - the nonce SET (`native_account::set_map_item`) — `set_nonce_marker`,
//!   - the mint + P2ID note emission (`p2id::new` + `faucet::create_fungible_asset` +
//!     `faucet::mint` + `output_note::add_asset`) — `mint_and_emit`,
//! and that the post-tx assertion APIs work: the committed `OutputNote` asset/amount/faucet_id,
//! the `StorageSlotDelta::Value` token_config delta, and the `StorageSlotDelta::Map` nonce delta.

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotDelta,
    StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_testing::{Auth, MockChain};

use xusdc_canary_mint_effects::{CANARY_MASM, CANARY_PATH, TOKEN_CONFIG_SLOT_LABEL, USED_SLOT_LABEL};

// Parity source of truth (Rust side) — the MASM `asm/canary_mint.masm` declares the SAME literals.
const AMOUNT: u64 = 1000;
const MAX_SUPPLY: u64 = 1_000_000;
const TEST_KEY: [u32; 4] = [11, 12, 13, 14];
const MARKER: [u32; 4] = [1, 0, 0, 0];

#[tokio::test]
async fn mint_effects_execute_and_commit_under_mockchain() -> anyhow::Result<()> {
    // 1. Assemble the canary component (SAFE CodeBuilder path) and bind its map slot.
    let code = CodeBuilder::new().compile_component_code(CANARY_PATH, CANARY_MASM)?;
    let used_slot =
        StorageSlot::with_map(StorageSlotName::new(USED_SLOT_LABEL)?, StorageMap::new());
    let canary_component = AccountComponent::new(
        code.clone(),
        vec![used_slot],
        AccountComponentMetadata::new("xusdc-canary-mint-effects"),
    )?;

    // 2. Build the standard FungibleFaucet component (provides the token_config value slot +
    //    faucet-ness). token_supply starts at 0; max_supply is generous.
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("XUSDC")?)
        .symbol(TokenSymbol::new("XUSDC")?)
        .decimals(6)
        .max_supply(AssetAmount::new(MAX_SUPPLY)?)
        .token_supply(AssetAmount::new(0)?)
        .build()?;

    // 3. MockChain: a recipient wallet + the faucet account carrying BOTH components.
    let mut builder = MockChain::builder();
    let recipient = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet_account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [faucet.into(), canary_component])?;
    let mock_chain = builder.build()?;

    let recipient_suffix = recipient.id().suffix();
    let recipient_prefix = recipient.id().prefix().as_felt();

    // 4. tx script: set the nonce marker, mint + emit the P2ID note to the recipient, bump supply.
    let tx_src = format!(
        r#"
use {CANARY_PATH}->canary

begin
    call.canary::set_nonce_marker

    push.{recipient_prefix} push.{recipient_suffix}
    call.canary::mint_and_emit

    call.canary::bump_token_supply

    exec.::miden::core::sys::truncate_stack
end
"#
    );
    let tx_script =
        CodeBuilder::new().with_dynamically_linked_library(&code)?.compile_tx_script(tx_src)?;

    // 5. Execute against the faucet account (no input notes).
    let executed = mock_chain
        .build_tx_context(faucet_account.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    // 6a. OutputNote: exactly one, carrying AMOUNT of the faucet's fungible asset.
    assert_eq!(executed.output_notes().num_notes(), 1, "one output note expected");
    let note = executed.output_notes().get_note(0);
    let asset = note
        .assets()
        .iter_fungible()
        .next()
        .expect("the output note must carry a fungible asset");
    assert_eq!(Felt::from(asset.amount()), Felt::from(AMOUNT as u32), "minted note amount");
    assert_eq!(asset.faucet_id(), faucet_account.id(), "asset faucet id");

    // the note is the canonical P2ID recipient note for the intended recipient (script root +
    // [suffix, prefix] storage) — proves p2id::new emits a real P2ID note, not just the asset.
    let recipient_note = note.recipient().expect("public output note must carry its recipient");
    assert_eq!(
        recipient_note.script().root(),
        P2idNote::script_root(),
        "output note must use the canonical P2ID script root"
    );
    assert_eq!(
        recipient_note.storage().items(),
        [recipient.id().suffix(), recipient.id().prefix().as_felt()].as_slice(),
        "output note storage must be [recipient_suffix, recipient_prefix]"
    );

    // 6b. token_config value-slot delta: token_supply rose to AMOUNT (word[0]).
    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotDelta::Value(cfg) = executed
        .account_delta()
        .storage()
        .get(&cfg_slot)
        .expect("token_config slot must carry a delta")
    else {
        panic!("token_config must be a Value slot delta");
    };
    assert_eq!(cfg[0], Felt::from(AMOUNT as u32), "token_supply must rise by AMOUNT");

    // 6c. nonce map delta: TEST_KEY -> MARKER.
    let used_slot = StorageSlotName::new(USED_SLOT_LABEL)?;
    let StorageSlotDelta::Map(map_delta) = executed
        .account_delta()
        .storage()
        .get(&used_slot)
        .expect("used slot must carry a delta")
    else {
        panic!("used slot must be a Map slot delta");
    };
    let written = map_delta
        .entries()
        .get(&StorageMapKey::new(Word::from(TEST_KEY)))
        .copied()
        .expect("TEST_KEY must appear in the map delta");
    assert_eq!(written, Word::from(MARKER), "nonce marker committed");

    println!("[mint-canary] executed under MockChain (real tx).");
    println!("[mint-canary] output note amount = {}, faucet = {}", AMOUNT, faucet_account.id());
    println!("[mint-canary] token_config delta word[0] = {}", cfg[0]);
    Ok(())
}
