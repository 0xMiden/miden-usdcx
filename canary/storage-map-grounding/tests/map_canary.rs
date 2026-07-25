//! P5-01 storage-map grounding canary — MockChain gate.
//!
//! Drives the trivial one-map-slot component through the SAFE pipeline (no raw `Assembler`):
//!   `CodeBuilder::compile_component_code` -> `StorageSlot::with_map` (declare the map slot) ->
//!   `AccountComponent::new` (bind) -> MockChain account -> tx script `call`s the map procs ->
//!   `execute` -> assert.
//!
//! It proves each `<questions_to_resolve>` item with RUNNING code, not just assembly:
//!   Q1 declare a map slot (`StorageSlot::with_map` + `word("...")[0..2]` binding),
//!   Q2 write `KEY -> VALUE` (`native_account::set_map_item`),
//!   Q3 read it back (`active_account::get_map_item`),
//!   Q4 an unset key returns EMPTY_WORD (asserted twice, in MASM),
//!   Q5 Word -> Word cardinality (the key and value are Words),
//!   Q6 post-tx map state via the `StorageMapDelta` on the account delta,
//!   Q7 MockChain auto-wires the storage-map SMT advice — there is NO manual advice/host wiring.

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotDelta,
    StorageSlotName,
};
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};

use xusdc_canary_storage_map::{CANARY_MASM, CANARY_PATH, USED_SLOT_LABEL};

// Parity source of truth (Rust side). `asm/canary_map.masm` declares the SAME literals as the
// named consts TEST_KEY and MARKER; the passing test IS the masm-rust-constant-parity check — if
// the two sides drift, the post-write read assertion (in MASM) and the delta assertion (here)
// fail. EMPTY_WORD is `[0, 0, 0, 0]`.
const TEST_KEY: [u32; 4] = [11, 12, 13, 14];
const MARKER: [u32; 4] = [1, 0, 0, 0];

/// Formats a 4-felt word as a MASM `push` literal, e.g. `[1,0,0,0]`.
fn word_lit(w: [u32; 4]) -> String {
    format!("[{},{},{},{}]", w[0], w[1], w[2], w[3])
}

#[tokio::test]
async fn storage_map_declare_write_read_empty_under_mockchain() -> anyhow::Result<()> {
    // 1. Assemble the canary component via the SAFE CodeBuilder path -> AccountComponentCode.
    let code = CodeBuilder::new().compile_component_code(CANARY_PATH, CANARY_MASM)?;

    // 2. Q1 — declare ONE map storage slot, bound by the same namespaced label the MASM
    //    `word("...")` const hashes. The map starts EMPTY, so TEST_KEY/UNSET_KEY are unset.
    let map_slot =
        StorageSlot::with_map(StorageSlotName::new(USED_SLOT_LABEL)?, StorageMap::new());
    let metadata = AccountComponentMetadata::new("xusdc-canary-storage-map");
    let component = AccountComponent::new(code.clone(), vec![map_slot], metadata)?;

    // 3. MockChain account built from the canary component (auth appended by the helper).
    let mut builder = MockChain::builder();
    let account = builder.add_existing_account_from_components(Auth::IncrNonce, [component])?;
    let mock_chain = builder.build()?;

    // 4. tx script `call`s the map procs. The component library is linked dynamically so the
    //    `call.canary::*` paths resolve at assembly time.
    let marker = word_lit(MARKER);
    let tx_src = format!(
        r#"
use {CANARY_PATH}->canary

begin
    # Q4: TEST_KEY is unwritten -> get_map_item returns EMPTY_WORD.
    call.canary::map_read_test
    push.[0,0,0,0]
    assert_eqw.err="test key must read EMPTY_WORD before write"

    # Q2: write MARKER at TEST_KEY via native_account::set_map_item.
    call.canary::map_write_marker

    # Q2 + Q3: TEST_KEY now reads MARKER via active_account::get_map_item.
    call.canary::map_read_test
    push.{marker}
    assert_eqw.err="test key must read MARKER after write"

    # Q4: a never-written key still reads EMPTY_WORD (writes are key-scoped).
    call.canary::map_read_unset
    push.[0,0,0,0]
    assert_eqw.err="unset key must read EMPTY_WORD"

    exec.::miden::core::sys::truncate_stack
end
"#
    );
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_library(&code)?
        .compile_tx_script(tx_src)?;

    // 5. Execute against MockChain. Q7: the storage-map SMT witnesses are auto-wired by
    //    build_tx_context/execute — there is NO manual advice-provider or host wiring here.
    let executed = mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    // The tx mutated account state (the auth component increments the nonce).
    assert_eq!(executed.account_delta().nonce_delta(), Felt::ONE);

    // 6. Q6 — assert post-tx map state via the StorageMapDelta on the account delta.
    let slot_name = StorageSlotName::new(USED_SLOT_LABEL)?;
    let test_key = StorageMapKey::new(Word::from(TEST_KEY));
    let marker_word = Word::from(MARKER);

    let slot_delta = executed
        .account_delta()
        .storage()
        .get(&slot_name)
        .expect("the USED slot must carry a storage delta after the write");
    let StorageSlotDelta::Map(map_delta) = slot_delta else {
        panic!("the USED slot delta must be a Map delta");
    };
    let written = map_delta
        .entries()
        .get(&test_key)
        .copied()
        .expect("TEST_KEY must appear in the storage-map delta");

    // Per-step running-code evidence (visible under `--nocapture`).
    println!("[canary] executed under MockChain (real tx, not assemble-only).");
    println!(
        "[canary] in-MASM assertions PASSED: (Q4) TEST_KEY read EMPTY_WORD before write; \
         (Q2/Q3) TEST_KEY read MARKER after write; (Q4) UNSET_KEY read EMPTY_WORD."
    );
    println!("[canary] nonce_delta = {}", executed.account_delta().nonce_delta());
    println!(
        "[canary] (Q6) StorageMapDelta on slot '{USED_SLOT_LABEL}': {} changed entr(y/ies); \
         TEST_KEY {test_key:?} -> {written:?}",
        map_delta.num_entries(),
    );

    assert_eq!(written, marker_word, "delta value at TEST_KEY must equal MARKER");

    Ok(())
}
