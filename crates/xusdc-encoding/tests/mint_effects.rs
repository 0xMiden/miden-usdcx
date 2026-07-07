//! 01 faucet D5e mint write-phase suite (P5-01 slice 5): drives the FAUCET(01)-owned
//! `xreserve::xreserve_mint::apply_mint_effects` shell through MockChain `execute().await` via a
//! CALL-entered driver on a `FungibleFaucet` account (the canary-proven construction). The shell
//! consumes a verified intent's outputs (amount, feeAmount, the nonce key, the recipient
//! AccountId felts) and applies the atomic mint effects: nonce SET, P2ID recipient note carrying
//! `amount - feeAmount`, and `token_supply += amount`.
//!
//! RED-SUITE (executing-red): `apply_mint_effects` runs the FULL real primitive sequence
//! (token_config read, nonce SET, P2ID note emission, supply write-back) then traps with the
//! terminal `ERR_XRESERVE_D5E_RED_PLACEHOLDER` as the last instruction — so the primitives
//! genuinely EXECUTE under MockChain (the trap rolls the tx back; NO effects commit in red, which
//! the canary proves separately). Every behavior test below asserts its FINAL (green) expectation
//! and is therefore RED here: the happy/conservation cases fail because the terminal trap reverts
//! the tx; the over-cap case fails because the kernel mint trap (no guard yet) is not the exact
//! `ERR_XRESERVE_SUPPLY_CAP`. The GREEN commit inserts the supply-cap asserts and removes the
//! terminal trap. `probe_mint_effects_exports` is a declared green scaffold.

mod support;

use anyhow::Result;
use miden_protocol::account::{StorageMapKey, StorageSlotDelta, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_standards::note::P2idNote;
use miden_testing::assert_transaction_executor_error;
use support::*;

const KEY: [u32; 4] = [11, 12, 13, 14];
const MARKER: [u32; 4] = [1, 0, 0, 0];
const SERIAL: [u32; 4] = [7, 7, 7, 7];

fn inputs(amount: u64, fee_amount: u64, key: [u32; 4]) -> MintInputs {
    MintInputs { amount, fee_amount, key, serial: SERIAL, tag: 0, note_type: 1 }
}

/// Reads the post-tx token_config value-slot word (panics if absent / not a Value delta).
fn token_config_delta(executed: &miden_protocol::transaction::ExecutedTransaction) -> Word {
    let slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL).expect("cfg slot label");
    match executed.account_delta().storage().get(&slot).expect("token_config slot delta") {
        StorageSlotDelta::Value(w) => *w,
        StorageSlotDelta::Map(_) => panic!("token_config must be a Value slot delta"),
    }
}

// HAPPY / CONSERVATION (G4) — feeAmount == 0 MVP single recipient note
// ================================================================================================

#[tokio::test]
async fn d5e_happy_conservation() -> Result<()> {
    let amount = 1000u64;
    let h = setup_mint_faucet_account(1_000_000, 0, &inputs(amount, 0, KEY))?;
    let executed =
        run_mint(&h).await.expect("apply_mint_effects must apply the effects on a valid mint");

    // recipient note carries amount - feeAmount (== amount at MVP), from this faucet.
    assert_eq!(executed.output_notes().num_notes(), 1, "exactly one recipient note");
    let note = executed.output_notes().get_note(0);
    let asset = note
        .assets()
        .iter_fungible()
        .next()
        .expect("the recipient note must carry a fungible asset");
    assert_eq!(Felt::from(asset.amount()), Felt::from(amount as u32), "note asset == amount - feeAmount");
    assert_eq!(asset.faucet_id(), h.account_id, "asset minted by this faucet");

    // the emitted note is the intended P2ID recipient note: canonical P2ID script root + storage
    // [target_id_suffix, target_id_prefix] for the intended recipient (not merely the right asset).
    let recipient = note.recipient().expect("public output note must carry its recipient");
    assert_eq!(
        recipient.script().root(),
        P2idNote::script_root(),
        "recipient note script root must be the canonical P2ID script root"
    );
    assert_eq!(
        recipient.storage().items(),
        [h.recipient_id.suffix(), h.recipient_id.prefix().as_felt()].as_slice(),
        "recipient note storage must be [target_id_suffix, target_id_prefix]"
    );

    // INV-SUPPLY-CONSERVATION: token_supply rose by exactly amount.
    assert_eq!(token_config_delta(&executed)[0], Felt::from(amount as u32), "token_supply delta == amount");

    // nonce SET committed: usedNonces[KEY] == MARKER.
    let used = StorageSlotName::new(USED_NONCES_SLOT_LABEL)?;
    let StorageSlotDelta::Map(map_delta) =
        executed.account_delta().storage().get(&used).expect("usedNonces slot delta")
    else {
        panic!("usedNonces must be a Map slot delta");
    };
    let written = map_delta
        .entries()
        .get(&StorageMapKey::new(Word::from(KEY)))
        .copied()
        .expect("KEY must appear in the usedNonces delta");
    assert_eq!(written, Word::from(MARKER), "nonce marker committed");
    Ok(())
}

/// F2 defensive guard: a non-zero `feeAmount` into `apply_mint_effects` must TRAP. At MVP the proc
/// mints ONE recipient note (`amount - feeAmount`) but raises `token_supply` by the FULL `amount`;
/// a live `feeAmount` would over-count `token_supply` vs minted assets (INV-SUPPLY-CONSERVATION),
/// since the relayer-fee leg is deferred (DEV-8). `mint` hardcodes `feeAmount = 0`
/// (xreserve_mint.masm), so only a direct effects-proc drive can inject a non-zero fee — this is the
/// only path that reaches the guard.
#[tokio::test]
async fn d5e_nonzero_fee_traps() -> Result<()> {
    let amount = 1000u64;
    let fee_amount = 250u64; // genuinely non-zero -> must trap the F2 guard
    let h = setup_mint_faucet_account(1_000_000, 0, &inputs(amount, fee_amount, KEY))?;
    let result = run_mint(&h).await;
    let expected = miden_protocol::errors::MasmError::from_static_str("mint fee amount must be zero");
    assert_transaction_executor_error!(result, &expected);
    Ok(())
}

/// Cap boundary ACCEPTS: token_supply + amount == max_supply is allowed (R-MINT-15 uses
/// `amount <= max_supply - token_supply`).
#[tokio::test]
async fn d5e_cap_boundary_accepts() -> Result<()> {
    let max = 1_000_000u64;
    let seeded = 400_000u64;
    let amount = max - seeded; // exactly hits the cap
    let h = setup_mint_faucet_account(max, seeded, &inputs(amount, 0, KEY))?;
    let executed = run_mint(&h).await.expect("minting exactly to the cap is allowed");
    assert_eq!(
        token_config_delta(&executed)[0],
        Felt::from((seeded + amount) as u32),
        "token_supply == max_supply at the cap"
    );
    Ok(())
}

/// Near-`FUNGIBLE_ASSET_MAX_AMOUNT` boundary (the catastrophic-case check): max_supply at the
/// AssetAmount cap, token_supply one mint below it. The ordered felt asserts + the supply write
/// must not wrap at values near 2^63. Mints exactly to the cap.
#[tokio::test]
async fn d5e_near_max_boundary() -> Result<()> {
    // FUNGIBLE_ASSET_MAX_AMOUNT = 2^63 - 2^31.
    let max = 9_223_372_034_707_292_160u64;
    let amount = 1000u64;
    let seeded = max - amount;
    let h = setup_mint_faucet_account(max, seeded, &inputs(amount, 0, KEY))?;
    let executed = run_mint(&h).await.expect("minting to the AssetAmount cap must not wrap");
    assert_eq!(
        token_config_delta(&executed)[0],
        miden_protocol::Felt::from(miden_protocol::asset::AssetAmount::new(max)?),
        "token_supply == max_supply at the AssetAmount cap, no wrap"
    );
    Ok(())
}

// SUPPLY-CAP REJECT (R-MINT-15)
// ================================================================================================

/// Over-cap by one: token_supply + amount == max_supply + 1 must trap ERR_XRESERVE_SUPPLY_CAP and
/// apply no effects (the green guard fires before any write). In red the kernel mint trap (no
/// guard yet) is a different error, so this case is RED via real execution.
#[tokio::test]
async fn d5e_over_cap_rejects() -> Result<()> {
    let max = 1_000_000u64;
    let seeded = 400_000u64;
    let amount = max - seeded + 1; // one over the cap
    let h = setup_mint_faucet_account(max, seeded, &inputs(amount, 0, KEY))?;
    let result = run_mint(&h).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_SUPPLY_CAP"));

    // No-effects proof (finding #3b): the rejected tx trapped at the guard (before any write) and
    // committed nothing; a follow-up readback on the SAME account confirms token_config and
    // usedNonces[KEY] are unchanged (genesis seed). It must execute cleanly (no assertion trap).
    run_noeffect_probe(&h)
        .await
        .expect("over-cap reject must leave token_config and usedNonces unchanged");
    Ok(())
}

// PROBE (declared green scaffold)
// ================================================================================================

/// D-1A: the assembled library exports the canonical nested mint-shell path.
#[test]
fn probe_mint_effects_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::xreserve_mint::apply_mint_effects";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical mint shell proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}
