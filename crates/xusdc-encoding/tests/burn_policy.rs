//! CMP-A10 `XReserveBurnPolicy` suite (P5-01, R-BURN-1/2/3): the real burn security predicate
//! (`burn_policy.masm::check_policy`) wired as the ACTIVE burn policy of the `XReserveStablecoinBuilder`
//! faucet's `TokenPolicyManager`. Stock `receive_and_burn` routes every burn through
//! `policy_manager::execute_burn_policy`, which (after the stock pause gate) `dynexec`s the active burn
//! policy — so this `check_policy` gates every burn on R-BURN-1 (`amount > 0`) + R-BURN-2
//! (`amount >= minBurnSize`). R-BURN-3 (pause) is the stock wrapper's gate, run BEFORE the policy
//! (DECISION-RBURN3), so the custom policy does NOT check pause.
//!
//! EXECUTING-RED: `burn_policy.masm::check_policy` is a behavioral NO-OP (`dropw dropw`) that ACCEPTS
//! every burn, and the builder wires the active burn policy WITHOUT the build-time guard. So the
//! policy-defining rejects (`burn_below_min_rejects`, `burn_zero_amount_rejects_direct`) and the builder
//! guard (`denies_non_policy_burn`, in `builder_api.rs`) are RED — the no-op accepts a burn the real
//! policy must reject / the missing guard composes Ok. The positive (`burn_valid_passes_and_decrements`),
//! the primary allow-all oracle (`burn_below_min_passes_under_allow_all`), the stock pause
//! (`burn_paused_rejects`), and the export probe are GREEN. The harness is the burn canary's real
//! MockChain 2-block lifecycle (user emits an asset-bearing BurnNote at block N → faucet consumes it via
//! `receive_and_burn` at block N+1), composed via the TEST-ONLY `support::oracle_burn_components`
//! non-vacuity oracle (real-vs-allow-all, code-identical, differing only in `active_burn_policy_proc_root`).

mod support;

use anyhow::Result;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::errors::MasmError;
use miden_protocol::Word;
use miden_testing::assert_transaction_executor_error;
use support::*;

// PLACEHOLDER magnitudes (the suite asserts policy behavior, not magnitudes).
const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
const MIN_BURN_SIZE: u64 = 1_000;
/// A valid burn: `MIN_BURN_SIZE <= VALID_BURN > 0` and `<= TOKEN_SUPPLY`.
const VALID_BURN: u64 = 5_000;
/// A below-minimum burn: `0 < BELOW_MIN < MIN_BURN_SIZE` (note-reachable, no zero-amount dependency).
const BELOW_MIN: u64 = 500;

/// The seeded `ATTEST_ADMIN` holder the burn oracle installs (`admin_holder` = id(2)); it can pause.
fn holder() -> AccountId {
    test_account_id(2)
}

// POSITIVE + ALLOW-ALL ORACLE (GREEN)
// ================================================================================================

/// A valid burn (`amount >= minBurnSize > 0`, not paused) on the REAL-policy account succeeds and
/// decrements `committed_token_supply` by exactly the burned amount — the burn analog of the proven
/// mint increment. GREEN: the no-op shell accepts the valid burn and stock `receive_and_burn`
/// decrements supply; the real R-BURN-1/2 checks (green commit) also accept a valid burn.
#[tokio::test]
async fn burn_valid_passes_and_decrements() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness { mut chain, faucet_id, user_id, burn_note, asset, .. } = h;

    let tx1 = run_burn_consume(&mut chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("a valid burn (amount >= minBurnSize > 0, not paused) must pass the burn policy");
    chain.add_pending_executed_transaction(&tx1)?;
    chain.prove_next_block()?;

    assert_eq!(
        committed_token_supply(&chain, faucet_id)?,
        AssetAmount::new(TOKEN_SUPPLY - VALID_BURN)?,
        "a valid burn must decrement committed token_supply by exactly the burned amount"
    );
    Ok(())
}

/// PRIMARY non-vacuity oracle: the SAME `0 < amount < minBurnSize` burn that the real policy rejects
/// SUCCEEDS and decrements on a CODE-IDENTICAL `BurnAllowAll`-active account (differing ONLY in
/// `active_burn_policy_proc_root`). Paired with `burn_below_min_rejects`, this proves the below-min trap
/// is policy-caused, not a fixture artifact — and it runs on a real, definitely-constructible note.
/// GREEN both before and after the green commit (allow-all accepts the below-min burn either way).
#[tokio::test]
async fn burn_below_min_passes_under_allow_all() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnAllowAll,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        BELOW_MIN,
    )?;
    let BurnPolicyHarness { mut chain, faucet_id, user_id, burn_note, asset, .. } = h;

    let tx1 = run_burn_consume(&mut chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("under BurnAllowAll the below-min burn must succeed (the non-vacuity control)");
    chain.add_pending_executed_transaction(&tx1)?;
    chain.prove_next_block()?;

    assert_eq!(
        committed_token_supply(&chain, faucet_id)?,
        AssetAmount::new(TOKEN_SUPPLY - BELOW_MIN)?,
        "under allow-all the below-min burn must decrement committed token_supply"
    );
    Ok(())
}

// POLICY-DEFINING REJECTS (RED against the no-op shell)
// ================================================================================================

/// R-BURN-2: a `0 < amount < minBurnSize` burn (the seeded minBurnSize slot) on the REAL-policy account
/// must trap the EXACT ERR_XRESERVE_BURN_BELOW_MIN. RED here: the no-op shell ACCEPTS the below-min burn
/// (no trap), so `receive_and_burn` succeeds and `assert_transaction_executor_error!` reports the burn
/// was "unexpectedly successful" — red for the right reason (a below-min burn the real policy must
/// reject got through). Goes green when `check_policy` enforces `amount >= minBurnSize`.
#[tokio::test]
async fn burn_below_min_rejects() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        BELOW_MIN,
    )?;
    let BurnPolicyHarness { mut chain, faucet_id, user_id, burn_note, asset, .. } = h;

    let result = run_burn_consume(&mut chain, &burn_note, &asset, faucet_id, user_id).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_BURN_BELOW_MIN"));
    Ok(())
}

/// R-BURN-1 (note-driven, plan §6 step 1): a real 0-amount burn note consumed by the faucet must trap
/// the EXACT ERR_XRESERVE_BURN_ZERO. The 0-amount burn is note-reachable (see
/// `zero_amount_burn_note_reachability`), so this is a real `receive_and_burn` consume on the REAL-policy
/// account. RED here: the no-op shell ACCEPTS the zero burn (no trap), so the consume succeeds and
/// `assert_transaction_executor_error!` reports "unexpectedly successful" — red for the right reason.
/// Goes green when `check_policy` enforces `amount > 0`.
#[tokio::test]
async fn burn_zero_amount_rejects() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        0,
    )?;
    let BurnPolicyHarness { mut chain, faucet_id, user_id, burn_note, asset, .. } = h;

    let result = run_burn_consume(&mut chain, &burn_note, &asset, faucet_id, user_id).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_BURN_ZERO"));
    Ok(())
}

/// R-BURN-1 (direct-policy defensive proof): `exec` `check_policy` with a crafted `[ASSET_KEY, [0,0,0,0]]`
/// stack — the faucet-independent guard proof the brief names. The real policy must trap
/// ERR_XRESERVE_BURN_ZERO; the no-op shell returns cleanly (`dropw dropw`) — RED for the right reason.
/// Complements the note-driven `burn_zero_amount_rejects` (the 0-amount burn turned out note-reachable).
#[tokio::test]
async fn burn_zero_amount_rejects_direct() -> Result<()> {
    let asset_key = Word::from([7u32, 7, 7, 7]);
    let driver = burn_policy_direct_driver_src(asset_key, 0);
    let h = setup_burn_policy_direct_account(MIN_BURN_SIZE, &driver)?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_BURN_ZERO"));
    Ok(())
}

// STOCK PAUSE GATE (GREEN) — R-BURN-3 traps the stock error BEFORE the custom policy runs
// ================================================================================================

/// R-BURN-3: a paused faucet halts the burn. After the ATTEST_ADMIN holder pauses the REAL-policy
/// faucet (stock `PausableManager::pause`), the burn consume traps the EXACT stock ERR_PAUSABLE_IS_PAUSED
/// (`"the contract is paused"`) — enforced by `execute_burn_policy`'s `assert_not_paused` BEFORE the
/// custom policy is dispatched (DECISION-RBURN3). GREEN regardless of the policy body (the stock gate
/// fires first); the real `PausableManager`-bearing account (not a bare faucet) makes this a real gate,
/// never a missing-slot artifact. Mirrors `set_attester_paused_rejects`.
#[tokio::test]
async fn burn_paused_rejects() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness { mut chain, faucet_id, user_id, burn_note, asset, .. } = h;

    // Block N: the user emits + commits the (valid-amount) burn note, while the faucet is NOT yet paused.
    let tx0 = try_emit_burn_note(&chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("the user emits the burn note (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // The ATTEST_ADMIN holder pauses the faucet; evolve the committed faucet with the pause delta (NOT
    // committed — the unauthenticated pause note can't be block-proven; mirrors set_attester_paused_rejects).
    let account = chain.committed_account(faucet_id)?.clone();
    let paused = run_pause_against(&chain, &account, holder(), 5)
        .await
        .expect("the ATTEST_ADMIN holder can pause the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;

    // The faucet consumes the committed burn note against the EVOLVED (paused) account: execute_burn_policy
    // runs assert_not_paused BEFORE the custom policy, trapping the stock pause error (the valid amount
    // isolates the gate). GREEN regardless of the policy body.
    let result = chain
        .build_tx_context(evolved, &[burn_note.id()], &[])?
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, MasmError::from_static_str("the contract is paused"));
    Ok(())
}

// R-BURN-1 ZERO-AMOUNT REACHABILITY PROBE (GREEN diagnostic)
// ================================================================================================

/// Empirically resolves R-BURN-1's note-reachability (plan §6 step 1). A 0-amount fungible asset is
/// constructible (only the UPPER bound is checked) AND note-reachable: the user emits a 0-amount burn
/// note (tx0), and the faucet's `receive_and_burn` reaches the burn policy with `amount == 0` (one
/// asset, `0 <= token_supply`). On a CODE-IDENTICAL `BurnAllowAll`-active account the consume therefore
/// SUCCEEDS — proving the 0-amount burn DOES reach the policy. So R-BURN-1 is proven by a real
/// note-driven consume (`burn_zero_amount_rejects`) AND, defensively, by the direct-policy driver
/// (`burn_zero_amount_rejects_direct`). GREEN before and after the green commit (allow-all accepts
/// either way); it is the non-vacuity mirror for the zero case.
#[tokio::test]
async fn zero_amount_burn_note_reachability() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnAllowAll,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        0,
    )?;
    let BurnPolicyHarness { mut chain, faucet_id, user_id, burn_note, asset, .. } = h;

    let result = run_burn_consume(&mut chain, &burn_note, &asset, faucet_id, user_id).await;
    assert!(
        result.is_ok(),
        "a 0-amount burn note must reach the burn policy via a real consume (one asset, \
         0 <= token_supply) and be accepted under BurnAllowAll, proving the 0-amount burn is \
         note-reachable; got: {:?}",
        result.err()
    );
    Ok(())
}

// STATIC SCAFFOLD (GREEN)
// ================================================================================================

/// The assembled `xreserve` library must export the burn policy's `check_policy` at the flat path
/// `xreserve::burn_policy::check_policy`. Twin of `mint_deny.rs::probe_mint_deny_guard_export`. GREEN.
#[test]
fn probe_burn_policy_export() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    assert!(
        lib.exports()
            .filter(|e| e.as_procedure().is_some())
            .any(|e| e.path().to_string().ends_with("xreserve::burn_policy::check_policy")),
        "the xreserve library must export xreserve::burn_policy::check_policy; exports: {:?}",
        lib.exports()
            .filter(|e| e.as_procedure().is_some())
            .map(|e| e.path().to_string())
            .collect::<Vec<_>>()
    );
    Ok(())
}
