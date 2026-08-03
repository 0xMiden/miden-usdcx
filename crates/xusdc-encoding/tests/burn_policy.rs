//! Burn floor-policy suite (the below-minimum, zero-amount, and paused-burn rejects): the STOCK
//! `MinBurnAmount` burn policy
//! (`miden_standards::account::policies::MinBurnAmount`) wired as the ACTIVE burn policy of the
//! `XReserveStablecoinBuilder` faucet's `TokenPolicyManager`. Stock `receive_and_burn`
//! routes every burn through `policy_manager::execute_burn_policy`, which (after the stock pause
//! gate) `dynexec`s the active burn policy — the stock `check_policy` reads its own floor slot
//! (`MinBurnAmount::slot_name()`) and asserts `minBurnAmount <= amount` ONLY (the below-minimum
//! reject). The zero-burn reject
//! (`amount > 0`) is preserved BY CONSTRUCTION: the floor is ALWAYS `>= 1` (builder-seeded `>= 1`;
//! the set_min_burn_size admin note asserts `new_min >= 1` before calling the stock
//! setter), so a zero-amount burn rejects with the SAME stock below-min error. The pause reject
//! is the stock wrapper's gate, run BEFORE the policy dispatch.
//!
//! Non-vacuity: the policy-defining rejects (`burn_below_min_rejects`, `burn_zero_amount_rejects`,
//! `burn_zero_amount_rejects_direct`) trap the EXACT stock below-min error on the
//! MinBurnAmount-active account, while the SAME invalid burn SUCCEEDS on a CODE-IDENTICAL
//! `BurnAllowAll`-active account (`burn_below_min_passes_under_allow_all`) — proving each trap is
//! policy-caused, not a fixture artifact. The harness is the real MockChain 2-block
//! lifecycle (the user emits an asset-bearing BurnNote at block N → the faucet consumes it via
//! `receive_and_burn` at block N+1), composed via the TEST-ONLY `support::oracle_burn_components`
//! oracle (MinBurnAmount-vs-allow-all, code-identical, differing only in
//! `active_burn_policy_proc_root`).

mod support;

use anyhow::Result;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::errors::MasmError;
use miden_protocol::Word;
use miden_standards::account::policies::MinBurnAmount;
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

/// The seeded DOM_PAUSER holder (id(2)) — the ONLY pause authority in the Domain-Pauser-only model
/// (the custom `xreserve::pause_admin` procs). The administrator (id(1), the sole ADMIN member)
/// has no direct pause path and no other role in this suite.
fn dom_pauser() -> AccountId {
    test_account_id(2)
}

// POSITIVE + ALLOW-ALL ORACLE (GREEN)
// ================================================================================================

/// A valid burn (`amount >= minBurnSize > 0`, not paused) on the MinBurnAmount-active account passes
/// the policy and decrements `committed_token_supply` by exactly the burned amount — the burn analog
/// of the proven mint increment, and proof the policy does not over-reject a valid burn.
#[tokio::test]
async fn burn_valid_passes_and_decrements() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = h;

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

/// PRIMARY non-vacuity oracle: the SAME `0 < amount < minBurnSize` burn that the MinBurnAmount
/// policy rejects SUCCEEDS and decrements on a CODE-IDENTICAL `BurnAllowAll`-active account
/// (differing ONLY in `active_burn_policy_proc_root`). Paired with `burn_below_min_rejects`, this
/// proves the below-min trap is policy-caused, not a fixture artifact — and it runs on a real,
/// definitely-constructible note.
#[tokio::test]
async fn burn_below_min_passes_under_allow_all() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnAllowAll,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        BELOW_MIN,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = h;

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

// POLICY-DEFINING REJECTS — exact-error traps on the MinBurnAmount-active account
// ================================================================================================

/// Below-minimum reject: a `0 < amount < minBurnSize` burn (against the seeded floor slot) on the
/// MinBurnAmount-active account traps the EXACT stock below-min error — the stock `check_policy`
/// reads `MinBurnAmount::slot_name()` and asserts `minBurnAmount <= amount`. Paired with
/// `burn_below_min_passes_under_allow_all` for non-vacuity.
#[tokio::test]
async fn burn_below_min_rejects() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        BELOW_MIN,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = h;

    let result = run_burn_consume(&mut chain, &burn_note, &asset, faucet_id, user_id).await;
    assert_transaction_executor_error!(result, &err_burn_below_min_burn_amount());
    Ok(())
}

/// Floor boundary (ACCEPT side): a burn of EXACTLY `minBurnSize` PASSES and decrements
/// `committed_token_supply` by that amount — the floor predicate is `amount >= minBurnSize`, so
/// `== min` is
/// accepted. Paired with `burn_at_min_minus_one_rejects`, this pins the `>=` boundary exactly: a
/// `lte`->`lt` regression in the stock `check_policy` (which would reject `== min`) flips THIS
/// test red.
#[tokio::test]
async fn burn_at_min_passes_and_decrements() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        MIN_BURN_SIZE,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = h;

    let tx1 = run_burn_consume(&mut chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("a burn of exactly minBurnSize must pass (R-BURN-2 is amount >= min)");
    chain.add_pending_executed_transaction(&tx1)?;
    chain.prove_next_block()?;

    assert_eq!(
        committed_token_supply(&chain, faucet_id)?,
        AssetAmount::new(TOKEN_SUPPLY - MIN_BURN_SIZE)?,
        "a burn at exactly minBurnSize must decrement committed token_supply by exactly that amount"
    );
    Ok(())
}

/// Floor boundary (REJECT side): a burn of `minBurnSize - 1` — the largest below-minimum amount,
/// one unit under the threshold — traps the EXACT stock below-min error. With
/// `burn_at_min_passes_and_decrements` this pins `amount >= minBurnSize` exactly (not `> min`, not
/// `>= min - 1`), so an off-by-one or `lte`->`lt` regression is caught.
#[tokio::test]
async fn burn_at_min_minus_one_rejects() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        MIN_BURN_SIZE - 1,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = h;

    let result = run_burn_consume(&mut chain, &burn_note, &asset, faucet_id, user_id).await;
    assert_transaction_executor_error!(result, &err_burn_below_min_burn_amount());
    Ok(())
}

/// Zero-amount reject (note-driven): a real 0-amount burn note consumed by the faucet traps the
/// EXACT stock
/// below-min error — the zero-burn invariant IS the floor: the seeded floor is `>= 1`, so
/// `amount == 0` is always below it (`0 < min`). There is no custom zero-burn
/// error. The 0-amount burn is note-reachable (see
/// `zero_amount_burn_note_reachability`), so this is a real `receive_and_burn` consume on the
/// MinBurnAmount-active account, not a synthetic one.
#[tokio::test]
async fn burn_zero_amount_rejects() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        0,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = h;

    let result = run_burn_consume(&mut chain, &burn_note, &asset, faucet_id, user_id).await;
    assert_transaction_executor_error!(result, &err_burn_below_min_burn_amount());
    Ok(())
}

/// Zero-amount reject (direct-policy defensive proof): `exec` the STOCK `min_burn_amount::check_policy` with
/// a crafted `[ASSET_ID, [0,0,0,0]]` stack — the faucet-independent floor proof. With the floor
/// seeded `>= 1` the policy traps the stock below-min error on `amount == 0` in isolation
/// (`0 < min` always), complementing the note-driven `burn_zero_amount_rejects` (the 0-amount burn
/// is also note-reachable).
#[tokio::test]
async fn burn_zero_amount_rejects_direct() -> Result<()> {
    let asset_key = Word::from([7u32, 7, 7, 7]);
    let driver = burn_policy_direct_driver_src(asset_key, 0);
    let h = setup_burn_policy_direct_account(MIN_BURN_SIZE, &driver)?;
    let result = run_call_driver(&h, "drive").await;
    assert_transaction_executor_error!(result, &err_burn_below_min_burn_amount());
    Ok(())
}

// PAUSE GATE (GREEN) — the paused-burn reject traps the stock error BEFORE the active policy runs
// ================================================================================================

/// Paused-burn reject: a paused faucet halts the burn. After the DOM_PAUSER pauses the MinBurnAmount-active
/// faucet (custom `xreserve::pause_admin::pause` — the ONLY pause surface in the Domain-Pauser-only
/// model), the burn consume traps the EXACT stock ERR_PAUSABLE_IS_PAUSED (`"the contract is
/// paused"`) — enforced by `execute_burn_policy`'s `assert_not_paused` BEFORE the active policy is
/// dispatched.
/// GREEN regardless of the policy body (the stock gate fires first); the
/// `Pausable`-installed `is_paused` slot (v0.16 #2944 moved it out of `FungibleFaucet`) makes this
/// a real gate, never a missing-slot artifact — which at v0.16 would be SILENT (#3047 no-ops
/// `assert_not_paused` on a missing slot).
/// Mirrors `set_attester_paused_rejects`.
#[tokio::test]
async fn burn_paused_rejects() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = h;

    // Block N: the user emits + commits the (valid-amount) burn note, while the faucet is NOT yet paused.
    let tx0 = try_emit_burn_note(&chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("the user emits the burn note (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // The DOM_PAUSER pauses the faucet; evolve the committed faucet with the pause delta (NOT committed —
    // the unauthenticated pause note can't be block-proven; mirrors set_attester_paused_rejects).
    let account = chain.committed_account(faucet_id)?.clone();
    let paused = run_dom_pauser_pause(&chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;

    // The faucet consumes the committed burn note against the EVOLVED (paused) account: execute_burn_policy
    // runs assert_not_paused BEFORE the active policy, trapping the stock pause error (the valid amount
    // isolates the gate). GREEN regardless of the policy body.
    let result = chain
        .build_transaction(evolved)
        .authenticated_input_note(burn_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        result,
        MasmError::from_static_str("the contract is paused")
    );
    Ok(())
}

// ZERO-AMOUNT REACHABILITY PROBE (GREEN diagnostic)
// ================================================================================================

/// Empirically resolves the zero-amount burn's note-reachability. A 0-amount fungible asset is
/// constructible (only the UPPER bound is checked) AND note-reachable: the user emits a 0-amount burn
/// note (tx0), and the faucet's `receive_and_burn` reaches the burn policy with `amount == 0` (one
/// asset, `0 <= token_supply`). On a CODE-IDENTICAL `BurnAllowAll`-active account the consume therefore
/// SUCCEEDS — proving the 0-amount burn DOES reach the policy. So the zero-amount reject is
/// proven by a real
/// note-driven consume (`burn_zero_amount_rejects`) AND, defensively, by the direct-policy driver
/// (`burn_zero_amount_rejects_direct`). This is the non-vacuity mirror for the zero case: allow-all
/// accepts the 0-amount burn the MinBurnAmount floor rejects.
#[tokio::test]
async fn zero_amount_burn_note_reachability() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnAllowAll,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        0,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = h;

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

/// The composed PRODUCTION component set carries the STOCK `MinBurnAmount` policy component: one
/// component's code exposes `MinBurnAmount::root()` (the stock `check_policy`), so the policy the
/// active-burn slot points at is INSTALLED on the faucet. (There is no custom
/// `xreserve::burn_policy` module.)
#[test]
fn probe_stock_burn_policy_installed() -> Result<()> {
    let components = production_component_set(1_000_000, 0)?;
    assert!(
        components
            .iter()
            .any(|c| c.has_procedure(MinBurnAmount::root())),
        "the production component set must carry a component exposing the stock \
         MinBurnAmount::check_policy root (the stock burn policy is installed)"
    );
    Ok(())
}
