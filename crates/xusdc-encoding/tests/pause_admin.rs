//! P5-01 CMP-F3 custom `pause`/`unpause` suite: the DOM_PAUSER-gated emergency halt (§5.12,
//! CIR-ADMIN-3/4/5, per DECISION-ADMIN-ROLE-MODEL). The stock `PausableManager` gates pause on the
//! account-wide `Authority` (= owner), so a distinct pause role needs a CUSTOM proc:
//! `xreserve::pause_admin::{pause,unpause}` = `rbac::assert_sender_has_role(DOM_PAUSER)` +
//! the unauthenticated `pausable::pause`/`unpause` primitives.
//!
//! The load-bearing proof is the PAUSE-HALT SEAM — a DOM_PAUSER pause must actually HALT the real
//! faucet, not just flip `is_paused`: a real `xreserve_mint` AND a real `receive_and_burn` trap
//! `ERR_PAUSABLE_IS_PAUSED` while paused, and both resume on unpause. Discovery found the burn already
//! halts (execute_burn_policy runs assert_not_paused first) but the custom `xreserve_mint` bypasses the
//! mint policy and did NOT honor `is_paused` — closed by adding `assert_not_paused` to
//! `xreserve_mint::mint` (the mint reconciliation; DECISION-CMPF3-MINT-PAUSE-GAP).
//!
//! OPTION-1 REVISION (IMPL-DEV-1 remediation): Circle's model is Domain-Pauser-ONLY
//! (CIRCLE-SPECIFICATION.md:121 — the owner has NO direct pause path), so the stock `PausableManager`
//! is REMOVED from the composition and the DOM_PAUSER custom procs are the ONLY pause surface.
//! RED-SUITE (executing-red): `owner_has_no_pause_path` / `owner_has_no_unpause_path` assert an
//! owner-sent STOCK `PausableManager::pause`/`unpause` note now fails with the exact
//! `UnknownAccountProcedure` (the roots are gone from the account code) — RED while the Option-2
//! baseline still installs the manager. `dom_pauser_pause_halts_mint`/`_burn` double as the
//! `is_paused`-slot-survival guards (the slot is FungibleFaucet-installed, NOT manager-installed).

mod support;

use anyhow::Result;
use miden_protocol::account::{Account, AccountId, StorageSlotDelta, StorageSlotName};
use miden_protocol::errors::MasmError;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use rstest::rstest;
use support::*;
use xusdc_encoding::vectors::{DiFields, DiVector, load, parse_hex32};
use xusdc_encoding::xreserve::encoding::bytes32_to_storage_map_key;

// The production builder seeds owner = id(1) (Ownable2Step), DOM_PAUSER = id(2), DOM_MANAGER = id(3).
fn owner() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn dom_manager() -> AccountId {
    test_account_id(3)
}
fn plain_non_owner() -> AccountId {
    test_account_id(99)
}

// Burn-faucet parameters (mirrors burn_policy.rs / set_min_burn.rs).
const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
const MIN_BURN_SIZE: u64 = 1_000;
const VALID_BURN: u64 = 5_000;

// The exact stock pause / role errors these tests pin (assert-specific-error-in-tests).
fn err_paused() -> MasmError {
    MasmError::from_static_str("the contract is paused")
}
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

// MINT-SEAM FIXTURES (reconstructed from the canonical accept payload — mirrors domain_config.rs)
// ================================================================================================

const BASE_VECTOR: &str = "di-pos-empty-hookdata";
const LEN_FELTS: u64 = 60;
const SCALE_EXP: u32 = 6;
const HAPPY_AMOUNT_RAW: u64 = 2_000_000;
const HAPPY_MAX_FEE_RAW: u64 = 1_000_000;
/// amount 2_000_000 reduced by scale_exp=6 → 2 (the token_supply delta a successful mint commits).
const REDUCED_AMOUNT: u32 = 2;
const MARKER: [u32; 4] = [1, 0, 0, 0];

fn di(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

fn fields_of(id: &str) -> &'static DiFields {
    di(id).fields.as_ref().expect("accept vector carries fields")
}

fn base_payload() -> Vec<u8> {
    di(BASE_VECTOR).bytes()
}

/// Splices `amount`/`maxFee` (uint256 BE) into a payload's byte image (so the keccak'd attestation
/// payload stays consistent with what the attester signs).
fn with_amounts(mut payload: Vec<u8>, amount: u64, max_fee: u64) -> Vec<u8> {
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(amount));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(max_fee));
    payload
}

fn happy_payload() -> Vec<u8> {
    with_amounts(base_payload(), HAPPY_AMOUNT_RAW, HAPPY_MAX_FEE_RAW)
}

fn pack(bytes: &[u8]) -> Vec<Felt> {
    miden_protocol::utils::bytes_to_packed_u32_elements(bytes)
}

/// The configured identifier = the canonical key-Word of the vector's remoteToken (what D5a compares).
fn identifier_of(id: &str) -> Word {
    Word::from(bytes32_to_storage_map_key(&parse_hex32(&fields_of(id).remote_token_hex)))
}

fn nonce_key() -> Word {
    Word::from(bytes32_to_storage_map_key(&fields_of(BASE_VECTOR).bytes32("nonce")))
}

/// A production faucet (owner=id(1), DOM_PAUSER=id(2)) pre-configured for a VALID mint: domain =
/// TEST_DOMAIN, identifier = the canonical remoteToken key, the attester allowlisted, cap 1_000_000,
/// supply 0. Returns the harness + the attester so a real `xreserve_mint` can be driven.
fn guarded_mint_ready() -> Result<(GuardedMint, AttesterVector)> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let identifier = identifier_of(BASE_VECTOR);
    let domain = Word::from([Felt::from(TEST_DOMAIN), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &probe,
        true,
    )?;
    Ok((gm, attester))
}

/// Reads the committed `token_supply` (token_config word element 0) of a burn faucet.
fn token_supply_of(account: &Account) -> Result<Felt> {
    Ok(read_token_config(account)?[0])
}

// EXPORT PROBE (declared green scaffold — D-1A flat-path check for the new pause procs)
// ================================================================================================

#[test]
fn probe_pause_admin_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    for canonical in ["::xreserve::pause_admin::pause", "::xreserve::pause_admin::unpause"] {
        assert!(
            exports.iter().any(|e| e == canonical),
            "canonical pause proc path {canonical} missing; exports: {exports:?}"
        );
    }
    Ok(())
}

// PAUSE-HALT SEAM — the non-vacuity must-have: a pause HALTS the real mint AND the real burn
// ================================================================================================

/// OPTION 1 (IMPL-DEV-1 remediation): the owner's STOCK pause path is GONE. An owner-sent stock
/// `PausableManager::pause` note still ASSEMBLES (StandardsLib is pre-linked) but the production
/// account no longer exposes the proc root, so execution fails with the EXACT
/// `UnknownAccountProcedure` host-event error ("… is not in the account procedure index map" — NOT
/// a MASM assert) and `is_paused` stays untouched. Replaces `paused_mint_traps` (the owner-stock-
/// pause → mint-trap scenario ceases to exist; its mint-halt purpose lives in
/// `dom_pauser_pause_halts_mint`). RED at the Option-2 baseline: the owner stock pause SUCCEEDS.
#[tokio::test]
async fn owner_has_no_pause_path() -> Result<()> {
    let (gm, _attester) = guarded_mint_ready()?;
    let account = faucet_account(&gm.harness);

    let result = run_pause_against(&gm.harness.mock_chain, &account, owner(), 5).await;
    let err = result.expect_err("the stock owner pause path must be gone (Option 1)");
    assert_unknown_account_procedure(&err);
    assert_eq!(
        read_is_paused(&account)?,
        Word::from([0u32, 0, 0, 0]),
        "a failed stock pause leaves is_paused unpaused"
    );
    Ok(())
}

/// The unpause twin: DOM_PAUSER pauses first (the flag REALLY flips), then an owner-sent stock
/// `PausableManager::unpause` note fails with the EXACT `UnknownAccountProcedure` and the faucet
/// STAYS paused — a surviving stock unpause would visibly clear the flag. RED at the Option-2
/// baseline: the owner stock unpause SUCCEEDS (gated only on the owner Authority).
#[tokio::test]
async fn owner_has_no_unpause_path() -> Result<()> {
    let (gm, _attester) = guarded_mint_ready()?;
    let account = faucet_account(&gm.harness);

    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "precondition: the DOM_PAUSER pause really flipped is_paused"
    );

    let result = run_stock_unpause_against(&gm.harness.mock_chain, &evolved, owner(), 6).await;
    let err = result.expect_err("the stock owner unpause path must be gone (Option 1)");
    assert_unknown_account_procedure(&err);
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "a failed stock unpause leaves the faucet paused"
    );
    Ok(())
}

/// A DOM_PAUSER-triggered pause HALTS the real mint: DOM_PAUSER (id 2) pauses, then a real
/// `xreserve_mint` traps the EXACT `ERR_PAUSABLE_IS_PAUSED`. RED: the pause placeholder traps first.
#[tokio::test]
async fn dom_pauser_pause_halts_mint() -> Result<()> {
    let (gm, attester) = guarded_mint_ready()?;
    let account = faucet_account(&gm.harness);

    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the mint faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;

    let result = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// A DOM_PAUSER-triggered pause HALTS the real burn: DOM_PAUSER pauses, then a real `receive_and_burn`
/// traps the EXACT `ERR_PAUSABLE_IS_PAUSED` (execute_burn_policy's stock pause gate). RED: the pause
/// placeholder traps first.
#[tokio::test]
async fn dom_pauser_pause_halts_burn() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness { mut chain, faucet_id, user_id, burn_note, asset, .. } = bh;

    // Block N: the user emits + commits the (valid-amount) burn note (faucet not yet paused).
    let tx0 = try_emit_burn_note(&chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("the user emits the burn note (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // DOM_PAUSER pauses the faucet; evolve the committed faucet with the (uncommitted) pause delta.
    let account = chain.committed_account(faucet_id)?.clone();
    let paused = run_dom_pauser_pause(&chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the burn faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;

    // The faucet consumes the committed burn note against the paused account → execute_burn_policy's
    // assert_not_paused traps the stock pause error (the valid amount isolates the pause gate).
    let result = chain
        .build_tx_context(evolved, &[burn_note.id()], &[])?
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// UNPAUSE RESUMES both surfaces: after a DOM_PAUSER pause→unpause, a real mint mints again (one
/// recipient note, token_supply += reduced amount) AND a real burn decrements token_supply. RED: the
/// pause/unpause placeholders trap.
#[tokio::test]
async fn dom_pauser_unpause_resumes_mint_and_burn() -> Result<()> {
    // --- mint side ---
    let (gm, attester) = guarded_mint_ready()?;
    let account = faucet_account(&gm.harness);

    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the mint faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;
    let unpaused = run_dom_pauser_unpause(&gm.harness.mock_chain, &evolved, dom_pauser(), 6)
        .await
        .expect("DOM_PAUSER unpauses the mint faucet");
    evolved.apply_delta(unpaused.account_delta())?;

    let minted = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester))
        .await
        .expect("after unpause, the real xreserve_mint mints again");
    assert_eq!(minted.output_notes().num_notes(), 1, "unpause resumes minting (one recipient note)");
    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotDelta::Value(cfg) =
        minted.account_delta().storage().get(&cfg_slot).expect("token_config slot delta")
    else {
        panic!("token_config must be a Value slot delta");
    };
    assert_eq!(cfg[0], Felt::from(REDUCED_AMOUNT), "token_supply rose by the reduced amount");

    // --- burn side ---
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness { mut chain, faucet_id, user_id, burn_note, asset, .. } = bh;
    let tx0 = try_emit_burn_note(&chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("the user emits the burn note (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    let bacct = chain.committed_account(faucet_id)?.clone();
    let bpaused = run_dom_pauser_pause(&chain, &bacct, dom_pauser(), 7)
        .await
        .expect("DOM_PAUSER pauses the burn faucet");
    let mut bevolved = bacct.clone();
    bevolved.apply_delta(bpaused.account_delta())?;
    let bunpaused = run_dom_pauser_unpause(&chain, &bevolved, dom_pauser(), 8)
        .await
        .expect("DOM_PAUSER unpauses the burn faucet");
    bevolved.apply_delta(bunpaused.account_delta())?;

    // The faucet consumes the committed burn note against the UNPAUSED account → the burn succeeds.
    let burned = chain
        .build_tx_context(bevolved.clone(), &[burn_note.id()], &[])?
        .build()?
        .execute()
        .await
        .expect("after unpause, the real receive_and_burn decrements supply");
    let mut bfinal = bevolved.clone();
    bfinal.apply_delta(burned.account_delta())?;
    assert_eq!(
        token_supply_of(&bfinal)?,
        Felt::from((TOKEN_SUPPLY - VALID_BURN) as u32),
        "unpause resumes burning (token_supply decremented by the burn amount)"
    );
    Ok(())
}

// ROLE GATE + SEPARATION — the custom pause is DOM_PAUSER-specific, and a pauser is not the owner
// ================================================================================================

/// Shared: a non-DOM_PAUSER `sender` is rejected from the CUSTOM pause with the EXACT
/// `ERR_SENDER_LACKS_ROLE`, and `is_paused` is unchanged (the gate traps before the pausable write).
async fn assert_custom_pause_rejects(sender: AccountId) -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();

    let result = run_dom_pauser_pause(&bh.chain, &account, sender, 5).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&account)?,
        Word::from([0u32, 0, 0, 0]),
        "a rejected custom pause leaves is_paused unchanged (unpaused)"
    );
    Ok(())
}

/// A plain non-holder (id 99) cannot pause via the custom proc.
#[tokio::test]
async fn non_dom_pauser_pause_rejects() -> Result<()> {
    assert_custom_pause_rejects(plain_non_owner()).await
}

/// The OWNER (id 1) is NOT a DOM_PAUSER holder, so the custom pause rejects the owner too — the custom
/// surface is role-gated, not owner-gated. Under Option 1 (the stock `PausableManager` removed —
/// `owner_has_no_pause_path`) this completes "the owner has no DIRECT pause path": neither the stock
/// nor the custom surface accepts the owner. (The owner keeps Circle-conformant ROLE-ADMINISTRATION
/// power — it could `grant_role` itself DOM_PAUSER, matching CIR-ADMIN-3's `onlyOwner` rotation
/// backstop; the operational rotation path is the CMP-F5 `DOM_MANAGER` delegation, proven in
/// `role_admin.rs` — a rotation concern, not a pause surface.)
#[tokio::test]
async fn owner_is_not_dom_pauser_on_custom_pause() -> Result<()> {
    assert_custom_pause_rejects(owner()).await
}

/// A DIFFERENT role holder (DOM_MANAGER id 3) cannot pause — forecloses a caller-supplied/spoofable role
/// symbol: only the hard-coded DOM_PAUSER symbol passes the gate.
#[tokio::test]
async fn other_role_holder_cannot_pause() -> Result<()> {
    assert_custom_pause_rejects(dom_manager()).await
}

/// The custom `unpause` role gate, proven NEGATIVELY (audit HIGH finding): a non-DOM_PAUSER sender
/// — stranger, owner, or a DIFFERENT role holder (DOM_MANAGER) — is rejected from `unpause` with
/// the EXACT stock `ERR_SENDER_LACKS_ROLE`, and the faucet STAYS paused (no state change). Unpause
/// is the security-critical direction (CIR-ADMIN-5 makes unpause joint-approval): an ungated
/// unpause would let anyone re-enable a paused — possibly compromised — bridge.
#[rstest]
#[case::stranger(plain_non_owner())]
#[case::owner(owner())]
#[case::dom_manager(dom_manager())]
#[tokio::test]
async fn non_dom_pauser_unpause_rejects(#[case] sender: AccountId) -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();

    // Arm the negative on a genuinely paused faucet: a real DOM_PAUSER pause first.
    let paused = run_dom_pauser_pause(&bh.chain, &account, dom_pauser(), 11)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "paused before the unpause probe"
    );

    let result = run_dom_pauser_unpause(&bh.chain, &evolved, sender, 12).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "a rejected custom unpause leaves the faucet paused (no state change)"
    );
    Ok(())
}

/// SEPARATION: the DOM_PAUSER holder (id 2) can pause but is NOT the owner — an owner-gated setter
/// (`set_min_burn_size`) rejects it with the EXACT `ERR_SENDER_NOT_OWNER` (reuses the CMP-F2 owner gate,
/// so this is a GREEN separation regression guard).
#[tokio::test]
async fn dom_pauser_cannot_call_owner_setters() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();

    let result = run_set_min_burn_size_against(&bh.chain, &account, dom_pauser(), 5_000, 7).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    Ok(())
}

// IDEMPOTENCY PINS (Item 11) — the stock pausable primitives are UNCONDITIONAL writes
// ================================================================================================

/// `pause` when ALREADY paused is idempotent SUCCESS: the stock `pausable::pause` is an
/// unconditional `set_item` write with no already-paused guard (pinned v0.15.3
/// `pausable/mod.masm:67-79`), so a redundant DOM_PAUSER pause succeeds and `is_paused` stays
/// `[1,0,0,0]`. Pin-bump drift tripwire: a future stock version that traps on a redundant pause
/// would silently change ops semantics — it fails HERE instead.
#[tokio::test]
async fn pause_when_already_paused_is_idempotent() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();

    let paused = run_dom_pauser_pause(&bh.chain, &account, dom_pauser(), 13)
        .await
        .expect("the first DOM_PAUSER pause succeeds");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;
    assert_eq!(read_is_paused(&evolved)?, Word::from([1u32, 0, 0, 0]), "paused after pause #1");

    let again = run_dom_pauser_pause(&bh.chain, &evolved, dom_pauser(), 14)
        .await
        .expect("a redundant pause is idempotent success (stock pause is an unconditional write)");
    evolved.apply_delta(again.account_delta())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "is_paused stays exactly [1,0,0,0] after the redundant pause"
    );
    Ok(())
}

/// `unpause` when NOT paused is idempotent SUCCESS: the stock `pausable::unpause` is an
/// unconditional `set_item` write with no not-paused guard (pinned v0.15.3
/// `pausable/mod.masm:89-101`) — the same pin-bump drift tripwire, in the unpause direction.
#[tokio::test]
async fn unpause_when_not_paused_is_idempotent() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();
    assert_eq!(read_is_paused(&account)?, Word::from([0u32, 0, 0, 0]), "fresh faucet is unpaused");

    let unpaused = run_dom_pauser_unpause(&bh.chain, &account, dom_pauser(), 15)
        .await
        .expect("unpausing an unpaused faucet is idempotent success (unconditional write)");
    let mut evolved = account.clone();
    evolved.apply_delta(unpaused.account_delta())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([0u32, 0, 0, 0]),
        "is_paused stays exactly [0,0,0,0] after the redundant unpause"
    );
    Ok(())
}

// OBSERVABILITY — is_paused reads back via GetAccount (CIR-ADMIN-4)
// ================================================================================================

/// `is_paused` is a network-observable value slot: it reads back unpaused pre-pause and paused after a
/// DOM_PAUSER pause. RED: the pause placeholder traps, so the flag never flips.
#[tokio::test]
async fn is_paused_publicly_readable() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();

    assert_eq!(
        read_is_paused(&account)?,
        Word::from([0u32, 0, 0, 0]),
        "is_paused reads back unpaused pre-pause (GetAccount observability)"
    );

    let paused = run_dom_pauser_pause(&bh.chain, &account, dom_pauser(), 9)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "after a DOM_PAUSER pause, is_paused reads back paused"
    );
    Ok(())
}
