//! Role-management suite (component CMP-F5): `DOM_PAUSER` administration delegated to `DOM_MANAGER`.
//! Circle's admin model has Domain Manager and Domain Pauser roles (rotation, pause control), gated
//! `onlyDomainManager`/`onlyOwner`.
//!
//! The delegation is a BUILD-TIME SEED: the production builder writes
//! `role_config[DOM_PAUSER] = [member_count=1, admin_role=DOM_MANAGER, 0, 0]` — byte-identical to the
//! post-state of an owner-sent stock `set_role_admin(DOM_PAUSER, DOM_MANAGER)` (rbac.masm:314-333).
//! `DOM_MANAGER.admin_role` stays 0 (owner-administered — Circle keeps rotation of the Manager itself
//! under the owner). All role-administration procs are the STOCK rbac procs the account already
//! exposes (account_components/access/rbac.masm re-exports); it ships ZERO custom MASM.
//!
//! The load-bearing proof is the ROTATION CAPABILITY SEAM, never a config read-back alone:
//! a DOM_MANAGER-sent `grant_role(DOM_PAUSER, new)` flips REAL pause power (the new member's pause
//! HALTS a real `xreserve_mint` at the exact `ERR_PAUSABLE_IS_PAUSED`), and a DOM_MANAGER-sent
//! `revoke_role` removes it (the revoked member's pause REJECTS the exact `ERR_SENDER_LACKS_ROLE`).
//! The OWNER's rotation authority is Circle's `onlyOwner` BACKSTOP (the stock owner-or-role-admin
//! gate's owner leg is structural, rbac.masm:411-417) — asserted as a POSITIVE, never stripped.
//!
//! FIXTURE RULE (shipped-build provenance): every test here runs on a PRODUCTION-composed account —
//! `setup_guarded_mint_account(GuardSelection::ProductionDeny, ...)` = the real
//! `XReserveStablecoinBuilder::build_components()`. The burn-oracle support-replica fixture
//! (`setup_burn_policy_account`) is used by NO test in this file; replica fidelity is pinned
//! separately in `set_min_burn.rs::support_replica_carries_delegation_seed`.
//!
//! RED-SUITE (executing-red): at the red commit the production seed still writes
//! `DOM_PAUSER.admin_role = 0`, so every delegation-dependent test (the seams + the provenance
//! read-back) is RED for exactly that reason — the DOM_MANAGER-sent grant/revoke notes reach real
//! MockChain execution and trap the exact `ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN` (rbac.masm:425, the
//! zero-admin leg). The owner-backstop and non-admin-reject tests are GREEN invariant pins that must
//! SURVIVE the green seed.

mod support;

use anyhow::Result;
use miden_protocol::account::{AccountId, RoleSymbol};
use miden_protocol::errors::MasmError;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::account::xreserve::{DOM_MANAGER_ROLE, DOM_PAUSER_ROLE};
use xusdc_encoding::vectors::{load, parse_hex32, DiFields, DiVector};
use xusdc_encoding::xreserve::encoding::bytes32_to_storage_map_key;

// The production builder seeds owner = id(1) (Ownable2Step), DOM_PAUSER = id(2), DOM_MANAGER = id(3).
// id(4)/id(5) are fresh member candidates the rotation grants; id(99) is a plain stranger.
fn owner() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn dom_manager() -> AccountId {
    test_account_id(3)
}
fn new_pauser() -> AccountId {
    test_account_id(4)
}
fn second_pauser() -> AccountId {
    test_account_id(5)
}
fn stranger() -> AccountId {
    test_account_id(99)
}

// The fixed role aliases, via the production Rust constants (builder.rs) — the single source the
// seed, the notes, and the read-backs all share.
fn pauser_sym() -> RoleSymbol {
    RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol (<=12)")
}
fn manager_sym() -> RoleSymbol {
    RoleSymbol::new(DOM_MANAGER_ROLE).expect("DOM_MANAGER is a fixed valid role symbol (<=12)")
}

// The exact stock errors these tests pin (assert-specific-error-in-tests; read from the pinned
// rbac.masm:50-51 / ownable2step.masm:38 / the stock pausable).
fn err_paused() -> MasmError {
    MasmError::from_static_str("the contract is paused")
}
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}
fn err_not_owner_or_role_admin() -> MasmError {
    MasmError::from_static_str("note sender is not the owner or a role admin")
}
fn err_account_not_in_role() -> MasmError {
    MasmError::from_static_str("account does not hold the role")
}

// PRODUCTION FIXTURES (both compose via XReserveStablecoinBuilder::build_components — never the
// burn-oracle replica). Recreated from public support helpers per the established per-file pattern
// (set_attester.rs `guarded_faucet`, pause_admin.rs `guarded_mint_ready` are private to their files).
// ================================================================================================

/// Config words the builder does not read (the gating tests invoke rbac procs via notes, never the
/// mint driver). Mirrors set_attester.rs.
fn dummy_config() -> (Word, Word) {
    (Word::from([7u32, 0, 0, 0]), Word::from([11u32, 12, 13, 14]))
}

/// The LEAN production faucet — the base for the gating-matrix cells that never execute a mint.
fn production_faucet() -> Result<GuardedMint> {
    let driver = mint_composition_driver_src(&[Felt::from(0u32)], 60, 6);
    let probe = composition_supply_probe_src(0);
    let (domain, identifier) = dummy_config();
    setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        None,
        &driver,
        &probe,
        true,
    )
}

// MINT-SEAM FIXTURES (reconstructed from the canonical accept payload — mirrors pause_admin.rs)
// ================================================================================================

const BASE_VECTOR: &str = "di-pos-empty-hookdata";
const LEN_FELTS: u64 = 60;
const SCALE_EXP: u32 = 6;
const HAPPY_AMOUNT_RAW: u64 = 2_000_000;
const HAPPY_MAX_FEE_RAW: u64 = 1_000_000;
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
    di(id)
        .fields
        .as_ref()
        .expect("accept vector carries fields")
}

fn with_amounts(mut payload: Vec<u8>, amount: u64, max_fee: u64) -> Vec<u8> {
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(amount));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(max_fee));
    payload
}

fn happy_payload() -> Vec<u8> {
    with_amounts(di(BASE_VECTOR).bytes(), HAPPY_AMOUNT_RAW, HAPPY_MAX_FEE_RAW)
}

fn pack(bytes: &[u8]) -> Vec<Felt> {
    miden_protocol::utils::bytes_to_packed_u32_elements(bytes)
}

fn identifier_of(id: &str) -> Word {
    Word::from(bytes32_to_storage_map_key(&parse_hex32(
        &fields_of(id).remote_token_hex,
    )))
}

fn nonce_key() -> Word {
    Word::from(bytes32_to_storage_map_key(
        &fields_of(BASE_VECTOR).bytes32("nonce"),
    ))
}

/// A production faucet pre-configured for a VALID real `xreserve_mint` (the halt-seam target):
/// domain = TEST_DOMAIN, identifier = the canonical remoteToken key, the attester allowlisted.
fn mint_ready() -> Result<(GuardedMint, AttesterVector)> {
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

// THE ROTATION SEAMS (RED) — role administration must change REAL pause capability, end-to-end
// ================================================================================================

/// THE grant seam (the Domain Manager rotates the Pauser): before the grant, id(4) has no
/// pause power (exact role trap); a DOM_MANAGER-sent `grant_role(DOM_PAUSER, id4)` then flips REAL
/// capability — id(4)'s pause HALTS a real `xreserve_mint` at the exact `ERR_PAUSABLE_IS_PAUSED`.
/// RED: the shipped seed still has `DOM_PAUSER.admin_role == 0`, so the DOM_MANAGER grant itself
/// traps `ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN` (rbac.masm:425 — no delegation).
#[tokio::test]
async fn dom_manager_grants_pauser_then_new_pauser_halts_mint() -> Result<()> {
    let (gm, attester) = mint_ready()?;
    let account = faucet_account(&gm.harness);

    // Pre-grant: the candidate's pause REJECTS — the capability is genuinely absent before the grant.
    let pre = run_dom_pauser_pause(&gm.harness.mock_chain, &account, new_pauser(), 31).await;
    assert_transaction_executor_error!(pre, err_sender_lacks_role());

    // The DOM_MANAGER holder grants DOM_PAUSER to id(4) (the delegated operational rotation path).
    let granted = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        dom_manager(),
        &pauser_sym(),
        new_pauser(),
        32,
    )
    .await
    .expect("the delegated DOM_MANAGER grant passes (DOM_PAUSER.admin_role == DOM_MANAGER)");
    let mut evolved = account.clone();
    evolved.apply_delta(granted.account_delta())?;
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), new_pauser())?[0],
        Felt::from(1u32),
        "the delegated grant landed the membership flag"
    );

    // The NEW member's pause now succeeds...
    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, new_pauser(), 33)
        .await
        .expect("the newly granted DOM_PAUSER member pauses the faucet");
    evolved.apply_delta(paused.account_delta())?;

    // ...and HALTS the real mint at the exact stock pause error — the capability change is REAL.
    let result = run_mint_against(
        &gm.harness,
        &evolved,
        composition_advice([0u32; 8], &attester),
    )
    .await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// The revoke seam: a DOM_MANAGER-sent `revoke_role(DOM_PAUSER, id2)` strips the SEEDED pauser's
/// power — the revoked member's pause REJECTS the exact `ERR_SENDER_LACKS_ROLE` and `is_paused`
/// stays untouched. Also pins the stock revoke effects (membership cleared, member_count 1 -> 0,
/// the delegation RETAINED in the config — rbac.rs:79-82). RED: the revoke itself traps (no delegation).
#[tokio::test]
async fn dom_manager_revokes_pauser_then_pause_rejects() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        dom_manager(),
        &pauser_sym(),
        dom_pauser(),
        34,
    )
    .await
    .expect("the delegated DOM_MANAGER revoke passes (DOM_PAUSER.admin_role == DOM_MANAGER)");
    let mut evolved = account.clone();
    evolved.apply_delta(revoked.account_delta())?;

    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), dom_pauser())?[0],
        Felt::ZERO,
        "the revoked member's membership flag is cleared"
    );
    let config = read_role_config(&evolved, &pauser_sym())?;
    assert_eq!(
        config[0],
        Felt::ZERO,
        "DOM_PAUSER member_count decremented to 0"
    );
    assert_eq!(
        config[1],
        Felt::from(&manager_sym()),
        "the delegation survives the last-member revoke (admin config retained)"
    );

    // The revoked member's pause now REJECTS with the exact role error; is_paused is unchanged.
    let result = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, dom_pauser(), 35).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::ZERO,
        "a failed pause leaves is_paused untouched"
    );
    Ok(())
}

/// The FULL rotation, revoke-FIRST (the ordering that must survive the empty role): DOM_MANAGER
/// revokes the incumbent id(2) (member_count -> 0), THEN grants the successor id(4) — possible only
/// because the admin config is retained when the last member is revoked (rbac.rs:79-82; a wiped
/// delegation would deadlock rotation). The OLD pauser's pause rejects; the NEW pauser's pause HALTS
/// a real mint. RED: the first revoke traps (no delegation).
#[tokio::test]
async fn dom_manager_rotates_pauser_revoke_then_grant() -> Result<()> {
    let (gm, attester) = mint_ready()?;
    let account = faucet_account(&gm.harness);

    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        dom_manager(),
        &pauser_sym(),
        dom_pauser(),
        36,
    )
    .await
    .expect("the rotation's revoke leg passes under the delegation");
    let mut evolved = account.clone();
    evolved.apply_delta(revoked.account_delta())?;

    let granted = run_grant_role_against(
        &gm.harness.mock_chain,
        &evolved,
        dom_manager(),
        &pauser_sym(),
        new_pauser(),
        37,
    )
    .await
    .expect("the rotation's grant leg passes through the empty role (admin config retained)");
    evolved.apply_delta(granted.account_delta())?;

    // The OLD pauser's pause rejects — rotation genuinely removed the incumbent's power.
    let old = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, dom_pauser(), 38).await;
    assert_transaction_executor_error!(old, err_sender_lacks_role());

    // The NEW pauser pauses, and the pause halts a REAL mint.
    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, new_pauser(), 39)
        .await
        .expect("the rotated-in DOM_PAUSER member pauses the faucet");
    evolved.apply_delta(paused.account_delta())?;
    let result = run_mint_against(
        &gm.harness,
        &evolved,
        composition_advice([0u32; 8], &attester),
    )
    .await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

// STOCK-BRANCH PINS — the grant no-op branch, the non-member revoke trap, self-renounce
// ================================================================================================

/// A double-grant leaves NO ghost member: the stock `grant_role_internal` takes its
/// "Already a member — no-op" branch BEFORE the count increment (pinned v0.15.3 rbac.masm:445-496
/// — `has_role → drop drop drop`; the `add.1` sits only in the else branch), so granting the
/// SEEDED DOM_PAUSER member a second time cannot double-increment `member_count`, and ONE revoke
/// fully removes the member — their pause then rejects with the exact role error. (The existing
/// pins cover count 1→0 and revoke-then-grant; neither touched the no-op branch.)
#[tokio::test]
async fn double_grant_pauser_leaves_no_ghost_member() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    // Grant DOM_PAUSER to the ALREADY-seeded member: idempotent success via the no-op branch...
    let granted = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        dom_manager(),
        &pauser_sym(),
        dom_pauser(),
        51,
    )
    .await
    .expect("granting an existing member succeeds via the stock no-op branch");
    let mut evolved = account.clone();
    evolved.apply_delta(granted.account_delta())?;

    // ...with NO count increment (the ghost-member hazard this test forecloses).
    assert_eq!(
        read_role_config(&evolved, &pauser_sym())?[0],
        Felt::from(1u32),
        "member_count stays exactly 1 after the double grant (no-op branch, no increment)"
    );
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), dom_pauser())?[0],
        Felt::from(1u32),
        "the membership flag is unchanged"
    );

    // ONE revoke fully removes the member — no ghost count survives.
    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &evolved,
        dom_manager(),
        &pauser_sym(),
        dom_pauser(),
        52,
    )
    .await
    .expect("one revoke removes the double-granted member");
    evolved.apply_delta(revoked.account_delta())?;
    assert_eq!(
        read_role_config(&evolved, &pauser_sym())?[0],
        Felt::ZERO,
        "ONE revoke takes member_count to 0 (a ghost would leave 1)"
    );
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), dom_pauser())?[0],
        Felt::ZERO,
        "the membership flag is cleared"
    );
    let result = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, dom_pauser(), 53).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

/// Revoking a NON-member traps the EXACT stock `ERR_ACCOUNT_NOT_IN_ROLE`
/// (pinned v0.15.3 rbac.masm:52, asserted in `revoke_role_internal` at :520) and leaves the role
/// config untouched — the first pin of this stock constant in the repo.
#[tokio::test]
async fn revoke_role_non_member_traps() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let result = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        dom_manager(),
        &pauser_sym(),
        stranger(),
        54,
    )
    .await;
    assert_transaction_executor_error!(result, err_account_not_in_role());
    assert_eq!(
        read_role_config(&account, &pauser_sym())?[0],
        Felt::from(1u32),
        "a rejected non-member revoke leaves member_count untouched"
    );
    Ok(())
}

/// CHARACTERIZATION pin of the stock `renounce_role` ops surface: a DOM_PAUSER holder can
/// SELF-remove (the stock proc is self-only by construction — it reads the note sender — and has
/// no owner/admin gate; re-exported on the account interface,
/// `account_components/access/rbac.masm:12`). After the renounce, their pause rejects with the
/// exact role error. Documents that self-renounce is possible BY DESIGN — an ops-surface fact,
/// not a defect.
#[tokio::test]
async fn dom_pauser_can_renounce_own_role() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let renounced = run_renounce_role_against(
        &gm.harness.mock_chain,
        &account,
        dom_pauser(),
        &pauser_sym(),
        55,
    )
    .await
    .expect("a DOM_PAUSER holder self-renounces (stock renounce_role, self-only)");
    let mut evolved = account.clone();
    evolved.apply_delta(renounced.account_delta())?;
    assert_eq!(
        read_role_config(&evolved, &pauser_sym())?[0],
        Felt::ZERO,
        "self-renounce decrements member_count to 0"
    );
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), dom_pauser())?[0],
        Felt::ZERO,
        "self-renounce clears the membership flag"
    );
    let result = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, dom_pauser(), 56).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

/// The shipped-build provenance read-back — against the PRODUCTION `XReserveStablecoinBuilder`
/// account (NOT the burn-oracle support replica; that is pinned separately in
/// `set_min_burn.rs::support_replica_carries_delegation_seed`). Supplementary to the capability
/// seams above (the only config-word-level assertion in this file). RED: the production seed still
/// writes `admin_role = 0`.
#[tokio::test]
async fn shipped_delegation_reads_back() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let pauser_config = read_role_config(&account, &pauser_sym())?;
    assert_eq!(
        pauser_config[0],
        Felt::from(1u32),
        "DOM_PAUSER member_count == 1"
    );
    assert_eq!(
        pauser_config[1],
        Felt::from(&manager_sym()),
        "DOM_PAUSER.admin_role == DOM_MANAGER (the CMP-F5 delegation, seeded at build)"
    );
    assert_eq!(
        pauser_config[2],
        Felt::ZERO,
        "DOM_PAUSER config felt 2 is zero"
    );
    assert_eq!(
        pauser_config[3],
        Felt::ZERO,
        "DOM_PAUSER config felt 3 is zero"
    );

    assert_eq!(
        read_role_config(&account, &manager_sym())?,
        Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        "DOM_MANAGER stays owner-administered: [member_count=1, admin_role=0, 0, 0]"
    );

    assert_eq!(
        read_role_membership(&account, &pauser_sym(), dom_pauser())?[0],
        Felt::from(1u32),
        "the seeded DOM_PAUSER member id(2) is unchanged"
    );
    assert_eq!(
        read_role_membership(&account, &manager_sym(), dom_manager())?[0],
        Felt::from(1u32),
        "the seeded DOM_MANAGER member id(3) is unchanged"
    );
    Ok(())
}

// THE OWNER BACKSTOP (GREEN pins) — Circle's onlyOwner rotation authority, asserted POSITIVE
// ================================================================================================

/// The Circle owner-only BACKSTOP as a POSITIVE (the owner-only rotation authority): the
/// owner grants id(5) and the new member's pause SUCCEEDS (`is_paused` flips) — capability-level, not
/// a config read-back. The stock gate's owner leg is structural (rbac.masm:412-417) and must NEVER be
/// stripped. GREEN at the red commit; must SURVIVE the delegation (the delegated admin does not
/// displace the owner).
#[tokio::test]
async fn owner_can_still_grant_pauser() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let granted = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        owner(),
        &pauser_sym(),
        second_pauser(),
        40,
    )
    .await
    .expect("the owner backstop grant passes (the stock owner leg is structural)");
    let mut evolved = account.clone();
    evolved.apply_delta(granted.account_delta())?;

    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, second_pauser(), 41)
        .await
        .expect("the owner-granted member pauses the faucet");
    evolved.apply_delta(paused.account_delta())?;
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::from(1u32),
        "the owner-granted pauser's pause is REAL (is_paused flipped)"
    );
    Ok(())
}

/// The backstop's other direction: the owner revokes the seeded pauser id(2) and the revoked member's
/// pause REJECTS the exact role error. GREEN at the red commit; must survive the delegation.
#[tokio::test]
async fn owner_can_still_revoke_pauser() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        owner(),
        &pauser_sym(),
        dom_pauser(),
        42,
    )
    .await
    .expect("the owner backstop revoke passes");
    let mut evolved = account.clone();
    evolved.apply_delta(revoked.account_delta())?;

    let result = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, dom_pauser(), 43).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::ZERO,
        "a failed pause leaves is_paused untouched"
    );
    Ok(())
}

// THE GATING MATRIX REJECT CELLS (GREEN pins) — exact errors + no state change
// ================================================================================================

/// Shared: a non-owner non-DOM_MANAGER `sender` can NEITHER grant NOR revoke DOM_PAUSER — both trap
/// the exact `ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN` (rbac.masm:411; at the red commit via the
/// zero-admin leg `:425`, post-green via the membership leg `:431` — same constant), and the failed
/// txs leave the committed membership/config words untouched.
async fn assert_non_admin_cannot_administer_pauser(sender: AccountId, seed: u64) -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let grant = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        sender,
        &pauser_sym(),
        new_pauser(),
        seed,
    )
    .await;
    assert_transaction_executor_error!(grant, err_not_owner_or_role_admin());

    let revoke = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        sender,
        &pauser_sym(),
        dom_pauser(),
        seed + 1,
    )
    .await;
    assert_transaction_executor_error!(revoke, err_not_owner_or_role_admin());

    // No state change: the rejected txs produced no delta; the committed words are intact.
    assert_eq!(
        read_role_membership(&account, &pauser_sym(), new_pauser())?[0],
        Felt::ZERO,
        "the rejected grant landed no membership"
    );
    assert_eq!(
        read_role_membership(&account, &pauser_sym(), dom_pauser())?[0],
        Felt::from(1u32),
        "the rejected revoke removed no membership"
    );
    assert_eq!(
        read_role_config(&account, &pauser_sym())?[0],
        Felt::from(1u32),
        "DOM_PAUSER member_count is unchanged"
    );
    Ok(())
}

/// A DOM_PAUSER holder cannot administer its own role (a pauser is not a role admin).
#[tokio::test]
async fn dom_pauser_holder_cannot_grant_or_revoke() -> Result<()> {
    assert_non_admin_cannot_administer_pauser(dom_pauser(), 44).await
}

/// A plain stranger cannot grant or revoke.
#[tokio::test]
async fn stranger_cannot_grant_or_revoke() -> Result<()> {
    assert_non_admin_cannot_administer_pauser(stranger(), 46).await
}

/// Shared: a non-owner `sender` is rejected from `set_role_admin` with the exact
/// `ERR_SENDER_NOT_OWNER` (the proc is OWNER-ONLY, rbac.masm:163-164) and the delegation word is
/// untouched. The DOM_MANAGER cell is the load-bearing one: the Manager rotates MEMBERS, never the
/// delegation itself.
async fn assert_set_role_admin_rejected(sender: AccountId, seed: u64) -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);
    let before = read_role_config(&account, &pauser_sym())?;

    let result = run_set_role_admin_against(
        &gm.harness.mock_chain,
        &account,
        sender,
        &pauser_sym(),
        Some(&manager_sym()),
        seed,
    )
    .await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    assert_eq!(
        read_role_config(&account, &pauser_sym())?,
        before,
        "a rejected set_role_admin leaves the role config untouched"
    );
    Ok(())
}

/// DOM_MANAGER cannot re-delegate role administration (owner-only).
#[tokio::test]
async fn set_role_admin_dom_manager_rejects() -> Result<()> {
    assert_set_role_admin_rejected(dom_manager(), 48).await
}

/// DOM_PAUSER cannot re-delegate role administration.
#[tokio::test]
async fn set_role_admin_dom_pauser_rejects() -> Result<()> {
    assert_set_role_admin_rejected(dom_pauser(), 49).await
}

/// A stranger cannot re-delegate role administration.
#[tokio::test]
async fn set_role_admin_stranger_rejects() -> Result<()> {
    assert_set_role_admin_rejected(stranger(), 50).await
}

/// SEPARATION: `DOM_MANAGER.admin_role` stays 0 (owner-administered), so a DOM_MANAGER holder cannot
/// administer DOM_MANAGER itself — self-expansion of the manager set is owner territory (Circle keeps
/// rotation of the Manager under the owner). Both ops trap the exact gate error; the seeded manager
/// state is untouched.
#[tokio::test]
async fn dom_manager_cannot_administer_dom_manager() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let grant = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        dom_manager(),
        &manager_sym(),
        new_pauser(),
        51,
    )
    .await;
    assert_transaction_executor_error!(grant, err_not_owner_or_role_admin());

    let revoke = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        dom_manager(),
        &manager_sym(),
        dom_manager(),
        52,
    )
    .await;
    assert_transaction_executor_error!(revoke, err_not_owner_or_role_admin());

    assert_eq!(
        read_role_config(&account, &manager_sym())?[1],
        Felt::ZERO,
        "DOM_MANAGER.admin_role stays 0 (owner-administered)"
    );
    assert_eq!(
        read_role_membership(&account, &manager_sym(), dom_manager())?[0],
        Felt::from(1u32),
        "the seeded DOM_MANAGER membership is unchanged"
    );
    Ok(())
}

// RUNTIME DELEGATION CONTROL (GREEN pin) — the shipped seed is config-driven, owner-rotatable state
// ================================================================================================

/// The delegation is CONFIG-DRIVEN state under runtime owner control, not baked-in behavior: the
/// owner CLEARS it (`set_role_admin(DOM_PAUSER, 0)`) and a DOM_MANAGER grant REJECTS; the owner
/// RE-SETS it and the same grant SUCCEEDS. `member_count` is preserved through both `set_role_admin`
/// writes (rbac.masm:168-174). GREEN at the red commit (the runtime machinery is stock); after the
/// green seed the clear-leg additionally proves the SHIPPED delegation is clearable.
#[tokio::test]
async fn owner_set_role_admin_controls_delegation() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    // The owner clears the delegation (admin_role -> 0).
    let cleared = run_set_role_admin_against(
        &gm.harness.mock_chain,
        &account,
        owner(),
        &pauser_sym(),
        None,
        53,
    )
    .await
    .expect("the owner clears the DOM_PAUSER delegation (set_role_admin is owner-only)");
    let mut evolved = account.clone();
    evolved.apply_delta(cleared.account_delta())?;
    let config = read_role_config(&evolved, &pauser_sym())?;
    assert_eq!(config[1], Felt::ZERO, "the delegation is cleared");
    assert_eq!(
        config[0],
        Felt::from(1u32),
        "member_count is preserved through set_role_admin"
    );

    // With the delegation cleared, the DOM_MANAGER holder can no longer grant.
    let denied = run_grant_role_against(
        &gm.harness.mock_chain,
        &evolved,
        dom_manager(),
        &pauser_sym(),
        new_pauser(),
        54,
    )
    .await;
    assert_transaction_executor_error!(denied, err_not_owner_or_role_admin());

    // The owner re-delegates; the DOM_MANAGER grant now passes.
    let reset = run_set_role_admin_against(
        &gm.harness.mock_chain,
        &evolved,
        owner(),
        &pauser_sym(),
        Some(&manager_sym()),
        55,
    )
    .await
    .expect("the owner re-delegates DOM_PAUSER administration to DOM_MANAGER");
    evolved.apply_delta(reset.account_delta())?;
    assert_eq!(
        read_role_config(&evolved, &pauser_sym())?[1],
        Felt::from(&manager_sym()),
        "the delegation is restored"
    );

    let granted = run_grant_role_against(
        &gm.harness.mock_chain,
        &evolved,
        dom_manager(),
        &pauser_sym(),
        new_pauser(),
        56,
    )
    .await
    .expect("with the delegation in place the DOM_MANAGER grant passes");
    evolved.apply_delta(granted.account_delta())?;
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), new_pauser())?[0],
        Felt::from(1u32),
        "the delegated grant landed"
    );
    Ok(())
}
