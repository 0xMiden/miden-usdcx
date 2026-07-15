//! Role-management suite (component CMP-F5): `DOM_PAUSER` administration delegated to `DOM_MANAGER`.
//! Circle's admin model has Domain Manager and Domain Pauser roles (rotation, pause control), gated
//! `onlyDomainManager`/`onlyOwner`.
//!
//! The delegation is a BUILD-TIME SEED: the production builder writes
//! `role_config[DOM_PAUSER] = [member_count=1, admin_role=DOM_MANAGER, 0, 0]` — byte-identical to the
//! post-state of a stock `set_role_admin(DOM_PAUSER, DOM_MANAGER)` (alpha.2 rbac.masm:196-211).
//! `DOM_MANAGER.admin_role` stays 0 (owner-administered via the seeded `ADMIN` role — Circle keeps
//! rotation of the Manager itself under the owner), and since the S21 disposition flip
//! (human-ratified 2026-07-14) the whole delegation graph deploys FROZEN at this seed: the runtime
//! `set_role_admin` note is removed from the allowlist, so no on-chain sender can re-point or clear
//! any role's admin (GLOSSARY IMPL-DEV-24; enforced by `account_callable_surface.rs`). All
//! role-administration procs are the STOCK rbac procs the account already
//! exposes (account_components/access/rbac.masm re-exports); it ships ZERO custom MASM.
//!
//! The load-bearing proof is the ROTATION CAPABILITY SEAM, never a config read-back alone:
//! a DOM_MANAGER-sent `grant_role(DOM_PAUSER, new)` flips REAL pause power (the new member's pause
//! HALTS a real `xreserve_mint` at the exact `ERR_PAUSABLE_IS_PAUSED`), and a DOM_MANAGER-sent
//! `revoke_role` removes it (the revoked member's pause REJECTS the exact `ERR_SENDER_LACKS_ROLE`).
//! The OWNER's rotation authority is Circle's BACKSTOP — at v0.16 (#3215 removed the owner's
//! implicit super-admin standing) it runs through the built-in `ADMIN` role the builder seeds on the
//! owner's account: owner (ADMIN) administers DOM_MANAGER, DOM_MANAGER administers DOM_PAUSER
//! (MIGRATION-V16-ALPHA2.md S2/S21). It is still asserted as a POSITIVE ending in REAL pause power
//! gained/lost, never a config read-back. Since the S21 flip the backstop cannot be stripped
//! on-chain: stock delegation is EXCLUSIVE (alpha.2 rbac.masm:20-22), but with the `set_role_admin`
//! note removed the delegation configuration is immutable post-deploy, so `ADMIN`'s authority over
//! `DOM_MANAGER` (and `DOM_MANAGER`'s over `DOM_PAUSER`) is structurally fixed at the seed. The
//! HOLDER side is account-bound (S2, operator-approved): `ADMIN` membership sits on the owner
//! ACCOUNT and does NOT auto-follow `transfer_ownership`/`accept_ownership` — the rotation
//! runbook re-seats it (grant-new BEFORE revoke-old, so there is no zero-ADMIN window); until
//! then a post-transfer owner lacks RBAC administration (builder.rs KNOWN DIVERGENCE).
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
//! MockChain execution and trap the exact role-admin error (at v0.16: `ERR_SENDER_NOT_ROLE_ADMIN`,
//! rbac.masm:66 — the v15 `ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN` was re-keyed by #3215). The
//! owner-backstop and non-admin-reject tests are GREEN invariant pins that must SURVIVE the green
//! seed.

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
fn err_not_role_admin() -> MasmError {
    // v16 #3215: the owner path is gone — the stock error re-keyed from
    // ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN to ERR_SENDER_NOT_ROLE_ADMIN (rbac.masm:66).
    MasmError::from_static_str("note sender does not hold the role's admin role")
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
/// traps `ERR_SENDER_NOT_ROLE_ADMIN` (the stock effective-admin gate with no delegation configured;
/// v0.16 re-keyed the v15 `ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN` — S2/S21).
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
    evolved.apply_patch(granted.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), new_pauser())?[0],
        Felt::from(1u32),
        "the delegated grant landed the membership flag"
    );

    // The NEW member's pause now succeeds...
    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, new_pauser(), 33)
        .await
        .expect("the newly granted DOM_PAUSER member pauses the faucet");
    evolved.apply_patch(paused.account_patch())?;

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
    evolved.apply_patch(revoked.account_patch())?;

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
    evolved.apply_patch(revoked.account_patch())?;

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
    evolved.apply_patch(granted.account_patch())?;

    // The OLD pauser's pause rejects — rotation genuinely removed the incumbent's power.
    let old = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, dom_pauser(), 38).await;
    assert_transaction_executor_error!(old, err_sender_lacks_role());

    // The NEW pauser pauses, and the pause halts a REAL mint.
    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, new_pauser(), 39)
        .await
        .expect("the rotated-in DOM_PAUSER member pauses the faucet");
    evolved.apply_patch(paused.account_patch())?;
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
/// "Already a member — no-op" branch BEFORE the count increment (the pinned `=0.16.0-alpha.2`
/// `rbac.masm` — `has_role → drop drop drop`; the `add.1` sits only in the else branch), so granting the
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
    evolved.apply_patch(granted.account_patch())?;

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
    evolved.apply_patch(revoked.account_patch())?;
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
/// (the pinned `=0.16.0-alpha.2` `rbac.masm`, asserted inside `revoke_role_internal`) and leaves
/// the role config untouched — the first pin of this stock constant in the repo.
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
    evolved.apply_patch(renounced.account_patch())?;
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
        "DOM_MANAGER stays ADMIN-administered (the seeded owner account's account-bound membership): [member_count=1, admin_role=0, 0, 0]"
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

/// The Circle owner BACKSTOP as a POSITIVE, in its v16 shape (S2, operator-approved): the owner
/// ACCOUNT holds the stock `ADMIN` role (an account-bound membership — it does not auto-follow an
/// ownership transfer; runbook re-seat, S2), which is DOM_MANAGER's effective admin (#3215 removed
/// the implicit owner super-admin; `admin_role = 0` now resolves to `ADMIN`, rbac.masm:427-438).
/// The ADMIN-holding owner therefore rotates the MANAGER, and the manager rotates the PAUSER —
/// the same ultimate authority, one hop longer. Capability-level: the chain ends in a REAL pause by an
/// owner-rooted member (`is_paused` flips), not a config read-back.
#[tokio::test]
async fn owner_can_still_grant_pauser() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    // Hop 1: the owner (ADMIN member) grants DOM_MANAGER to a new account.
    let granted_manager = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        owner(),
        &manager_sym(),
        second_pauser(),
        40,
    )
    .await
    .expect("the owner backstop grant of DOM_MANAGER passes (owner holds ADMIN)");
    let mut evolved = account.clone();
    evolved.apply_patch(granted_manager.account_patch())?;

    // Hop 2: the owner-installed manager grants DOM_PAUSER to a new pauser.
    let granted_pauser = run_grant_role_against(
        &gm.harness.mock_chain,
        &evolved,
        second_pauser(),
        &pauser_sym(),
        new_pauser(),
        41,
    )
    .await
    .expect("the owner-installed DOM_MANAGER grants DOM_PAUSER (CMP-F5 delegation)");
    evolved.apply_patch(granted_pauser.account_patch())?;

    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, new_pauser(), 42)
        .await
        .expect("the owner-rooted member pauses the faucet");
    evolved.apply_patch(paused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::from(1u32),
        "the owner-rooted pauser's pause is REAL (is_paused flipped)"
    );
    Ok(())
}

/// The backstop's other direction — the v15 proof re-expressed through the v16 authority chain,
/// ending (as it must) in a REAL loss of pause authority by an EXISTING pauser: the owner (ADMIN
/// member) grants itself DOM_MANAGER — DOM_PAUSER's effective admin, #3215/S21 — then, so
/// empowered, REVOKES DOM_PAUSER from the seeded pauser id(2); that pauser's pause is then
/// REJECTED with the exact role error and `is_paused` never flips. The (seeded-ADMIN-member)
/// owner therefore retains Circle's backstop ability to strip a live pauser, one hop longer than
/// at v15 (account-bound across ownership transfer — S2 runbook re-seat).
#[tokio::test]
async fn owner_can_still_revoke_pauser() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    // Hop 1: the owner (ADMIN member) takes DOM_MANAGER — DOM_PAUSER's effective admin.
    let self_manager = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        owner(),
        &manager_sym(),
        owner(),
        42,
    )
    .await
    .expect("the owner (ADMIN member) grants itself DOM_MANAGER");
    let mut evolved = account.clone();
    evolved.apply_patch(self_manager.account_patch())?;

    // Hop 2: now DOM_MANAGER-holding, the owner revokes the SEEDED pauser id(2)'s DOM_PAUSER.
    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &evolved,
        owner(),
        &pauser_sym(),
        dom_pauser(),
        43,
    )
    .await
    .expect("the DOM_MANAGER-holding owner revokes the seeded pauser's DOM_PAUSER");
    evolved.apply_patch(revoked.account_patch())?;

    // The REAL loss of authority: the revoked pauser's pause is rejected and is_paused stays 0.
    let result = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, dom_pauser(), 44).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::ZERO,
        "the revoked pauser's failed pause leaves is_paused untouched"
    );
    Ok(())
}

/// The backstop's OTHER lever (v16, additive): the owner (ADMIN member) can CUT the delegation
/// chain outright — revoking DOM_MANAGER from the seeded manager id(3) leaves that holder unable
/// to administer DOM_PAUSER at all (the exact role-admin error). Complements
/// [`owner_can_still_revoke_pauser`], which strips an existing pauser directly.
#[tokio::test]
async fn owner_can_revoke_dom_manager_cutting_the_delegation_chain() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        owner(),
        &manager_sym(),
        dom_manager(),
        45,
    )
    .await
    .expect("the owner backstop revoke of DOM_MANAGER passes (owner holds ADMIN)");
    let mut evolved = account.clone();
    evolved.apply_patch(revoked.account_patch())?;

    let denied = run_grant_role_against(
        &gm.harness.mock_chain,
        &evolved,
        dom_manager(),
        &pauser_sym(),
        new_pauser(),
        46,
    )
    .await;
    assert_transaction_executor_error!(denied, err_not_role_admin());
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::ZERO,
        "a failed grant leaves is_paused untouched"
    );
    Ok(())
}

// THE GATING MATRIX REJECT CELLS (GREEN pins) — exact errors + no state change
// ================================================================================================

/// Shared: a non-owner non-DOM_MANAGER `sender` can NEITHER grant NOR revoke DOM_PAUSER — both trap
/// the exact `ERR_SENDER_NOT_ROLE_ADMIN` (the stock `assert_sender_is_role_admin` gate — reached at
/// the red commit via its zero-admin leg and post-green via its membership leg, the same constant
/// either way), and the failed txs leave the committed membership/config words untouched.
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
    assert_transaction_executor_error!(grant, err_not_role_admin());

    let revoke = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        sender,
        &pauser_sym(),
        dom_pauser(),
        seed + 1,
    )
    .await;
    assert_transaction_executor_error!(revoke, err_not_role_admin());

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

/// Shared: a sender who does NOT hold DOM_PAUSER's effective admin role is rejected from
/// `set_role_admin(DOM_PAUSER, …)` with the exact `ERR_SENDER_NOT_ROLE_ADMIN`, and the delegation
/// word is untouched. v16 #3215 (S21): the gate is the ROLE's effective admin.
///
/// NOTE (S21 disposition flip, human-ratified 2026-07-14): every `set_role_admin` test in this
/// file is a PROC-LEVEL CHARACTERIZATION pin under the permissive-auth fixture — the same
/// treatment as `dom_pauser_can_renounce_own_role`. In PRODUCTION the proc is
/// present-but-UNREACHABLE: the runtime `set_role_admin` note was REMOVED from the note-script
/// allowlist (12 roots, no set_role_admin; tx-script allowlist empty), so the role-admin graph is
/// frozen at the build seed and rotation is `grant_role`/`revoke_role` only. Proofs:
/// `account_callable_surface.rs` (membership + MAST sweep) and `f5_admin_notes.rs` (the preserved
/// former note is consumed and rejected).
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
    assert_transaction_executor_error!(result, err_not_role_admin());
    assert_eq!(
        read_role_config(&account, &pauser_sym())?,
        before,
        "a rejected set_role_admin leaves the role config untouched"
    );
    Ok(())
}

/// v16 #3215 (S21): the OWNER — an ADMIN member but not a DOM_MANAGER holder — is rejected by the
/// STOCK PROC's gate on a direct `set_role_admin(DOM_PAUSER, …)`; the gate is DOM_PAUSER's
/// effective admin (DOM_MANAGER). Proc-level characterization only: in production NO sender
/// reaches this proc at all (the note is not allowlisted — S21 removal). The owner's rotation
/// backstop is the build-seeded fixed graph + `grant_role`/`revoke_role` (CIR-ADMIN-3), not any
/// runtime re-delegation guarantee.
#[tokio::test]
async fn set_role_admin_owner_direct_rejects() -> Result<()> {
    assert_set_role_admin_rejected(owner(), 48).await
}

/// CHARACTERIZATION pin of the STOCK PROC's v16 gate (#3215/S21): at proc level, DOM_MANAGER —
/// DOM_PAUSER's delegated admin — passes the `set_role_admin(DOM_PAUSER, …)` gate (a capability
/// the proc did not expose to it at v15, where the gate was owner-only). Kept loud so the stock
/// semantics are pinned, exactly like `dom_pauser_can_renounce_own_role`. In PRODUCTION this path
/// is structurally unreachable — the runtime `set_role_admin` note was removed from the allowlist
/// (S21 flip, 2026-07-14) precisely so this Manager re-delegation (and owner self-lockout) cannot
/// occur on-chain.
#[tokio::test]
async fn set_role_admin_dom_manager_can_redelegate_pauser() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let cleared = run_set_role_admin_against(
        &gm.harness.mock_chain,
        &account,
        dom_manager(),
        &pauser_sym(),
        None,
        49,
    )
    .await
    .expect("v16: DOM_PAUSER's delegated admin (DOM_MANAGER) may re-delegate it");
    let mut evolved = account.clone();
    evolved.apply_patch(cleared.account_patch())?;
    let config = read_role_config(&evolved, &pauser_sym())?;
    assert_eq!(config[1], Felt::ZERO, "the delegation is cleared");
    assert_eq!(
        config[0],
        Felt::from(1u32),
        "member_count is preserved through set_role_admin"
    );
    Ok(())
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

/// SEPARATION: `DOM_MANAGER.admin_role` stays 0 (→ ADMIN = the seeded owner account), so a
/// DOM_MANAGER holder cannot administer DOM_MANAGER itself — self-expansion of the manager set is
/// ADMIN territory, i.e. the seeded owner account's (Circle keeps rotation of the Manager under
/// the owner; account-bound per S2). Both ops trap the exact gate error; the seeded manager
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
    assert_transaction_executor_error!(grant, err_not_role_admin());

    let revoke = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        dom_manager(),
        &manager_sym(),
        dom_manager(),
        52,
    )
    .await;
    assert_transaction_executor_error!(revoke, err_not_role_admin());

    assert_eq!(
        read_role_config(&account, &manager_sym())?[1],
        Felt::ZERO,
        "DOM_MANAGER.admin_role stays 0 (ADMIN-administered: the seeded owner account)"
    );
    assert_eq!(
        read_role_membership(&account, &manager_sym(), dom_manager())?[0],
        Felt::from(1u32),
        "the seeded DOM_MANAGER membership is unchanged"
    );
    Ok(())
}

// DELEGATION SEED SEMANTICS (proc-level characterization) — the seed is stock-config-shaped state
// ================================================================================================

/// PROC-LEVEL CHARACTERIZATION (permissive-auth fixture): the seeded delegation word is exactly
/// the state the stock procs operate on — the (DOM_MANAGER-holding) owner CLEARS it
/// (`set_role_admin(DOM_PAUSER, 0)`) and a DOM_MANAGER grant REJECTS; re-SETTING it makes the same
/// grant SUCCEED. `member_count` is preserved through both `set_role_admin` writes
/// (rbac.masm:168-174). This proves the build seed is byte-faithful stock-RBAC state, NOT that the
/// graph is runtime-rotatable in production: there the `set_role_admin` note is not allowlisted
/// (S21 removal, 2026-07-14), so the deployed graph is FROZEN at the seed and only membership
/// (`grant_role`/`revoke_role`) rotates.
#[tokio::test]
async fn owner_reaches_set_role_admin_through_dom_manager() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    // v16 #3215 (S21): `set_role_admin(DOM_PAUSER)` is gated on DOM_PAUSER's effective admin
    // (DOM_MANAGER), so the owner reaches it by first granting ITSELF DOM_MANAGER — which it may
    // do as the ADMIN member (DOM_MANAGER's own effective admin). Two hops, same end authority.
    let self_manager = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        owner(),
        &manager_sym(),
        owner(),
        52,
    )
    .await
    .expect("the owner (ADMIN member) grants itself DOM_MANAGER");
    let mut evolved = account.clone();
    evolved.apply_patch(self_manager.account_patch())?;

    // Now DOM_MANAGER-holding, the owner clears the delegation (admin_role -> 0).
    let cleared = run_set_role_admin_against(
        &gm.harness.mock_chain,
        &evolved,
        owner(),
        &pauser_sym(),
        None,
        53,
    )
    .await
    .expect("the DOM_MANAGER-holding owner clears the DOM_PAUSER delegation");
    evolved.apply_patch(cleared.account_patch())?;
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
    assert_transaction_executor_error!(denied, err_not_role_admin());

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
    evolved.apply_patch(reset.account_patch())?;
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
    evolved.apply_patch(granted.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), new_pauser())?[0],
        Felt::from(1u32),
        "the delegated grant landed"
    );
    Ok(())
}
