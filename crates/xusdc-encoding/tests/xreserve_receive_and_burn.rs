//! CMP-B3 burn-consume composition (`xreserve_receive_and_burn`, P5-01, §5.11).
//!
//! DETERMINATION (source-verified, plan §2): the stock `receive_and_burn` + the active CMP-A10 burn
//! policy + the CMP-B2 note ARE the complete burn-consume path — there is NO custom
//! `xreserve_receive_and_burn.masm` (a needless proc is forbidden). So this slice is test/audit only.
//!
//! The load-bearing piece is the SOLE-SUPPLY-DECREMENT audit (the burn twin of the accepted mint
//! sole-raise sweep): the built faucet has exactly ONE `token_supply`-lowering surface — the stock
//! `receive_and_burn`, gated by CMP-A10 — and no other proc decrements supply. It is asserted at the
//! code/storage-COMMITMENT level (not a supply-delta):
//!   - N1A (in `mint_deny.rs::no_other_supply_surface_static_sweep`): the LOCAL xreserve tree has
//!     exactly one `TOKEN_CONFIG_SLOT` write and it RAISES — no local lowering surface, by design.
//!   - N1B (`only_receive_and_burn_lowers_supply` + the allow-all negative): the built faucet's ACTIVE
//!     burn-policy STORAGE slot holds the CMP-A10 root, so the sole decrement path is policy-gated.
//!   - N1D (`pinned_standards_*`): the inherited decrement primitive `exec.faucet::burn` has exactly
//!     one standards caller (`receive_and_burn`) at the pinned dependency baseline.
//! N2/N3 re-confirm the end-to-end composition (real `XReserveBurnNote` → `receive_and_burn` → CMP-A10):
//! a valid burn decrements exactly once; invalid burns (below-min / zero / paused) trap the exact
//! CMP-A10/stock error. They consume CMP-A10/CMP-B2 — they do not rebuild them.

mod support;

use anyhow::Result;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::xreserve::encoding::XReserveBurnItems;

// PLACEHOLDER magnitudes (the suite asserts composition/commitment behavior, not magnitudes), mirroring
// the CMP-A10 / CMP-B2 suites so the shared harness behaves identically.
const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
const MIN_BURN_SIZE: u64 = 1_000;
/// A valid burn: `MIN_BURN_SIZE <= VALID_BURN` and `<= TOKEN_SUPPLY`.
const VALID_BURN: u64 = 5_000;
/// A below-minimum burn: `0 < BELOW_MIN < MIN_BURN_SIZE`.
const BELOW_MIN: u64 = 500;

/// The Ownable2Step OWNER the burn oracle installs (id(1)). Under the reconciled Circle-faithful admin
/// model (DECISION-ADMIN-ROLE-MODEL) the setters gate on the owner (`Authority::OwnerControlled`).
fn owner() -> AccountId {
    test_account_id(1)
}

/// The seeded DOM_PAUSER holder (id(2)) — the ONLY pause authority under Option 1 (CMP-F3,
/// Domain-Pauser-only; the custom `xreserve::pause_admin` procs).
fn dom_pauser() -> AccountId {
    test_account_id(2)
}

/// A deterministic standalone note rng (only the serial number depends on it; never the schema/tag).
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// A DC-7 payload with an arbitrary round-trippable destination + salt (off-chain observability; does
/// not affect the consume).
fn items(amount: u64) -> Result<XReserveBurnItems> {
    Ok(XReserveBurnItems {
        amount: AssetAmount::new(amount)?,
        dest_domain: 9,
        dest_recipient: [0xABu8; 32],
        salt: [0xCDu8; 32],
    })
}

// N1B — SOLE-SUPPLY-DECREMENT, STORAGE-COMMITMENT WIRING
// ================================================================================================

/// N1B (the mandated sole-decrement test): the built faucet's ACTIVE burn-policy storage slot holds the
/// CMP-A10 `check_policy` root — so the sole supply-decrement path (stock `receive_and_burn`, the only
/// `faucet::burn` caller, see N1D) is CMP-A10-gated. This reads what the account WIRED (storage
/// commitment), which is stronger than resolving the merely-EXPORTED proc root.
#[tokio::test]
async fn only_receive_and_burn_lowers_supply() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = h.chain.committed_account(h.faucet_id)?.clone();
    let stored = read_active_burn_policy_root(&account)?;
    assert_eq!(
        stored, h.burn_root,
        "the built faucet's active burn-policy storage slot must hold the CMP-A10 check_policy root: \
         the sole supply-decrement path (stock receive_and_burn) is policy-gated"
    );
    Ok(())
}

/// N1B negative (required non-vacuity): a CODE-IDENTICAL faucet with `BurnAllowAll` ACTIVE stores a
/// DIFFERENT active root, so the sole-decrement clause (`stored == CMP-A10 root`) FAILS here — proving
/// the clause catches a repointed burn policy. (The dropped/zero-root case is foreclosed at build by
/// `MissingBurnPolicyGuard`, `builder_api.rs`.)
#[tokio::test]
async fn allow_all_active_burn_policy_fails_sole_decrement_audit() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnAllowAll,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = h.chain.committed_account(h.faucet_id)?.clone();
    let stored = read_active_burn_policy_root(&account)?;
    assert_ne!(
        stored, h.burn_root,
        "under BurnAllowAll the active burn root must NOT equal the CMP-A10 root, so the sole-decrement \
         clause must fail here — the audit catches a repointed policy"
    );
    Ok(())
}

// N1D — INHERITED-UNIQUENESS (vendored-fixture sweep + checksum + Cargo-rev pin)
// ================================================================================================

const PINNED_FUNGIBLE_MASM: &str = include_str!("fixtures/pinned-standards/fungible.masm");
const PINNED_POLICY_MANAGER_MASM: &str = include_str!("fixtures/pinned-standards/policy_manager.masm");

/// N1D: across the vendored pinned standards faucet code, `exec.faucet::burn` (the inherited
/// supply-decrement primitive) is called by exactly ONE proc — `receive_and_burn`. Combined with N1A
/// (no LOCAL lowering surface) this proves the SOLE supply-decrement surface is the stock
/// `receive_and_burn`.
#[test]
fn pinned_standards_single_faucet_burn_caller() {
    let callers: Vec<String> = [PINNED_FUNGIBLE_MASM, PINNED_POLICY_MANAGER_MASM]
        .into_iter()
        .flat_map(faucet_burn_caller_procs)
        .collect();
    assert_eq!(
        callers,
        vec!["receive_and_burn".to_string()],
        "exactly one stock proc may call exec.faucet::burn across the vendored standards faucet code \
         (receive_and_burn); saw: {callers:?}"
    );
}

/// N1D (decrement-WRITE twin): across the vendored standards faucet code, exactly ONE
/// `TOKEN_CONFIG_SLOT` supply-DECREMENT write (a `set_item` write whose value is produced by `sub`)
/// exists, inside `receive_and_burn`. Together with `pinned_standards_single_faucet_burn_caller` this
/// proves the SOLE inherited supply-lowering surface is the stock `receive_and_burn` — both the burn
/// primitive AND the supply write-back, with `sub` feeding it (anchor: `fungible.masm` receive_and_burn
/// @390, faucet::burn @420, sub @440, the TOKEN_CONFIG_SLOT set_item write-back @444).
#[test]
fn pinned_standards_single_supply_decrement_write() {
    let writers: Vec<String> = [PINNED_FUNGIBLE_MASM, PINNED_POLICY_MANAGER_MASM]
        .into_iter()
        .flat_map(faucet_supply_decrement_write_procs)
        .collect();
    assert_eq!(
        writers,
        vec!["receive_and_burn".to_string()],
        "exactly one TOKEN_CONFIG_SLOT supply-decrement write (sub-fed) may exist across the vendored \
         standards faucet code, inside receive_and_burn; saw: {writers:?}"
    );
}

// FNV-1a (std-only, portable) drift tripwire on the vendored copies. Re-vendoring at a new rev requires
// recomputing these (run the test; the assert prints `left` = the actual digest).
const FUNGIBLE_FNV1A: u64 = 17252926805552427287;
const POLICY_MANAGER_FNV1A: u64 = 12570707895715501309;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// N1D drift tripwire: the vendored fixtures are unchanged from the baseline snapshot. A local edit of a
/// committed copy (or a stale re-vendor) trips this.
#[test]
fn pinned_standards_fixture_unchanged() {
    assert_eq!(
        fnv1a(PINNED_FUNGIBLE_MASM.as_bytes()),
        FUNGIBLE_FNV1A,
        "vendored fungible.masm changed; re-derive from the pinned rev (PROVENANCE.md) and update FUNGIBLE_FNV1A"
    );
    assert_eq!(
        fnv1a(PINNED_POLICY_MANAGER_MASM.as_bytes()),
        POLICY_MANAGER_FNV1A,
        "vendored policy_manager.masm changed; re-derive from the pinned rev and update POLICY_MANAGER_FNV1A"
    );
}

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const PINNED_STANDARDS_REV: &str = "681fc90584131560b87db8f7487685f4fa8420a8";

/// N1D provenance anchor: the vendored fixtures are a snapshot of `miden-standards` at this rev. If the
/// Cargo dep rev is bumped, this fails — re-vendor + re-checksum (PROVENANCE.md) before trusting N1D.
/// Extracts the `rev = "..."` value from every `miden-standards = { git = ..., rev = "..." }` entry in
/// a Cargo manifest — binds to the `miden-standards` key SPECIFICALLY (the key left of the first `=`),
/// so a sibling dep's rev (e.g. miden-protocol) can never satisfy the pin.
fn miden_standards_revs(cargo_toml: &str) -> Vec<&str> {
    cargo_toml
        .lines()
        .filter(|l| l.split('=').next().map(str::trim) == Some("miden-standards"))
        .filter_map(|l| l.split("rev = \"").nth(1).and_then(|a| a.split('"').next()))
        .collect()
}

/// N1D provenance anchor: every `miden-standards` dependency entry (the dep + the dev-dep) pins the
/// vendored-fixture rev. A standards bump fails this even if a sibling dep still carries the old rev —
/// re-vendor + re-checksum (PROVENANCE.md) before trusting N1D.
#[test]
fn pinned_standards_rev_matches_cargo() {
    let revs = miden_standards_revs(CARGO_TOML);
    assert!(
        !revs.is_empty(),
        "Cargo.toml must declare a git-pinned miden-standards dependency (the fixtures' source crate)"
    );
    for rev in &revs {
        assert_eq!(
            *rev, PINNED_STANDARDS_REV,
            "the miden-standards dep rev must equal the vendored-fixture rev ({PINNED_STANDARDS_REV}); a \
             bump was detected — re-vendor the pinned-standards fixtures and update the checksums"
        );
    }
}

/// Non-vacuity for the rev binding: a sibling dep (miden-protocol) carrying the OLD rev must NOT mask a
/// `miden-standards` bump. A naive `Cargo.toml.contains(old_rev)` would falsely pass; the
/// miden-standards-specific parse extracts the bumped standards rev.
#[test]
fn rev_pin_binds_to_miden_standards_specifically() {
    let synthetic = "miden-protocol  = { git = \"x\", rev = \"OLDREV\" }\n\
                     miden-standards = { git = \"x\", rev = \"BUMPED\" }\n";
    assert_eq!(
        miden_standards_revs(synthetic),
        vec!["BUMPED"],
        "must extract the miden-standards rev, not a sibling dep's"
    );
    assert!(
        synthetic.contains("OLDREV"),
        "a naive contains(OLDREV) check would have falsely passed despite the miden-standards bump"
    );
}

// N2 — END-TO-END COMPOSITION + CONSERVATION (re-confirm; do not rebuild)
// ================================================================================================

/// N2: a real `XReserveBurnNote` consumed by the faucet runs `receive_and_burn` → CMP-A10 and
/// decrements committed `token_supply` by EXACTLY the burned amount, ONCE (no double-count). The stock
/// exactly-one-asset assert (`ERR_FUNGIBLE_BURN_WRONG_NUMBER_OF_ASSETS`) forecloses a multi-asset drain.
#[tokio::test]
async fn burn_consume_composition_decrements_once() -> Result<()> {
    const AMOUNT: u64 = VALID_BURN;
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        AMOUNT,
    )?;
    let note = XReserveBurnNote::create(h.user_id, h.faucet_id, items(AMOUNT)?, &mut note_rng(42))?;
    let mut chain = h.chain;
    assert_eq!(
        committed_token_supply(&chain, h.faucet_id)?,
        AssetAmount::new(TOKEN_SUPPLY)?
    );

    let tx1 = run_burn_consume(&mut chain, &note, &h.asset, h.faucet_id, h.user_id)
        .await
        .expect("the faucet consumes the real XReserveBurnNote via receive_and_burn → CMP-A10");
    chain.add_pending_executed_transaction(&tx1)?;
    chain.prove_next_block()?;

    assert_eq!(
        committed_token_supply(&chain, h.faucet_id)?,
        AssetAmount::new(TOKEN_SUPPLY - AMOUNT)?,
        "committed token_supply decremented by EXACTLY the burned amount, once (no double-count)"
    );
    Ok(())
}

// N3 — INVALID-BURN REJECTS THROUGH THE COMPOSITION (re-confirm CMP-A10 fires; do not rebuild)
// ================================================================================================

/// N3 (R-BURN-2): a real `XReserveBurnNote` with `0 < amount < minBurnSize` consumed through the
/// composition traps the EXACT `ERR_XRESERVE_BURN_BELOW_MIN`.
#[tokio::test]
async fn burn_below_min_rejected_through_composition() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        BELOW_MIN,
    )?;
    let note = XReserveBurnNote::create(h.user_id, h.faucet_id, items(BELOW_MIN)?, &mut note_rng(7))?;
    let mut chain = h.chain;
    let result = run_burn_consume(&mut chain, &note, &h.asset, h.faucet_id, h.user_id).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_BURN_BELOW_MIN"));
    Ok(())
}

/// N3 (R-BURN-1): a real `XReserveBurnNote` with `amount == 0` consumed through the composition traps
/// the EXACT `ERR_XRESERVE_BURN_ZERO`.
#[tokio::test]
async fn burn_zero_rejected_through_composition() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        0,
    )?;
    let note = XReserveBurnNote::create(h.user_id, h.faucet_id, items(0)?, &mut note_rng(13))?;
    let mut chain = h.chain;
    let result = run_burn_consume(&mut chain, &note, &h.asset, h.faucet_id, h.user_id).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_BURN_ZERO"));
    Ok(())
}

/// N3 (R-BURN-3): a paused faucet halts the consume. After the DOM_PAUSER pauses the faucet (custom
/// `xreserve::pause_admin::pause` — the ONLY pause surface under Option 1), consuming a committed
/// (valid-amount) real `XReserveBurnNote` traps the stock `ERR_PAUSABLE_IS_PAUSED` ("the contract is
/// paused") — `execute_burn_policy` runs `assert_not_paused` BEFORE the custom policy
/// (DECISION-RBURN3). Mirrors `burn_policy::burn_paused_rejects` but through the real note.
#[tokio::test]
async fn burn_paused_rejected_through_composition() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let note = XReserveBurnNote::create(h.user_id, h.faucet_id, items(VALID_BURN)?, &mut note_rng(99))?;
    let faucet_id = h.faucet_id;
    let user_id = h.user_id;
    let mut chain = h.chain;

    // Block N: the user emits + commits the (valid-amount) real note while the faucet is NOT yet paused.
    let tx0 = try_emit_burn_note(&chain, &note, &h.asset, faucet_id, user_id)
        .await
        .expect("the user emits the XReserveBurnNote (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // The DOM_PAUSER pauses the faucet; evolve the committed faucet with the (unauthenticated) pause
    // delta — mirrors burn_policy::burn_paused_rejects.
    let account = chain.committed_account(faucet_id)?.clone();
    let paused = run_dom_pauser_pause(&chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;

    // The faucet consumes the committed note against the EVOLVED (paused) account: execute_burn_policy
    // runs assert_not_paused BEFORE the custom policy, trapping the stock pause error.
    let result = chain
        .build_tx_context(evolved, &[note.id()], &[])?
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, MasmError::from_static_str("the contract is paused"));
    Ok(())
}

// CMP-F2 BURN-MIN SEAM — set the floor, then the SAME slot CMP-A10 reads decides the burn (two txs)
// ================================================================================================

/// Two-tx apply_delta plumbing shared by both seam directions: emit + commit the burn note, run an
/// OWNER-sent `set_min_burn_size(new_min)` against the committed faucet, evolve the faucet with the
/// setter delta, then consume the committed note against that evolved (floor-updated) faucet. Returns
/// the consume RESULT (mirrors `burn_paused_rejected_through_composition`).
async fn run_set_min_burn_then_consume(
    seed_floor: u64,
    new_min: u64,
    burn_amount: u64,
) -> Result<std::result::Result<ExecutedTransaction, TransactionExecutorError>> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        seed_floor,
        burn_amount,
    )?;
    let note = XReserveBurnNote::create(h.user_id, h.faucet_id, items(burn_amount)?, &mut note_rng(23))?;
    let faucet_id = h.faucet_id;
    let user_id = h.user_id;
    let mut chain = h.chain;

    // Block N: the user emits + commits the burn note (floor still `seed_floor`).
    let tx0 = try_emit_burn_note(&chain, &note, &h.asset, faucet_id, user_id)
        .await
        .expect("the user emits the XReserveBurnNote (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // The OWNER moves the floor to `new_min`; evolve the committed faucet with the setter delta.
    let account = chain.committed_account(faucet_id)?.clone();
    let set = run_set_min_burn_size_against(&chain, &account, owner(), new_min, 31)
        .await
        .expect("the owner's set_min_burn_size must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;

    // The faucet consumes the committed note against the EVOLVED (floor-updated) faucet — CMP-A10 reads
    // the SAME MIN_BURN_SIZE_SLOT the setter wrote (the seam).
    let result = chain
        .build_tx_context(evolved, &[note.id()], &[])?
        .build()?
        .execute()
        .await;
    Ok(result)
}

/// SEAM (negative = raise): floor seeded `MIN_BURN_SIZE`, owner RAISES it above a burn that passed
/// before; that burn now traps the EXACT `ERR_XRESERVE_BURN_BELOW_MIN` via CMP-A10. `VALID_BURN`
/// (5_000) passes at the seeded 1_000 floor but is below the new 10_000 floor.
#[tokio::test]
async fn set_min_burn_raise_then_below_new_min_rejects() -> Result<()> {
    let result = run_set_min_burn_then_consume(MIN_BURN_SIZE, 10_000, VALID_BURN).await?;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_BURN_BELOW_MIN"));
    Ok(())
}

/// SEAM (positive = lower): floor seeded HIGH (10_000), owner LOWERS it to exactly the burn amount
/// (2_000); the burn that would trap at the seeded floor now PASSES (consume succeeds). Proves the
/// setter's write actually relaxes CMP-A10's R-BURN-2 gate.
#[tokio::test]
async fn set_min_burn_lower_then_at_new_min_passes() -> Result<()> {
    let result = run_set_min_burn_then_consume(10_000, 2_000, 2_000).await?;
    result.expect("a burn == the lowered floor passes CMP-A10 after set_min_burn_size");
    Ok(())
}
