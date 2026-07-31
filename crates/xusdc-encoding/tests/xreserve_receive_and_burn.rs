//! Audit of the burn-consume path: how a burn note is destroyed and supply is lowered.
//!
//! The faucet writes no code of its own for this. Consuming a burn note runs the standard
//! `receive_and_burn` script, which applies the standard minimum-burn policy the builder installs
//! as the faucet's active burn policy. There is no custom burn proc in this repository, so nothing
//! here is a unit test of xUSDC code — the suite exists to hold the COMPOSITION in place.
//!
//! The property it protects is that the faucet has exactly one way to lower `token_supply`. A
//! second, ungated decrement path would let tokens be destroyed without a public burn note, and
//! the off-chain listener would have nothing to show Circle for tokens that no longer exist. The
//! proof is made against code and storage commitments rather than by observing supply deltas,
//! because a delta test can only find the paths it thinks to exercise:
//!
//!   - The faucet's own MASM tree contains no supply surface at all: no file calls the standard
//!     burn primitive, and no file writes — or even names — the faucet's token-config slot. All
//!     supply arithmetic lives in the standard library code.
//!   - The built account's active burn-policy storage slot holds the standard minimum-burn
//!     policy's root, so the one decrement path that does exist is policy-gated. A companion test
//!     shows the assertion is not vacuous by building a faucet with an allow-all policy and
//!     watching it fail.
//!   - Within the pinned standard library itself, the burn primitive has exactly one caller,
//!     `receive_and_burn`. That is what makes "one entry point" true of the dependency too, and it
//!     is re-checked at the pinned baseline so an upgrade that adds a caller is caught.
//!
//! The remaining tests re-confirm the composition end to end with a real note: a valid burn lowers
//! supply exactly once, and a burn that is below the minimum, zero, or attempted while the faucet
//! is paused traps with the standard library's own error. Zero is rejected because the minimum is
//! held at one or above — the faucet has no separate zero-amount check to fail.

mod support;

use anyhow::Result;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::MinBurnAmount;
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::xreserve::encoding::XReserveBurnItems;

// Amounts are arbitrary: this suite asserts which code path runs and what it is gated by, never
// the magnitudes themselves. They match the ones the burn-policy and burn-note suites use so the
// shared harness behaves identically across all three.
const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
const MIN_BURN_SIZE: u64 = 1_000;
/// A valid burn: `MIN_BURN_SIZE <= VALID_BURN` and `<= TOKEN_SUPPLY`.
const VALID_BURN: u64 = 5_000;
/// A below-minimum burn: `0 < BELOW_MIN < MIN_BURN_SIZE`.
const BELOW_MIN: u64 = 500;

/// The Ownable2Step OWNER the burn oracle installs (id(1)). Under the reconciled Circle-faithful admin
/// model the setters resolve to the built-in `ADMIN` role under the account's role-based authority.
fn administrator() -> AccountId {
    test_account_id(1)
}

/// The account seeded with the Domain Pauser role, which is the only authority that can pause or
/// unpause the faucet. Pausing is a custom `xreserve::pause_admin` proc, not a standard one.
fn dom_pauser() -> AccountId {
    test_account_id(2)
}

/// A fixed-seed rng for standalone note construction. It feeds only the note's serial number, so
/// the payload layout and tag are unaffected by the seed.
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

/// A withdrawal payload for the given amount, with an arbitrary destination and salt. Those fields
/// exist for the off-chain listener to read; consuming the note does not look at them.
fn items(amount: u64) -> Result<XReserveBurnItems> {
    Ok(XReserveBurnItems {
        amount: AssetAmount::new(amount)?,
        dest_domain: 9,
        dest_recipient: [0xABu8; 32],
        salt: [0xCDu8; 32],
    })
}

// THE ACTIVE BURN POLICY — read off the built account's storage, not inferred from behavior
// ================================================================================================

/// The built faucet's ACTIVE burn-policy storage slot holds
/// the STOCK `MinBurnAmount::root()` — so the sole supply-decrement path (stock `receive_and_burn`,
/// the only caller of the standard burn primitive, pinned below) is gated by the standard floor
/// policy. This reads what the
/// account WIRED (storage commitment), which is stronger than resolving the merely-EXPORTED proc
/// root, and pins the slot DIRECTLY against the stock constant (not a harness-echoed root).
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
        stored,
        MinBurnAmount::root().as_word(),
        "the built faucet's active burn-policy storage slot must hold the STOCK \
         MinBurnAmount::check_policy root: the sole supply-decrement path (stock receive_and_burn) \
         is policy-gated"
    );
    Ok(())
}

/// The non-vacuity twin: a CODE-IDENTICAL faucet with `BurnAllowAll` ACTIVE stores a
/// DIFFERENT active root, so the sole-decrement clause (`stored == MinBurnAmount root`) FAILS here —
/// proving the clause catches a repointed burn policy. (The dropped/zero-root case cannot be built:
/// the production `XReserveStablecoinBuilder` installs the MinBurnAmount policy unconditionally —
/// the allow-all-active variant exists ONLY through the TEST-side `oracle_burn_components`.)
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
        stored,
        MinBurnAmount::root().as_word(),
        "under BurnAllowAll the active burn root must NOT equal the stock MinBurnAmount root, so \
         the sole-decrement clause must fail here — the audit catches a repointed policy"
    );
    Ok(())
}

// THE FAUCET'S OWN MASM TREE — no supply surface anywhere in it
// ================================================================================================

/// Every shipped `.masm` source under `asm/standards/xreserve` (recursively), by path.
fn xreserve_masm_sources() -> Result<Vec<(std::path::PathBuf, String)>> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, out)?;
            } else if path.extension().is_some_and(|e| e == "masm") {
                let src = std::fs::read_to_string(&path)?;
                out.push((path, src));
            }
        }
        Ok(())
    }
    let mut sources = Vec::new();
    walk(&xusdc_encoding::xreserve_asm_dir(), &mut sources)?;
    Ok(sources)
}

/// No file the faucet ships can move supply at all.
///
/// Every `.masm` file under `asm/standards/xreserve` is read and checked for the two ways supply
/// could be touched: calling the standard burn primitive, and writing — or even naming — the
/// faucet's token-config slot, where the supply figure lives. Neither appears anywhere. That makes
/// the sole-decrement claim structural rather than behavioral: supply arithmetic happens only in
/// the standard library code, whose own single decrement caller is pinned by the sweeps below.
#[test]
fn xreserve_tree_has_no_supply_surface() -> Result<()> {
    let sources = xreserve_masm_sources()?;
    assert!(
        !sources.is_empty(),
        "the shipped xreserve tree must contain .masm sources (empty-walk guard)"
    );
    for (path, src) in &sources {
        assert!(
            !src.contains("faucet::burn"),
            "{} must not call the faucet burn primitive (no local supply-decrement surface)",
            path.display()
        );
        assert!(
            !src.to_lowercase().contains("token_config"),
            "{} must not reference the faucet token_config slot at all (no local supply write)",
            path.display()
        );
    }
    Ok(())
}

// THE INHERITED CODE — the standard library's own decrement path, swept, checksummed, and pinned
// ================================================================================================

const PINNED_FUNGIBLE_MASM: &str = include_str!("fixtures/pinned-standards/fungible.masm");
const PINNED_POLICY_MANAGER_MASM: &str =
    include_str!("fixtures/pinned-standards/policy_manager.masm");

/// Across the vendored snapshot of the standard faucet code, `exec.faucet::burn` (the inherited
/// supply-decrement primitive) is called by exactly ONE proc — `receive_and_burn`. Combined with the
/// sweep of the faucet's own tree
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

/// The write-side twin: across the vendored standard faucet code, exactly ONE
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
const FUNGIBLE_FNV1A: u64 = 13171367163648116355;
const POLICY_MANAGER_FNV1A: u64 = 9086050222570077779;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Drift tripwire: the vendored fixtures are unchanged from the baseline snapshot. A local edit of a
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
const PINNED_STANDARDS_REV: &str = "4971ec4b38fb1f54e8f73969e6da81ee0cbf850c";

/// Ties the vendored fixture copies to the dependency they were taken from.
///
/// The sweeps above reason about the standard library's source, but they read a vendored snapshot
/// of it rather than the dependency itself. That snapshot is only meaningful while it matches the
/// exact git revision the crate actually builds against, so this test extracts the pinned revision
/// from the manifest and compares. Bumping the dependency fails here first: re-vendor the fixtures
/// and re-checksum them (see their `PROVENANCE.md`) before the sweeps can be believed again.
///
/// It extracts the `rev = "..."` value
/// from every `miden-standards = { git = "...", rev = "...", ... }` entry in a Cargo manifest —
/// binds to the `miden-standards` key SPECIFICALLY (the key left of the first `=`), so a sibling
/// dep's pin (e.g. miden-protocol) can never satisfy the anchor.
fn miden_standards_revs(cargo_toml: &str) -> Vec<&str> {
    cargo_toml
        .lines()
        .filter(|l| l.split('=').next().map(str::trim) == Some("miden-standards"))
        .filter_map(|l| l.split("rev = \"").nth(1).and_then(|a| a.split('"').next()))
        .collect()
}

/// Provenance anchor: every `miden-standards` dependency entry (the dep + the dev-dep) pins the
/// vendored-fixture rev. A standards bump fails this even if a sibling dep still carries the
/// old pin — re-vendor and re-checksum (see their `PROVENANCE.md`) before trusting the sweeps above.
#[test]
fn pinned_standards_rev_matches_cargo() {
    let revs = miden_standards_revs(CARGO_TOML);
    assert!(
        !revs.is_empty(),
        "Cargo.toml must declare a rev-pinned miden-standards dependency (the fixtures' source crate)"
    );
    for rev in &revs {
        assert_eq!(
            *rev, PINNED_STANDARDS_REV,
            "the miden-standards dep pin must equal the vendored-fixture rev ({PINNED_STANDARDS_REV}); \
             a bump was detected — re-vendor the pinned-standards fixtures and update the checksums"
        );
    }
}

/// Non-vacuity for the rev binding: a sibling dep (miden-protocol) carrying the OLD rev must NOT mask a
/// `miden-standards` bump. A naive `Cargo.toml.contains(old_rev)` would falsely pass; the
/// miden-standards-specific parse extracts the bumped standards rev.
#[test]
fn rev_pin_binds_to_miden_standards_specifically() {
    let synthetic = "miden-protocol  = { git = \"g\", rev = \"OLDPIN\" }\n\
                     miden-standards = { git = \"g\", rev = \"BUMPED\" }\n";
    assert_eq!(
        miden_standards_revs(synthetic),
        vec!["BUMPED"],
        "must extract the miden-standards rev pin, not a sibling dep's"
    );
    assert!(
        synthetic.contains("OLDPIN"),
        "a naive contains(OLDPIN) check would have falsely passed despite the miden-standards bump"
    );
}

// END TO END — the whole composition on a real note, and the supply arithmetic it produces
// ================================================================================================

/// A real `XReserveBurnNote` consumed by the faucet runs `receive_and_burn` → the stock
/// `MinBurnAmount` policy and decrements committed `token_supply` by EXACTLY the burned amount, ONCE
/// (no double-count). The stock exactly-one-asset assert
/// (`ERR_FUNGIBLE_BURN_WRONG_NUMBER_OF_ASSETS`) forecloses a multi-asset drain.
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
        .expect(
            "the faucet consumes the real XReserveBurnNote via receive_and_burn → the stock \
             MinBurnAmount policy",
        );
    chain.add_pending_executed_transaction(&tx1)?;
    chain.prove_next_block()?;

    assert_eq!(
        committed_token_supply(&chain, h.faucet_id)?,
        AssetAmount::new(TOKEN_SUPPLY - AMOUNT)?,
        "committed token_supply decremented by EXACTLY the burned amount, once (no double-count)"
    );
    Ok(())
}

// INVALID BURNS THROUGH THE FULL COMPOSITION — the standard policy fires on a real note
// ================================================================================================

/// A burn below the configured minimum is rejected when a real note is consumed.
///
/// The amount is above zero but under the floor, so this isolates the minimum-burn policy from the
/// zero case below, and it traps with the standard library's own below-minimum error rather than
/// anything the faucet defines.
#[tokio::test]
async fn burn_below_min_rejected_through_composition() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        BELOW_MIN,
    )?;
    let note =
        XReserveBurnNote::create(h.user_id, h.faucet_id, items(BELOW_MIN)?, &mut note_rng(7))?;
    let mut chain = h.chain;
    let result = run_burn_consume(&mut chain, &note, &h.asset, h.faucet_id, h.user_id).await;
    assert_transaction_executor_error!(result, &err_burn_below_min_burn_amount());
    Ok(())
}

/// A zero-amount burn is rejected too — by the same minimum-burn check, not a separate one.
///
/// The faucet has no dedicated zero-amount error. It does not need one: the minimum burn size is
/// held at one or above everywhere it can be set, so zero is always below the floor and trips the
/// standard below-minimum error. The floor guards are what make that reasoning safe, and they are
/// tested where the floor is set.
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
    assert_transaction_executor_error!(result, &err_burn_below_min_burn_amount());
    Ok(())
}

/// A paused faucet halts withdrawals, not just deposits.
///
/// The Domain Pauser pauses the faucet through the custom `xreserve::pause_admin::pause` — the
/// account's only pause authority — and then a real burn note carrying a perfectly valid amount is
/// consumed. It traps with the standard "the contract is paused" error, because the standard burn
/// wrapper checks the pause flag before it ever reaches the minimum-burn policy. The equivalent
/// case in the burn-policy suite drives a synthetic note; this one drives the production note
/// through the production composition.
#[tokio::test]
async fn burn_paused_rejected_through_composition() -> Result<()> {
    let h = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let note = XReserveBurnNote::create(
        h.user_id,
        h.faucet_id,
        items(VALID_BURN)?,
        &mut note_rng(99),
    )?;
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
    evolved.apply_patch(paused.account_patch())?;

    // The faucet consumes the committed note against the EVOLVED (paused) account: execute_burn_policy
    // runs assert_not_paused BEFORE the active policy, trapping the stock pause error.
    let result = chain
        .build_transaction(evolved)
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(
        result,
        MasmError::from_static_str("the contract is paused")
    );
    Ok(())
}

// THE SEAM BETWEEN SETTING THE FLOOR AND ENFORCING IT — the setter writes the very slot the
// burn policy reads, so a change takes effect on the next burn
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
    let note = XReserveBurnNote::create(
        h.user_id,
        h.faucet_id,
        items(burn_amount)?,
        &mut note_rng(23),
    )?;
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
    let set = run_set_min_burn_size_against(&chain, &account, administrator(), new_min, 31)
        .await
        .expect("the administrator's set_min_burn_size must succeed");
    let mut evolved = account.clone();
    evolved.apply_patch(set.account_patch())?;

    // The faucet consumes the committed note against the EVOLVED (floor-updated) faucet — the stock
    // check_policy reads the SAME MinBurnAmount floor slot the stock setter wrote (the seam).
    let result = chain
        .build_transaction(evolved)
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await;
    Ok(result)
}

/// Raising the floor immediately starts rejecting a burn that was fine a moment earlier.
///
/// The amount used (5,000) passes at the seeded floor of 1,000 and fails at the new floor of
/// 10,000, so the only thing that changed between accept and reject is the setter's write. This is
/// the direction that matters for safety: the administrator can tighten the limit and it binds at once.
#[tokio::test]
async fn set_min_burn_raise_then_below_new_min_rejects() -> Result<()> {
    let result = run_set_min_burn_then_consume(MIN_BURN_SIZE, 10_000, VALID_BURN).await?;
    assert_transaction_executor_error!(result, &err_burn_below_min_burn_amount());
    Ok(())
}

/// Lowering the floor immediately admits a burn that would have been rejected.
///
/// The mirror of the test above, and the one that proves the seam is not vacuous: seeded at 10,000
/// the burn of 2,000 would trap, and after the setter lowers the floor to exactly 2,000 the same
/// consume succeeds — so the setter's write genuinely relaxes the minimum the burn policy
/// enforces, rather than the burn passing for some unrelated reason.
#[tokio::test]
async fn set_min_burn_lower_then_at_new_min_passes() -> Result<()> {
    let result = run_set_min_burn_then_consume(10_000, 2_000, 2_000).await?;
    result.expect(
        "a burn == the lowered floor passes the stock check_policy after set_min_burn_size",
    );
    Ok(())
}
