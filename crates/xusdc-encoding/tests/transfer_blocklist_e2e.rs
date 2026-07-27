//! F4-REVERSAL transfer-blocklist — the DELEGATION CONTRACT (role gate), MockChain (see
//! `DECISION-F4-REVERSAL-TRANSFER-BLOCKLIST.md`). The §1.5 blocklist SEMANTICS matrix lives in the
//! sibling `transfer_blocklist_semantics.rs` (split for the G3 file-size ceiling).
//!
//! The two new admin notes `block_account` / `unblock_account` are gated on the dedicated
//! `BLK_MANAGER` role held by an EXTERNAL entity, NOT the owner. A block/unblock from the BLK_MANAGER
//! holder SUCCEEDS and mutates the `blocked_accounts` map; from a stranger, the OWNER (two-way
//! capability isolation — the owner has NO block power), or a DIFFERENT role holder (spoof-proof) it is
//! REJECTED with the EXACT stock rbac role error; after the owner (as `ADMIN`) revokes `BLK_MANAGER`
//! via the EXISTING `revoke_role` note, the former holder is REJECTED — rotation with ZERO new machinery.

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountId, RoleSymbol, StorageMapKey, StorageSlotName};
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use rstest::rstest;
use support::*;
use xusdc_encoding::account::xreserve::BLK_MANAGER_ROLE;
use xusdc_encoding::note::xreserve_admin::{XReserveBlockAccountNote, XReserveUnblockAccountNote};

const MAX_SUPPLY: u64 = 1_000_000;

// The production builder seeds owner = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3),
// BLK_MANAGER = id(4).
fn owner() -> AccountId {
    test_account_id(1)
}
fn dom_manager() -> AccountId {
    test_account_id(3)
}
fn blk_manager() -> AccountId {
    test_account_id(4)
}
fn stranger() -> AccountId {
    test_account_id(99)
}
/// A dummy account id used as the block/unblock TARGET in the role-gate tests (its identity is
/// immaterial there — only the SENDER's role is under test).
fn target() -> AccountId {
    test_account_id(50)
}

/// The exact stock role error these tests pin (assert-specific-error-in-tests).
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(5u32),
        Felt::from(9u32),
    ]))
}

/// The stock `blocked_accounts` map slot (installed by the `BasicBlocklist` companion), the primitive's
/// storage home (`transfer::blocklist::mod.masm`).
const BLOCKED_ACCOUNTS_SLOT: &str =
    "miden::standards::faucets::policies::transfer::blocklist::blocked_accounts";

/// Reads the `blocked_accounts[account]` word from a committed/evolved faucet account.
/// `[1,0,0,0]` = blocked, `[0,0,0,0]` = not blocked (the primitive's key is `[0, 0, suffix, prefix]`).
fn read_blocked(faucet: &Account, account: AccountId) -> Result<Word> {
    let slot =
        StorageSlotName::new(BLOCKED_ACCOUNTS_SLOT).context("blocked_accounts slot label")?;
    let key = Word::from([
        Felt::ZERO,
        Felt::ZERO,
        account.suffix(),
        account.prefix().as_felt(),
    ]);
    faucet
        .storage()
        .get_map_item(&slot, StorageMapKey::new(key))
        .map_err(|e| anyhow::anyhow!("reading blocked_accounts[{account}]: {e}"))
}

fn blocked_word() -> Word {
    Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}
fn unblocked_word() -> Word {
    Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

// PART A — the delegation contract (role gate on block_account / unblock_account)
// ================================================================================================

/// A policed + Enabled production faucet (deny-only production composition), IncrNonce auth so admin
/// notes execute directly and the BLK_MANAGER role gate is the only gate under test.
fn policed_faucet() -> Result<GuardedMint> {
    let driver = mint_composition_driver_src(&[Felt::from(0u32)], 60, 6);
    let probe = composition_supply_probe_src(0);
    setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        MAX_SUPPLY,
        0,
        Word::from([7u32, 0, 0, 0]),
        Word::from([11u32, 12, 13, 14]),
        None,
        None,
        &driver,
        &probe,
        true,
    )
}

/// Executes a `block_account(target)` admin note SENT BY `sender` against the faucet `account`. The
/// note carries no assets, so the faucet is the native account and no foreign attachment is needed.
async fn run_block(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    target: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note =
        XReserveBlockAccountNote::create(sender, test_faucet_id(1), target, &mut note_rng(seed))
            .expect("building the block_account note (test-setup invariant)");
    chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the block tx context")
        .build()
        .expect("building the block tx")
        .execute()
        .await
}

/// The `unblock_account` twin of [`run_block`].
async fn run_unblock(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    target: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note =
        XReserveUnblockAccountNote::create(sender, test_faucet_id(1), target, &mut note_rng(seed))
            .expect("building the unblock_account note (test-setup invariant)");
    chain
        .build_tx_context(account.clone(), &[], core::slice::from_ref(&note))
        .expect("building the unblock tx context")
        .build()
        .expect("building the unblock tx")
        .execute()
        .await
}

/// The BLK_MANAGER holder can block an account: the note SUCCEEDS and `blocked_accounts[target]`
/// flips to the blocked marker (a non-vacuous success — the map write really happened).
#[tokio::test]
async fn block_by_blk_manager_holder_succeeds_and_writes_the_map() -> Result<()> {
    let gm = policed_faucet()?;
    let faucet = faucet_account(&gm.harness);
    assert_eq!(
        read_blocked(&faucet, target())?,
        unblocked_word(),
        "precondition: the target starts unblocked (empty initial blocklist)"
    );

    let tx = run_block(&gm.harness.mock_chain, &faucet, blk_manager(), target(), 1)
        .await
        .expect("the BLK_MANAGER holder blocks the account");
    let mut evolved = faucet.clone();
    evolved.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_blocked(&evolved, target())?,
        blocked_word(),
        "after a BLK_MANAGER block, blocked_accounts[target] == [1,0,0,0]"
    );
    Ok(())
}

/// The BLK_MANAGER holder can unblock an account: block then unblock, and the map returns to the
/// unblocked word.
#[tokio::test]
async fn unblock_by_blk_manager_holder_succeeds_and_clears_the_map() -> Result<()> {
    let gm = policed_faucet()?;
    let faucet = faucet_account(&gm.harness);

    let blocked = run_block(&gm.harness.mock_chain, &faucet, blk_manager(), target(), 1)
        .await
        .expect("the BLK_MANAGER holder blocks the account");
    let mut evolved = faucet.clone();
    evolved.apply_patch(blocked.account_patch())?;
    assert_eq!(read_blocked(&evolved, target())?, blocked_word(), "blocked");

    let unblocked = run_unblock(&gm.harness.mock_chain, &evolved, blk_manager(), target(), 2)
        .await
        .expect("the BLK_MANAGER holder unblocks the account");
    evolved.apply_patch(unblocked.account_patch())?;
    assert_eq!(
        read_blocked(&evolved, target())?,
        unblocked_word(),
        "after a BLK_MANAGER unblock, blocked_accounts[target] returns to [0,0,0,0]"
    );
    Ok(())
}

/// The block gate is BLK_MANAGER-specific: a stranger, the OWNER (two-way capability isolation — the
/// owner holds no block power), and a DIFFERENT role holder (DOM_MANAGER — spoof-proof, only the
/// hard-coded BLK_MANAGER symbol passes) are ALL rejected with the EXACT stock role error, and the
/// map is unchanged.
#[rstest]
#[case::stranger(stranger())]
#[case::owner(owner())]
#[case::dom_manager(dom_manager())]
#[tokio::test]
async fn block_by_non_blk_manager_is_rejected(#[case] sender: AccountId) -> Result<()> {
    let gm = policed_faucet()?;
    let faucet = faucet_account(&gm.harness);

    let result = run_block(&gm.harness.mock_chain, &faucet, sender, target(), 3).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_blocked(&faucet, target())?,
        unblocked_word(),
        "a rejected block leaves blocked_accounts[target] unchanged (unblocked)"
    );
    Ok(())
}

/// The unblock gate is likewise BLK_MANAGER-specific (the security-critical direction: an ungated
/// unblock would let anyone lift a compliance freeze). A stranger / owner / other-role holder is
/// rejected with the EXACT role error while the account STAYS blocked.
#[rstest]
#[case::stranger(stranger())]
#[case::owner(owner())]
#[case::dom_manager(dom_manager())]
#[tokio::test]
async fn unblock_by_non_blk_manager_is_rejected(#[case] sender: AccountId) -> Result<()> {
    let gm = policed_faucet()?;
    let faucet = faucet_account(&gm.harness);

    // Arm the negative on a genuinely blocked account: a real BLK_MANAGER block first.
    let blocked = run_block(&gm.harness.mock_chain, &faucet, blk_manager(), target(), 4)
        .await
        .expect("the BLK_MANAGER holder blocks the account");
    let mut evolved = faucet.clone();
    evolved.apply_patch(blocked.account_patch())?;

    let result = run_unblock(&gm.harness.mock_chain, &evolved, sender, target(), 5).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_blocked(&evolved, target())?,
        blocked_word(),
        "a rejected unblock leaves the account blocked"
    );
    Ok(())
}

/// ROTATION with ZERO new machinery: the owner (as the built-in `ADMIN`, `BLK_MANAGER`'s effective
/// admin) revokes `BLK_MANAGER` from its holder via the EXISTING `revoke_role` note; the former
/// holder can then no longer block — the block is rejected with the EXACT role error.
#[tokio::test]
async fn former_blk_manager_holder_rejected_after_revoke() -> Result<()> {
    let gm = policed_faucet()?;
    let faucet = faucet_account(&gm.harness);
    let blk_role = RoleSymbol::new(BLK_MANAGER_ROLE).expect("BLK_MANAGER is a valid role symbol");

    // Precondition: the holder CAN block before the revoke.
    run_block(&gm.harness.mock_chain, &faucet, blk_manager(), target(), 6)
        .await
        .expect("precondition: the BLK_MANAGER holder can block before revoke");

    // The owner (ADMIN) revokes BLK_MANAGER from its holder via the existing revoke_role note.
    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &faucet,
        owner(),
        &blk_role,
        blk_manager(),
        7,
    )
    .await
    .expect("the owner (ADMIN) revokes BLK_MANAGER via the existing revoke_role note");
    let mut evolved = faucet.clone();
    evolved.apply_patch(revoked.account_patch())?;

    // The former holder can no longer block.
    let result = run_block(&gm.harness.mock_chain, &evolved, blk_manager(), target(), 8).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}
