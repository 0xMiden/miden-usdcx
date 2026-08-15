//! Transfer blocklist — who is allowed to block, run against a MockChain.
//!
//! This file covers the delegation contract only: the authorization around the block and unblock
//! admin notes. What being blocked actually does to transfers, burns, and consumption is the
//! sibling `transfer_blocklist_semantics.rs`; the two are split only to keep each file within its
//! size ceiling. The decision record behind the feature is the transfer-blocklist decision
//! document under `docs/`.
//!
//! The two new admin notes `block_account` / `unblock_account` are gated on the dedicated
//! `BLOCK_LISTER` role held by an EXTERNAL entity, NOT the administrator. A block/unblock from the BLOCK_LISTER
//! holder SUCCEEDS and mutates the `blocked_accounts` map; from a stranger, the OWNER (two-way
//! capability isolation — the administrator has NO block power), or a DIFFERENT role holder (spoof-proof) it is
//! REJECTED with the EXACT stock rbac role error; after the administrator (as `ADMIN`) revokes `BLOCK_LISTER`
//! via the EXISTING `revoke_role` note, the former holder is REJECTED — rotation with ZERO new machinery.

mod support;

use anyhow::Result;
use miden_protocol::account::{Account, AccountId, RoleSymbol, StorageMapKey};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::BlocklistStorage;
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use rstest::rstest;
use support::*;
use xusdc_encoding::account::xreserve::BLOCK_LISTER_ROLE;

const MAX_SUPPLY: u64 = 1_000_000;

// The production builder seeds owner = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3),
// BLOCK_LISTER = id(4).
fn administrator() -> AccountId {
    test_account_id(1)
}
fn dom_manager() -> AccountId {
    test_account_id(3)
}
fn block_lister() -> AccountId {
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

/// Reads the `blocked_accounts[account]` word from a committed/evolved faucet account.
/// `[1,0,0,0]` = blocked, `[0,0,0,0]` = not blocked (the primitive's key is `[0, 0, suffix, prefix]`).
fn read_blocked(faucet: &Account, account: AccountId) -> Result<Word> {
    let key = Word::from([
        Felt::ZERO,
        Felt::ZERO,
        account.suffix(),
        account.prefix().as_felt(),
    ]);
    faucet
        .storage()
        .get_map_item(
            BlocklistStorage::blocked_accounts_slot(),
            StorageMapKey::new(key),
        )
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

/// A do-nothing component that satisfies the shared fixture's requirement for a driver.
///
/// These tests reach the account through admin notes and never invoke it, so it only has to
/// compile.
fn placeholder_driver_src() -> String {
    "#! Test driver stand-in: never invoked by this suite (the custom mint entry was deleted by\n\
     #! the Wave-1 S1 recomposition); the guarded fixture only requires a compilable component.\n\
     #!\n\
     #! Inputs:  [pad(16)]\n\
     #! Outputs: [pad(16)]\n\
     #!\n\
     #! Invocation: call\n\
     @account_procedure\n\
     pub proc drive\n\
     \x20\x20\x20\x20push.0 drop\n\
     end\n"
        .to_string()
}

/// A policed + Enabled production faucet (attestation-gated production composition), IncrNonce auth
/// so admin notes execute directly and the BLOCK_LISTER role gate is the only gate under test.
fn policed_faucet() -> Result<GuardedMint> {
    let driver = placeholder_driver_src();
    let probe = composition_supply_probe_src(0);
    setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        MAX_SUPPLY,
        0,
        Word::from([7u32, 0, 0, 0]),
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
    let note = stock_block_note(sender, account.id(), target, seed)
        .expect("building the block_account note (test-setup invariant)");
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
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
    let note = stock_unblock_note(sender, account.id(), target, seed)
        .expect("building the unblock_account note (test-setup invariant)");
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the unblock tx")
        .execute()
        .await
}

/// The BLOCK_LISTER holder can block an account: the note SUCCEEDS and `blocked_accounts[target]`
/// flips to the blocked marker (a non-vacuous success — the map write really happened).
#[tokio::test]
async fn block_by_block_lister_holder_succeeds_and_writes_the_map() -> Result<()> {
    let gm = policed_faucet()?;
    let faucet = faucet_account(&gm.harness);
    assert_eq!(
        read_blocked(&faucet, target())?,
        unblocked_word(),
        "precondition: the target starts unblocked (empty initial blocklist)"
    );

    let tx = run_block(&gm.harness.mock_chain, &faucet, block_lister(), target(), 1)
        .await
        .expect("the BLOCK_LISTER holder blocks the account");
    let mut evolved = faucet.clone();
    evolved.apply_patch(tx.account_patch())?;
    assert_eq!(
        read_blocked(&evolved, target())?,
        blocked_word(),
        "after a BLOCK_LISTER block, blocked_accounts[target] == [1,0,0,0]"
    );
    Ok(())
}

/// The BLOCK_LISTER holder can unblock an account: block then unblock, and the map returns to the
/// unblocked word.
#[tokio::test]
async fn unblock_by_block_lister_holder_succeeds_and_clears_the_map() -> Result<()> {
    let gm = policed_faucet()?;
    let faucet = faucet_account(&gm.harness);

    let blocked = run_block(&gm.harness.mock_chain, &faucet, block_lister(), target(), 1)
        .await
        .expect("the BLOCK_LISTER holder blocks the account");
    let mut evolved = faucet.clone();
    evolved.apply_patch(blocked.account_patch())?;
    assert_eq!(read_blocked(&evolved, target())?, blocked_word(), "blocked");

    let unblocked = run_unblock(
        &gm.harness.mock_chain,
        &evolved,
        block_lister(),
        target(),
        2,
    )
    .await
    .expect("the BLOCK_LISTER holder unblocks the account");
    evolved.apply_patch(unblocked.account_patch())?;
    assert_eq!(
        read_blocked(&evolved, target())?,
        unblocked_word(),
        "after a BLOCK_LISTER unblock, blocked_accounts[target] returns to [0,0,0,0]"
    );
    Ok(())
}

/// The block gate is BLOCK_LISTER-specific: a stranger, the OWNER (two-way capability isolation — the
/// owner holds no block power), and a DIFFERENT role holder (DOM_MANAGER — spoof-proof, only the
/// hard-coded BLOCK_LISTER symbol passes) are ALL rejected with the EXACT stock role error, and the
/// map is unchanged.
#[rstest]
#[case::stranger(stranger())]
#[case::owner(administrator())]
#[case::dom_manager(dom_manager())]
#[tokio::test]
async fn block_by_non_block_lister_is_rejected(#[case] sender: AccountId) -> Result<()> {
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

/// The unblock gate is likewise BLOCK_LISTER-specific (the security-critical direction: an ungated
/// unblock would let anyone lift a compliance freeze). A stranger / owner / other-role holder is
/// rejected with the EXACT role error while the account STAYS blocked.
#[rstest]
#[case::stranger(stranger())]
#[case::owner(administrator())]
#[case::dom_manager(dom_manager())]
#[tokio::test]
async fn unblock_by_non_block_lister_is_rejected(#[case] sender: AccountId) -> Result<()> {
    let gm = policed_faucet()?;
    let faucet = faucet_account(&gm.harness);

    // Arm the negative on a genuinely blocked account: a real BLOCK_LISTER block first.
    let blocked = run_block(&gm.harness.mock_chain, &faucet, block_lister(), target(), 4)
        .await
        .expect("the BLOCK_LISTER holder blocks the account");
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

/// ROTATION with ZERO new machinery: the administrator (as the built-in `ADMIN`, `BLOCK_LISTER`'s effective
/// admin) revokes `BLOCK_LISTER` from its holder via the EXISTING `revoke_role` note; the former
/// holder can then no longer block — the block is rejected with the EXACT role error.
#[tokio::test]
async fn former_block_lister_holder_rejected_after_revoke() -> Result<()> {
    let gm = policed_faucet()?;
    let faucet = faucet_account(&gm.harness);
    let block_lister_role =
        RoleSymbol::new(BLOCK_LISTER_ROLE).expect("BLOCK_LISTER is a valid role symbol");

    // Precondition: the holder CAN block before the revoke.
    run_block(&gm.harness.mock_chain, &faucet, block_lister(), target(), 6)
        .await
        .expect("precondition: the BLOCK_LISTER holder can block before revoke");

    // The administrator (ADMIN) revokes BLOCK_LISTER from its holder via the existing revoke_role note.
    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &faucet,
        administrator(),
        &block_lister_role,
        block_lister(),
        7,
    )
    .await
    .expect("the administrator (ADMIN) revokes BLOCK_LISTER via the standard role-action note");
    let mut evolved = faucet.clone();
    evolved.apply_patch(revoked.account_patch())?;

    // The former holder can no longer block.
    let result = run_block(
        &gm.harness.mock_chain,
        &evolved,
        block_lister(),
        target(),
        8,
    )
    .await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}
