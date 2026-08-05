//! Shared fixtures for the standard-admin suites: the role holders, the two account shapes those
//! suites drive, and the readers that inspect the state an admin action leaves behind.
//!
//! Two compositions appear here because the suites need both. The **grounding** account carries
//! only the standard pieces the admin model is built from — the pause flag and its manager, the
//! blocklist storage and its manager, a role-seeded RBAC component and the faucet's authority — so
//! a test can exercise the model without the rest of the faucet in the way. The **production**
//! faucet is the real shipped composition, which is what the effects have to hold on.
//!
//! The grounding account runs under permissive auth on purpose: the gate under test is the
//! authority and role dispatch inside the called procedures, not the note-script allowlist. Mixing
//! the two would make a rejection ambiguous.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountComponent, AccountId, RoleSymbol, StorageMapKey};
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_protocol::note::NoteType;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Authority;
use miden_standards::account::access::{
    Pausable, PausableManager, PausableStorage, RoleBasedAccessControl,
};
use miden_standards::account::policies::{BasicBlocklist, BlocklistManager, BlocklistStorage};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{BlocklistConfig, BlocklistConfigNote, PauseAction, PauseActionNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, MockChainBuilder};
use miden_tx::TransactionExecutorError;
use xusdc_encoding::account::xreserve::{
    XReserveAdminAuthority, BLK_MANAGER_ROLE, DOM_MANAGER_ROLE, DOM_PAUSER_ROLE,
};
use xusdc_encoding::note::xreserve_admin::XReserveBlocklistNote;

use super::{add_faucet_account, setup_production_faucet, test_account_id, ProductionFaucet};

// THE RATIFIED NUMBERS
// ================================================================================================

/// The note-script allowlist once every admin capability rides a standard note that covers all of
/// its actions behind one script root — pause and unpause, block and unblock, and grant, revoke,
/// set-role-admin and renounce — the two ownership notes are gone with the administratorship
/// component, and the identifier-init note is gone with the stored identifier it used to seed.
/// Human-ratified.
pub const RATIFIED_ALLOWLIST_ROOTS: usize = 8;

/// The callable procedure count: four custom procedures out, four standard manager procedures in,
/// the two-step ownership component's five rows removed, and the mint-path
/// `encoding::pubkey_commitment` de-export (it became an exec-only export of `attestation_verify`,
/// no longer a callable account root) drops the total by one more to 69. The deposit-intent
/// consolidation then took the parser's three assertion procedures and the shared
/// `encoding::parse_deposit_intent` off the surface too — they are the exec-only
/// `deposit_intent_parser::{parse,validate}` pair now — leaving 65. The MASM-hygiene pass then
/// dropped `@account_procedure` from the three remaining `exec`-only xreserve helpers
/// (`encoding::bytes32_to_key`, `encoding::verify_uint256_to_asset_amount` and
/// `attestation_verify::verify_attestation`), leaving 62. The identifier-derivation change then
/// took `init_identifier` with the stored identifier the mint path no longer reads, leaving the two
/// genuine entry points (`set_attester`, `check_policy`) plus the stock rows = 61.
/// Human-ratified.
pub const RATIFIED_CALLABLE_PROCEDURES: usize = 61;

/// The `DOM_PAUSER` role symbol felt the retired `pause_admin.masm` hard-coded. The role identity
/// had to survive the move from a MASM literal into the procedure-role map, so it is pinned here as
/// a literal rather than read from a file that no longer exists.
pub const DOM_PAUSER_ROLE_FELT: u64 = 728_098_706_988_649;

/// The `BLK_MANAGER` role symbol felt the retired `blocklist_admin.masm` hard-coded.
pub const BLK_MANAGER_ROLE_FELT: u64 = 7_907_587_873_290_749;

// ROLE HOLDERS
// ================================================================================================
// The production builder seeds owner = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3),
// BLK_MANAGER = id(4). The grounding account seeds the same identities so both suites read alike.

/// The bootstrap administrator — the sole member of the built-in `ADMIN` role, which is the
/// faucet's only authority handle.
pub fn admin_holder() -> AccountId {
    test_account_id(1)
}
/// The Domain pauser: the only identity the role map lets pause or unpause.
pub fn pauser_holder() -> AccountId {
    test_account_id(2)
}
/// The Domain manager: administers roles and holds no admin capability of its own.
pub fn role_manager_holder() -> AccountId {
    test_account_id(3)
}
/// The external blocklist administrator: the only identity the role map lets block or unblock.
pub fn blocklist_holder() -> AccountId {
    test_account_id(4)
}
/// An account holding nothing at all.
pub fn stranger() -> AccountId {
    test_account_id(99)
}

pub fn pauser_symbol() -> RoleSymbol {
    RoleSymbol::new(DOM_PAUSER_ROLE).expect("the Domain pauser role symbol is valid")
}

pub fn blocklist_symbol() -> RoleSymbol {
    RoleSymbol::new(BLK_MANAGER_ROLE).expect("the blocklist administrator role symbol is valid")
}

/// The Domain manager role symbol — the seeded administrator of the Domain pauser role, and so the
/// identity the standard role note's grant, revoke and re-point actions answer to for that role.
pub fn role_manager_symbol() -> RoleSymbol {
    RoleSymbol::new(DOM_MANAGER_ROLE).expect("the Domain manager role symbol is valid")
}

/// The trap the standard pause gate raises when a paused faucet is asked to mint or burn.
pub fn err_paused() -> MasmError {
    MasmError::from_static_str("the contract is paused")
}

/// The trap the standard role component raises when the sender does not hold the target role's
/// effective administrator role. It is what refuses a grant, a revoke or a re-point sent by the
/// wrong party — including the administrator role itself, for a role that was delegated away.
pub fn err_sender_not_role_admin() -> MasmError {
    MasmError::from_static_str("note sender does not hold the role's admin role")
}

/// The word a set pause flag or a blocked account reads back as.
pub fn set_word() -> Word {
    Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

// THE GROUNDING ACCOUNT
// ================================================================================================

/// The standard pieces the admin model is built from, and nothing else.
///
/// The RBAC seed deliberately uses `RoleBasedAccessControl::new` rather than the faucet's
/// hand-seeded component: the grounding account needs no delegated role admin, so the stock
/// constructor covers it — which doubles as a check that the constructor seeds role membership the
/// way the admin model assumes.
pub fn grounding_components() -> Vec<AccountComponent> {
    let role_members = BTreeMap::from([
        (pauser_symbol(), BTreeSet::from([pauser_holder()])),
        (blocklist_symbol(), BTreeSet::from([blocklist_holder()])),
    ]);
    vec![
        Pausable::unpaused().into(),
        PausableManager.into(),
        BasicBlocklist::default().into(),
        BlocklistManager.into(),
        RoleBasedAccessControl::new(BTreeSet::from([admin_holder()]), role_members).into(),
        XReserveAdminAuthority::new().into(),
    ]
}

/// A chain carrying the grounding account, with `seed_notes_for` producing the notes to commit at
/// genesis (they need the account id, which only exists once the account is built).
pub fn setup_grounding(
    seed_notes_for: impl FnOnce(AccountId) -> Vec<Note>,
) -> Result<(MockChain, Account, Vec<Note>)> {
    let mut mc = MockChainBuilder::new();
    let account = add_faucet_account(&mut mc, Auth::IncrNonce, grounding_components())
        .context("adding the grounding account")?;
    let notes = seed_notes_for(account.id());
    for note in &notes {
        mc.add_output_note(RawOutputNote::Full(note.clone()));
    }
    let chain = mc.build().context("building the grounding chain")?;
    Ok((chain, account, notes))
}

/// Consumes a committed note against `account`, returning the executor's verdict so a test can
/// assert either success or the specific trap.
pub async fn consume_against(
    chain: &MockChain,
    account: &Account,
    note: &Note,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()
        .expect("building the consume transaction")
        .execute()
        .await
}

/// Consumes a note that must succeed, commits its block, and returns the committed account.
///
/// Committing matters for the tests that act twice: a transaction is always built from the chain's
/// committed state, so an uncommitted first step would leave the second one starting from the
/// original state and quietly turning into a no-op.
pub async fn consume_and_commit_against(
    chain: &mut MockChain,
    account: &Account,
    note: &Note,
    what: &str,
) -> Result<Account> {
    let tx = consume_against(chain, account, note)
        .await
        .map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
    chain
        .add_pending_executed_transaction(&tx)
        .with_context(|| format!("queueing the transaction of {what}"))?;
    chain
        .prove_next_block()
        .with_context(|| format!("committing the block of {what}"))?;
    Ok(chain
        .committed_account(account.id())
        .with_context(|| format!("reading the committed account after {what}"))?
        .clone())
}

// THE PRODUCTION FAUCET
// ================================================================================================

/// A production faucet with no bring-up notes — enough for the admin actions, which need neither an
/// attester nor an identifier.
pub fn admin_faucet(
    seed_notes_for: impl FnOnce(AccountId) -> Vec<Note>,
) -> Result<ProductionFaucet> {
    setup_production_faucet(1_000_000, 0, |_recipient, faucet_id| {
        seed_notes_for(faucet_id)
    })
}

/// Consumes a committed note against the production faucet.
pub async fn consume(
    pf: &ProductionFaucet,
    note: &Note,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    pf.mock_chain
        .build_transaction(pf.faucet_id)
        .authenticated_input_note(note.id())
        .build()
        .expect("building the consume transaction")
        .execute()
        .await
}

/// Consumes a note that must succeed against the production faucet, commits its block, and returns
/// the committed faucet.
pub async fn consume_and_commit(
    pf: &mut ProductionFaucet,
    note: &Note,
    what: &str,
) -> Result<Account> {
    let tx = consume(pf, note)
        .await
        .map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
    pf.mock_chain.add_pending_executed_transaction(&tx)?;
    pf.mock_chain.prove_next_block()?;
    Ok(pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .with_context(|| format!("reading the committed faucet after {what}"))?
        .clone())
}

// NOTE FACTORIES
// ================================================================================================

/// A deterministic serial number: nothing about these notes' authorization depends on it — the
/// sender carries that — so a fixed draw per seed keeps note ids stable.
pub fn serial(seed: u32) -> Word {
    Word::from([seed, 31, 37, 41])
}

/// A deterministic note rng for the factories that draw their own serial.
pub fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(23u32),
        Felt::from(29u32),
    ]))
}

/// The standard pause-action note for `action`, sent by `sender` and tagged for `account`.
pub fn pause_action_note(
    sender: AccountId,
    account: AccountId,
    action: PauseAction,
    seed: u32,
) -> Result<Note> {
    let note = PauseActionNote::builder()
        .sender(sender)
        .account(account)
        .action(action)
        .serial_number(serial(seed))
        .build()
        .map_err(|e| anyhow::anyhow!("building the pause action note: {e}"))?;
    Ok(Note::from(note))
}

/// A blocklist config note assembled straight from the standard builder.
///
/// Two callers want this rather than the faucet's factory. The bare admin model is not a faucet, so
/// its factory's faucet-shaped refusal does not apply there. And the self-block tests need to get
/// PAST that refusal on purpose: it is an off-chain guard, and the point of those tests is what the
/// chain does when someone hand-rolls the note anyway.
pub fn raw_blocklist_note(
    sender: AccountId,
    target_account: AccountId,
    config: BlocklistConfig,
    seed: u32,
) -> Result<Note> {
    let note = BlocklistConfigNote::builder()
        .sender(sender)
        .target(target_account)
        .config(config)
        .serial_number(serial(seed))
        .build()
        .map_err(|e| anyhow::anyhow!("building the blocklist config note: {e}"))?;
    Ok(Note::from(note))
}

/// A note that calls the authority component's `freeze` emergency switch.
///
/// `freeze` carries no entry in the procedure-role map, so consuming this note exercises the
/// fallback that keeps every unmapped setter on the administrator role.
pub fn freeze_note(sender: AccountId, seed: u64) -> Result<Note> {
    let src = "use miden::standards::components::access::authority\n\
               @note_script\n\
               pub proc main\n\
               \x20\x20\x20\x20repeat.16 push.0 end\n\
               \x20\x20\x20\x20call.authority::freeze\n\
               \x20\x20\x20\x20dropw dropw dropw dropw\n\
               end\n";
    let script = CodeBuilder::new()
        .with_dynamically_linked_package(Authority::code().clone())
        .context("linking the authority component into the freeze note script")?
        .compile_note_script(src)
        .map_err(|e| anyhow::anyhow!("the freeze note script failed to compile: {e}"))?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(17u32),
        Felt::from(19u32),
    ]));
    NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Public)
        .script(script)
        .build()
        .map_err(|e| anyhow::anyhow!("building the freeze note: {e}"))
}

/// A component binding for the assembled xreserve library, used to resolve a procedure root by
/// path without composing a whole faucet.
pub fn xreserve_root_probe_component() -> Result<AccountComponent> {
    let library = super::assemble_xreserve_lib()?;
    AccountComponent::new(
        library,
        Vec::new(),
        AccountComponentMetadata::new("xusdc-xreserve-root-probe"),
    )
    .context("binding the assembled xreserve library to read a procedure root")
}

// STATE READERS
// ================================================================================================

/// The `is_paused` flag word.
pub fn read_paused(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(PausableStorage::is_paused_slot())
        .map_err(|e| anyhow::anyhow!("reading the is_paused slot: {e}"))
}

/// The `blocked_accounts[target]` word: `[1,0,0,0]` blocked, empty not blocked.
pub fn read_blocked(account: &Account, target: AccountId) -> Result<Word> {
    let key = Word::from([
        Felt::ZERO,
        Felt::ZERO,
        target.suffix(),
        target.prefix().as_felt(),
    ]);
    account
        .storage()
        .get_map_item(
            BlocklistStorage::blocked_accounts_slot(),
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading blocked_accounts[{target}]: {e}"))
}

/// Every procedure root a built account exposes.
pub fn callable_roots(account: &Account) -> BTreeSet<Word> {
    account
        .code()
        .procedures()
        .iter()
        .map(|root| Word::from(*root))
        .collect()
}

// STOCK ADMIN CONFIG NOTES — the pause and blocklist admin surface
// ================================================================================================

/// A deterministic serial number for the stock config notes. Nothing about their authorization
/// depends on it — the sender carries that — so a fixed draw per seed keeps note ids stable.
fn config_note_serial(seed: u64) -> Word {
    Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(43u32),
        Felt::from(47u32),
    ])
}

/// The stock pause-action note for `action`, sent by `sender` and tagged for `faucet_id`. One script
/// root covers pausing and unpausing; the Domain pauser role opens both.
pub fn stock_pause_action_note(
    sender: AccountId,
    faucet_id: AccountId,
    action: PauseAction,
    seed: u64,
) -> Result<Note> {
    let note = PauseActionNote::builder()
        .sender(sender)
        .account(faucet_id)
        .action(action)
        .serial_number(config_note_serial(seed))
        .build()
        .map_err(|e| anyhow::anyhow!("building the stock pause action note: {e}"))?;
    Ok(Note::from(note))
}

/// The stock pause-action note that pauses `faucet_id`.
pub fn stock_pause_note(sender: AccountId, faucet_id: AccountId, seed: u64) -> Result<Note> {
    stock_pause_action_note(sender, faucet_id, PauseAction::Pause, seed)
}

/// The stock pause-action note that unpauses `faucet_id`.
pub fn stock_unpause_note(sender: AccountId, faucet_id: AccountId, seed: u64) -> Result<Note> {
    stock_pause_action_note(sender, faucet_id, PauseAction::Unpause, seed)
}

/// The faucet's block note for `target`, built through the factory that refuses a self-block.
pub fn stock_block_note(
    sender: AccountId,
    faucet_id: AccountId,
    target: AccountId,
    seed: u64,
) -> Result<Note> {
    let mut rng = RandomCoin::new(config_note_serial(seed));
    XReserveBlocklistNote::block(sender, faucet_id, target, &mut rng)
        .map_err(|e| anyhow::anyhow!("building the block note: {e}"))
}

/// The faucet's unblock note for `target`.
pub fn stock_unblock_note(
    sender: AccountId,
    faucet_id: AccountId,
    target: AccountId,
    seed: u64,
) -> Result<Note> {
    let mut rng = RandomCoin::new(config_note_serial(seed));
    XReserveBlocklistNote::unblock(sender, faucet_id, target, &mut rng)
        .map_err(|e| anyhow::anyhow!("building the unblock note: {e}"))
}

/// A block note assembled straight from the standard builder, bypassing the factory's self-block
/// refusal. Only the tests that exercise a self-block need it: the refusal is off-chain, and the
/// point is what the chain does when someone hand-rolls the note anyway.
pub fn raw_stock_block_note(
    sender: AccountId,
    faucet_id: AccountId,
    target: AccountId,
    seed: u64,
) -> Result<Note> {
    let note = BlocklistConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(BlocklistConfig::BlockAccount { account: target })
        .serial_number(config_note_serial(seed))
        .build()
        .map_err(|e| anyhow::anyhow!("building the raw block note: {e}"))?;
    Ok(Note::from(note))
}
