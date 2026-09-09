//! The LNV-4 rows-G/H/I/J driver: one deterministic burn-lifecycle arc against a fresh local node,
//! producing the [`RowsGjObservations`] the rows-G/H/I/J assertion suite judges.
//!
//! Execution model (LNV-1 posture, LNV-2/3-confirmed, reused):
//! - **The committed mint (to the holder) and the Row-G two-block burn commit via path N (the
//!   ntx-builder).** The mint note is emitted from the owner/relayer wallet; the Row-G burn note is
//!   emitted from the HOLDER wallet (a regular-account tx the user RPC accepts) carrying the burned
//!   xUSDC and the `NetworkAccountTarget(faucet)` routing attachment; the running ntx-builder
//!   auto-executes the faucet's consumption (network notes are identified by the routing ATTACHMENT,
//!   not the tag, so the fixed `0x4255524E` burn tag does not impede routing). The driver polls
//!   `GetAccount` for the committed effect and captures the raw `GetNotesById` / `SyncNotes` /
//!   nullifier evidence.
//! - **The Row-H F7 RIV both executes CLIENT-SIDE and SUBMITS to the node; the Row-I negatives run
//!   CLIENT-SIDE (`execute_transaction`, no submission).** Row H (1) consumes a freshly-built
//!   (never-committed) production `XReserveBurnNote` as an UNAUTHENTICATED input to record what a
//!   same-block/never-committed consume would apply (accepted; supply delta == amount), (2) SUBMITS
//!   the faucet's consume via user RPC and records the node's REJECTION (a real-node round-trip
//!   proving a COMMITTED same-block create+consume is unreachable — the network-account faucet + the
//!   stock client's missing `x-miden-network-tx-auth` header + the ntx-builder's committed-only
//!   consumption), and (3) queries the node to confirm nothing discoverable persists (the
//!   canary `c2_same_block_erasure_...` starvation, against the PRODUCTION note). Each Row-I negative
//!   is a client-side trap + committed read-back proving zero state change.
//!
//! The arc: deploy (identifier_init) → allowlist attester A (path N) → set_min_burn_size (path N) →
//! mint to the holder (path N, holder consumes the P2ID) → Row-I negatives (below-min, wrong-asset,
//! while-paused — the last pauses + unpauses via path N) → Row-H RIV (client-side execute + user-RPC
//! submit-rejection) → Row-G two-block burn (path N) → Row-J conservation ledger.
//!
//! **Validator-not-fixer:** a failing row is a SURFACED finding, never a faucet hot-fix; row H is an
//! EVIDENCE packet (DEV-7 stays OPEN), not an acceptability decision.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use miden_client::rpc::domain::account::AccountStorageRequirements;
use miden_client::rpc::domain::note::FetchedNote;
use miden_client::rpc::NodeRpcClient;
use miden_client::store::TransactionFilter;
use miden_client::transaction::{
    ForeignAccount, TransactionId, TransactionRequestBuilder, TransactionStatus,
};
use miden_protocol::account::{
    Account, AccountId, StorageMapKey, StorageSlotName, StorageSlotPatch,
};
use miden_protocol::asset::{Asset, AssetAmount};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId, NoteInclusionProof, NoteTag};
use miden_protocol::transaction::InputNote;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::Word;
use miden_standards::account::access::PausableStorage;
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::policies::MinBurnAmount;
use miden_standards::note::MinBurnAmountConfigNote;
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_encoding::note::xreserve_admin::{
    XReserveIdentifierInitNote, XReservePauseNote, XReserveSetAttesterNote, XReserveUnpauseNote,
};
use xusdc_encoding::note::xreserve_burn::FIXED_XUSDC_BURN_TAG;

use crate::actors::{create_actors, Actors};
use crate::assertions_gj::{ERR_BURN_BELOW_MIN, ERR_PAUSED, ERR_WRONG_ASSET_ORIGIN};
use crate::client::{build_client, os_seed, HarnessClient};
use crate::config::RunConfig;
use crate::deploy::build_faucet_account;
use crate::mintburn::{
    self, burn_note, burn_note_wrong_asset, raw_for_units, BASE_VECTOR, MINT_DOMAIN,
};
use crate::observations_cf::{Verdict, Word4, MARKER_CLEAR, MARKER_SET};
use crate::observations_gj::{
    BurnNegative, BurnSameBlock, BurnTwoBlock, ConservationLedger, RowsGjObservations, SupplyStep,
};
use crate::stack::NodeStack;

// FIXTURE VALUES (all reduced / on-chain units; every value stays within the default 1e12 cap).
// ================================================================================================

/// The amount minted to the holder (units) — the whole committed supply of this arc, later burned in
/// full by the Row-G two-block burn.
const MINT_UNITS: u64 = 100;
/// The maxFee every mint carries (units); reduces to 1 ≤ the mint amount, so R-MINT-10 holds.
const MAX_FEE_UNITS: u64 = 1;
/// The configured minimum burn size committed via `set_min_burn_size` (units).
const MIN_BURN: u64 = 10;
/// A burn strictly BELOW `MIN_BURN` (units) — the Row-I below-min negative.
const BURN_BELOW_MIN: u64 = 5;
/// The Row-G two-block burn amount (units) — the holder burns its entire minted balance.
const ROW_G_BURN: u64 = MINT_UNITS;
/// The Row-H same-block RIV burn amount (units) — valid against the committed supply (≤ supply).
const ROW_H_BURN: u64 = MINT_UNITS;
/// A valid (≥ MIN_BURN) burn used by the paused + wrong-asset negatives (units).
const NEG_BURN: u64 = 50;

/// The nonce salt for the single committed mint (distinct from any admin op).
const SALT_MINT: u8 = 0x51;
/// Legacy per-case burn variants; the burn payload carries no salt.
const SALT_BURN_BELOW: u8 = 0x61;
const SALT_BURN_WRONG_ASSET: u8 = 0x62;
const SALT_BURN_PAUSED: u8 = 0x63;
const SALT_BURN_SAME_BLOCK: u8 = 0x64;
const SALT_BURN_TWO_BLOCK: u8 = 0x65;

/// Bounded wait for the ntx-builder to commit a path-N faucet consumption.
const PATHN_TIMEOUT: Duration = Duration::from_secs(240);
/// Bounded wait for a submitted (wallet) transaction to commit.
const TX_COMMIT_TIMEOUT: Duration = Duration::from_secs(180);
/// Bounded wait for the client to sync a committed public note.
const NOTE_SYNC_TIMEOUT: Duration = Duration::from_secs(120);

// READ-BACK HELPERS (NODE `GetAccount` state → observation values).
// ================================================================================================

fn word4(w: Word) -> Word4 {
    [
        w[0].as_canonical_u64(),
        w[1].as_canonical_u64(),
        w[2].as_canonical_u64(),
        w[3].as_canonical_u64(),
    ]
}

fn value_slot(account: &Account, name: &StorageSlotName) -> Result<Word> {
    account
        .storage()
        .get_item(name)
        .with_context(|| format!("reading value slot '{name}'"))
}

fn token_supply(account: &Account) -> Result<u64> {
    Ok(value_slot(account, FungibleFaucet::token_config_slot())?[0].as_canonical_u64())
}

/// The committed minimum burn size — read from the STOCK [`MinBurnAmount`] floor slot (`[min,0,0,0]`;
/// Wave-1 S1: the custom `min_burn_size` slot is gone — the stock policy companion owns the floor).
fn min_burn(account: &Account) -> Result<u64> {
    account
        .storage()
        .get_item(MinBurnAmount::slot_name())
        .map(|w| w[0].as_canonical_u64())
        .context("reading the stock MinBurnAmount floor slot")
}

fn is_paused(account: &Account) -> Result<Word4> {
    Ok(word4(value_slot(
        account,
        PausableStorage::is_paused_slot(),
    )?))
}

/// A wallet's total balance of the faucet's fungible asset (vault iteration — the custody read-back).
fn wallet_balance(account: &Account, faucet_id: AccountId) -> u64 {
    account
        .vault()
        .assets()
        .filter_map(|asset| match asset {
            Asset::Fungible(f) if f.faucet_id() == faucet_id => Some(u64::from(f.amount())),
            _ => None,
        })
        .sum()
}

/// Declares the faucet as a foreign account IFF `note` carries the faucet's (policed) xUSDC asset —
/// the F4-reversal client-side coupling: a policed send/consume by a non-faucet account dyncalls the
/// faucet's `basic_blocklist::check_policy`, so the faucet must be a foreign account. Admin notes
/// (mint/domain/pause) carry no faucet asset and need none.
fn policed_faucet_foreign(note: &Note, faucet_id: AccountId) -> Result<Vec<ForeignAccount>> {
    let policed = note
        .assets()
        .iter()
        .any(|a| matches!(a, Asset::Fungible(f) if f.faucet_id() == faucet_id));
    if policed {
        Ok(vec![ForeignAccount::public(
            faucet_id,
            AccountStorageRequirements::default(),
        )
        .context(
            "declaring the faucet as a foreign account for the policed transfer",
        )?])
    } else {
        Ok(vec![])
    }
}

// THE DRIVER
// ================================================================================================

struct Driver {
    hc: HarnessClient,
    actors: Actors,
    faucet_id: AccountId,
    /// A throwaway (undeployed) second faucet whose id issues the Row-I wrong-asset note's asset.
    other_faucet_id: AccountId,
}

impl Driver {
    async fn try_fetch(&mut self, account_id: AccountId) -> Result<Option<Account>> {
        self.hc
            .client
            .sync_state()
            .await
            .context("syncing before a node read")?;
        self.hc
            .rpc
            .get_account_details(account_id)
            .await
            .map_err(|e| anyhow::anyhow!("GetAccount({account_id}): {e}"))
    }

    async fn fetch_faucet(&mut self) -> Result<Account> {
        let id = self.faucet_id;
        self.try_fetch(id)
            .await?
            .with_context(|| format!("the node does not recognize the faucet {id}"))
    }

    /// A wallet's committed faucet-asset balance from the client's synced store (0 before the wallet
    /// has materialized on-chain — the LNV-3 `balance_of` posture: the raw `GetAccount` RPC rejects
    /// an account the node has never seen, so the pre-materialization balance is read from the
    /// client's own synced view).
    async fn balance_of(&mut self, account_id: AccountId) -> Result<u64> {
        let faucet_id = self.faucet_id;
        self.hc
            .client
            .sync_state()
            .await
            .context("syncing before a balance read")?;
        Ok(self
            .hc
            .client
            .get_account(account_id)
            .await
            .map_err(|e| anyhow::anyhow!("client get_account({account_id}): {e}"))?
            .map(|a| wallet_balance(&a, faucet_id))
            .unwrap_or(0))
    }

    async fn wait_commit(&mut self, tx_id: TransactionId) -> Result<u32> {
        let deadline = Instant::now() + TX_COMMIT_TIMEOUT;
        loop {
            self.hc
                .client
                .sync_state()
                .await
                .context("syncing while waiting for a tx")?;
            let record = self
                .hc
                .client
                .get_transactions(TransactionFilter::Ids(vec![tx_id]))
                .await
                .context("querying tx status")?
                .pop()
                .with_context(|| format!("tx {tx_id} not tracked"))?;
            match record.status {
                TransactionStatus::Committed { block_number, .. } => {
                    return Ok(block_number.as_u32())
                }
                TransactionStatus::Discarded(cause) => bail!("tx {tx_id} DISCARDED: {cause:?}"),
                TransactionStatus::Pending => {
                    if Instant::now() > deadline {
                        bail!("tx {tx_id} did not commit within {TX_COMMIT_TIMEOUT:?}");
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    /// Emits a note from `sender` (a regular-account tx the user RPC accepts) and waits for the emit
    /// to commit. Returns the emit block.
    async fn emit(&mut self, sender: AccountId, note: Note) -> Result<u32> {
        let foreign = policed_faucet_foreign(&note, self.faucet_id)?;
        let req = TransactionRequestBuilder::new()
            .foreign_accounts(foreign)
            .own_output_notes(vec![note])
            .build()
            .context("building an emit request")?;
        let tx = self
            .hc
            .client
            .submit_new_transaction(sender, req)
            .await
            .context("submitting an emit transaction")?;
        self.wait_commit(tx).await
    }

    /// Commits a positive op via path N: emit the routed allowlisted note, then poll `GetAccount`
    /// until `ready` observes the committed effect. Returns the committed faucet account.
    async fn commit_via_ntx<F>(
        &mut self,
        sender: AccountId,
        note: Note,
        op: &str,
        ready: F,
    ) -> Result<Account>
    where
        F: Fn(&Account) -> bool,
    {
        self.emit(sender, note)
            .await
            .with_context(|| format!("emitting the {op} note"))?;
        self.wait_for_faucet(op, ready).await
    }

    /// Polls `GetAccount` until `ready` observes the committed effect on the faucet (used both after
    /// an emit and to await an autonomous ntx-builder consumption). Returns the committed account.
    async fn wait_for_faucet<F>(&mut self, op: &str, ready: F) -> Result<Account>
    where
        F: Fn(&Account) -> bool,
    {
        let deadline = Instant::now() + PATHN_TIMEOUT;
        loop {
            let account = self.fetch_faucet().await?;
            if ready(&account) {
                return Ok(account);
            }
            if Instant::now() > deadline {
                bail!(
                    "path-N commit of '{op}' timed out after {PATHN_TIMEOUT:?} — the ntx-builder did \
                     not commit the faucet's consumption of the routed allowlisted note"
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Client-side execute of the faucet consuming `note` (no submission). Ok = ACCEPTED, a trap =
    /// REJECTED with the captured error.
    async fn probe_consume(&mut self, note: Note) -> Result<Verdict> {
        self.hc
            .client
            .sync_state()
            .await
            .context("syncing before a probe")?;
        let req = TransactionRequestBuilder::new()
            .input_notes(vec![(note, None)])
            .build()
            .context("building a probe consume request")?;
        Ok(
            match self
                .hc
                .client
                .execute_transaction(self.faucet_id, req)
                .await
            {
                Ok(_) => Verdict::Accepted,
                Err(e) => Verdict::Rejected(format!("{e:?}")),
            },
        )
    }

    /// Client-side execute of the faucet consuming `note` as an UNAUTHENTICATED input — the Row-H
    /// same-block RIV. Returns `(accepted, executed_supply_delta)`: the delta is the `token_supply`
    /// decrement the (never-submitted) executed transaction would apply, read from its account-state
    /// delta (`None` when the consume trapped or the delta could not be read).
    async fn probe_same_block(
        &mut self,
        note: Note,
        supply_before: u64,
    ) -> Result<(bool, Option<u64>)> {
        self.hc
            .client
            .sync_state()
            .await
            .context("syncing before the same-block RIV")?;
        let req = TransactionRequestBuilder::new()
            .input_notes(vec![(note, None)])
            .build()
            .context("building the same-block RIV request")?;
        match self
            .hc
            .client
            .execute_transaction(self.faucet_id, req)
            .await
        {
            Ok(result) => {
                // v16: `account_delta()`→`account_patch()`; `StorageSlotDelta::Value(word)`→
                // `StorageSlotPatch::Value(StorageValuePatch)` read via `.value() -> Option<Word>`.
                let new_supply = match result
                    .account_patch()
                    .storage()
                    .get(FungibleFaucet::token_config_slot())
                {
                    Some(StorageSlotPatch::Value(vp)) => {
                        vp.value().map(|w| w[0].as_canonical_u64())
                    }
                    _ => None,
                };
                let delta = new_supply.map(|s| supply_before.saturating_sub(s));
                Ok((true, delta))
            }
            Err(_) => Ok((false, None)),
        }
    }

    /// The current chain tip (sync height).
    async fn tip(&mut self) -> Result<u32> {
        self.hc
            .client
            .sync_state()
            .await
            .context("syncing before a tip read")?;
        Ok(self
            .hc
            .client
            .get_sync_height()
            .await
            .context("reading sync height")?
            .as_u32())
    }

    /// Fetches the committed note via `GetNotesById`; returns the FULL public response content
    /// `(Note, NoteInclusionProof)` — both halves of the byte-exact response envelope — if the node
    /// has it committed, else `None`.
    async fn get_note_capture(
        &self,
        note_id: NoteId,
    ) -> Result<Option<(Note, NoteInclusionProof)>> {
        let fetched = self
            .hc
            .rpc
            .get_notes_by_id(&[note_id])
            .await
            .map_err(|e| anyhow::anyhow!("GetNotesById({note_id}): {e}"))?;
        for f in fetched {
            if let FetchedNote::Public(note, proof) = f {
                if note.id() == note_id {
                    return Ok(Some((note, proof)));
                }
            }
        }
        Ok(None)
    }

    /// Attempts to SUBMIT the faucet's consume of `note` (an unauthenticated input) to the node via
    /// user RPC — the REAL-NODE round-trip that proves a committed same-block create+consume of the
    /// production burn note is unreachable here. Returns `(rejected, error)`: the faucet is a network
    /// account, so post-deploy the node rejects a user-submitted consume (`Err` → `(true, msg)`); an
    /// `Ok` (the tx was accepted for inclusion) is the surprising case (`(false, "")`).
    async fn submit_probe(&mut self, note: Note) -> Result<(bool, String)> {
        self.hc
            .client
            .sync_state()
            .await
            .context("syncing before the submit probe")?;
        let req = TransactionRequestBuilder::new()
            .input_notes(vec![(note, None)])
            .build()
            .context("building the submit-probe request")?;
        match self
            .hc
            .client
            .submit_new_transaction(self.faucet_id, req)
            .await
        {
            Ok(_) => Ok((false, String::new())),
            Err(e) => Ok((true, format!("{e:?}"))),
        }
    }

    /// Whether `SyncNotes` filtered by `tag` over `[0, tip]` discovers `note_id`.
    async fn syncnotes_discovers(&mut self, tag: u32, note_id: NoteId) -> Result<bool> {
        let to = self.tip().await?;
        let tags = BTreeSet::from([NoteTag::new(tag)]);
        let blocks = self
            .hc
            .rpc
            .sync_notes(BlockNumber::from(0u32), BlockNumber::from(to), &tags)
            .await
            .map_err(|e| anyhow::anyhow!("SyncNotes(tag={tag:#010x}): {e}"))?;
        Ok(blocks.iter().any(|b| b.notes.contains_key(&note_id)))
    }

    /// The block a note's nullifier was recorded in on-chain, or `None` if unspent.
    async fn nullifier_block(&self, note: &Note) -> Result<Option<u32>> {
        let nf = note.nullifier();
        let heights = self
            .hc
            .rpc
            .get_nullifier_commit_heights(BTreeSet::from([nf]), BlockNumber::from(0u32))
            .await
            .map_err(|e| anyhow::anyhow!("querying nullifier heights: {e}"))?;
        Ok(heights.get(&nf).copied().flatten().map(|b| b.as_u32()))
    }

    /// Waits (syncing) until the target has a consumable committed note carrying exactly
    /// `amount_units` of this faucet's asset; returns the discovered `(Note, inclusion_block)`.
    async fn wait_for_target_note(
        &mut self,
        target: AccountId,
        amount_units: u64,
    ) -> Result<(Note, u32)> {
        let faucet_id = self.faucet_id;
        let deadline = Instant::now() + NOTE_SYNC_TIMEOUT;
        loop {
            self.hc
                .client
                .sync_state()
                .await
                .context("syncing for the target P2ID note")?;
            let consumable = self
                .hc
                .client
                .get_consumable_notes(Some(target))
                .await
                .context("querying the target's consumable notes")?;
            for (record, _) in &consumable {
                let carries_amount =
                    record.details().assets().iter_fungible().any(|a| {
                        a.faucet_id() == faucet_id && u64::from(a.amount()) == amount_units
                    });
                if !carries_amount {
                    continue;
                }
                let block = record
                    .inclusion_proof()
                    .map(|p| p.location().block_num().as_u32())
                    .context("the discovered note lacks an inclusion proof")?;
                let input: InputNote = record
                    .clone()
                    .try_into()
                    .context("converting the note record to an InputNote")?;
                return Ok((input.note().clone(), block));
            }
            if Instant::now() > deadline {
                bail!(
                    "the target {target} did not receive its committed P2ID note carrying \
                     {amount_units} units within {NOTE_SYNC_TIMEOUT:?}"
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// The target wallet consumes `note` (a regular-account tx the user RPC accepts). Returns the
    /// consume block.
    async fn target_consume(&mut self, target: AccountId, note: Note) -> Result<u32> {
        let foreign = policed_faucet_foreign(&note, self.faucet_id)?;
        let req = TransactionRequestBuilder::new()
            .foreign_accounts(foreign)
            .build_consume_notes(vec![note])
            .context("building the target consume request")?;
        let tx = self
            .hc
            .client
            .submit_new_transaction(target, req)
            .await
            .context("submitting the target consume")?;
        self.wait_commit(tx).await
    }

    fn owner(&self) -> AccountId {
        self.actors.owner.id()
    }
    fn holder(&self) -> AccountId {
        self.actors.holder.id()
    }
}

/// Runs the full LNV-4 rows-G/H/I/J arc on its own fresh stack. See the module docs for the
/// execution model + arc order.
pub async fn run_rows_gj(cfg: &RunConfig) -> Result<RowsGjObservations> {
    // 1. Fresh stack.
    let mut stack = NodeStack::bootstrap_and_start(&cfg.stack)
        .context("bootstrapping + starting the local node stack")?;
    if cfg.keep_stack {
        stack.keep_on_drop();
    }

    let obs = run_rows_gj_on(cfg, "main").await?;

    // Teardown (Drop also covers the error paths above).
    if !cfg.keep_stack {
        stack.stop().context("stopping the node stack")?;
    }
    Ok(obs)
}

/// Runs the rows-G/H/I/J arc against an ALREADY-RUNNING stack (the LNV-5 consolidated run boots
/// ONE stack and drives every slice on it in matrix order). `client_label` namespaces this
/// slice's client store, keystore, and actor secrets under `<run_root>/client-<label>/` so
/// composed slices cannot collide. No stack lifecycle happens here.
pub async fn run_rows_gj_on(cfg: &RunConfig, client_label: &str) -> Result<RowsGjObservations> {
    let main_commit = git_head_commit();

    // 2. Client + actors + the production faucet account (domain config BUILD-SEEDED to match the
    //    mint vector; the identifier committed by the identifier_init note below).
    let mut hc = build_client(&cfg.stack, client_label).await?;
    hc.client.sync_state().await.context("initial sync")?;
    let actor_root = cfg.stack.run_root.join(format!("client-{client_label}"));
    let actors = create_actors(&mut hc, &actor_root).await?;
    let owner_id = actors.owner.id();
    let domain = mintburn::lnv2_domain_params();
    let faucet = build_faucet_account(
        owner_id,
        actors.pauser.id(),
        actors.manager.id(),
        actors.blk_manager.id(),
        cfg.max_supply,
        &domain,
        os_seed(),
    )?;
    let faucet_id = faucet.id();
    // A throwaway SECOND faucet (never deployed) — only its id is used, to issue the wrong-asset
    // note's asset in Row I.
    let other_faucet = build_faucet_account(
        owner_id,
        actors.pauser.id(),
        actors.manager.id(),
        actors.blk_manager.id(),
        cfg.max_supply,
        &domain,
        os_seed(),
    )?;
    let other_faucet_id = other_faucet.id();

    // 3. Deploy: the faucet's first tx consumes the owner's identifier_init (first-deploy exemption).
    //    The seeded identifier is the faucet's own-id fixpoint (derived from faucet_id).
    let note1 = XReserveIdentifierInitNote::create(owner_id, faucet_id, hc.client.rng())
        .context("building the identifier_init note")?;
    let emit1 = TransactionRequestBuilder::new()
        .own_output_notes(vec![note1.clone()])
        .build()
        .context("building the identifier_init emit")?;
    let emit1_tx = hc
        .client
        .submit_new_transaction(owner_id, emit1)
        .await
        .context("emit identifier_init")?;
    let mut d = Driver {
        hc,
        actors,
        faucet_id,
        other_faucet_id,
    };
    d.wait_commit(emit1_tx)
        .await
        .context("waiting for the identifier_init emit")?;
    d.hc.client
        .add_account(&faucet, false)
        .await
        .context("registering the faucet with the client")?;
    let deploy = TransactionRequestBuilder::new()
        .input_notes(vec![(note1.clone(), None)])
        .build()
        .context("building the deploy request")?;
    let deploy_tx =
        d.hc.client
            .submit_new_transaction(faucet_id, deploy)
            .await
            .context("deploy tx")?;
    d.wait_commit(deploy_tx)
        .await
        .context("waiting for the deploy")?;

    // Track the holder's account-target tag so the client discovers the emitted public P2ID note.
    let holder_id = d.holder();
    d.hc.client
        .add_note_tag(NoteTag::with_account_target(holder_id))
        .await
        .context("tracking the holder note tag")?;

    // 4. Allowlist attester A (path N) — the mint attests with A.
    let a_commitment = d.actors.attester.commitment_word();
    let set_a =
        XReserveSetAttesterNote::create(owner_id, faucet_id, a_commitment, 1, d.hc.client.rng())
            .context("building set_attester(A)")?;
    d.commit_via_ntx(owner_id, set_a, "set_attester(A, enabled=1)", |a| {
        attester_enabled(a, a_commitment)
    })
    .await
    .context("allowlisting attester A via path N")?;

    // 5. set_min_burn_size(MIN_BURN) (path N) — so the Row-I below-min negative has a floor to fail.
    let set_min = Note::from(
        MinBurnAmountConfigNote::builder()
            .sender(owner_id)
            .target(faucet_id)
            .min_burn_amount(AssetAmount::new(MIN_BURN).context("invalid minimum burn amount")?)
            .generate_serial_number(d.hc.client.rng())
            .build()
            .context("building the minimum-burn configuration note")?,
    );
    d.commit_via_ntx(owner_id, set_min, "set_min_burn_size", |a| {
        min_burn(a).map(|m| m == MIN_BURN).unwrap_or(false)
    })
    .await
    .context("committing set_min_burn_size via path N")?;

    // 6. Mint MINT_UNITS to the holder (path N), holder consumes the emitted P2ID → holder vault.
    let supply_after_mint = mint_to_holder(&mut d, MINT_UNITS, SALT_MINT).await?;

    // 7. Row I — burn negatives (client-side rejects + zero-state-change read-backs).
    let i = run_row_i(&mut d).await?;

    // 8. Row H — the F7 same-block RIV (client-side; captures the erasure evidence).
    let h = run_row_h(&mut d).await?;

    // 9. Row G — the two-block burn (holder emits, ntx-builder consumes; the Circle read-path).
    let g = run_row_g(&mut d).await?;

    // 10. Row J — the conservation ledger for the committed arc.
    let final_supply = token_supply(&d.fetch_faucet().await?)?;
    let holder_final_balance = d.balance_of(holder_id).await?;
    let j = ConservationLedger {
        total_minted: MINT_UNITS,
        total_burned: ROW_G_BURN,
        final_supply,
        steps: vec![
            SupplyStep {
                label: "after-mint".to_string(),
                supply: supply_after_mint,
            },
            SupplyStep {
                label: "after-two-block-burn".to_string(),
                supply: final_supply,
            },
        ],
        holder_final_balance,
    };

    Ok(RowsGjObservations {
        main_commit,
        faucet_id: faucet_id.to_string(),
        holder_id: holder_id.to_string(),
        g,
        h,
        i,
        j,
    })
}

/// Mints `units` to the holder via path N and has the holder consume the emitted P2ID note.
/// Returns the committed `token_supply` after the mint.
async fn mint_to_holder(d: &mut Driver, units: u64, salt: u8) -> Result<u64> {
    let owner = d.owner();
    let holder = d.holder();
    let faucet_id = d.faucet_id;
    let supply_before = token_supply(&d.fetch_faucet().await?)?;

    // Produce the attestation under an immutable borrow that ends before the rng borrow. Fresh
    // faucet: splice the OWN-ID remoteToken so structural validation's identifier compare passes against the
    // note-derived own-id identifier (R2 identifier-binding fix).
    let payload = mintburn::mint_payload_own_id(
        faucet_id,
        BASE_VECTOR,
        holder,
        raw_for_units(units),
        raw_for_units(MAX_FEE_UNITS),
        salt,
    );
    let attestation = d.actors.attester.attestation_for(&payload);
    let note = xusdc_encoding::note::xreserve_mint::XUsdcMintNote::create(
        owner,
        faucet_id,
        &payload,
        &attestation,
        d.hc.client.rng(),
    )
    .context("building the mint-to-holder note")?;

    let committed = d
        .commit_via_ntx(owner, note, "mint to holder", |a| {
            token_supply(a)
                .map(|s| s >= supply_before + units)
                .unwrap_or(false)
        })
        .await
        .context("committing the mint to the holder via path N")?;
    let supply_after = token_supply(&committed)?;

    // The holder consumes the emitted P2ID note → the burned funds enter its vault.
    let (p2id, _block) = d.wait_for_target_note(holder, units).await?;
    d.target_consume(holder, p2id)
        .await
        .context("holder consuming its mint P2ID")?;
    Ok(supply_after)
}

/// Row I — the three burn negatives (below-min, wrong-asset, while-paused), each a client-side
/// reject + committed-`token_supply` read-back proving zero state change.
async fn run_row_i(d: &mut Driver) -> Result<Vec<BurnNegative>> {
    let holder = d.holder();
    let faucet_id = d.faucet_id;
    let other_faucet_id = d.other_faucet_id;
    let mut out = Vec::new();

    // I1 — BELOW-MIN: a burn strictly below the configured minimum burn size.
    {
        let supply_before = token_supply(&d.fetch_faucet().await?)?;
        let note = burn_note(
            holder,
            faucet_id,
            BURN_BELOW_MIN,
            SALT_BURN_BELOW,
            d.hc.client.rng(),
        )
        .context("building the below-min burn note")?;
        let verdict = d.probe_consume(note).await?;
        let supply_after = token_supply(&d.fetch_faucet().await?)?;
        out.push(BurnNegative {
            label: "below-min".to_string(),
            expected_error: ERR_BURN_BELOW_MIN.to_string(),
            verdict,
            supply_before,
            supply_after,
        });
    }

    // I2 — WRONG-ASSET: a burn whose vault asset is issued by a DIFFERENT faucet.
    {
        let supply_before = token_supply(&d.fetch_faucet().await?)?;
        let note = burn_note_wrong_asset(
            holder,
            faucet_id,
            other_faucet_id,
            NEG_BURN,
            SALT_BURN_WRONG_ASSET,
            d.hc.client.rng(),
        )
        .context("building the wrong-asset burn note")?;
        let verdict = d.probe_consume(note).await?;
        let supply_after = token_supply(&d.fetch_faucet().await?)?;
        out.push(BurnNegative {
            label: "wrong-asset".to_string(),
            expected_error: ERR_WRONG_ASSET_ORIGIN.to_string(),
            verdict,
            supply_before,
            supply_after,
        });
    }

    // I3 — WHILE-PAUSED: pause (path N), probe a valid burn (rejected — paused), then unpause.
    {
        let owner_pauser = d.actors.pauser.id();
        let pause = XReservePauseNote::create(owner_pauser, faucet_id, d.hc.client.rng())
            .context("building the pause note")?;
        d.commit_via_ntx(owner_pauser, pause, "pause", |a| {
            is_paused(a).map(|p| p == MARKER_SET).unwrap_or(false)
        })
        .await
        .context("pausing via path N")?;

        let supply_before = token_supply(&d.fetch_faucet().await?)?;
        let note = burn_note(
            holder,
            faucet_id,
            NEG_BURN,
            SALT_BURN_PAUSED,
            d.hc.client.rng(),
        )
        .context("building the while-paused burn note")?;
        let verdict = d.probe_consume(note).await?;
        let supply_after = token_supply(&d.fetch_faucet().await?)?;
        out.push(BurnNegative {
            label: "while-paused".to_string(),
            expected_error: ERR_PAUSED.to_string(),
            verdict,
            supply_before,
            supply_after,
        });

        // Restore: unpause (path N) so Row G / conservation run against an unpaused faucet.
        let unpause = XReserveUnpauseNote::create(owner_pauser, faucet_id, d.hc.client.rng())
            .context("building the unpause note")?;
        d.commit_via_ntx(owner_pauser, unpause, "unpause", |a| {
            is_paused(a).map(|p| p == MARKER_CLEAR).unwrap_or(false)
        })
        .await
        .context("unpausing via path N")?;
    }

    Ok(out)
}

/// Row H — the F7 same-block-erasure RIV (EVIDENCE, no acceptability decision). Builds a fresh
/// production `XReserveBurnNote`, consumes it CLIENT-SIDE as an unauthenticated input (the
/// never-committed same-block lifecycle), and captures precisely what survives via raw RPC.
async fn run_row_h(d: &mut Driver) -> Result<BurnSameBlock> {
    let holder = d.holder();
    let faucet_id = d.faucet_id;
    let onchain_supply_before = token_supply(&d.fetch_faucet().await?)?;

    let note = burn_note(
        holder,
        faucet_id,
        ROW_H_BURN,
        SALT_BURN_SAME_BLOCK,
        d.hc.client.rng(),
    )
    .context("building the same-block RIV burn note")?;
    let note_id = note.id();
    let note_tag = note.metadata().tag().as_u32();

    // (1) Client-side execute the unauthenticated consume — the burn is valid and its account-state
    //     delta shows exactly what supply movement a same-block/never-committed consume WOULD apply.
    let (consume_accepted, executed_supply_delta) = d
        .probe_same_block(note.clone(), onchain_supply_before)
        .await?;

    // (2) REAL-NODE round-trip: SUBMIT the faucet's consume via user RPC. The faucet is a network
    //     account, so post-deploy the node REJECTS a user-submitted consume — proving a COMMITTED
    //     same-block create+consume of the production note is unreachable on this stack (the only
    //     commit path, the ntx-builder, consumes COMMITTED notes → always strictly-later-block, Row
    //     G). This is what makes Row H a real-node test, not merely a local execute.
    let (submit_via_user_rpc_rejected, submit_rejection_error) =
        d.submit_probe(note.clone()).await?;

    // (3) Raw RPC: what survives? The note never committed → GetNotesById finds nothing, no
    //     nullifier, SyncNotes cannot discover it. (Read AFTER the submit attempt so an unexpected
    //     commit would surface here + in the supply read.)
    let committed = d.get_note_capture(note_id).await?;
    let committed_note_found = committed.is_some();
    let nullifier_recorded = d.nullifier_block(&note).await?.is_some();
    let discovered_by_syncnotes = d.syncnotes_discovers(FIXED_XUSDC_BURN_TAG, note_id).await?;
    let onchain_supply_after = token_supply(&d.fetch_faucet().await?)?;

    let raw_getnotesbyid_response = match &committed {
        None => format!(
            "GetNotesById([{note_id}]) -> [] (note not found: the never-committed burn note is absent \
             from the note tree — Circle SyncNotes/GetNotesById discovery is starved)"
        ),
        Some((n, proof)) => format!(
            "GetNotesById([{note_id}]) -> [Public(note, inclusion@block {})] (UNEXPECTED — a \
             never-committed note should not be found); note_bytes_hex={}",
            proof.location().block_num().as_u32(),
            hex_lower(&n.to_bytes())
        ),
    };

    Ok(BurnSameBlock {
        label: "same-block-erasure".to_string(),
        amount_units: ROW_H_BURN,
        mechanism: "the production XReserveBurnNote consumed as an unauthenticated input (the \
                    same-block/never-committed lifecycle, mirroring canary \
                    c2_same_block_erasure_unauthenticated_consume): (1) a client-side execute shows \
                    the burn is valid and applies a supply delta; (2) submitting the faucet's consume \
                    via user RPC is REJECTED by the node — a COMMITTED same-block create+consume is \
                    unreachable (network-account faucet; the ntx-builder consumes only COMMITTED \
                    notes → always strictly-later-block, Row G); (3) the note never commits → no \
                    committed note, no nullifier, not SyncNotes-discoverable. Evidence for DEV-7; no \
                    acceptability decision"
            .to_string(),
        note_tag,
        note_id: note_id.to_hex(),
        consume_accepted,
        executed_supply_delta,
        submit_via_user_rpc_rejected,
        submit_rejection_error,
        onchain_supply_before,
        onchain_supply_after,
        committed_note_found,
        nullifier_recorded,
        discovered_by_syncnotes,
        raw_getnotesbyid_response,
    })
}

/// Row G — the two-block burn (the Circle read-path). The holder emits the production burn note
/// (committed block N), the driver captures the committed note + tag-filtered discovery + byte-exact
/// `GetNotesById`, then the ntx-builder consumes it (block N+1) and the driver re-reads the persisted
/// note + nullifier + supply decrement.
async fn run_row_g(d: &mut Driver) -> Result<BurnTwoBlock> {
    let holder = d.holder();
    let faucet_id = d.faucet_id;

    let supply_before = token_supply(&d.fetch_faucet().await?)?;
    let holder_balance_before = d.balance_of(holder).await?;

    // Build + emit the production burn note from the HOLDER (asset moves holder-vault → note).
    let note = burn_note(
        holder,
        faucet_id,
        ROW_G_BURN,
        SALT_BURN_TWO_BLOCK,
        d.hc.client.rng(),
    )
    .context("building the two-block burn note")?;
    let note_id = note.id();
    let note_tag = note.metadata().tag().as_u32();
    let fungible: Vec<_> = note.assets().iter_fungible().collect();
    let (note_asset_amount, note_asset_is_faucet) = match fungible.first() {
        Some(a) => (u64::from(a.amount()), a.faucet_id() == faucet_id),
        None => (0, false),
    };

    let note_commit_block = d
        .emit(holder, note.clone())
        .await
        .context("emitting the burn note")?;
    let holder_balance_after = d.balance_of(holder).await?;

    // Capture at block N (committed, pre-consume): the FULL byte-exact GetNotesById response content
    // (Note + NoteInclusionProof) + tag-filtered SyncNotes discovery.
    let capture = d.get_note_capture(note_id).await?;
    let committed_before_consume = capture.is_some();
    let (
        getnotesbyid_note_bytes_hex,
        getnotesbyid_inclusion_proof_bytes_hex,
        getnotesbyid_inclusion_block,
    ) = match &capture {
        Some((n, proof)) => (
            hex_lower(&n.to_bytes()),
            hex_lower(&proof.to_bytes()),
            proof.location().block_num().as_u32(),
        ),
        None => (String::new(), String::new(), 0),
    };
    let discovered_by_syncnotes = d.syncnotes_discovers(FIXED_XUSDC_BURN_TAG, note_id).await?;

    // The ntx-builder consumes it (path N) — token_supply falls by the burned amount.
    let target_supply = supply_before.saturating_sub(ROW_G_BURN);
    d.wait_for_faucet("two-block burn consume", |a| {
        token_supply(a).map(|s| s <= target_supply).unwrap_or(false)
    })
    .await
    .context("awaiting the ntx-builder's consumption of the burn note")?;
    let supply_after = token_supply(&d.fetch_faucet().await?)?;

    // The nullifier records the consume block; the committed note PERSISTS (durable read-path).
    let consume_block = d
        .nullifier_block(&note)
        .await?
        .context("the burn note's nullifier was not recorded after the consume")?;
    let nullifier_recorded_after_consume = true;
    let found_after_consume = d.get_note_capture(note_id).await?.is_some();

    Ok(BurnTwoBlock {
        label: "two-block-burn".to_string(),
        amount_units: ROW_G_BURN,
        supply_before,
        supply_after,
        holder_balance_before,
        holder_balance_after,
        note_id: note_id.to_hex(),
        note_tag,
        note_commit_block,
        consume_block,
        committed_before_consume,
        discovered_by_syncnotes,
        found_after_consume,
        nullifier_recorded_after_consume,
        note_asset_amount,
        note_asset_is_faucet,
        getnotesbyid_note_bytes_hex,
        getnotesbyid_inclusion_proof_bytes_hex,
        getnotesbyid_inclusion_block,
    })
}

/// Whether `commitment`'s `xReserveAttesters` marker is the enabled word [1,0,0,0].
fn attester_enabled(account: &Account, commitment: Word) -> bool {
    account
        .storage()
        .get_map_item(
            XReserveFaucetExtension::xreserve_attesters_slot(),
            StorageMapKey::new(commitment),
        )
        .ok()
        .map(|w| word4(w) == MARKER_SET)
        .unwrap_or(false)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The repo HEAD commit (ledger metadata; best-effort).
fn git_head_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
