//! The LNV-2 rows-C/F driver: one deterministic arc against a fresh local node, producing the
//! [`RowsCfObservations`] the rows-C/F assertion suite judges.
//!
//! Execution model (LNV-1 §3.2 posture finding, empirically re-confirmed for LNV-2):
//! - **Positive admin state changes commit via path N (the ntx-builder).** Every `set_attester` /
//!   `set_max_supply` / `set_min_burn_size` / `pause` / `unpause` / role grant/revoke is emitted as a
//!   routed, allowlisted admin note from its (kernel-forced) sender wallet — a regular-account tx the
//!   user RPC accepts — and the running ntx-builder auto-executes the faucet's consumption. The
//!   driver polls `GetAccount` until the committed effect appears ([`Driver::commit_admin`]). (User
//!   RPC rejects post-deploy network-account txs, and the client cannot present the
//!   `x-miden-network-tx-auth` header, so path N is the only commit path at v0.15.1.)
//! - **Accept/reject PROBES run client-side (no submission).** A mint/burn/P2ID/tx-script
//!   consumption is executed locally against the committed on-chain state
//!   ([`Driver::probe_consume`] / [`Driver::probe_tx_script`]); executing Ok = ACCEPTED, a trap =
//!   REJECTED with the captured error. This is the LNV-1 row-B kernel-trap technique — a reject needs
//!   no submission path, and an accept proves the consumption is valid against the real chain state
//!   without mutating it (so the arc stays deterministic: committed `token_supply` is fixed by the
//!   single path-N supply mint).
//!
//! The arc (single evolving chain): deploy (domain_init) → allowlist A → commit one supply mint (A) →
//! C3 cap → C2 min-burn → C1 rotation A→B → C4 pause/unpause (+F6 owner-setters-while-paused) → C5
//! DOM_MANAGER role rotation → C6 non-authorized-sender negatives → row-F auth boundary.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use miden_client::rpc::NodeRpcClient;
use miden_client::store::TransactionFilter;
use miden_client::transaction::{
    TransactionId, TransactionRequestBuilder, TransactionScript, TransactionStatus,
};
use miden_protocol::account::{Account, AccountId, RoleSymbol, StorageSlotName};
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteAttachments, NoteType};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::RoleBasedAccessControl;
use miden_standards::note::P2idNote;
use xusdc_encoding::account::xreserve::{
    DOM_PAUSER_ROLE, MIN_BURN_SIZE_SLOT_LABEL, XRESERVE_ATTESTERS_SLOT_LABEL,
};
use xusdc_encoding::note::xreserve_admin::{
    XReserveDomainInitNote, XReserveGrantRoleNote, XReservePauseNote, XReserveRevokeRoleNote,
    XReserveSetAttesterNote, XReserveSetMaxSupplyNote, XReserveSetMinBurnSizeNote,
    XReserveUnpauseNote,
};
use xusdc_encoding::note::xreserve_mint::XReserveMintNote;

use crate::actors::{create_actors, Actors, AttesterKey};
use crate::assertions_cf::{ERR_LACKS_ROLE, ERR_NOT_OWNER};
use crate::client::{build_client, os_seed, HarnessClient};
use crate::config::RunConfig;
use crate::deploy::build_faucet_account;
use crate::mintburn::{self, lnv2_domain_params, raw_for_units};
use crate::observations_cf::{
    AdminGateReject, C1SetAttester, C2MinBurn, C3MaxSupply, C4Pause, C5RoleRotation, RowF,
    RowsCfObservations, Verdict, Word4,
};
use crate::stack::NodeStack;

// FIXTURE VALUES (all Circle-owned values are LOCAL TEST parameters; the amounts keep every mint
// within the C3 cap and every burn within the single committed supply). Reduced (on-chain) units.
// ================================================================================================

/// The committed supply established by the single path-N mint (units). Fixed for the whole arc
/// (all other mints/burns are execute-only, so committed `token_supply` never moves off this).
const SUPPLY_UNITS: u64 = 100;
/// The C3 cap the driver commits (units). `SUPPLY_UNITS + within-cap amount <= cap < SUPPLY_UNITS + over-cap amount`.
const CAP_UNITS: u64 = 300;
/// A mint whose committed effect would keep `token_supply` within the cap (100 + 100 = 200 <= 300).
const WITHIN_CAP_UNITS: u64 = 100;
/// A mint that would push `token_supply` over the cap (100 + 250 = 350 > 300).
const OVER_CAP_UNITS: u64 = 250;
/// The small mint the C1/C4 probes use (100 + 50 = 150 <= 300).
const PROBE_MINT_UNITS: u64 = 50;
/// A maxFee that reduces to 1 unit (≤ every mint amount above, so R-MINT-10 holds).
const MAX_FEE_UNITS: u64 = 1;

/// The raised minimum burn size (C2): a burn below it rejects.
const RAISED_MIN: u64 = 50;
/// The lowered minimum burn size (C2): an at-min burn passes.
const LOWERED_MIN: u64 = 10;
/// A burn strictly below `RAISED_MIN`.
const BURN_BELOW: u64 = 5;
/// The F6 min-burn the owner commits WHILE PAUSED (any non-zero value).
const F6_MIN: u64 = 7;

/// Bounded wait for the ntx-builder to commit a path-N faucet consumption (generous for the mint,
/// which proves client-side then is re-proven by the ntx-builder).
const PATHN_TIMEOUT: Duration = Duration::from_secs(180);
/// Bounded wait for a submitted (wallet) transaction to commit.
const TX_COMMIT_TIMEOUT: Duration = Duration::from_secs(180);
/// How many blocks to watch a rejected admin note staying unconsumed (C6 node-side confirmation).
const UNCONSUMED_WATCH_BLOCKS: u32 = 3;

// READ-BACK HELPERS (NODE `GetAccount` state → the observation values).
// ================================================================================================

fn word4(w: Word) -> Word4 {
    [w[0].as_canonical_u64(), w[1].as_canonical_u64(), w[2].as_canonical_u64(), w[3].as_canonical_u64()]
}

fn value_slot(account: &Account, label: &str) -> Result<Word> {
    let name = StorageSlotName::new(label).with_context(|| format!("slot label '{label}'"))?;
    account
        .storage()
        .get_item(&name)
        .with_context(|| format!("reading value slot '{label}'"))
}

fn map_item(account: &Account, label: &str, key: Word) -> Result<Word> {
    let name = StorageSlotName::new(label).with_context(|| format!("slot label '{label}'"))?;
    account
        .storage()
        .get_map_item(&name, key)
        .map_err(|e| anyhow::anyhow!("reading map slot '{label}': {e}"))
}

fn attester_marker(account: &Account, commitment: Word) -> Result<Word4> {
    Ok(word4(map_item(account, XRESERVE_ATTESTERS_SLOT_LABEL, commitment)?))
}

fn min_burn(account: &Account) -> Result<u64> {
    Ok(value_slot(account, MIN_BURN_SIZE_SLOT_LABEL)?[0].as_canonical_u64())
}

fn max_supply(account: &Account) -> Result<u64> {
    // token_config = [token_supply, max_supply, decimals, symbol].
    Ok(value_slot(account, "miden::standards::faucets::fungible::token_config")?[1].as_canonical_u64())
}

fn token_supply(account: &Account) -> Result<u64> {
    Ok(value_slot(account, "miden::standards::faucets::fungible::token_config")?[0].as_canonical_u64())
}

fn is_paused(account: &Account) -> Result<Word4> {
    Ok(word4(value_slot(account, "miden::standards::access::pausable::is_paused")?))
}

fn role_membership(account: &Account, role: &RoleSymbol, member: AccountId) -> Result<Word4> {
    let key = Word::from([Felt::ZERO, Felt::from(role), member.suffix(), member.prefix().as_felt()]);
    account
        .storage()
        .get_map_item(RoleBasedAccessControl::role_membership_slot(), key)
        .map(word4)
        .map_err(|e| anyhow::anyhow!("reading role_membership: {e}"))
}

// THE DRIVER
// ================================================================================================

struct Driver {
    hc: HarnessClient,
    actors: Actors,
    faucet_id: AccountId,
}

impl Driver {
    /// The NODE's current view of the faucet account (`GetAccount`); errors if the node does not
    /// recognize it.
    async fn fetch(&mut self) -> Result<Account> {
        self.hc.client.sync_state().await.context("syncing before a node read")?;
        self.hc
            .rpc
            .get_account_details(self.faucet_id)
            .await
            .map_err(|e| anyhow::anyhow!("GetAccount({}): {e}", self.faucet_id))?
            .with_context(|| format!("the node does not recognize the faucet {}", self.faucet_id))
    }

    async fn wait_commit(&mut self, tx_id: TransactionId) -> Result<u32> {
        let deadline = Instant::now() + TX_COMMIT_TIMEOUT;
        loop {
            self.hc.client.sync_state().await.context("syncing while waiting for a tx")?;
            let record = self
                .hc
                .client
                .get_transactions(TransactionFilter::Ids(vec![tx_id]))
                .await
                .context("querying tx status")?
                .pop()
                .with_context(|| format!("tx {tx_id} not tracked"))?;
            match record.status {
                TransactionStatus::Committed { block_number, .. } => return Ok(block_number.as_u32()),
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
        let req = TransactionRequestBuilder::new()
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

    /// Commits a positive admin op via path N: emit the routed allowlisted note, then poll
    /// `GetAccount` until `ready` observes the committed effect. Returns the committed account.
    async fn commit_admin<F>(&mut self, sender: AccountId, note: Note, op: &str, ready: F) -> Result<Account>
    where
        F: Fn(&Account) -> bool,
    {
        self.emit(sender, note).await.with_context(|| format!("emitting the {op} note"))?;
        let deadline = Instant::now() + PATHN_TIMEOUT;
        loop {
            let account = self.fetch().await?;
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
        self.hc.client.sync_state().await.context("syncing before a probe")?;
        let req = TransactionRequestBuilder::new()
            .input_notes(vec![(note, None)])
            .build()
            .context("building a probe consume request")?;
        Ok(match self.hc.client.execute_transaction(self.faucet_id, req).await {
            Ok(_) => Verdict::Accepted,
            Err(e) => Verdict::Rejected(format!("{e:?}")),
        })
    }

    /// Client-side execute of a tx-script transaction against the faucet (row F). Ok = ACCEPTED, a
    /// trap = REJECTED.
    async fn probe_tx_script(&mut self, script: TransactionScript) -> Result<Verdict> {
        self.hc.client.sync_state().await.context("syncing before the tx-script probe")?;
        let req = TransactionRequestBuilder::new()
            .custom_script(script)
            .build()
            .context("building the tx-script request")?;
        Ok(match self.hc.client.execute_transaction(self.faucet_id, req).await {
            Ok(_) => Verdict::Accepted,
            Err(e) => Verdict::Rejected(format!("{e:?}")),
        })
    }

    /// Node-truth: is `note`'s nullifier in the node's spent set?
    async fn note_consumed(&self, note: &Note) -> Result<bool> {
        let nf = note.nullifier();
        let heights = self
            .hc
            .rpc
            .get_nullifier_commit_heights(BTreeSet::from([nf]), BlockNumber::from(0u32))
            .await
            .map_err(|e| anyhow::anyhow!("querying nullifier heights: {e}"))?;
        Ok(heights.get(&nf).copied().flatten().is_some())
    }

    /// Waits until the chain tip advances `blocks` past `from` (bounded).
    async fn wait_blocks_past(&mut self, from: u32, blocks: u32) -> Result<()> {
        let deadline = Instant::now() + PATHN_TIMEOUT;
        loop {
            self.hc.client.sync_state().await.context("syncing while watching blocks")?;
            let tip = self.hc.client.get_sync_height().await.context("reading sync height")?.as_u32();
            if tip >= from + blocks {
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!("the chain did not advance {blocks} blocks past {from} in time (tip {tip})");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    fn rng(&mut self) -> &mut impl miden_protocol::crypto::rand::FeltRng {
        self.hc.client.rng()
    }
}

// ── admin-note builders bound to this run's ids ──────────────────────────────────────────────

impl Driver {
    fn owner(&self) -> AccountId {
        self.actors.owner.id()
    }
    fn set_attester_note(&mut self, sender: AccountId, commitment: Word, enabled: u8) -> Result<Note> {
        let f = self.faucet_id;
        XReserveSetAttesterNote::create(sender, f, commitment, enabled, self.rng())
            .context("building a set_attester note")
    }
    fn set_max_supply_note(&mut self, sender: AccountId, cap: u64) -> Result<Note> {
        let f = self.faucet_id;
        XReserveSetMaxSupplyNote::create(sender, f, cap, self.rng()).context("building a set_max_supply note")
    }
    fn set_min_burn_note(&mut self, sender: AccountId, min: u64) -> Result<Note> {
        let f = self.faucet_id;
        XReserveSetMinBurnSizeNote::create(sender, f, min, self.rng()).context("building a set_min_burn note")
    }
    fn pause_note(&mut self, sender: AccountId) -> Result<Note> {
        let f = self.faucet_id;
        XReservePauseNote::create(sender, f, self.rng()).context("building a pause note")
    }
    fn unpause_note(&mut self, sender: AccountId) -> Result<Note> {
        let f = self.faucet_id;
        XReserveUnpauseNote::create(sender, f, self.rng()).context("building an unpause note")
    }
    fn mint_note(&mut self, attester_is_b: bool, recipient: AccountId, units: u64, salt: u8) -> Result<Note> {
        let f = self.faucet_id;
        let sender = self.owner();
        let payload = mintburn::mint_payload(recipient, raw_for_units(units), raw_for_units(MAX_FEE_UNITS), salt);
        // Produce the owned attestation under an immutable borrow of `actors`, which ends here; the
        // mint-note builder then takes the (disjoint) mutable rng borrow — no field-split gymnastics.
        let attestation = {
            let attester: &AttesterKey =
                if attester_is_b { &self.actors.attester_b } else { &self.actors.attester };
            attester.attestation_for(&payload)
        };
        XReserveMintNote::create(sender, f, &payload, &attestation, self.hc.client.rng())
            .context("building the XReserveMintNote probe")
    }
    fn burn_note(&mut self, units: u64, salt: u8) -> Result<Note> {
        let f = self.faucet_id;
        let holder = self.actors.holder.id();
        mintburn::burn_note(holder, f, units, salt, self.rng())
    }
    fn grant_pauser_note(&mut self, member: AccountId) -> Result<Note> {
        let f = self.faucet_id;
        let manager = self.actors.manager.id();
        let role = RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a valid role symbol");
        XReserveGrantRoleNote::create(manager, f, Felt::from(&role), member, self.rng())
            .context("building a grant_role note")
    }
    fn revoke_pauser_note(&mut self, member: AccountId) -> Result<Note> {
        let f = self.faucet_id;
        let manager = self.actors.manager.id();
        let role = RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a valid role symbol");
        XReserveRevokeRoleNote::create(manager, f, Felt::from(&role), member, self.rng())
            .context("building a revoke_role note")
    }
}

/// Runs the full LNV-2 rows-C/F arc. See the module docs for the execution model + arc order.
pub async fn run_rows_cf(cfg: &RunConfig) -> Result<RowsCfObservations> {
    let main_commit = git_head_commit();

    // 1. Fresh stack.
    let mut stack = NodeStack::bootstrap_and_start(&cfg.stack)
        .context("bootstrapping + starting the local node stack")?;
    if cfg.keep_stack {
        stack.keep_on_drop();
    }

    // 2. Client + actors + the production faucet account (domain_init matching the mint vector).
    let mut hc = build_client(&cfg.stack, "main").await?;
    hc.client.sync_state().await.context("initial sync")?;
    let actors = create_actors(&mut hc, &cfg.stack.run_root).await?;
    let owner_id = actors.owner.id();
    let domain = lnv2_domain_params();
    let faucet =
        build_faucet_account(owner_id, actors.pauser.id(), actors.manager.id(), cfg.max_supply, os_seed())?;
    let faucet_id = faucet.id();

    // 3. Deploy: the faucet's first tx consumes the owner's domain_init (first-deploy exemption).
    let note1 = XReserveDomainInitNote::create(
        owner_id,
        faucet_id,
        domain.domain,
        domain.source_domain,
        &domain.xreserve_contract,
        domain.identifier_word(),
        hc.client.rng(),
    )
    .context("building the domain_init note")?;
    let emit1 = TransactionRequestBuilder::new()
        .own_output_notes(vec![note1.clone()])
        .build()
        .context("building the domain_init emit")?;
    let emit1_tx = hc.client.submit_new_transaction(owner_id, emit1).await.context("emit domain_init")?;
    // Reuse the driver's wait after we build it; here we poll inline via a temporary.
    let mut d = Driver { hc, actors, faucet_id };
    d.wait_commit(emit1_tx).await.context("waiting for the domain_init emit")?;
    d.hc.client.add_account(&faucet, false).await.context("registering the faucet with the client")?;
    let deploy = TransactionRequestBuilder::new()
        .input_notes(vec![(note1.clone(), None)])
        .build()
        .context("building the deploy request")?;
    let deploy_tx = d.hc.client.submit_new_transaction(faucet_id, deploy).await.context("deploy tx")?;
    d.wait_commit(deploy_tx).await.context("waiting for the deploy")?;

    let recipient = d.actors.recipient.id();
    let pauser_id = d.actors.pauser.id();
    let manager_id = d.actors.manager.id();
    let a_commitment = d.actors.attester.commitment_word();
    let b_commitment = d.actors.attester_b.commitment_word();
    let pauser_role = RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a valid role symbol");

    // ── C1 (part 1) — allowlist attester A (path N), and commit ONE supply mint (attested by A)
    //    to establish committed token_supply for the burn probes + prove A works pre-rotation. ──
    let note = d.set_attester_note(owner_id, a_commitment, 1)?;
    let acct = d
        .commit_admin(owner_id, note, "set_attester(A, enabled=1)", |a| {
            attester_marker(a, a_commitment).map(|m| m == crate::observations_cf::MARKER_SET).unwrap_or(false)
        })
        .await?;
    let c1_a_marker_after_enable = attester_marker(&acct, a_commitment)?;

    // The single committed supply mint (path N): raises token_supply to SUPPLY_UNITS.
    let supply_mint = d.mint_note(false, recipient, SUPPLY_UNITS, 0)?;
    d.commit_admin(owner_id, supply_mint, "supply mint (attested by A)", |a| {
        token_supply(a).map(|s| s >= SUPPLY_UNITS).unwrap_or(false)
    })
    .await
    .context("committing the supply-establishing mint via path N")?;

    // ── C3 — set_max_supply(CAP); a within-cap mint ACCEPTS, an over-cap mint REJECTS. ──
    // max_supply is stored (and the D5e cap-check `token_supply + amount <= max_supply` compares) in
    // ON-CHAIN reduced units — the SAME units as token_supply and the mint's reduced amount — NOT the
    // raw uint256. So the cap is committed in reduced units (CAP_UNITS), not `raw_for_units(...)`.
    let note = d.set_max_supply_note(owner_id, CAP_UNITS)?;
    let acct = d
        .commit_admin(owner_id, note, "set_max_supply", |a| {
            max_supply(a).map(|m| m == CAP_UNITS).unwrap_or(false)
        })
        .await?;
    let c3_max_supply_readback = max_supply(&acct)?;
    let within = d.mint_note(false, recipient, WITHIN_CAP_UNITS, 0x21)?;
    let c3_within = d.probe_consume(within).await?;
    let over = d.mint_note(false, recipient, OVER_CAP_UNITS, 0x22)?;
    let c3_over = d.probe_consume(over).await?;
    let c3 = C3MaxSupply {
        committed_cap: CAP_UNITS,
        max_supply_readback: c3_max_supply_readback,
        over_cap_mint: c3_over,
        within_cap_mint: c3_within,
    };

    // ── C2 — set_min_burn_size(raise) → below-min burn REJECTS; (lower) → at-min burn PASSES. ──
    let note = d.set_min_burn_note(owner_id, RAISED_MIN)?;
    let acct = d
        .commit_admin(owner_id, note, "set_min_burn_size(raise)", |a| {
            min_burn(a).map(|m| m == RAISED_MIN).unwrap_or(false)
        })
        .await?;
    let c2_after_raise = min_burn(&acct)?;
    let below = d.burn_note(BURN_BELOW, 0x01)?;
    let c2_below = d.probe_consume(below).await?;
    let note = d.set_min_burn_note(owner_id, LOWERED_MIN)?;
    let acct = d
        .commit_admin(owner_id, note, "set_min_burn_size(lower)", |a| {
            min_burn(a).map(|m| m == LOWERED_MIN).unwrap_or(false)
        })
        .await?;
    let c2_after_lower = min_burn(&acct)?;
    let at_min = d.burn_note(LOWERED_MIN, 0x02)?;
    let c2_at = d.probe_consume(at_min).await?;
    let c2 = C2MinBurn {
        raised_min: RAISED_MIN,
        committed_after_raise: c2_after_raise,
        burn_below_raised: c2_below,
        lowered_min: LOWERED_MIN,
        committed_after_lower: c2_after_lower,
        burn_at_lowered: c2_at,
    };

    // ── C1 (part 2) — rotation A→B: disable A, enable B; mint by A REJECTS, by B ACCEPTS. ──
    let note = d.set_attester_note(owner_id, a_commitment, 0)?;
    let acct = d
        .commit_admin(owner_id, note, "set_attester(A, enabled=0)", |a| {
            attester_marker(a, a_commitment).map(|m| m == crate::observations_cf::MARKER_CLEAR).unwrap_or(false)
        })
        .await?;
    let c1_a_marker_after_rotate = attester_marker(&acct, a_commitment)?;
    let note = d.set_attester_note(owner_id, b_commitment, 1)?;
    let acct = d
        .commit_admin(owner_id, note, "set_attester(B, enabled=1)", |a| {
            attester_marker(a, b_commitment).map(|m| m == crate::observations_cf::MARKER_SET).unwrap_or(false)
        })
        .await?;
    let c1_b_marker_after_rotate = attester_marker(&acct, b_commitment)?;
    let mint_a = d.mint_note(false, recipient, PROBE_MINT_UNITS, 0x31)?;
    let c1_mint_by_a = d.probe_consume(mint_a).await?;
    let mint_b = d.mint_note(true, recipient, PROBE_MINT_UNITS, 0x32)?;
    let c1_mint_by_b = d.probe_consume(mint_b).await?;
    let c1 = C1SetAttester {
        a_marker_after_enable: c1_a_marker_after_enable,
        a_marker_after_rotate: c1_a_marker_after_rotate,
        b_marker_after_rotate: c1_b_marker_after_rotate,
        mint_by_a: c1_mint_by_a,
        mint_by_b: c1_mint_by_b,
    };

    // ── C4 — pause (DOM_PAUSER) halts mint AND burn; owner setters still commit (F6); unpause. ──
    let note = d.pause_note(pauser_id)?;
    let acct = d
        .commit_admin(pauser_id, note, "pause", |a| {
            is_paused(a).map(|p| p == crate::observations_cf::MARKER_SET).unwrap_or(false)
        })
        .await?;
    let c4_paused = is_paused(&acct)?;
    let m = d.mint_note(true, recipient, PROBE_MINT_UNITS, 0x41)?;
    let c4_mint_paused = d.probe_consume(m).await?;
    let b = d.burn_note(LOWERED_MIN, 0x03)?;
    let c4_burn_paused = d.probe_consume(b).await?;
    // F6: the owner's set_attester (re-enable A) still commits WHILE PAUSED.
    let note = d.set_attester_note(owner_id, a_commitment, 1)?;
    let acct = d
        .commit_admin(owner_id, note, "owner set_attester WHILE PAUSED (F6)", |a| {
            attester_marker(a, a_commitment).map(|m| m == crate::observations_cf::MARKER_SET).unwrap_or(false)
        })
        .await?;
    let c4_owner_attester_paused = attester_marker(&acct, a_commitment)?;
    // F6: the owner's set_min_burn_size still commits WHILE PAUSED.
    let note = d.set_min_burn_note(owner_id, F6_MIN)?;
    let acct = d
        .commit_admin(owner_id, note, "owner set_min_burn WHILE PAUSED (F6)", |a| {
            min_burn(a).map(|m| m == F6_MIN).unwrap_or(false)
        })
        .await?;
    let c4_owner_min_paused = min_burn(&acct)?;
    // Unpause; a mint (attested by B) then ACCEPTS.
    let note = d.unpause_note(pauser_id)?;
    let acct = d
        .commit_admin(pauser_id, note, "unpause", |a| {
            is_paused(a).map(|p| p == crate::observations_cf::MARKER_CLEAR).unwrap_or(false)
        })
        .await?;
    let c4_unpaused = is_paused(&acct)?;
    let m = d.mint_note(true, recipient, PROBE_MINT_UNITS, 0x42)?;
    let c4_mint_after = d.probe_consume(m).await?;
    let c4 = C4Pause {
        is_paused_after_pause: c4_paused,
        mint_while_paused: c4_mint_paused,
        burn_while_paused: c4_burn_paused,
        owner_set_attester_while_paused_marker: c4_owner_attester_paused,
        owner_set_min_burn_while_paused: c4_owner_min_paused,
        is_paused_after_unpause: c4_unpaused,
        mint_after_unpause: c4_mint_after,
    };

    // ── C5 — DOM_MANAGER grants DOM_PAUSER to new_pauser (who can pause), then revokes it. ──
    let new_pauser = d.actors.new_pauser.id();
    let note = d.grant_pauser_note(new_pauser)?;
    let acct = d
        .commit_admin(manager_id, note, "grant_role(DOM_PAUSER, new_pauser)", |a| {
            role_membership(a, &pauser_role, new_pauser).map(|m| m == crate::observations_cf::MARKER_SET).unwrap_or(false)
        })
        .await?;
    let c5_grant = role_membership(&acct, &pauser_role, new_pauser)?;
    // The new pauser can pause (capability proven).
    let note = d.pause_note(new_pauser)?;
    let acct = d
        .commit_admin(new_pauser, note, "new_pauser pause", |a| {
            is_paused(a).map(|p| p == crate::observations_cf::MARKER_SET).unwrap_or(false)
        })
        .await?;
    let c5_new_pause = is_paused(&acct)?;
    // Restore (unpause) so later state is clean.
    let note = d.unpause_note(new_pauser)?;
    d.commit_admin(new_pauser, note, "new_pauser unpause (restore)", |a| {
        is_paused(a).map(|p| p == crate::observations_cf::MARKER_CLEAR).unwrap_or(false)
    })
    .await?;
    // Revoke; the revoked account can no longer pause.
    let note = d.revoke_pauser_note(new_pauser)?;
    let acct = d
        .commit_admin(manager_id, note, "revoke_role(DOM_PAUSER, new_pauser)", |a| {
            role_membership(a, &pauser_role, new_pauser).map(|m| m == crate::observations_cf::MARKER_CLEAR).unwrap_or(false)
        })
        .await?;
    let c5_revoke = role_membership(&acct, &pauser_role, new_pauser)?;
    let revoked_pause = d.pause_note(new_pauser)?;
    let c5_revoked_pause = d.probe_consume(revoked_pause).await?;
    let c5 = C5RoleRotation {
        new_pauser_membership_after_grant: c5_grant,
        is_paused_after_new_pauser_pause: c5_new_pause,
        new_pauser_membership_after_revoke: c5_revoke,
        revoked_pauser_pause: c5_revoked_pause,
    };

    // ── C6 — non-authorized-sender negatives (client-side trap + node-side stays unconsumed). ──
    let stranger = d.actors.holder.id();
    let c6 = run_c6(&mut d, stranger, a_commitment).await?;

    // ── Row F — the auth boundary. ──
    let f = run_row_f(&mut d, stranger).await?;

    // Teardown.
    if !cfg.keep_stack {
        stack.stop().context("stopping the node stack")?;
    }

    Ok(RowsCfObservations {
        main_commit,
        faucet_id: faucet_id.to_string(),
        c1,
        c2,
        c3,
        c4,
        c5,
        c6,
        f,
    })
}

/// The C6 negatives: an owner-gated op from a non-owner, a second owner-gated op from a non-owner,
/// and a pause from a non-DOM_PAUSER. Each: client-side execute traps at the proc gate, AND the
/// emitted (allowlisted, routed) note stays UNCONSUMED after a bounded watch (the ntx-builder
/// attempted and failed the same gate).
async fn run_c6(d: &mut Driver, stranger: AccountId, a_commitment: Word) -> Result<Vec<AdminGateReject>> {
    // Build the three negative notes (sent by the stranger).
    let n_attester = d.set_attester_note(stranger, a_commitment, 1)?;
    let n_max = d.set_max_supply_note(stranger, raw_for_units(CAP_UNITS))?;
    let n_pause = d.pause_note(stranger)?;

    // Emit each (commit on-chain) so the ntx-builder can attempt + fail them, and record the emit tip.
    let emit_block = d.emit(stranger, n_attester.clone()).await?;
    d.emit(stranger, n_max.clone()).await?;
    d.emit(stranger, n_pause.clone()).await?;

    // Client-side execute each → the proc-gate trap (the primary reject proof).
    let v_attester = d.probe_consume(n_attester.clone()).await?;
    let v_max = d.probe_consume(n_max.clone()).await?;
    let v_pause = d.probe_consume(n_pause.clone()).await?;

    // Node-side: after a bounded window none of the three was consumed.
    d.wait_blocks_past(emit_block, UNCONSUMED_WATCH_BLOCKS).await?;
    let u_attester = !d.note_consumed(&n_attester).await?;
    let u_max = !d.note_consumed(&n_max).await?;
    let u_pause = !d.note_consumed(&n_pause).await?;

    Ok(vec![
        AdminGateReject {
            op: "set_attester".to_string(),
            sender: "non-owner".to_string(),
            expected_gate: ERR_NOT_OWNER.to_string(),
            verdict: v_attester,
            note_unconsumed: u_attester,
        },
        AdminGateReject {
            op: "set_max_supply".to_string(),
            sender: "non-owner".to_string(),
            expected_gate: ERR_NOT_OWNER.to_string(),
            verdict: v_max,
            note_unconsumed: u_max,
        },
        AdminGateReject {
            op: "pause".to_string(),
            sender: "non-DOM_PAUSER".to_string(),
            expected_gate: ERR_LACKS_ROLE.to_string(),
            verdict: v_pause,
            note_unconsumed: u_pause,
        },
    ])
}

/// Row F: the faucet consuming a stock P2ID note (non-allowlisted script root) rejects; a tx-script
/// transaction against the faucet rejects (empty tx-script allowlist).
async fn run_row_f(d: &mut Driver, sender: AccountId) -> Result<RowF> {
    let faucet_id = d.faucet_id;
    // A stock P2ID note targeting the faucet — its script root is NOT in the note allowlist.
    let p2id = P2idNote::create(
        sender,
        faucet_id,
        Vec::<Asset>::new(),
        NoteType::Public,
        NoteAttachments::new(vec![]).context("empty P2ID attachments")?,
        d.rng(),
    )
    .context("building the stock P2ID note")?;
    let non_allowlisted_note = d.probe_consume(p2id).await?;

    // A trivial tx-script — the empty tx-script allowlist rejects any tx-script transaction.
    let assembler = TransactionKernel::assembler();
    let program = assembler
        .assemble_program("begin push.1 drop end")
        .map_err(|e| anyhow::anyhow!("assembling the trivial tx-script: {e}"))?;
    let tx_script = TransactionScript::new(program);
    let tx_script_verdict = d.probe_tx_script(tx_script).await?;

    Ok(RowF { non_allowlisted_note, tx_script: tx_script_verdict })
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
