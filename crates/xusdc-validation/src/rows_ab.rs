//! The LNV-1 row-A/B driver: one deterministic flow against a fresh local node, producing the
//! [`RowsAbObservations`] the assertion suite judges.
//!
//! Flow (path C — client-side build+prove+submit; discovered mechanics recorded in
//! `VALIDATION-RECORD.md` §3):
//!
//! 1. Bootstrap + start the fresh four-process stack ([`crate::stack`]).
//! 2. Assemble the client ([`crate::client`]) and the actors ([`crate::actors`]).
//! 3. Build the production faucet account locally ([`crate::deploy`]) — its id exists before any
//!    chain contact.
//! 4. The OWNER emits `domain_init` note #1 (creator-committed domain-config params). This is the owner
//!    wallet's first transaction, which also materializes the owner on-chain.
//! 5. **Deploy = the faucet's first transaction consuming that note.** At v0.15.1 the user RPC
//!    admits network-account transactions ONLY at first deployment, so `domain_init` rides the
//!    deploy transaction — this IS "the first admin note" realized against the real node. The
//!    scriptless request consumes note #1 under `AuthNetworkAccount` (allowlisted note, new
//!    account → nonce 0→1).
//! 6. Fetch the account from the NODE (`GetAccount`) → row-A + row-B read-back observations.
//! 7. The OWNER emits `domain_init` note #2 (everywhere-different params) and the harness
//!    attempts the faucet-side consumption client-side: the kernel must trap the init-once gate
//!    (`ERR_XRESERVE_DOMAIN_REINIT`) during execution — no provable second-init transaction
//!    exists. The error text is captured verbatim.
//! 8. Watch a bounded window: note #2 must stay unconsumed on-chain (checked against the NODE's
//!    nullifier set — nothing, including the node's own ntx-builder, which sees an allowlisted
//!    note routed at a network account, may execute it), and the re-fetched account state must be
//!    unchanged on every asserted surface.
//! 9. Tear the stack down (unless `keep_stack`), leaving logs + evidence under the run root.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use miden_client::store::TransactionFilter;
use miden_client::transaction::{TransactionId, TransactionRequestBuilder, TransactionStatus};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Note;
use xusdc_encoding::note::xreserve_admin::XReserveDomainInitNote;

use crate::actors::create_actors;
use crate::client::{build_client, os_seed, HarnessClient};
use crate::config::{DomainParams, RunConfig};
use crate::deploy::build_faucet_account;
use crate::observations::RowsAbObservations;
use crate::stack::NodeStack;

/// Bounded wait for a submitted transaction to commit (local node; proving is client-side so
/// this only covers batching + block production).
const TX_COMMIT_TIMEOUT: Duration = Duration::from_secs(180);
/// How many additional blocks to watch for an (illegal) consumption of the second note.
const REINIT_WATCH_BLOCKS: u32 = 3;
/// Bounded wait for the watch window's blocks to be produced.
const WATCH_TIMEOUT: Duration = Duration::from_secs(180);

/// Polls `sync_state` until `tx_id` is committed; returns the commit block number.
async fn wait_for_tx_commit(hc: &mut HarnessClient, tx_id: TransactionId) -> Result<u32> {
    let deadline = Instant::now() + TX_COMMIT_TIMEOUT;
    loop {
        hc.client
            .sync_state()
            .await
            .context("syncing while waiting for a transaction")?;
        let record = hc
            .client
            .get_transactions(TransactionFilter::Ids(vec![tx_id]))
            .await
            .context("querying the transaction status")?
            .pop()
            .with_context(|| format!("transaction {tx_id} is not tracked by the client"))?;
        match record.status {
            TransactionStatus::Committed { block_number, .. } => {
                return Ok(block_number.as_u32());
            }
            TransactionStatus::Discarded(cause) => {
                bail!("transaction {tx_id} was DISCARDED: {cause:?}");
            }
            TransactionStatus::Pending => {
                if Instant::now() > deadline {
                    bail!("transaction {tx_id} did not commit within {TX_COMMIT_TIMEOUT:?}");
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

/// Waits until the chain tip advances `blocks` past `from_block` (bounded by [`WATCH_TIMEOUT`]).
async fn wait_for_blocks_past(hc: &mut HarnessClient, from_block: u32, blocks: u32) -> Result<u32> {
    let deadline = Instant::now() + WATCH_TIMEOUT;
    loop {
        hc.client
            .sync_state()
            .await
            .context("syncing while waiting for blocks")?;
        let height = hc
            .client
            .get_sync_height()
            .await
            .context("reading the sync height")?;
        if height.as_u32() >= from_block + blocks {
            return Ok(height.as_u32());
        }
        if Instant::now() > deadline {
            bail!(
                "the chain did not advance {blocks} blocks past {from_block} within \
                 {WATCH_TIMEOUT:?} (tip {height})"
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Node-truth consumption check: is the note's nullifier in the node's spent set?
async fn note_consumed_on_chain(hc: &HarnessClient, note: &Note) -> Result<bool> {
    use miden_client::rpc::NodeRpcClient;
    let nullifier = note.nullifier();
    let heights = hc
        .rpc
        .get_nullifier_commit_heights(BTreeSet::from([nullifier]), BlockNumber::from(0u32))
        .await
        .map_err(|e| anyhow::anyhow!("querying nullifier commit heights: {e}"))?;
    Ok(heights.get(&nullifier).copied().flatten().is_some())
}

/// Builds a `domain_init` note from `params` (owner-sent, faucet-targeted).
fn domain_init_note(
    hc: &mut HarnessClient,
    owner: miden_protocol::account::AccountId,
    faucet: miden_protocol::account::AccountId,
    params: &DomainParams,
) -> Result<Note> {
    XReserveDomainInitNote::create(
        owner,
        faucet,
        params.domain,
        params.source_domain,
        &params.xreserve_contract,
        params.identifier_word(),
        hc.client.rng(),
    )
    .context("building a domain_init note")
}

/// Runs the full LNV-1 row-A/B flow on its own fresh stack. See the module docs for the step
/// list.
pub async fn run_rows_ab(cfg: &RunConfig) -> Result<RowsAbObservations> {
    // 1. Fresh stack.
    let mut stack = NodeStack::bootstrap_and_start(&cfg.stack)
        .context("bootstrapping + starting the local node stack")?;
    if cfg.keep_stack {
        stack.keep_on_drop();
    }

    let obs = run_rows_ab_on(cfg, "main").await?;

    // Teardown (Drop also covers the error paths above).
    if !cfg.keep_stack {
        stack.stop().context("stopping the node stack")?;
    }
    Ok(obs)
}

/// Runs the row-A/B flow against an ALREADY-RUNNING stack (the LNV-5 consolidated run boots ONE
/// stack and drives every slice on it in matrix order). `client_label` namespaces this slice's
/// client store, keystore, and actor secrets under `<run_root>/client-<label>/` so composed
/// slices cannot collide. No stack lifecycle happens here.
pub async fn run_rows_ab_on(cfg: &RunConfig, client_label: &str) -> Result<RowsAbObservations> {
    use miden_client::rpc::NodeRpcClient;

    let main_commit = git_head_commit();

    // 2. Client + actors.
    let mut hc = build_client(&cfg.stack, client_label).await?;
    hc.client.sync_state().await.context("initial sync")?;
    let actor_root = cfg.stack.run_root.join(format!("client-{client_label}"));
    let actors = create_actors(&mut hc, &actor_root).await?;
    let owner_id = actors.owner.id();

    // 3. The production faucet account, locally composed (nonce 0, seed embedded).
    let faucet = build_faucet_account(
        owner_id,
        actors.pauser.id(),
        actors.manager.id(),
        cfg.max_supply,
        os_seed(),
    )?;
    let faucet_id = faucet.id();

    // 4. Owner emits domain_init #1 (also the owner wallet's materializing first transaction).
    let note1 = domain_init_note(&mut hc, owner_id, faucet_id, &cfg.domain_params)?;
    let emit1 = TransactionRequestBuilder::new()
        .own_output_notes(vec![note1.clone()])
        .build()
        .context("building the owner's first emit request")?;
    let emit1_tx = hc
        .client
        .submit_new_transaction(owner_id, emit1)
        .await
        .context("submitting the owner's domain_init #1 emit transaction")?;
    wait_for_tx_commit(&mut hc, emit1_tx).await?;

    // 5. Deploy: the faucet's FIRST transaction consumes the first admin note (path C; the
    //    v0.15.1 user RPC admits network-account transactions only at first deployment).
    hc.client
        .add_account(&faucet, false)
        .await
        .context("registering the new faucet account with the client")?;
    let deploy = TransactionRequestBuilder::new()
        .input_notes(vec![(note1.clone(), None)])
        .build()
        .context("building the deploy request")?;
    let deploy_tx = hc
        .client
        .submit_new_transaction(faucet_id, deploy)
        .await
        .context("submitting the faucet deploy (+domain_init) transaction")?;
    let deploy_block = wait_for_tx_commit(&mut hc, deploy_tx).await?;

    // 6. Node-truth fetch (GetAccount) for rows A + B.
    let deployed = hc
        .rpc
        .get_account_details(faucet_id)
        .await
        .map_err(|e| anyhow::anyhow!("GetAccount({faucet_id}) after deploy: {e}"))?;

    // 7. Owner emits domain_init #2 (everywhere-different params), then the harness attempts the
    //    faucet-side consumption CLIENT-SIDE: the init-once gate must trap during execution.
    let note2 = domain_init_note(&mut hc, owner_id, faucet_id, &cfg.reinit_params)?;
    let emit2 = TransactionRequestBuilder::new()
        .own_output_notes(vec![note2.clone()])
        .build()
        .context("building the owner's second emit request")?;
    let emit2_tx = hc
        .client
        .submit_new_transaction(owner_id, emit2)
        .await
        .context("submitting the owner's domain_init #2 emit transaction")?;
    let emit2_block = wait_for_tx_commit(&mut hc, emit2_tx).await?;

    let reinit = TransactionRequestBuilder::new()
        .input_notes(vec![(note2.clone(), None)])
        .build()
        .context("building the reinit-attempt request")?;
    let reinit_error = match hc.client.execute_transaction(faucet_id, reinit).await {
        // A successful execution would be the init-once gate FAILING — the assertion layer
        // judges that; the driver only observes.
        Ok(_) => None,
        Err(e) => Some(format!("{e:?}")),
    };

    // 8. Watch window: the second note must stay unconsumed (the running ntx-builder sees an
    //    allowlisted, routed note — the MASM gate is what must stop it), and the account state
    //    must be unchanged.
    wait_for_blocks_past(&mut hc, emit2_block, REINIT_WATCH_BLOCKS).await?;
    let second_note_consumed = note_consumed_on_chain(&hc, &note2).await?;
    let after_reinit =
        hc.rpc.get_account_details(faucet_id).await.map_err(|e| {
            anyhow::anyhow!("GetAccount({faucet_id}) after the reinit attempt: {e}")
        })?;

    Ok(RowsAbObservations {
        main_commit,
        faucet_id,
        deployed,
        deploy_tx_id: deploy_tx.to_string(),
        deploy_block,
        owner_id,
        domain_params: cfg.domain_params.clone(),
        reinit_params: cfg.reinit_params.clone(),
        first_note_id: note1.id().to_string(),
        second_note_id: note2.id().to_string(),
        reinit_error,
        after_reinit,
        second_note_consumed,
    })
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
