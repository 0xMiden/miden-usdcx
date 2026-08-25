//! The LNV-1 row-A driver: one deterministic flow against a fresh local node, producing the
//! [`RowsAbObservations`] the assertion suite judges.
//!
//! Flow (path C — client-side build+prove+submit):
//!
//! 1. Bootstrap + start the fresh four-service stack ([`crate::stack`]).
//! 2. Assemble the client ([`crate::client`]) and the actors ([`crate::actors`]).
//! 3. Build the production faucet account locally ([`crate::deploy`]) against the chain's own fee
//!    parameters — its id exists before any chain contact, and all four domain-config fields are
//!    BUILD-SEEDED into it.
//! 4. **Deploy = the faucet's first transaction.** A scriptless, noteless request under
//!    `AuthNetworkAccount` authorizes trivially and bumps the new account's nonce 0 → 1, which is
//!    what materializes the faucet on chain.
//! 5. Fetch the account from the NODE (`GetAccount`) → the row-A observations.
//! 6. Tear the stack down (unless `keep_stack`), leaving logs + evidence under the run root.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use miden_client::store::TransactionFilter;
use miden_client::transaction::{TransactionId, TransactionRequestBuilder, TransactionStatus};

use crate::actors::create_actors;
use crate::client::{build_client, node_fee_parameters, os_seed, HarnessClient};
use crate::config::RunConfig;
use crate::deploy::build_faucet_account;
use crate::observations::RowsAbObservations;
use crate::stack::NodeStack;

/// Bounded wait for a submitted transaction to commit (local node; proving is client-side so
/// this only covers batching + block production).
const TX_COMMIT_TIMEOUT: Duration = Duration::from_secs(180);

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

/// Runs the full LNV-1 row-A flow on its own fresh stack. See the module docs for the step
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

/// Runs the row-A flow against an ALREADY-RUNNING stack (the LNV-5 consolidated run boots ONE
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

    // 3. The production faucet account, locally composed (nonce 0, seed embedded; all four
    //    domain-config fields BUILD-SEEDED from the run params, priced against the chain's own
    //    fee parameters).
    let fee_parameters = node_fee_parameters(&hc.rpc).await?;
    let faucet = build_faucet_account(
        owner_id,
        actors.pauser.id(),
        actors.manager.id(),
        actors.blk_manager.id(),
        cfg.max_supply,
        &cfg.domain_params,
        fee_parameters,
        os_seed(),
    )?;
    let faucet_id = faucet.id();

    // 4. Deploy: the faucet's FIRST transaction (path C). It consumes no notes and runs no script,
    //    so `AuthNetworkAccount` authorizes it and increments the new account's nonce 0 → 1.
    hc.client
        .add_account(&faucet, false)
        .await
        .context("registering the new faucet account with the client")?;
    let deploy = TransactionRequestBuilder::new()
        .build()
        .context("building the deploy request")?;
    let deploy_tx = hc
        .client
        .submit_new_transaction(faucet_id, deploy)
        .await
        .context("submitting the faucet deploy transaction")?;
    let deploy_block = wait_for_tx_commit(&mut hc, deploy_tx).await?;

    // 5. Node-truth fetch (GetAccount) for row A.
    let deployed = hc
        .rpc
        .get_account_details(faucet_id)
        .await
        .map_err(|e| anyhow::anyhow!("GetAccount({faucet_id}) after deploy: {e}"))?;

    Ok(RowsAbObservations {
        main_commit,
        faucet_id,
        deployed,
        deploy_tx_id: deploy_tx.to_string(),
        deploy_block,
        owner_id,
        domain_params: cfg.domain_params.clone(),
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
