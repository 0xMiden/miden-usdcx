//! Starts both bridge services and stops them together on a signal or when either one exits.

use std::future::Future;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use tokio_util::sync::CancellationToken;
use tracing::info;
use usdcx_telemetry::{cancel_on_signal, stop_within, SHUTDOWN_TIMEOUT};
use xreserve_deposit_relayer::{miden::NodeClient, Relayer};
use xusdc_attester::service::AttesterService;

use crate::config::Config;

pub(crate) async fn run(config: Config) -> Result<()> {
    let shutdown = CancellationToken::new();
    cancel_on_signal(shutdown.clone())?;

    // No deposit work starts until the attester and both KMS signers pass startup.
    let attester = AttesterService::start(config.attester).await?;
    info!(service = "attester", "startup checks passed");
    let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
    // The Miden client's futures are not `Send`, so the relayer cannot be spawned as a task.
    // It runs on a blocking thread of its own, driven by this runtime, which also keeps proving a
    // mint transaction from stalling the attester.
    let relayer_shutdown = shutdown.clone();
    let runtime = tokio::runtime::Handle::current();
    let relayer = tokio::task::spawn_blocking(move || {
        runtime.block_on(async move {
            let node = NodeClient::new(&config.relayer)
                .await
                .context("connecting relayer to Miden")?;
            let relayer = Relayer::new(config.relayer, node)?;
            info!(service = "relayer", "startup checks passed");
            let _ = ready_sender.send(());
            relayer.run_until(relayer_shutdown).await
        })
    });
    let relayer = async { relayer.await.context("relayer task failed")? };
    if ready_receiver.await.is_err() {
        // The relayer only drops its readiness sender without sending when its startup fails.
        return relayer.await.context("relayer startup failed");
    }
    info!("deposit relayer and withdrawal attester started");

    supervise(
        attester.run(shutdown.clone()),
        relayer,
        shutdown,
        SHUTDOWN_TIMEOUT,
    )
    .await
}

/// Runs both services until both have stopped. Either one stopping requests shutdown of the other,
/// and one that stops before shutdown was requested is an error. If they have not both stopped
/// within `timeout` of shutdown being requested, the process exits with a failure status.
async fn supervise(
    attester: impl Future<Output = Result<()>> + 'static,
    relayer: impl Future<Output = Result<()>>,
    shutdown: CancellationToken,
    timeout: Duration,
) -> Result<()> {
    // On its own task, an attester panic becomes an error that stops the relayer under the
    // shutdown deadline, instead of unwinding past it while the runtime waits on the relayer.
    // The attester's store is not thread-safe, so the task stays on this thread.
    let tasks = tokio::task::LocalSet::new();
    let attester = tasks.spawn_local(attester);
    let attester = async { attester.await.context("attester task failed")? };
    let services = tasks.run_until(async {
        tokio::join!(
            stop_peer_on_exit("attester", attester, &shutdown),
            stop_peer_on_exit("relayer", relayer, &shutdown),
        )
    });
    // The relayer can wait on a chain confirmation indefinitely if blocks stop.
    let (attester, relayer) = stop_within(services, &shutdown, timeout).await;
    let result = attester.and(relayer);
    info!(success = result.is_ok(), "bridge shutdown complete");
    result
}

async fn stop_peer_on_exit(
    name: &str,
    service: impl Future<Output = Result<()>>,
    shutdown: &CancellationToken,
) -> Result<()> {
    let result = service.await;
    let shutdown_requested = shutdown.is_cancelled();
    if !shutdown_requested {
        info!(service = name, "service exited; stopping its peer");
        shutdown.cancel();
    }
    result.with_context(|| format!("{name} failed"))?;
    ensure!(shutdown_requested, "{name} stopped unexpectedly");
    Ok(())
}

#[cfg(test)]
#[path = "tests/supervisor.rs"]
mod tests;
