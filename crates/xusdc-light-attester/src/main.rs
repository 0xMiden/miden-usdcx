use anyhow::{Context, Result};
use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use xusdc_attester::config::{Config, Invocation};
use xusdc_attester::service::{run_command, AttesterService};

#[tokio::main]
async fn main() -> Result<()> {
    let _telemetry = usdcx_telemetry::init("xusdc-attester")?;
    let invocation = Invocation::parse();
    if let Some(command) = invocation.command {
        return run_command(command);
    }
    let config = Config::try_from(invocation.run.context("missing run arguments")?)
        .context("invalid configuration")?;
    let miden_rpc_url = config.miden_rpc_url().clone();
    let service = AttesterService::start(config).await?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;
    let shutdown = CancellationToken::new();
    let signal_token = shutdown.clone();
    let signal_task = tokio::spawn(async move {
        tokio::select! {
            Some(()) = sigterm.recv() => {}
            Ok(()) = tokio::signal::ctrl_c() => {}
            else => return,
        }
        signal_token.cancel();
    });
    warn!(%miden_rpc_url, "attester started");
    let result = service.run(shutdown).await;
    signal_task.abort();
    result
}
