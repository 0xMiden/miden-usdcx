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
    let shutdown = CancellationToken::new();
    usdcx_telemetry::cancel_on_signal(shutdown.clone())?;
    warn!(%miden_rpc_url, "attester started");
    usdcx_telemetry::stop_within(
        service.run(shutdown.clone()),
        &shutdown,
        usdcx_telemetry::SHUTDOWN_TIMEOUT,
    )
    .await
}
