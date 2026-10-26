use anyhow::{Context, Result};
use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use xusdc_attester::config::{Config, Invocation};
use xusdc_attester::service::{run_command, AttesterService};

#[tokio::main]
async fn main() -> Result<()> {
    let invocation = Invocation::parse();
    let _telemetry = usdcx_telemetry::init("xusdc-attester", &invocation.telemetry)?;
    if let Some(command) = invocation.command {
        return run_command(command).await;
    }
    // Installed before startup so that a signal during it still lets `main` return and the
    // telemetry guard send the buffered spans. Startup then finishes under the same time limit as
    // the work in flight, and the attester sees the shutdown before its first cycle.
    let shutdown = CancellationToken::new();
    usdcx_telemetry::cancel_on_signal(shutdown.clone())?;
    let config = Config::try_from(invocation.run.context("missing run arguments")?)
        .context("invalid configuration")?;
    let miden_rpc_url = config.miden_rpc_url().clone();
    usdcx_telemetry::stop_within(
        async {
            let service = AttesterService::start(config).await?;
            warn!(%miden_rpc_url, "attester started");
            service.run(shutdown.clone()).await
        },
        &shutdown,
        usdcx_telemetry::SHUTDOWN_TIMEOUT,
    )
    .await
}
