//! Assembles and starts the deposit relayer.
//!
//! Node access, account tracking and local progress persistence are checked before the first Circle
//! request. Installing the relayer account's signing key remains an operator prerequisite.

use anyhow::{Context, Result};
use clap::Parser;
use tokio_util::sync::CancellationToken;

use xreserve_deposit_relayer::config::Config;
use xreserve_deposit_relayer::miden::NodeClient;
use xreserve_deposit_relayer::Relayer;

#[tokio::main]
async fn main() -> Result<()> {
    let _telemetry = usdcx_telemetry::init("xreserve-deposit-relayer")?;

    let config = Config::parse();

    // A signal lets the page in flight finish and save its progress, and `main` then returns so the
    // telemetry guard sends the spans that are still buffered. The handler is installed before
    // startup, which finishes under the same time limit, and the relayer then stops before its
    // first page.
    let shutdown = CancellationToken::new();
    usdcx_telemetry::cancel_on_signal(shutdown.clone())?;
    usdcx_telemetry::stop_within(
        async { start(config).await?.run_until(shutdown.clone()).await },
        &shutdown,
        usdcx_telemetry::SHUTDOWN_TIMEOUT,
    )
    .await
}

async fn start(config: Config) -> Result<Relayer<NodeClient>> {
    let miden = NodeClient::new(&config)
        .await
        .context("connecting to miden")?;
    Relayer::new(config, miden)
}
