//! Assembles and starts the deposit relayer.
//!
//! Node access, account tracking and local progress persistence are checked before the first Circle
//! request. Installing the relayer account's signing key remains an operator prerequisite.

use anyhow::{Context, Result};
use clap::Parser;
use tokio_util::sync::CancellationToken;

use xreserve_deposit_relayer::config::Config;
use xreserve_deposit_relayer::Relayer;

#[tokio::main]
async fn main() -> Result<()> {
    let _telemetry = usdcx_telemetry::init("xreserve-deposit-relayer")?;

    let config = Config::parse();

    let relayer = Relayer::start(config).await?;
    let shutdown = CancellationToken::new();
    usdcx_telemetry::cancel_on_signal(shutdown.clone())?;

    // A signal lets the page in flight finish and save its progress, and `main` then returns so the
    // telemetry guard sends the spans that are still buffered.
    usdcx_telemetry::stop_within(
        relayer.run_until(shutdown.clone()),
        &shutdown,
        usdcx_telemetry::SHUTDOWN_TIMEOUT,
    )
    .await
}
