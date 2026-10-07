//! Assembles and starts the deposit relayer.
//!
//! Node access, account tracking and local progress persistence are checked before the first Circle
//! request. Installing the relayer account's signing key remains an operator prerequisite.

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};

use xreserve_deposit_relayer::config::Config;
use xreserve_deposit_relayer::miden::NodeClient;
use xreserve_deposit_relayer::Relayer;

#[tokio::main]
async fn main() -> Result<()> {
    let _telemetry = usdcx_telemetry::init("xreserve-deposit-relayer")?;

    let config = Config::parse();

    let miden = NodeClient::new(&config)
        .await
        .context("connecting to miden")?;

    let relayer = Relayer::new(config, miden)?;
    let mut terminate =
        signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;

    // A signal ends `main` instead of killing the process, so the telemetry guard sends the spans
    // that are still buffered. The page in flight is abandoned, as the kill would have abandoned
    // it, and the next start resumes at it.
    tokio::select! {
        result = relayer.run() => result,
        _ = terminate.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
    }
}
