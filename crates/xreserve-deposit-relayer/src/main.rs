//! Assembles and starts the deposit relayer.
//!
//! Node access, account tracking and local progress persistence are checked before the first Circle
//! request. Installing the relayer account's signing key remains an operator prerequisite.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use xreserve_deposit_relayer::config::Config;
use xreserve_deposit_relayer::miden::NodeClient;
use xreserve_deposit_relayer::Relayer;

/// How long a signal waits for the page in flight to finish before the process exits anyway.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[tokio::main]
async fn main() -> Result<()> {
    let _telemetry = usdcx_telemetry::init("xreserve-deposit-relayer")?;

    let config = Config::parse();

    let miden = NodeClient::new(&config)
        .await
        .context("connecting to miden")?;

    let relayer = Relayer::new(config, miden)?;
    let shutdown = CancellationToken::new();
    cancel_on_signal(shutdown.clone())?;

    // A signal lets the page in flight finish and save its progress, and `main` then returns so the
    // telemetry guard sends the spans that are still buffered.
    let deadline = async {
        shutdown.cancelled().await;
        info!("stopping the relayer");
        tokio::time::sleep(SHUTDOWN_TIMEOUT).await;
    };
    tokio::select! {
        result = relayer.run_until(shutdown.clone()) => result,
        // Waiting for a mint transaction can go on indefinitely if the chain stops producing blocks.
        () = deadline => {
            error!(
                timeout = %humantime::format_duration(SHUTDOWN_TIMEOUT),
                "relayer shutdown did not finish in time; terminating the process"
            );
            // Exiting skips the telemetry guard, so send the buffered spans first.
            usdcx_telemetry::flush();
            std::process::exit(1);
        }
    }
}

/// Requests shutdown on the first SIGTERM or SIGINT.
fn cancel_on_signal(shutdown: CancellationToken) -> Result<()> {
    let mut terminate =
        signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    tokio::spawn(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        info!(reason = "process signal", "shutdown requested");
        shutdown.cancel();
    });
    Ok(())
}
