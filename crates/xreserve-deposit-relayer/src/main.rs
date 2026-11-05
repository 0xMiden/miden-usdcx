//! Assembles and starts the deposit relayer.
//!
//! Node access, account tracking and local progress persistence are checked before the first Circle
//! request. Installing the relayer account's signing key remains an operator prerequisite.

use anyhow::Result;
use clap::Parser;
use tokio_util::sync::CancellationToken;

use usdcx_telemetry::TelemetryArgs;
use xreserve_deposit_relayer::config::Config;
use xreserve_deposit_relayer::initialize_state_at_current_head;
use xreserve_deposit_relayer::Relayer;

#[derive(Parser)]
#[command(name = "xreserve-deposit-relayer")]
#[command(about = "Relays Circle xReserve deposit attestations to the xUSDC faucet")]
struct Cli {
    #[command(flatten)]
    config: Config,
    #[command(flatten)]
    telemetry: TelemetryArgs,
    /// Create a NEW progress file at Circle's current head, excluding all earlier feed entries.
    /// Run before any new deposit; never use this to replace existing progress.
    #[arg(long, conflicts_with = "require_head_watermark")]
    init_state_at_current_head: bool,
    /// Stop unless the saved completed-scan watermark is present in each fetched head page.
    #[arg(long)]
    require_head_watermark: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli {
        config,
        telemetry,
        init_state_at_current_head,
        require_head_watermark,
    } = Cli::parse();
    let _telemetry = usdcx_telemetry::init("xreserve-deposit-relayer", &telemetry)?;

    if init_state_at_current_head {
        let watermark = initialize_state_at_current_head(&config).await?;
        println!(
            "initialized {} at Circle head {watermark}",
            config.state_file.display()
        );
        return Ok(());
    }

    // A signal lets the page in flight finish and save its progress, and `main` then returns so the
    // telemetry guard sends the spans that are still buffered. The handler is installed before
    // startup, which finishes under the same time limit, and the relayer then stops before its
    // first page.
    let shutdown = CancellationToken::new();
    usdcx_telemetry::cancel_on_signal(shutdown.clone())?;
    usdcx_telemetry::stop_within(
        async {
            Relayer::start_with_head_watermark(config, require_head_watermark)
                .await?
                .run_until(shutdown.clone())
                .await
        },
        &shutdown,
        usdcx_telemetry::SHUTDOWN_TIMEOUT,
    )
    .await
}
