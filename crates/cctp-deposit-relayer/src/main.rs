use clap::Parser;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use usdcx_telemetry::{cancel_on_signal, stop_within, TelemetryArgs, SHUTDOWN_TIMEOUT};

#[derive(Parser)]
#[command(about = "Independent CCTP source discovery and fixed Arc helper completion")]
struct Args {
    /// Fixed private JSON configuration bound to this durable journal.
    #[arg(long)]
    config: PathBuf,
    /// Initialize once with a genuinely fresh dedicated sender; exits without sending.
    #[arg(long)]
    init: bool,
    #[command(flatten)]
    telemetry: TelemetryArgs,
}
#[tokio::main]
async fn main() {
    let args = Args::parse();
    let result = async {
        let _telemetry = usdcx_telemetry::init("cctp-deposit-relayer", &args.telemetry)?;
        let shutdown = CancellationToken::new();
        cancel_on_signal(shutdown.clone())?;
        stop_within(
            cctp_deposit_relayer::run(&args.config, args.init, shutdown.clone()),
            &shutdown,
            SHUTDOWN_TIMEOUT,
        )
        .await
    }
    .await;
    if let Err(error) = result {
        cctp_deposit_relayer::report_failure(&error);
        std::process::exit(1);
    }
}
