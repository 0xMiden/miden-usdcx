mod config;
mod supervisor;

use anyhow::Result;
use clap::Parser;
use xusdc_attester::service::run_command;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = config::Cli::parse();
    let _telemetry = usdcx_telemetry::init("usdcx-bridge", &cli.telemetry)?;
    let run = match cli.command {
        config::Command::Run(run) => *run,
        config::Command::Attester(command) => return run_command(command).await,
    };
    let config = config::Config::try_from(run)?;
    supervisor::run(config).await
}
