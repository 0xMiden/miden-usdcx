mod config;
mod supervisor;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;
use xusdc_attester::service::run_command;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = config::Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_writer(std::io::stdout)
        .init();
    let run = match cli.command {
        config::Command::Run(run) => *run,
        config::Command::Attester(command) => return run_command(command),
    };
    let config = config::Config::try_from(run)?;
    supervisor::run(config).await
}
