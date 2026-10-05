mod config;
mod supervisor;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = config::Config::try_from(config::Cli::parse())?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_writer(std::io::stdout)
        .init();
    let signals = supervisor::Signals::install()?;
    supervisor::run(config, signals).await
}
