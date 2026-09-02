//! Assembles and starts the deposit relayer.
//!
//! Startup fails because a compatible Miden client is not available.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use xreserve_deposit_relayer_lite::config::Config;
use xreserve_deposit_relayer_lite::miden::production_miden_client;
use xreserve_deposit_relayer_lite::Relayer;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = Config::parse();

    // Startup stops here until a compatible Miden client is available.
    let miden = production_miden_client()?;

    Relayer::new(config, miden)?.run()
}
