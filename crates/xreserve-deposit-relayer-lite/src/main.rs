//! Starts the deposit relayer.
//!
//! Startup fails because a compatible Miden client is not available.

use anyhow::{bail, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use xreserve_deposit_relayer_lite::config::Config;
use xreserve_deposit_relayer_lite::mint::Minter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = Config::parse();
    let _minter = Minter::from_config(&config);
    tracing::info!(remote_domain = %config.remote_domain, "arguments validated");

    bail!(
        "Miden integration requires a miden-client release for protocol v0.16. No compatible \
         release is available."
    )
}
