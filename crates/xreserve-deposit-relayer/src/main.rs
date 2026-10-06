//! Assembles and starts the deposit relayer.
//!
//! Node access, account tracking and local progress persistence are checked before the first Circle
//! request. Installing the relayer account's signing key remains an operator prerequisite.

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use xreserve_deposit_relayer::config::Config;
use xreserve_deposit_relayer::miden::NodeClient;
use xreserve_deposit_relayer::Relayer;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_forest::ForestLayer::default())
        .init();

    let config = Config::parse();

    let miden = NodeClient::new(&config).context("connecting to miden")?;

    Relayer::new(config, Box::new(miden))?.run()
}
