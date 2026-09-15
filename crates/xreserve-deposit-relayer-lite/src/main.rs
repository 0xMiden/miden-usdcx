//! Assembles and starts the deposit relayer.
//!
//! The Miden client is built before the first Circle request, so a node the relayer cannot mint
//! through stops the service at startup rather than after it has read the feed.

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use xreserve_deposit_relayer_lite::config::Config;
use xreserve_deposit_relayer_lite::miden::NodeClient;
use xreserve_deposit_relayer_lite::Relayer;

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_forest::ForestLayer::default())
        .init();

    let config = Config::parse();

    let miden = NodeClient::new(&config).context("connecting to miden")?;

    Relayer::new(config, Box::new(miden))?.run()
}
