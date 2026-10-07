//! Assembles and starts the deposit relayer.
//!
//! Node access, account tracking and local progress persistence are checked before the first Circle
//! request. Installing the relayer account's signing key remains an operator prerequisite.

use anyhow::{Context, Result};
use clap::Parser;

use xreserve_deposit_relayer::config::Config;
use xreserve_deposit_relayer::miden::NodeClient;
use xreserve_deposit_relayer::Relayer;

#[tokio::main]
async fn main() -> Result<()> {
    let _telemetry = usdcx_telemetry::init("xreserve-deposit-relayer")?;

    let config = Config::parse();

    let miden = NodeClient::new(&config)
        .await
        .context("connecting to miden")?;

    Relayer::new(config, miden)?.run().await
}
