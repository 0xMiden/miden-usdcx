//! Assembles and starts the deposit relayer.
//!
//! Startup fails because a compatible Miden client is not available.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use xreserve_deposit_relayer_lite::config::Config;
use xreserve_deposit_relayer_lite::miden::production_miden_client;
use xreserve_deposit_relayer_lite::Relayer;

fn main() -> Result<()> {
    // One indented tree per page (process_next_page is a detached root — see its doc comment),
    // not a flat line stream. Always on; RUST_LOG filters as usual.
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_forest::ForestLayer::default())
        .init();

    let config = Config::parse();

    // Startup stops here until a compatible Miden client is available.
    let miden = production_miden_client()?;

    Relayer::new(config, miden)?.run()
}
