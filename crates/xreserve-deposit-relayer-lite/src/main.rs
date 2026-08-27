//! Assembles and starts the deposit relayer.
//!
//! Startup fails because a compatible Miden client is not available.

use anyhow::Result;
use clap::Parser;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::{Felt, Word};
use tracing_subscriber::EnvFilter;

use xreserve_deposit_relayer_lite::circle::CircleClient;
use xreserve_deposit_relayer_lite::config::Config;
use xreserve_deposit_relayer_lite::miden::production_miden_client;
use xreserve_deposit_relayer_lite::mint::Identities;
use xreserve_deposit_relayer_lite::store::CursorStore;
use xreserve_deposit_relayer_lite::{run, Relayer};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = Config::parse();
    let identities = Identities::from_config(&config)?;
    let store = CursorStore::new(config.state_file.clone());
    let circle = CircleClient::new(
        config.circle_url.clone(),
        config.page_size,
        config.request_timeout,
    )?;

    // Startup stops here until a compatible Miden client is available.
    let miden = production_miden_client()?;

    let mut rng = RandomCoin::new(entropy_seed());
    let mut relayer = Relayer {
        config: &config,
        circle: &circle,
        store: &store,
        miden: miden.as_ref(),
        identities: &identities,
        rng: &mut rng,
    };

    run(&mut relayer).await
}

/// Returns a seed for note serial numbers from the operating system.
fn entropy_seed() -> Word {
    use rand::RngCore;

    let mut rng = rand::rngs::OsRng;
    Word::from([
        Felt::from(rng.next_u32()),
        Felt::from(rng.next_u32()),
        Felt::from(rng.next_u32()),
        Felt::from(rng.next_u32()),
    ])
}
