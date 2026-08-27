//! The binary reads the config, then exits until the Miden client adapter is available.
//!
//! Everything past the config needs a `miden-client` for protocol v0.16, and there is no such
//! release. Until the seam is implemented, starting up would mean polling Circle while minting
//! nothing — healthy in every log except the chain's — so the binary validates its config and
//! exits non-zero instead. Later slices in this stack replace the refusal with the real service.

use std::path::PathBuf;

use anyhow::{bail, Result};
use tracing_subscriber::EnvFilter;

use xreserve_deposit_relayer_lite::config::Config;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("relayer.toml"));

    let config = Config::load(&path)?;
    tracing::info!(remote_domain = config.remote_domain, "config loaded");

    bail!(
        "the miden leg is not implemented: it needs a miden-client for protocol v0.16 and there \
         is no such release. Refusing to run rather than poll circle without minting."
    )
}
