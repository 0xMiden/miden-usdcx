//! `xusdc-genesis` — builds the genesis xUSDC faucet offline and writes its `.mac` account
//! file.
//!
//! ```text
//! cargo run -p xusdc-genesis -- --config <config.json> [--out-dir <dir>]
//! ```
//!
//! Exit 0 = the faucet built and its account file written. The id listing goes to stdout.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use xusdc_genesis::accounts::build_faucet;
use xusdc_genesis::config::GenesisToolConfig;
use xusdc_genesis::output::{render_listing, write_outputs};

/// Builds the genesis xUSDC faucet offline from the config's faucet parameters and role-account
/// ids, writes its .mac account file, and prints the ids (hex + bech32).
#[derive(Parser)]
struct Args {
    /// The JSON config (see the crate README for the schema).
    #[arg(long)]
    config: PathBuf,
    /// Where to write the outputs; overrides the config's output_dir and is required when the
    /// config sets none.
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let config = GenesisToolConfig::load(&args.config)
        .with_context(|| format!("loading the config from {}", args.config.display()))?;
    let Some(out_dir) = args.out_dir.or_else(|| config.output_dir.clone()) else {
        bail!("no output directory: pass --out-dir or set output_dir in the config");
    };

    let faucet = build_faucet(&config).context("building the genesis faucet")?;
    write_outputs(&faucet, &out_dir)
        .with_context(|| format!("writing the outputs to {}", out_dir.display()))?;

    print!("{}", render_listing(&faucet, &config));
    println!("outputs written to {}", out_dir.display());
    Ok(())
}
