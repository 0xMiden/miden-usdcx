use std::path::PathBuf;

use anyhow::{Context, Result};

use xusdc_attester::chain::MidenChainReader;
use xusdc_attester::circle::CircleClient;
use xusdc_attester::config::Config;
use xusdc_attester::Attester;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config_path = config_path_from_args()?;

    let config = Config::load(&config_path)
        .with_context(|| format!("failed to load {}", config_path.display()))?;
    let circle = CircleClient::new(&config).context("failed to initialize Circle HTTP client")?;

    let _attester = Attester::start(
        config,
        Box::new(MidenChainReader::devnet()),
        Box::new(circle),
    )
    .await
    .context("startup failed")?;
    println!("startup preflight passed; the attester loop is not implemented yet");
    Ok(())
}

fn config_path_from_args() -> Result<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    if args.next().is_some() {
        anyhow::bail!("usage: xusdc-attester [CONFIG_PATH]")
    } else {
        Ok(path)
    }
}
