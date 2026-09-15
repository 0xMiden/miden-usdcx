use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};

use xusdc_attester::chain::MidenChainReader;
use xusdc_attester::circle::CircleClient;
use xusdc_attester::config::Config;
use xusdc_attester::signer::{DevelopmentSigner, Signer};
use xusdc_attester::Attester;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config_path = config_path_from_args()?;

    let config = Config::load(&config_path)
        .with_context(|| format!("failed to load {}", config_path.display()))?;
    let circle = CircleClient::new(&config).context("failed to initialize Circle HTTP client")?;
    let signers = development_signers().context("failed to initialize development signers")?;

    let mut attester = Attester::start(
        config,
        Box::new(MidenChainReader::devnet()),
        Box::new(circle),
        signers,
    )
    .await
    .context("startup failed")?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_flag = Arc::clone(&shutdown);
    // The only spawned task: notify the sequential loop, without interrupting its current cycle.
    let signal_task = tokio::spawn(async move {
        if sigterm.recv().await.is_some() {
            signal_flag.store(true, Ordering::Release);
        }
    });
    eprintln!(
        "attester started with development keys; local rolling-limit enforcement is not implemented yet"
    );
    attester.run(shutdown).await;
    signal_task.abort();
    Ok(())
}

fn development_signers() -> Result<[Box<dyn Signer>; 2]> {
    // Replace only this construction with the two independent KMS providers for deployment.
    // Never include environment values or private-key bytes in an error.
    let load = |name: &str| {
        let value = std::env::var(name).with_context(|| format!("missing signing key: {name}"))?;
        let mut bytes = [0; 32];
        hex::decode_to_slice(value.strip_prefix("0x").unwrap_or(&value), &mut bytes)
            .map_err(|_| anyhow!("{name} must contain a 32-byte hex signing key"))?;
        DevelopmentSigner::from_bytes(bytes)
            .map_err(|_| anyhow!("{name} is not a valid signing key"))
    };
    Ok([
        Box::new(load("XUSDC_ATTESTER_SIGNING_KEY_1_HEX")?),
        Box::new(load("XUSDC_ATTESTER_SIGNING_KEY_2_HEX")?),
    ])
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
