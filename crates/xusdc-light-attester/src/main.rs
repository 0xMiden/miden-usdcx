use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing::warn;
use tracing_subscriber::EnvFilter;

use xusdc_attester::chain::MidenChainReader;
use xusdc_attester::circle::ReqwestTransport;
use xusdc_attester::config::{Cli, Config};
use xusdc_attester::signer::{DevelopmentSigner, Signer};
use xusdc_attester::Attester;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    init_tracing();
    let config = Config::try_from(Cli::parse()).context("invalid configuration")?;
    let circle_transport =
        ReqwestTransport::new().context("failed to initialize Circle HTTP client")?;
    let signers = development_signers().context("failed to initialize development signers")?;
    let miden_network = config.miden_network();

    let mut attester = Attester::start(
        config,
        Box::new(MidenChainReader::for_network(miden_network)),
        Box::new(circle_transport),
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
    warn!(?miden_network, "attester started with development signers");
    attester.run(shutdown).await;
    signal_task.abort();
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stdout)
        .init();
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
