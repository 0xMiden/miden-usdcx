use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use tokio_util::sync::CancellationToken;

use xusdc_attester::chain::MidenChainReader;
use xusdc_attester::circle::CircleClient;
use xusdc_attester::config::Config;
use xusdc_attester::signer::{DevelopmentSigner, Signer, SignerPair};
use xusdc_attester::Attester;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config_path = config_path_from_args()?;

    let config = Config::load(&config_path)
        .with_context(|| format!("failed to load {}", config_path.display()))?;
    let (circle, circle_worker) =
        CircleClient::start(&config).context("failed to initialize Circle HTTP client")?;
    let signers = development_signers().context("failed to initialize development signers")?;
    let signers = SignerPair::new(signers)
        .await
        .context("failed to initialize the signer pair")?;

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
    let shutdown = CancellationToken::new();
    let signal_token = shutdown.clone();
    // Besides the Circle request worker, the only spawned task: notify the sequential loop, without
    // interrupting its current cycle.
    let signal_task = tokio::spawn(async move {
        tokio::select! {
            Some(()) = sigterm.recv() => {}
            Ok(()) = tokio::signal::ctrl_c() => {}
            else => return,
        }
        signal_token.cancel();
    });
    eprintln!(
        "attester started with development keys; local rolling-limit enforcement is not implemented yet"
    );
    let result = attester.run(shutdown).await;
    signal_task.abort();
    // Dropping the attester closes the request queue; the worker then finishes any request in
    // flight and stops.
    drop(attester);
    circle_worker
        .await
        .context("Circle request worker failed")?;
    result
}

fn development_signers() -> Result<[Box<dyn Signer>; 2]> {
    // Replace only this construction with the two independent KMS providers for deployment.
    // Never include environment values or private-key bytes in an error.
    let load = |name: &str| {
        let value = std::env::var(name).map_err(|_| anyhow!("missing signing key: {name}"))?;
        DevelopmentSigner::from_hex(&value)
            .with_context(|| format!("{name} is not a valid signing key"))
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
