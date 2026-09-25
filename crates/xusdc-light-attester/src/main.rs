use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use tracing_subscriber::EnvFilter;

use xusdc_attester::chain::MidenChainReader;
use xusdc_attester::circle::CircleClient;
use xusdc_attester::config::{Cli, Config, SignerConfig};
use xusdc_attester::signer::{DevelopmentSigner, KmsSigner, Signer};
use xusdc_attester::Attester;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    init_tracing();
    let config = Config::try_from(Cli::parse()).context("invalid configuration")?;
    let circle = CircleClient::new(&config).context("failed to initialize Circle HTTP client")?;
    let (signers, provider): ([Box<dyn Signer>; 2], _) = match config.signer() {
        SignerConfig::Development => (
            development_signers().context("failed to initialize development signers")?,
            "development",
        ),
        SignerConfig::AwsKms {
            region,
            key_arns,
            operation_timeout,
        } => {
            let client = KmsSigner::client(region, *operation_timeout).await;
            let expected = config.expected_signing_public_keys_hex();
            let first = KmsSigner::connect(client.clone(), &key_arns[0], &expected[0])
                .await
                .context("failed to initialize first AWS KMS signer")?;
            let second = KmsSigner::connect(client, &key_arns[1], &expected[1])
                .await
                .context("failed to initialize second AWS KMS signer")?;
            ([Box::new(first), Box::new(second)], "aws-kms")
        }
    };
    let miden_rpc_url = config.miden_rpc_url().clone();

    let mut attester = Attester::start(
        config,
        Box::new(MidenChainReader::new(&miden_rpc_url)),
        Box::new(circle),
        signers,
    )
    .await
    .context("startup failed")?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;
    let shutdown = CancellationToken::new();
    let signal_token = shutdown.clone();
    // The only spawned task: notify the sequential loop, without interrupting its current cycle.
    let signal_task = tokio::spawn(async move {
        tokio::select! {
            Some(()) = sigterm.recv() => {}
            Ok(()) = tokio::signal::ctrl_c() => {}
            else => return,
        }
        signal_token.cancel();
    });
    warn!(%miden_rpc_url, signer_provider = provider, "attester started");
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
