//! A serial relay from configured finalized CCTP burns to one immutable Arc helper.
mod abi;
mod arc;
mod circle;
mod config;
mod diagnostics;
mod discovery;
mod message;
mod rpc;
mod store;
#[cfg(test)]
mod tests;
mod worker;

pub async fn run(
    path: &std::path::Path,
    initialize: bool,
    shutdown: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    use usdcx_kms_signer::Signer;
    let startup = |error| diagnostics::at(error, "startup", "provider_unavailable");
    let config = config::Config::load(path)
        .map_err(|error| diagnostics::at(error, "configuration", "configuration_invalid"))?;
    // Refuse a new store for an old sender before creating any journal.
    if initialize {
        let mut arc = arc::ArcSender::new(&config)?;
        arc.verify(&config).await.map_err(startup)?;
        if arc.nonces(&config).await.map_err(startup)? != (0, 0) {
            return Err(startup(anyhow::anyhow!(
                "initialization requires a genuinely fresh dedicated sender at nonce zero"
            )));
        }
    }
    let store = store::Store::open(&config, initialize)
        .map_err(|error| diagnostics::at(error, "journal_open", "journal_unavailable"))?;
    let client =
        usdcx_kms_signer::KmsSigner::client(&config.kms.region, std::time::Duration::from_secs(10))
            .await;
    let signer = usdcx_kms_signer::KmsSigner::connect(client, &config.kms.key_arn)
        .await
        .map_err(|error| {
            diagnostics::at(
                error.into(),
                "signer_connect",
                "authentication_or_key_unavailable",
            )
        })?;
    if initialize {
        if signer.public_key().await?.address()? != config.signer {
            return Err(diagnostics::at(
                anyhow::anyhow!("loaded signer mismatch"),
                "signer_connect",
                "signer_unavailable",
            ));
        }
        return Ok(());
    }
    worker::Worker::new(config, store, Box::new(signer))
        .await?
        .run(shutdown)
        .await
}

/// Reports only controlled local labels; never format an upstream error chain here.
pub fn report_failure(error: &anyhow::Error) {
    let (stage, reason) = diagnostics::summary(error);
    tracing::error!(stage, reason, "CCTP worker stopped");
    eprintln!("CCTP worker stopped: stage={stage} reason={reason}");
}
