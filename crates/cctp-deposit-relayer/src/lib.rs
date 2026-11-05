//! A serial relay from configured finalized CCTP burns to one immutable Arc helper.
mod abi;
mod arc;
mod circle;
mod config;
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
    let config = config::Config::load(path)?;
    // Refuse a new store for an old sender before creating any journal.
    if initialize {
        let mut arc = arc::ArcSender::new(&config)?;
        arc.verify(&config).await?;
        anyhow::ensure!(
            arc.nonces(&config).await? == (0, 0),
            "initialization requires a genuinely fresh dedicated sender at nonce zero"
        );
    }
    let store = store::Store::open(&config, initialize)?;
    let client =
        usdcx_kms_signer::KmsSigner::client(&config.kms.region, std::time::Duration::from_secs(10))
            .await;
    let signer = usdcx_kms_signer::KmsSigner::connect(client, &config.kms.key_arn).await?;
    if initialize {
        anyhow::ensure!(
            signer.public_key().await?.address()? == config.signer,
            "loaded signer mismatch"
        );
        return Ok(());
    }
    worker::Worker::new(config, store, Box::new(signer))
        .await?
        .run(shutdown)
        .await
}
