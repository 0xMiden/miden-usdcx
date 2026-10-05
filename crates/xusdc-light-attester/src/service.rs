//! Shared startup and shutdown for the attester binaries.

use anyhow::{Context, Result};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::chain::MidenChainReader;
use crate::circle::CircleClient;
use crate::config::{Config, SignerConfig};
use crate::signer::{KmsSigner, Signer, SignerPair};
use crate::Attester;

/// An initialized attester that has not started its withdrawal loop yet.
pub struct AttesterService {
    attester: Attester,
    circle_worker: JoinHandle<()>,
}

impl AttesterService {
    pub async fn start(config: Config) -> Result<Self> {
        let (circle, circle_worker) =
            CircleClient::start(&config).context("failed to initialize Circle HTTP client")?;
        let SignerConfig::AwsKms {
            region,
            key_arns,
            operation_timeout,
        } = config.signer();
        let client = KmsSigner::client(region, *operation_timeout).await;
        let first = KmsSigner::connect(client.clone(), &key_arns[0])
            .await
            .context("failed to initialize first AWS KMS signer")?;
        let second = KmsSigner::connect(client, &key_arns[1])
            .await
            .context("failed to initialize second AWS KMS signer")?;
        let signers: [Box<dyn Signer>; 2] = [Box::new(first), Box::new(second)];
        let signers = SignerPair::new(signers)
            .await
            .context("failed to initialize the signer pair")?;
        let chain = MidenChainReader::new(config.miden_rpc_url());
        let attester = Attester::start(config, Box::new(chain), Box::new(circle), signers)
            .await
            .context("startup failed")?;
        Ok(Self {
            attester,
            circle_worker,
        })
    }

    /// Runs the attester, then waits for its Circle worker to finish outstanding requests.
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        let Self {
            mut attester,
            circle_worker,
        } = self;
        let result = attester.run(shutdown).await;
        // Closing the request queue lets the worker finish its current request and stop.
        drop(attester);
        circle_worker
            .await
            .context("Circle request worker failed")?;
        result
    }

    /// Closes an initialized service before its withdrawal loop starts.
    pub async fn shutdown(self) -> Result<()> {
        drop(self.attester);
        self.circle_worker
            .await
            .context("Circle request worker failed")
    }
}
