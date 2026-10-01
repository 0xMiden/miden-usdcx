//! Starts the attester and closes its Circle worker when it stops.

use std::future::Future;

use anyhow::{anyhow, Context, Result};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::chain::MidenChainReader;
use crate::circle::CircleClient;
use crate::config::{Config, SignerConfig};
use crate::signer::{KmsSigner, Signer, SignerPair};
use crate::Attester;

/// An initialized attester. No withdrawal cycle runs until [`Self::run`] is called.
pub struct AttesterService {
    attester: Attester,
    circle_worker: JoinHandle<()>,
}

impl AttesterService {
    pub async fn start(config: Config) -> Result<Self> {
        let (circle, circle_worker) =
            CircleClient::start(&config).context("failed to initialize Circle HTTP client")?;
        let result = async move {
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
            Attester::start(config, Box::new(chain), Box::new(circle), signers)
                .await
                .context("startup failed")
        }
        .await;

        match result {
            Ok(attester) => Ok(Self {
                attester,
                circle_worker,
            }),
            Err(error) => {
                // The failed startup dropped the client, so the worker can now finish.
                if let Err(worker_error) = circle_worker.await {
                    warn!(%worker_error, "Circle request worker failed during startup");
                }
                Err(error)
            }
        }
    }

    /// Finish the current cycle on shutdown, then close the request queue and wait for its worker.
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        let Self {
            mut attester,
            circle_worker,
        } = self;
        let (result, circle_worker) =
            watch_worker(attester.run(shutdown.clone()), shutdown, circle_worker).await;
        drop(attester);
        if let Some(circle_worker) = circle_worker {
            let worker_result = circle_worker.await.context("Circle request worker failed");
            return result.and(worker_result);
        }
        result
    }

    /// Close an initialized service without starting a withdrawal cycle.
    pub async fn shutdown(self) -> Result<()> {
        drop(self.attester);
        self.circle_worker
            .await
            .context("Circle request worker failed")
    }
}

async fn watch_worker(
    run: impl Future<Output = Result<()>>,
    shutdown: CancellationToken,
    mut circle_worker: JoinHandle<()>,
) -> (Result<()>, Option<JoinHandle<()>>) {
    tokio::pin!(run);
    tokio::select! {
        biased;
        worker_result = &mut circle_worker => {
            shutdown.cancel();
            // Keep polling the cycle so a worker failure does not interrupt a saved withdrawal.
            if let Err(error) = run.await {
                warn!(%error, "attester also failed while stopping its cycle");
            }
            let error = match worker_result {
                Ok(()) => anyhow!("Circle request worker stopped unexpectedly"),
                Err(error) => anyhow!(error).context("Circle request worker failed"),
            };
            (Err(error), None)
        }
        result = &mut run => (result, Some(circle_worker)),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[tokio::test]
    async fn worker_failure_finishes_the_cycle_and_returns_an_error() {
        for panic in [false, true] {
            let shutdown = CancellationToken::new();
            let finished = Cell::new(false);
            let run = async {
                shutdown.cancelled().await;
                tokio::task::yield_now().await;
                finished.set(true);
                Ok(())
            };
            let worker = tokio::spawn(async move {
                assert!(!panic, "test worker panic");
            });
            let (result, worker) = watch_worker(run, shutdown.clone(), worker).await;
            assert!(result.is_err());
            assert!(finished.get());
            assert!(worker.is_none());
        }
    }

    #[tokio::test]
    async fn run_completion_keeps_the_worker_available_for_cleanup() {
        let (client, requests) = tokio::sync::oneshot::channel::<()>();
        let worker = tokio::spawn(async move {
            let _ = requests.await;
        });
        let (result, worker) = watch_worker(
            async { Err(anyhow!("cycle failed")) },
            CancellationToken::new(),
            worker,
        )
        .await;
        assert_eq!(result.unwrap_err().to_string(), "cycle failed");
        let worker = worker.unwrap();
        assert!(!worker.is_finished());
        drop(client);
        worker.await.unwrap();
    }
}
