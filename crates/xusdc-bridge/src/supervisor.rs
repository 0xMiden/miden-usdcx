use std::future::Future;
use std::panic::AssertUnwindSafe;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::FutureExt;
use tokio::signal::unix::{signal, Signal, SignalKind};
use tracing::{info, warn};
use xreserve_deposit_relayer::{miden::NodeClient, Relayer};
use xusdc_attester::service::AttesterService;

use crate::config::Config;
use crate::shutdown::Shutdown;
use crate::worker::RelayerWorker;

pub(crate) struct Signals {
    terminate: Signal,
    interrupt: Signal,
}

impl Signals {
    pub(crate) fn install() -> Result<Self> {
        Ok(Self {
            terminate: signal(SignalKind::terminate())
                .context("failed to install SIGTERM handler")?,
            interrupt: signal(SignalKind::interrupt())
                .context("failed to install SIGINT handler")?,
        })
    }

    async fn recv(&mut self) -> Result<()> {
        let received = tokio::select! {
            received = self.terminate.recv() => received,
            received = self.interrupt.recv() => received,
        };
        received.context("process signal stream closed")
    }
}

pub(crate) async fn run(config: Config, mut signals: Signals) -> Result<()> {
    let mut shutdown = Shutdown::new(config.shutdown_grace);
    let result = run_services(config, &mut signals, &mut shutdown).await;
    shutdown.finish();
    result
}

async fn run_services(
    config: Config,
    signals: &mut Signals,
    shutdown: &mut Shutdown,
) -> Result<()> {
    let startup = guarded("attester startup", AttesterService::start(config.attester));
    tokio::pin!(startup);
    let attester = tokio::select! {
        biased;
        signal = signals.recv() => {
            shutdown.request();
            let attester = startup.await?;
            let cleanup = guarded("attester shutdown", attester.shutdown()).await;
            return signal.and(cleanup);
        }
        result = &mut startup => result?,
    };

    let worker = RelayerWorker::spawn(shutdown, move || {
        let node = NodeClient::new(&config.relayer).context("connecting relayer to Miden")?;
        let relayer = Relayer::new(config.relayer, Box::new(node))?;
        Ok(move |stop| relayer.run_until(stop))
    });
    let mut worker = match worker {
        Ok(worker) => worker,
        Err(error) => {
            shutdown.request();
            report_cleanup(guarded("attester shutdown", attester.shutdown()).await);
            return Err(error);
        }
    };

    let mut stop_signal = None;
    let ready = tokio::select! {
        biased;
        signal = signals.recv() => {
            stop_signal = Some(signal);
            false
        }
        ready = &mut worker.ready => ready.is_ok(),
    };
    if !ready {
        shutdown.request();
        let cleanup = guarded("attester shutdown", attester.shutdown()).await;
        let relayer = worker.join().await;
        return match stop_signal {
            Some(signal) => signal.and(relayer).and(cleanup),
            None => {
                report_cleanup(cleanup);
                relayer.context("relayer startup failed")?;
                bail!("relayer stopped before reporting ready")
            }
        };
    }
    if let Err(error) = shutdown.begin_relayer() {
        shutdown.request();
        report_cleanup(guarded("attester shutdown", attester.shutdown()).await);
        report_cleanup(worker.join().await);
        return Err(error);
    }
    info!("deposit relayer and withdrawal attester started");
    monitor(
        guarded("attester", attester.run(shutdown.token.clone())),
        worker.join(),
        signals.recv(),
        shutdown,
    )
    .await
}

async fn guarded<T>(name: &'static str, future: impl Future<Output = Result<T>>) -> Result<T> {
    AssertUnwindSafe(future)
        .catch_unwind()
        .await
        .map_err(|_| anyhow!("{name} panicked"))?
}

async fn monitor(
    attester: impl Future<Output = Result<()>>,
    relayer: impl Future<Output = Result<()>>,
    signal: impl Future<Output = Result<()>>,
    shutdown: &mut Shutdown,
) -> Result<()> {
    tokio::pin!(attester, relayer, signal);
    let token = shutdown.token.clone();
    let mut attester_done = false;
    let mut relayer_done = false;
    let first = tokio::select! {
        biased;
        result = &mut signal => result,
        () = token.cancelled() => Ok(()),
        result = &mut attester => {
            attester_done = true;
            service_exit("attester", result, token.is_cancelled())
        }
        result = &mut relayer => {
            relayer_done = true;
            service_exit("relayer", result, token.is_cancelled())
        }
    };
    shutdown.request();
    info!("stopping bridge services");
    let attester = if attester_done {
        Ok(())
    } else {
        attester.await.context("attester failed while stopping")
    };
    let relayer = if relayer_done {
        Ok(())
    } else {
        relayer.await.context("relayer failed while stopping")
    };
    if let Err(error) = &attester {
        warn!(error = %format_args!("{error:#}"), "attester shutdown failed");
    }
    if let Err(error) = &relayer {
        warn!(error = %format_args!("{error:#}"), "relayer shutdown failed");
    }
    first.and(attester).and(relayer)
}

fn service_exit(name: &str, result: Result<()>, stopping: bool) -> Result<()> {
    result.with_context(|| format!("{name} failed"))?;
    if !stopping {
        bail!("{name} stopped unexpectedly");
    }
    Ok(())
}

fn report_cleanup(result: Result<()>) {
    if let Err(error) = result {
        warn!(error = %format_args!("{error:#}"), "service cleanup failed");
    }
}

#[cfg(test)]
#[path = "tests/supervisor.rs"]
mod tests;
