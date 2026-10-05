use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::FutureExt;
use tokio::signal::unix::{signal, Signal, SignalKind};
use tokio_util::sync::CancellationToken;
use tracing::info;
use xreserve_deposit_relayer::{miden::NodeClient, Relayer};
use xusdc_attester::service::AttesterService;

use crate::config::Config;

pub(crate) struct Signals {
    terminate: Signal,
    interrupt: Signal,
}

impl Signals {
    pub(crate) fn install() -> Result<Self> {
        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
        })
    }

    async fn recv(&mut self) -> Result<()> {
        tokio::select! {
            received = self.terminate.recv() => received,
            received = self.interrupt.recv() => received,
        }
        .context("process signal stream closed")
    }
}

pub(crate) async fn run(config: Config, mut signals: Signals) -> Result<()> {
    // No deposit work starts until the attester and both KMS signers pass startup.
    let startup = AttesterService::start(config.attester);
    tokio::pin!(startup);
    let attester = tokio::select! {
        biased;
        signal = signals.recv() => {
            let cleanup = drain(async { startup.await?.shutdown().await }).await;
            return signal.and(cleanup);
        }
        result = &mut startup => result?,
    };
    let (stop, shutdown) = mpsc::channel();
    let (ready, started) = tokio::sync::oneshot::channel();
    // The blocking relayer owns an SDK runtime and must run outside the async runtime.
    let relayer = tokio::task::spawn_blocking(move || {
        let node = NodeClient::new(&config.relayer).context("connecting relayer to Miden")?;
        let relayer = Relayer::new(config.relayer, Box::new(node))?;
        let _ = ready.send(());
        relayer.run_until(shutdown)
    });
    let relayer = async { relayer.await.context("relayer task failed")? };
    tokio::pin!(relayer);
    let ready = tokio::select! {
        biased;
        signal = signals.recv() => signal.map(|()| false),
        ready = started => ready.context("relayer startup failed").map(|()| true),
    };
    if !matches!(ready, Ok(true)) {
        drop(stop);
        let (relayer, cleanup) =
            drain(async { tokio::join!(&mut relayer, attester.shutdown()) }).await;
        return relayer.and(cleanup).and(ready.map(|_| ()));
    }
    info!("deposit relayer and withdrawal attester started");
    let token = CancellationToken::new();
    monitor(
        guarded(attester.run(token.clone())),
        relayer,
        signals.recv(),
        token,
        stop,
    )
    .await
}

async fn guarded(future: impl Future<Output = Result<()>>) -> Result<()> {
    AssertUnwindSafe(future)
        .catch_unwind()
        .await
        .map_err(|_| anyhow!("attester panicked"))?
}

async fn monitor(
    attester: impl Future<Output = Result<()>>,
    relayer: impl Future<Output = Result<()>>,
    signal: impl Future<Output = Result<()>>,
    shutdown: CancellationToken,
    stop: mpsc::Sender<()>,
) -> Result<()> {
    tokio::pin!(attester, relayer, signal);
    let mut attester_done = false;
    let mut relayer_done = false;
    let first = tokio::select! {
        biased;
        result = &mut signal => result,
        result = &mut attester => {
            attester_done = true;
            service_exit("attester", result)
        }
        result = &mut relayer => {
            relayer_done = true;
            service_exit("relayer", result)
        }
    };
    shutdown.cancel();
    drop(stop);
    info!("stopping bridge services");
    let (attester, relayer) = drain(async {
        tokio::join!(
            async {
                if attester_done {
                    Ok(())
                } else {
                    attester.await
                }
            },
            async {
                if relayer_done {
                    Ok(())
                } else {
                    relayer.await
                }
            },
        )
    })
    .await;
    first.and(attester).and(relayer)
}

async fn drain<T>(cleanup: impl Future<Output = T>) -> T {
    // Bound shutdown even when the blocking relayer's chain stops advancing.
    match tokio::time::timeout(Duration::from_secs(300), cleanup).await {
        Ok(result) => result,
        Err(_) => {
            eprintln!(
                "bridge shutdown did not finish within five minutes; terminating the process"
            );
            std::process::exit(1);
        }
    }
}

fn service_exit(name: &str, result: Result<()>) -> Result<()> {
    result.with_context(|| format!("{name} failed"))?;
    bail!("{name} stopped unexpectedly")
}

#[cfg(test)]
#[path = "tests/supervisor.rs"]
mod tests;
