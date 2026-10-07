//! Stopping a service on a signal instead of being killed by it, so that `main` returns and the
//! [`Telemetry`](crate::Telemetry) guard sends the spans that are still buffered.

use std::future::Future;
use std::time::Duration;

use anyhow::Context as _;
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// How long a service has to finish the work in flight once shutdown is requested.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Requests shutdown on the first SIGTERM or SIGINT by cancelling `shutdown`.
///
/// # Errors
///
/// Either signal handler cannot be installed.
pub fn cancel_on_signal(shutdown: CancellationToken) -> anyhow::Result<()> {
    let mut terminate =
        signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    tokio::spawn(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        info!(reason = "process signal", "shutdown requested");
        shutdown.cancel();
    });
    Ok(())
}

/// Runs `service` to completion, giving it `timeout` to finish once `shutdown` is cancelled.
///
/// A service waiting on the chain can wait indefinitely if blocks stop. If it is still running
/// when `timeout` passes, the buffered spans are sent and the process exits with a failure status.
pub async fn stop_within<T>(
    service: impl Future<Output = T>,
    shutdown: &CancellationToken,
    timeout: Duration,
) -> T {
    let deadline = async {
        shutdown.cancelled().await;
        info!("waiting for the work in flight to finish");
        tokio::time::sleep(timeout).await;
    };
    tokio::select! {
        output = service => output,
        () = deadline => {
            error!(
                timeout = %humantime::format_duration(timeout),
                "shutdown did not finish in time; terminating the process"
            );
            // Exiting skips the telemetry guard, so send the buffered spans first.
            crate::flush();
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_service_that_finishes_after_shutdown_returns_its_output() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let service = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            7
        };
        assert_eq!(stop_within(service, &shutdown, TIMEOUT).await, 7);
    }

    #[tokio::test]
    async fn a_service_runs_unbounded_until_shutdown_is_requested() {
        let shutdown = CancellationToken::new();
        let service = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            7
        };
        // Without a shutdown request the timeout does not apply.
        assert_eq!(
            stop_within(service, &shutdown, Duration::from_millis(1)).await,
            7
        );
    }

    /// Long enough that no test above reaches it.
    const TIMEOUT: Duration = Duration::from_secs(60);
}
