//! Exponential backoff under the rate ceilings, and the §8.4 obligations that ride on it: nothing
//! fetched is ever silently dropped, and an operator hears about what matters — no more.

use std::future::Future;
use std::time::Duration;

use crate::circle::rate::RateGovernor;
use crate::config::RelayerConfig;
use crate::error::RelayerError;
use crate::observability::{EventSink, RelayerEvent};

/// Caps the exponential backoff shift, so a large `max_attempts` cannot overflow the delay.
const MAX_BACKOFF_SHIFT: u32 = 20;

/// The exponential-backoff policy: `max_attempts` attempts, waiting `base_delay_ms · 2^(n-1)` before
/// attempt n+1, alerting once `alert_after_attempts` consecutive attempts have failed with a failure
/// that warrants an alert (5xx / transport / deadline — a 404 does not; see
/// `RelayerError::alerts_while_retrying`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_delay_ms: u64,
    alert_after_attempts: u32,
}

impl RetryPolicy {
    /// # Errors
    /// [`RelayerError::BadRetryPolicy`] — fewer than one attempt (nothing would ever be tried), or a
    /// 0 alert threshold (which would alert before anything had failed). An `alert_after_attempts`
    /// ABOVE `max_attempts` is legal and means "never alert mid-retry; alert only if the budget runs
    /// out".
    pub fn new(
        max_attempts: u32,
        base_delay_ms: u64,
        alert_after_attempts: u32,
    ) -> Result<Self, RelayerError> {
        if max_attempts == 0 || alert_after_attempts == 0 {
            return Err(RelayerError::BadRetryPolicy {
                max_attempts,
                alert_after_attempts,
            });
        }

        Ok(Self {
            max_attempts,
            base_delay_ms,
            alert_after_attempts,
        })
    }

    /// # Errors
    /// [`RelayerError::BadRetryPolicy`] — as [`Self::new`].
    pub fn from_config(config: &RelayerConfig) -> Result<Self, RelayerError> {
        Self::new(
            config.max_retry_attempts(),
            config.backoff_base_ms(),
            config.alert_after_attempts(),
        )
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    pub fn base_delay_ms(&self) -> u64 {
        self.base_delay_ms
    }

    pub fn alert_after_attempts(&self) -> u32 {
        self.alert_after_attempts
    }

    /// The wait before attempt `attempt + 1`: `base · 2^(attempt-1)`, saturating.
    fn backoff_for(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(MAX_BACKOFF_SHIFT);
        Duration::from_millis(self.base_delay_ms.saturating_mul(1u64 << shift))
    }
}

/// Everything [`with_backoff`] needs that is not the operation itself: the ceilings to respect, the
/// host they are keyed by, the policy to apply, the sink to report to, and the endpoint label those
/// reports carry.
///
/// (The spec sketches `with_backoff(governor, max_attempts, op)`. Bundling the parameters is a
/// deliberate deviation, reported per §14: the governor cannot rate-limit without knowing the HOST,
/// and §8.4's "never silently drop / alert after a threshold" obligations cannot be met without a
/// sink and an endpoint label. The retry SEMANTICS are unchanged.)
pub struct RetryContext<'a> {
    governor: &'a RateGovernor,
    host: &'a str,
    policy: &'a RetryPolicy,
    sink: &'a dyn EventSink,
    endpoint: &'a str,
}

impl<'a> RetryContext<'a> {
    pub fn new(
        governor: &'a RateGovernor,
        host: &'a str,
        policy: &'a RetryPolicy,
        sink: &'a dyn EventSink,
        endpoint: &'a str,
    ) -> Self {
        Self {
            governor,
            host,
            policy,
            sink,
            endpoint,
        }
    }
}

/// Runs `op` under the rate ceilings, retrying TRANSIENT failures with exponential backoff and
/// surfacing everything (§8.4).
///
/// * A rate-limit permit is taken before EVERY attempt, retries included.
/// * A permanent failure (400, a redirect, a decode error, a broken binding, an oversized body, a bad
///   parameter) returns immediately — `Rejected` + `Alert`, no retry. Retrying it would re-issue an
///   identical request that must fail identically, spending the rate budget the transient failures
///   need.
/// * A transient failure (404, 429, 5xx, a transport error, a deadline) is logged `Pending` — so it
///   is never silently dropped — and retried; it alerts once `alert_after_attempts` consecutive
///   attempts have failed AND the failure is one that warrants an alert (a 404 does not: a
///   just-landed deposit is *expected* to 404 for a while).
/// * When the attempt budget runs out, the LAST error is returned — with an `Alert`, because
///   "retried until we gave up" is exactly the state an operator must hear about.
pub async fn with_backoff<T, F, Fut>(
    context: &RetryContext<'_>,
    mut op: F,
) -> Result<T, RelayerError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, RelayerError>>,
{
    let mut attempt: u32 = 1;
    loop {
        let _permit = context.governor.acquire(context.host).await;

        let error = match op().await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };

        if !error.is_retryable() {
            context.sink.emit(RelayerEvent::Rejected {
                endpoint: context.endpoint.to_string(),
                reason: error.to_string(),
            });
            context.sink.emit(RelayerEvent::Alert {
                endpoint: context.endpoint.to_string(),
                reason: error.to_string(),
            });
            return Err(error);
        }

        if attempt >= context.policy.max_attempts() {
            context.sink.emit(RelayerEvent::Alert {
                endpoint: context.endpoint.to_string(),
                reason: format!("giving up after {attempt} attempts: {error}"),
            });
            return Err(error);
        }

        // transient, and attempts remain: the attestation is NOT dropped — it is Pending
        context.sink.emit(RelayerEvent::Pending {
            endpoint: context.endpoint.to_string(),
            status: error.http_status(),
            attempt,
            reason: error.to_string(),
        });
        if attempt == context.policy.alert_after_attempts() && error.alerts_while_retrying() {
            context.sink.emit(RelayerEvent::Alert {
                endpoint: context.endpoint.to_string(),
                reason: format!("{attempt} consecutive failed attempts: {error}"),
            });
        }

        tokio::time::sleep(context.policy.backoff_for(attempt)).await;
        attempt += 1;
    }
}
