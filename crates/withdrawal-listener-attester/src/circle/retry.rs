//! The retry / backoff policy (Circle documents "Transient errors: 5xx → bounded retry with
//! backoff; deterministic 400 (schema/validation/malformed) → abort/fix-request, not retried").
//!
//! # What may be retried, and why the list is a single entry
//!
//! Retrying is not free and it is not neutral. The request being replayed here is a **withdrawal
//! submission** — a NON-IDEMPOTENT call that releases real money — so a retry is not "ask again",
//! it is "ask Circle to release the funds again". The bar is correspondingly high: a failure may be
//! retried only where Circle DEMONSTRABLY did not act.
//!
//! Circle's documentation names exactly one such failure, and this module retries exactly that one:
//!
//! * A **`5xx`** is the documented transient ("5xx → bounded retry with backoff"). Circle ANSWERED,
//!   with a server-side error, so the request was seen and refused. Retried, BOUNDED, then
//!   SURFACED.
//! * A **status-less transport failure** (a timeout, a connection reset) is **NOT retried**, and
//!   this is the sharp case. "No answer" is not evidence of no action: the withdrawal may already
//!   be created and releasing, with only the RESPONSE lost. Re-POSTing on a timeout is therefore a
//!   blind resubmission — the very thing the `409` rule exists to prevent — so the ambiguity is
//!   surfaced and [`submit_withdraw`](crate::submit::submit_withdraw) leaves the burn
//!   reconciliation-required.
//! * A **`400`** is deterministic. The identical request must fail identically, so a retry only
//!   burns the rate budget. One attempt, surfaced.
//! * A **`409`** is never reached here: [`submit_withdraw`](crate::submit::submit_withdraw)
//!   intercepts it as a conflict OUTCOME before the error path, precisely so it can never be
//!   classified as retryable. If one ever did reach [`is_retryable`], the answer is `false` —
//!   re-sending a duplicate conflict is the double-withdrawal footgun this whole slice exists to
//!   close.
//! * A **malformed body** / an **oversized body** / a **cardinality mismatch** is a property of
//!   what the peer sends, not of the moment. It will be sent again.
//!
//! (It would be tempting to argue a transport retry is safe *because* a duplicate would come back
//! as a `409` this module now recovers correctly. That reasoning leans the money path on Circle's
//! dedup being perfect, and the task's rule is the opposite: unknown/timeout ⇒ do not assume, do
//! not resubmit, surface. Defence in depth means not spending the `409` guard to buy a retry the
//! spec never asked for.)
//!
//! **No `Retry-After` and no `429` is documented** for these endpoints (`CIRCLE-API-SURFACE.md`),
//! so none is invented: an undocumented status is an exact [`ListenerError::Http`], surfaced, not
//! retried.

use std::future::Future;
use std::time::Duration;

use crate::circle::client::CircleClient;
use crate::error::ListenerError;

/// Caps the exponential shift, so a large attempt count cannot wrap the delay.
const MAX_BACKOFF_SHIFT: u32 = 20;

/// The default attempt budget: 4 tries (the first plus three retries).
const DEFAULT_MAX_ATTEMPTS: u32 = 4;
/// The default backoff base: 500ms → waits of 0.5s, 1s, 2s.
const DEFAULT_BASE_DELAY_MS: u64 = 500;

/// Whether `error` may be retried by re-issuing an identical **non-idempotent** request — i.e.
/// whether Circle demonstrably did NOT act.
///
/// This is the retry POLICY's judgement about an error, deliberately not a method on
/// [`ListenerError`]: the same error is "retry" to a submission and could be "escalate" to
/// something else, and the taxonomy should not have to pick. (A future GET-only driver — the status
/// poll, which IS idempotent — could safely use a laxer rule; it would be a different function, and
/// it would have to say so.)
///
/// `false` for everything not named: fail closed. A new error variant is not retryable until
/// someone decides it is.
pub fn is_retryable(error: &ListenerError) -> bool {
    match error {
        // 5xx ONLY — Circle answered, so the request was seen and refused. Two deliberate
        // `false`s hide in the catch-all below, and both are money-path decisions:
        //
        //   * `Transport` — a timeout/reset carries NO evidence about whether Circle acted. The
        //     withdrawal may be created and releasing with only the response lost, so re-POSTing it is
        //     a blind resubmission. Surfaced, never retried.
        //   * `Http { status: 409 }` — retrying a duplicate conflict is the double-withdrawal footgun.
        //     (Unreachable in practice: `submit_withdraw` takes the 409 as an outcome, not an error.)
        ListenerError::Http { status } => (500..=599).contains(status),
        _ => false,
    }
}

/// The bounded exponential-backoff policy: `max_attempts` attempts in total, waiting
/// `base_delay_ms · 2^(n-1)` before attempt `n+1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_delay_ms: u64,
}

impl RetryPolicy {
    /// `max_attempts` is CLAMPED to at least `1` — a 0-attempt budget would mean the request is
    /// never tried at all, which is a silently withheld withdrawal rather than a refused one. (The
    /// same clamp, for the same reason, as [`PollPolicy::new`](super::client::PollPolicy::new).)
    pub fn new(max_attempts: u32, base_delay_ms: u64) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            base_delay_ms,
        }
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    pub fn base_delay_ms(&self) -> u64 {
        self.base_delay_ms
    }

    /// The wait before attempt `attempt + 1`: `base · 2^(attempt-1)`, saturating at both the shift
    /// and the multiply, so a large budget or a large base cannot wrap round to a tiny delay.
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(MAX_BACKOFF_SHIFT);
        Duration::from_millis(self.base_delay_ms.saturating_mul(1u64 << shift))
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ATTEMPTS, DEFAULT_BASE_DELAY_MS)
    }
}

/// Retries TRANSIENT failures of `op` with exponential backoff, surfacing everything else
/// immediately.
///
/// * A permanent failure returns immediately, unretried.
/// * When the attempt budget runs out, the LAST error is returned. It is a FAILURE — "we retried
///   until we gave up" is never an outcome a caller may read as success.
///
/// **The rate ceilings are NOT applied here.** Every attempt still takes a permit — but it takes it
/// in [`CircleClient::execute`](crate::circle::client::CircleClient), the boundary every request
/// passes through, so the `prepare` POST and the recovery `GET`s are governed by the same budget
/// rather than only the retried POST. Acquiring here as well would spend two permits per attempt
/// and quietly halve the documented rate.
pub(crate) async fn with_backoff<T, F, Fut>(
    circle: &CircleClient,
    mut op: F,
) -> Result<T, ListenerError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ListenerError>>,
{
    let policy = *circle.retry_policy();
    let mut attempt: u32 = 1;
    loop {
        let error = match op().await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };

        if !is_retryable(&error) || attempt >= policy.max_attempts() {
            return Err(error);
        }

        tokio::time::sleep(policy.backoff_for(attempt)).await;
        attempt += 1;
    }
}
