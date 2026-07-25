//! The rate governor — 5 QPS/IP, 35 QPS global (CIR-API-4).
//!
//! A permit is taken before EVERY attempt, retries included: a retry storm that ignored the ceiling
//! would be the fastest way to get the partner's IP throttled by Circle, which is exactly what a 429
//! means. Sharing one governor (`Arc`) across clients makes the global ceiling genuinely global.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::RelayerConfig;
use crate::error::RelayerError;

/// The rate-limit window (both ceilings are QPS — "queries per second").
const RATE_WINDOW: Duration = Duration::from_secs(1);

/// The shortest sleep the governor takes when it must wait: keeps a wait from degenerating into a
/// spin when the window is about to roll.
const MIN_GOVERNOR_SLEEP: Duration = Duration::from_millis(1);

/// A sliding-window rate limiter: at most `qps_per_ip` acquisitions for any one host, and
/// `qps_global` overall, inside any 1-second window.
///
/// Sliding, not fixed-bucket: a fixed 1-second bucket permits a 2× burst across a boundary (5 at
/// 0.99s + 5 at 1.01s = 10 requests inside 20ms), which is precisely the burst that earns a 429.
///
/// The per-host window is keyed BY HOST because the documented ceiling is per-IP; one shared window
/// would make the limit 5 QPS in TOTAL across every host the process talks to.
#[derive(Debug)]
pub struct RateGovernor {
    qps_per_ip: u32,
    qps_global: u32,
    state: Mutex<GovernorState>,
}

#[derive(Debug, Default)]
struct GovernorState {
    global: VecDeque<Instant>,
    per_host: HashMap<String, VecDeque<Instant>>,
}

impl RateGovernor {
    /// The documented ceilings are `RateGovernor::new(5, 35)` (CIR-API-4).
    ///
    /// # Errors
    /// [`RelayerError::BadRateLimit`] — a 0-QPS ceiling. Its window never opens, so an acquisition
    /// would block forever; refusing it here turns a runtime deadlock into a startup error.
    pub fn new(qps_per_ip: u32, qps_global: u32) -> Result<Self, RelayerError> {
        if qps_per_ip == 0 || qps_global == 0 {
            return Err(RelayerError::BadRateLimit {
                qps_per_ip,
                qps_global,
            });
        }

        Ok(Self {
            qps_per_ip,
            qps_global,
            state: Mutex::new(GovernorState::default()),
        })
    }

    /// The client's ceilings, straight from config.
    ///
    /// # Errors
    /// [`RelayerError::BadRateLimit`] — as [`Self::new`].
    pub fn from_config(config: &RelayerConfig) -> Result<Self, RelayerError> {
        Self::new(config.rate_qps_per_ip(), config.rate_qps_global())
    }

    pub fn qps_per_ip(&self) -> u32 {
        self.qps_per_ip
    }

    pub fn qps_global(&self) -> u32 {
        self.qps_global
    }

    /// Waits until a request to `host` fits inside BOTH ceilings, records it, and returns **the
    /// instant it recorded**.
    ///
    /// The returned instant is the governor's OWN clock sample — the one it put in its windows and
    /// enforces the ceiling against. It is returned rather than kept private so that a caller (or a
    /// test) can reason about the ceiling on the same samples the governor used: a second
    /// `Instant::now()` taken after this returns is a *different* sample, and near a window boundary
    /// the two disagree — the governor can legitimately expire its own earlier stamp while an
    /// observer's later stamp still counts, "showing" 6 acquisitions in a window that only ever
    /// admitted 5.
    ///
    /// The re-check after each sleep is what makes this safe under concurrency: a task that wakes to
    /// find another task took the slot it was waiting for simply waits again, so the invariant
    /// ("never more than N inside any 1s window") holds no matter how many callers race.
    pub async fn acquire(&self, host: &str) -> Instant {
        loop {
            let wait = {
                let mut state = self
                    .state
                    .lock()
                    .expect("rate governor mutex is never poisoned");
                let GovernorState { global, per_host } = &mut *state;
                let now = Instant::now();

                prune(global, now);
                let host_window = per_host.entry(host.to_string()).or_default();
                prune(host_window, now);

                let host_wait = window_wait(host_window, self.qps_per_ip, now);
                let global_wait = window_wait(global, self.qps_global, now);

                match host_wait.max(global_wait) {
                    None => {
                        // both windows have room: take the slot in the same instant in both, so the
                        // two windows can never disagree about when this request happened
                        host_window.push_back(now);
                        global.push_back(now);
                        return now;
                    }
                    Some(wait) => wait.max(MIN_GOVERNOR_SLEEP),
                }
            };

            tokio::time::sleep(wait).await;
        }
    }
}

/// Drops the acquisitions that have aged out of the 1-second window.
fn prune(window: &mut VecDeque<Instant>, now: Instant) {
    while let Some(oldest) = window.front() {
        if now.duration_since(*oldest) >= RATE_WINDOW {
            window.pop_front();
        } else {
            break;
        }
    }
}

/// How long until `window` has room for one more acquisition under `limit`, or `None` if it already
/// does. (`window` is assumed pruned.)
fn window_wait(window: &VecDeque<Instant>, limit: u32, now: Instant) -> Option<Duration> {
    if window.len() < limit as usize {
        return None;
    }
    // full: the next slot opens when the OLDEST acquisition leaves the window
    let oldest = *window.front().expect("a full window is non-empty");
    Some(RATE_WINDOW.saturating_sub(now.duration_since(oldest)))
}
