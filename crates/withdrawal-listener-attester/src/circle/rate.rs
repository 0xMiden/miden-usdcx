//! The rate governor — **5 QPS/IP, 35 QPS global** (Circle documents: `CIRCLE-API-SURFACE.md:18`,
//! tagged "at NDA writing").
//!
//! A permit is taken before **every request** — the `prepare` POST, the `withdraw` POST and each of
//! its retries, and every `GET /v1/withdrawal/{id}` a `409` recovery polls. It is taken in
//! [`CircleClient::execute`](super::client::CircleClient), the one boundary they all pass through,
//! so the coverage is structural: a driver cannot make a Circle request that the ceiling does not
//! see.
//!
//! That placement is load-bearing rather than tidy. Governing only the retry loop covers the POST
//! attempts and misses the recovery polls entirely — and the polls are where the request count
//! actually explodes: a `GET` per poll, per conflict, with concurrent conflicts running independent
//! loops. Getting the partner's IP throttled while the service is trying to establish whether real
//! money has already moved is the worst possible moment for it.
//!
//! Sharing one governor (an `Arc`) across clients is what makes the GLOBAL ceiling genuinely
//! global.
//!
//! The implementation mirrors the deposit relayer's `circle::rate` — the two services talk to the
//! same Circle, under the same documented ceilings, and a second sliding-window design would be a
//! second set of bugs. It is duplicated rather than shared because it is an operational convention,
//! not a wire format: the single-owner rule binds the formats and codecs the two services must
//! agree on (they live in `xusdc-encoding` and are consumed by reference), and a cross-dependency
//! between two sibling services just to share a window would couple them for no protection.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The rate-limit window — both ceilings are QPS ("queries per second").
const RATE_WINDOW: Duration = Duration::from_secs(1);

/// The shortest sleep the governor takes when it must wait: keeps a wait from degenerating into a
/// spin when the window is about to roll.
const MIN_GOVERNOR_SLEEP: Duration = Duration::from_millis(1);

/// The documented per-IP ceiling.
pub const DOCUMENTED_QPS_PER_IP: u32 = 5;
/// The documented global ceiling.
pub const DOCUMENTED_QPS_GLOBAL: u32 = 35;

/// A sliding-window rate limiter: at most `qps_per_ip` acquisitions for any one host, and
/// `qps_global` overall, inside any 1-second window.
///
/// **Sliding, not fixed-bucket.** A fixed 1-second bucket permits a 2× burst across a boundary (5
/// at 0.99s + 5 at 1.01s = 10 requests inside 20ms), which is precisely the burst a ceiling exists
/// to prevent.
///
/// The per-host window is keyed BY HOST because the documented ceiling is per-IP; one shared window
/// would silently turn it into 5 QPS in TOTAL across every host the process talks to.
#[derive(Debug)]
pub struct RateGovernor {
    qps_per_ip: u32,
    qps_global: u32,
    state: Mutex<GovernorState>,
    /// Every permit ever granted, monotonic — the windows themselves are pruned, so they cannot
    /// answer "how many requests has this process actually made?".
    ///
    /// It is a genuine operational counter (an ops dashboard wants exactly this), and it is also
    /// the seam that makes the ceiling's COVERAGE checkable rather than merely timed: "did this
    /// request take a permit at all?" is a question a stopwatch answers only when the ceiling
    /// happens to bind, and an ungoverned request is invisible to a stopwatch that is not looking
    /// at the right second.
    granted: AtomicUsize,
}

#[derive(Debug, Default)]
struct GovernorState {
    global: VecDeque<Instant>,
    per_host: HashMap<String, VecDeque<Instant>>,
}

impl RateGovernor {
    /// A governor with the given ceilings.
    ///
    /// A `0` ceiling is CLAMPED to `1`, not honoured: a 0-QPS window never opens, so an acquisition
    /// against it would block forever — a config typo would become a silent, permanent hang with no
    /// error anywhere. Clamping turns that into a 1-QPS crawl an operator can actually see and fix.
    /// (Same reasoning, same shape, as [`PollPolicy::new`](super::client::PollPolicy::new)'s
    /// attempt-ceiling clamp; 0 QPS is never a legitimate configuration of a service whose job is
    /// to make requests.)
    pub fn new(qps_per_ip: u32, qps_global: u32) -> Self {
        Self {
            qps_per_ip: qps_per_ip.max(1),
            qps_global: qps_global.max(1),
            state: Mutex::new(GovernorState::default()),
            granted: AtomicUsize::new(0),
        }
    }

    /// The ceilings as DOCUMENTED (Circle documents 5 QPS/IP, 35 QPS global, "at NDA writing").
    /// Mirrored from the API surface, never invented — and tagged as Circle's to change.
    pub fn documented() -> Self {
        Self::new(DOCUMENTED_QPS_PER_IP, DOCUMENTED_QPS_GLOBAL)
    }

    pub fn qps_per_ip(&self) -> u32 {
        self.qps_per_ip
    }

    pub fn qps_global(&self) -> u32 {
        self.qps_global
    }

    /// How many permits this governor has granted, ever — i.e. how many requests it actually
    /// admitted.
    ///
    /// Monotonic, and NOT the window contents (those are pruned every second). It answers the
    /// coverage question the ceilings depend on: a request that never took a permit is a request
    /// the ceiling never saw, and it is invisible to any timing measurement taken while the ceiling
    /// is not binding.
    pub fn granted(&self) -> usize {
        self.granted.load(Ordering::SeqCst)
    }

    /// Waits until a request to `host` fits inside BOTH ceilings, records it, and returns **the
    /// instant it recorded**.
    ///
    /// The returned instant is the governor's OWN clock sample — the one it put in its windows and
    /// enforces the ceiling against. It is handed back rather than kept private so a caller (or a
    /// test) can reason about the ceiling on the same samples the governor used: a second
    /// `Instant::now()` taken after this returns is a *different* sample, and near a window
    /// boundary the two disagree — the governor can legitimately expire its own earlier stamp while
    /// an observer's later stamp still counts, "showing" 6 acquisitions in a window that only ever
    /// admitted 5.
    ///
    /// The re-check after each sleep is what makes this safe under concurrency: a task that wakes
    /// to find another took the slot it was waiting for simply waits again, so the invariant
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
                        // two can never disagree about when this request happened
                        host_window.push_back(now);
                        global.push_back(now);
                        self.granted.fetch_add(1, Ordering::SeqCst);
                        return now;
                    }
                    Some(wait) => wait.max(MIN_GOVERNOR_SLEEP),
                }
            };

            tokio::time::sleep(wait).await;
        }
    }
}

impl Default for RateGovernor {
    /// The documented ceilings — see [`RateGovernor::documented`].
    fn default() -> Self {
        Self::documented()
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
