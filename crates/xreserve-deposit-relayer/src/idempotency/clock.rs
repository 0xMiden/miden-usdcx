//! The store's time source.

use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// The source of a record's `timestamp`. A trait, not a `SystemTime::now()` call at the write site,
/// for one reason: the tests must be able to assert that a re-observed nonce did NOT rewrite its
/// record. That is only checkable if the clock can be moved between the two observations and the
/// stored value compared against an exact expectation.
pub trait Clock: fmt::Debug + Send + Sync {
    /// Seconds since the Unix epoch.
    fn unix_seconds(&self) -> u64;
}

/// The production clock: the host's wall clock.
///
/// A clock that steps BACKWARDS (an NTP correction) can only mis-stamp a `timestamp`, which is
/// diagnostic. It cannot trigger a [`crate::idempotency::IdempotencyStore::reclaim_stale_pending`]
/// early — the record's age is computed from this same clock, so a backwards step makes records look
/// *younger*, delaying a reclaim rather than firing a spurious one.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            // a host clock set before 1970 is not a condition the relayer can act on, and the stamp
            // is diagnostic: it degrades to the epoch rather than taking the process down
            .map_or(0, |since_epoch| since_epoch.as_secs())
    }
}
