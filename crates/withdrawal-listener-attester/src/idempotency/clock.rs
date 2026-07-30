//! The ledger's time source.

use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// The source of a record's `timestamp`. A trait, not a `SystemTime::now()` call at the write site,
/// for one reason: a test must be able to assert that a re-observed burn did NOT rewrite its
/// record. That is only checkable if the clock can be moved between the two observations and the
/// stored value compared against an exact expectation.
///
/// Nothing in this ledger DECIDES on the timestamp — it is diagnostic (an operator asks "when was
/// this burn claimed?"). No claim, refusal, or transition reads it, so a skewed clock cannot
/// authorize a submission. That is deliberate: it is why this ledger has no age-based automatic
/// reclaim (see the module docs).
pub trait Clock: fmt::Debug + Send + Sync {
    /// Seconds since the Unix epoch.
    fn unix_seconds(&self) -> u64;
}

/// The production clock: the host's wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            // a host clock set before 1970 is not a condition this service can act on, and the stamp
            // is diagnostic: it degrades to the epoch rather than taking the process down
            .map_or(0, |since_epoch| since_epoch.as_secs())
    }
}
