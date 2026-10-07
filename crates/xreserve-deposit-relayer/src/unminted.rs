//! The deposits whose mint notes the relayer put on chain and the faucet has not minted yet.
//!
//! The relayer is done with a page once its notes are on chain, but the faucet consumes them later
//! in transactions of its own, and may refuse them: a paused faucet, or an attester key it does not
//! accept. Every scan would still succeed, so the age of the oldest deposit still waiting is the
//! only sign of it.
//!
//! The list is kept in memory and lost on restart, which is enough for alerting. A deposit the
//! faucet will never mint stays listed until then, which is how an operator clears it once they
//! have looked into it.

use std::time::{Duration, Instant};

use miden_usdcx::xreserve::encoding::DepositNonce;

/// Deposits on chain and not minted yet, oldest first.
#[derive(Debug, Default)]
pub(crate) struct Unminted {
    deposits: Vec<(DepositNonce, Instant)>,
}

impl Unminted {
    /// The nonces still waiting, to check against the faucet's used-nonce map.
    pub(crate) fn nonces(&self) -> impl Iterator<Item = DepositNonce> + '_ {
        self.deposits.iter().map(|(nonce, _)| *nonce)
    }

    /// Starts tracking deposits whose mint notes landed on chain at `at`.
    pub(crate) fn submitted(
        &mut self,
        nonces: impl IntoIterator<Item = DepositNonce>,
        at: Instant,
    ) {
        self.deposits
            .extend(nonces.into_iter().map(|nonce| (nonce, at)));
    }

    /// Stops tracking every deposit that is not in `unminted`, the nonces the faucet has not
    /// minted as of the last check.
    pub(crate) fn retain(&mut self, unminted: &[DepositNonce]) {
        self.deposits.retain(|(nonce, _)| unminted.contains(nonce));
    }

    pub(crate) fn count(&self) -> usize {
        self.deposits.len()
    }

    /// How long the oldest deposit has been waiting at `now`, or zero when none is.
    pub(crate) fn oldest_age(&self, now: Instant) -> Duration {
        self.deposits
            .first()
            .map(|(_, at)| now.saturating_duration_since(*at))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(seed: u8) -> DepositNonce {
        DepositNonce::new([seed; 32])
    }

    #[test]
    fn nothing_waiting_is_zero() {
        let unminted = Unminted::default();
        assert_eq!(unminted.count(), 0);
        assert_eq!(unminted.oldest_age(Instant::now()), Duration::ZERO);
    }

    /// A minted deposit is dropped, and the age is the oldest of those still waiting.
    #[test]
    fn minted_deposits_are_dropped_and_the_oldest_remaining_sets_the_age() {
        let start = Instant::now();
        let mut unminted = Unminted::default();
        unminted.submitted([nonce(1), nonce(2)], start);
        unminted.submitted([nonce(3)], start + Duration::from_secs(10));
        assert_eq!(
            unminted.nonces().collect::<Vec<_>>(),
            [nonce(1), nonce(2), nonce(3)]
        );

        let now = start + Duration::from_secs(25);
        assert_eq!(unminted.oldest_age(now), Duration::from_secs(25));

        unminted.retain(&[nonce(3)]);
        assert_eq!(unminted.count(), 1);
        assert_eq!(unminted.oldest_age(now), Duration::from_secs(15));

        unminted.retain(&[]);
        assert_eq!(unminted.count(), 0);
        assert_eq!(unminted.oldest_age(now), Duration::ZERO);
    }
}
