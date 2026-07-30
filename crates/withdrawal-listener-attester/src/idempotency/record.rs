//! The ledger's value types and its status machine.

use core::fmt;

/// A burn's stable identity in the ledger: its `burnTxId`, NORMALIZED.
///
/// # Why normalized, and why only this much
///
/// `burnTxId` is hex (`^0x[a-fA-F0-9]+$` on the response side; the request side has no documented
/// pattern at all — the asymmetry is the OpenAPI's). Hex is case-insensitive **as an identifier**:
/// the same burn rendered `0xAB…` and `0xab…` is one burn, and a ledger that treated them as two
/// would hand the second one a fresh claim and submit the same withdrawal twice. So the key
/// lower-cases the value and strips nothing else.
///
/// It does NOT canonicalize beyond that — no `0x` stripping, no leading-zero trimming, no length
/// bound. Whether a Miden transaction id is an acceptable `burnTxId` at all is OPEN, so the
/// value's structure is Circle's to settle; inventing a canonical form here would be this crate
/// deciding an open question. Two spellings that differ by more than case are treated as two burns
/// which fails toward a refused-by-Circle `409` (recoverable), not toward a double release.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BurnKey(String);

impl BurnKey {
    /// The key for `burn_tx_id`, as this burn's identity.
    pub fn new(burn_tx_id: impl AsRef<str>) -> Self {
        Self(burn_tx_id.as_ref().to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BurnKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a claimed burn sits in the submission machine.
///
/// It is deliberately NOT `#[non_exhaustive]`: every arm of the machine below must be forced to
/// confront a new state rather than fall into a catch-all, because a catch-all here is how a state
/// silently becomes re-claimable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionStatus {
    /// Claimed; the `POST /v1/withdraw` is in flight, or the process died while it was.
    ///
    /// **This BLOCKS resubmission, and there is no automatic way out.** The state is ambiguous —
    /// the POST may have reached Circle — and the only safe resolutions are an operator reconciling
    /// it against `GET /v1/withdrawal/{id}`, or Circle's own `409`. An age-based auto-reclaim would
    /// be an auto blind re-send (see the module docs).
    Pending,

    /// Circle answered `201`: the withdrawal exists. Terminal for submission purposes — the burn is
    /// never re-sent.
    Submitted,

    /// The withdrawal reached `finalized`, the ONE terminal success. Terminal.
    Finalized,

    /// The burn needs an OPERATOR. Every ambiguity lands here: a `409` with no `withdrawalId` to
    /// recover through, a `409` echoing another burn, an exhausted `5xx` budget, an unreadable
    /// `201`. Terminal, and blocking: what these have in common is that Circle may already be
    /// releasing the funds, so the one thing that must not happen next is another submission.
    ReconciliationRequired,

    /// Circle REJECTED the request deterministically (a `400`): nothing was created, so nothing can
    /// be double-released. This is the ONLY re-claimable state — the spec's "abort/fix-request"
    /// path — and the next `super::SubmitLedger::claim_burns` takes it back to `Pending`.
    Failed,
}

impl SubmissionStatus {
    /// The token stored in the database.
    pub(super) fn as_token(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Submitted => "submitted",
            Self::Finalized => "finalized",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::Failed => "failed",
        }
    }

    /// The token's status, or `None` for a token this build does not know. A `None` here becomes
    /// [`LedgerError::CorruptLedgerRecord`](super::LedgerError::CorruptLedgerRecord) — never
    /// "absent", which would re-claim and re-submit a burn that may already be settled.
    pub(super) fn parse(token: &str) -> Option<Self> {
        match token {
            "pending" => Some(Self::Pending),
            "submitted" => Some(Self::Submitted),
            "finalized" => Some(Self::Finalized),
            "reconciliation_required" => Some(Self::ReconciliationRequired),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Whether a second submission of this burn must NOT be made.
    ///
    /// True for everything except [`Self::Failed`]. The default is BLOCK: a burn is re-sendable
    /// only where it is positively known that Circle created nothing.
    pub fn blocks_resubmission(self) -> bool {
        !matches!(self, Self::Failed)
    }

    /// Whether the machine has a `self → to` edge.
    ///
    /// The shape, and the two absences that matter:
    ///
    /// * `Pending` may become anything — it is the in-flight state, and the answer decides.
    /// * `Submitted → Failed` does NOT exist. `Failed` is the re-claimable state; an edge into it
    ///   from a burn Circle has already accepted would let a retry driver re-POST a withdrawal that
    ///   may be mid-release. A submitted burn that goes wrong becomes `ReconciliationRequired`.
    /// * `Finalized` and `ReconciliationRequired` are terminal — nothing re-opens a settled burn.
    pub fn can_transition_to(self, to: Self) -> bool {
        match (self, to) {
            (Self::Pending, Self::Submitted)
            | (Self::Pending, Self::ReconciliationRequired)
            | (Self::Pending, Self::Failed)
            | (Self::Pending, Self::Finalized)
            | (Self::Submitted, Self::Finalized)
            | (Self::Submitted, Self::ReconciliationRequired) => true,
            // the re-claim (Failed → Pending) is acquired through `claim_burns`, atomically, and
            // routes through this same edge check
            (Self::Failed, Self::Pending) => true,
            _ => false,
        }
    }
}

impl fmt::Display for SubmissionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_token())
    }
}

/// One burn's ledger entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionRecord {
    pub(super) burn_key: BurnKey,
    /// The `withdrawalId` this burn is tied to, once one is known — from the `201` response, or
    /// from a `409`'s `conflict.withdrawalId`. `None` until then; it is the handle an operator
    /// polls.
    pub(super) withdrawal_id: Option<String>,
    pub(super) status: SubmissionStatus,
    /// Unix seconds. Diagnostic only — nothing decides on it.
    pub(super) timestamp: u64,
}

impl SubmissionRecord {
    pub fn burn_key(&self) -> &BurnKey {
        &self.burn_key
    }

    pub fn withdrawal_id(&self) -> Option<&str> {
        self.withdrawal_id.as_deref()
    }

    pub fn status(&self) -> SubmissionStatus {
        self.status
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

/// The answer to a claim — and the ONE place a submission decision is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// This caller owns the burns and may submit. One record per requested key, in order.
    Claimed(Vec<SubmissionRecord>),

    /// One of the burns is already accounted for — its record is carried so the caller can say
    /// WHICH, and in what state. **Nothing was claimed**: the whole set rolls back, so a refused
    /// request leaves no burn stranded in [`SubmissionStatus::Pending`].
    AlreadySeen(SubmissionRecord),
}
