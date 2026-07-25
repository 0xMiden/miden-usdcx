//! [`RunError`] — why a B3→B10 run stopped, named by the stage that refused.
//!
//! Split from [`super`] under G3's ~700-line Rust ceiling.

use core::fmt;

use super::{ONE_BATCH_PER_BURN, ONE_INTENT_PER_BURN};
use crate::circle::wire::SchemaError;
use crate::error::{
    DiscoveryReject, ListenerError, QuorumError, SignError, SubmitGateError, ValidationMismatch,
};
use crate::evidence::EvidenceError;
use crate::submit::SubmitError;

/// Why a B3→B10 run stopped, named by the stage that refused.
///
/// It is a family of its own rather than more variants on [`ListenerError`], which is the crate's
/// CIRCLE-facing taxonomy (a base URL, an HTTP status, a body that would not decode). Folding B3's
/// discovery rejects, B5's mismatch, the quorum contract and the ledger into it would make every
/// caller of a Circle driver match on withdrawal-orchestration variants that driver can never return.
/// So each stage's own error is carried UNFLATTENED (`preserve-error-source`), and this enum says
/// only which stage produced it.
///
/// Every variant means the same operational thing: **this burn stopped, and no stage after it ran.**
#[derive(Debug)]
#[non_exhaustive]
pub enum RunError {
    /// **B3** — the discovered note is not a burn this listener acts on: a wrong tag, a private note,
    /// or a payload/sender that did not decode. Circle was never touched.
    Discovery(DiscoveryReject),

    /// **B4** — the `DC-9` request could not be built from the burn + config (an out-of-range
    /// `remoteDomain`, or a `remoteDomain` equal to the burn's destination domain).
    Request(SchemaError),

    /// **B5 / B10** — Circle's answer, surfaced with its exact [`ListenerError`]. Never softened: a
    /// `500`, an unreadable body, or an exhausted poll is not a withdrawal.
    Circle(ListenerError),

    /// **B5, THE gate** — Circle's returned data does not match the burn payload
    /// (`INV-CIRCLE-CANONICAL-WITHDRAWAL`). This is the DO-NOT-SIGN abort: no
    /// [`ValidatedWithdrawal`](crate::validate::ValidatedWithdrawal) was minted, so no signature over
    /// the mismatching data can exist and no submission can follow.
    Validation(ValidationMismatch),

    /// **B5** — Circle returned a number of prepared batches other than [`ONE_BATCH_PER_BURN`] for a
    /// single-burn request. Refused BEFORE the signer: one burn is one payload is one batch, and a
    /// signature over an extra batch's digest is the artifact that must not exist.
    BatchCardinality { returned: usize },

    /// **B5** — the one prepared batch carried a number of burn intents other than
    /// [`ONE_INTENT_PER_BURN`]. Refused BEFORE the signer, and its own variant rather than a shade of
    /// [`Self::BatchCardinality`] because it is the case a batch count cannot see.
    ///
    /// `burnIntents` is `1..=10` on the wire, and B5 clears every intent that matches the burn
    /// payload — so repeats of the burn's own intent all pass. One digest covers the whole set, so one
    /// signature would authorize every member: one burn, N releases. An operator reading this variant
    /// is being told Circle prepared a SET for a single-burn request, which is a different
    /// conversation from "Circle prepared several batches".
    IntentCardinality { returned: usize },

    /// **B6** — the signer refused a cleared digest.
    Sign(SignError),

    /// **B6** — the signer returned a number of signature sets other than the validated batch count.
    /// A set that does not line up 1:1 with the digests cannot be assembled against them, and
    /// guessing an alignment is how a batch is submitted with another batch's signatures.
    SignerCardinality { batches: usize, signed: usize },

    /// **B6** — the signatures are not the shape Circle's source-chain verifier accepts: not exactly
    /// the threshold, one not verifying to its claimed signer, a duplicate signer, or not ascending.
    /// No [`QuorumBundle`](crate::attester::QuorumBundle), therefore no batch, therefore no
    /// `POST /v1/withdraw`.
    Quorum(QuorumError),

    /// **B7** — the `DC-8` evidence could not be assembled honestly. Fail-closed: no package, no
    /// submission (`INV-BURN-EVIDENCE-TRUST`).
    Evidence(EvidenceError),

    /// **B7** — the pre-submit signer-allowlist gate refused: a signer that is not a registered
    /// attester, or no allowlist configured at all. ZERO `/v1/withdraw` calls.
    Gate(SubmitGateError),

    /// **B7** — the submission itself: the ledger refused, or Circle's answer was one the submission
    /// path surfaces rather than resolves.
    Submit(SubmitError),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(source) => write!(f, "b3 discovery refused the note: {source}"),
            Self::Request(source) => write!(f, "b4 could not build the prepare request: {source}"),
            Self::Circle(source) => write!(f, "circle refused the withdrawal flow: {source}"),
            Self::Validation(source) => write!(
                f,
                "b5 validation failed, so the burn is not signed: {source}"
            ),
            Self::BatchCardinality { returned } => write!(
                f,
                "b5 returned {returned} prepared batches for one burn, expected exactly \
                 {ONE_BATCH_PER_BURN}"
            ),
            Self::IntentCardinality { returned } => write!(
                f,
                "b5 returned a batch of {returned} burn intents for one burn, expected exactly \
                 {ONE_INTENT_PER_BURN} — one digest would authorize every one of them"
            ),
            Self::Sign(source) => write!(f, "b6 signing failed: {source}"),
            Self::SignerCardinality { batches, signed } => write!(
                f,
                "b6 signed {signed} batches but {batches} were validated; they must line up 1:1"
            ),
            Self::Quorum(source) => {
                write!(f, "b6 could not assemble the signature quorum: {source}")
            }
            Self::Evidence(source) => {
                write!(f, "b7 could not assemble the burn evidence: {source}")
            }
            Self::Gate(source) => write!(f, "b7 refused to authorize the submission: {source}"),
            Self::Submit(source) => write!(f, "b7 could not submit the withdrawal: {source}"),
        }
    }
}

impl core::error::Error for RunError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Discovery(source) => Some(source),
            Self::Request(source) => Some(source),
            Self::Circle(source) => Some(source),
            Self::Validation(source) => Some(source),
            Self::Sign(source) => Some(source),
            Self::Quorum(source) => Some(source),
            Self::Evidence(source) => Some(source),
            Self::Gate(source) => Some(source),
            Self::Submit(source) => Some(source),
            Self::BatchCardinality { .. }
            | Self::IntentCardinality { .. }
            | Self::SignerCardinality { .. } => None,
        }
    }
}

impl From<DiscoveryReject> for RunError {
    fn from(source: DiscoveryReject) -> Self {
        Self::Discovery(source)
    }
}

impl From<SchemaError> for RunError {
    fn from(source: SchemaError) -> Self {
        Self::Request(source)
    }
}

impl From<ListenerError> for RunError {
    fn from(source: ListenerError) -> Self {
        Self::Circle(source)
    }
}

impl From<ValidationMismatch> for RunError {
    fn from(source: ValidationMismatch) -> Self {
        Self::Validation(source)
    }
}

impl From<SignError> for RunError {
    fn from(source: SignError) -> Self {
        Self::Sign(source)
    }
}

impl From<QuorumError> for RunError {
    fn from(source: QuorumError) -> Self {
        Self::Quorum(source)
    }
}

impl From<EvidenceError> for RunError {
    fn from(source: EvidenceError) -> Self {
        Self::Evidence(source)
    }
}

impl From<SubmitGateError> for RunError {
    fn from(source: SubmitGateError) -> Self {
        Self::Gate(source)
    }
}

impl From<SubmitError> for RunError {
    fn from(source: SubmitError) -> Self {
        Self::Submit(source)
    }
}
