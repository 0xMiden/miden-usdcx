//! Structured logging + metrics. The §8.4 obligation is non-negotiable: **no fetched attestation is
//! ever silently dropped** — every fetched-but-not-submitted attestation is surfaced with a reason.
//!
//! Two surfaces serve it. [`RelayerMetrics`] counts (scaffold; the poll loop wires it), and
//! [`EventSink`] receives one [`RelayerEvent`] per thing-that-happened-to-an-attestation: it is
//! `Pending` while a transient failure is being retried, `Alert` when an operator must look, and
//! `Rejected` when the input is permanently refused. The Circle client emits into whichever sink the
//! operator installed; the concrete backend (tracing / a metrics exporter) is wired in the
//! monitoring slice, and [`NoopSink`] is the default until then.
//!
//! The sink is a trait, not a concrete logger, for one reason beyond taste: a TEST can install a
//! recording sink and assert the obligation directly — that a 404 really was logged `Pending` rather
//! than swallowed, that a 400 really did alert. An obligation nothing can observe is an obligation
//! nobody keeps.

use core::fmt;

/// Relayer metric counters (§4 single-responsibility: `observability`). Private fields mutated only
/// through the `record_*` API and read only through the accessors — a counter cannot be set out of
/// band. Counters saturate rather than overflow: a metric is diagnostic, never load-bearing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RelayerMetrics {
    attestations_fetched: u64,
    attestations_rejected: u64,
    mint_notes_built: u64,
    mint_notes_submitted: u64,
    submit_retries: u64,
}

impl RelayerMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_fetched(&mut self) {
        self.attestations_fetched = self.attestations_fetched.saturating_add(1);
    }

    pub fn record_rejected(&mut self) {
        self.attestations_rejected = self.attestations_rejected.saturating_add(1);
    }

    pub fn record_note_built(&mut self) {
        self.mint_notes_built = self.mint_notes_built.saturating_add(1);
    }

    pub fn record_note_submitted(&mut self) {
        self.mint_notes_submitted = self.mint_notes_submitted.saturating_add(1);
    }

    pub fn record_submit_retry(&mut self) {
        self.submit_retries = self.submit_retries.saturating_add(1);
    }

    /// Attestations fetched from Circle.
    pub fn attestations_fetched(&self) -> u64 {
        self.attestations_fetched
    }

    /// Attestations rejected (structural / transport) before submission.
    pub fn attestations_rejected(&self) -> u64 {
        self.attestations_rejected
    }

    /// Mint notes built (validated triple crossed the seam).
    pub fn mint_notes_built(&self) -> u64 {
        self.mint_notes_built
    }

    /// Mint notes submitted to the Miden node.
    pub fn mint_notes_submitted(&self) -> u64 {
        self.mint_notes_submitted
    }

    /// Transient-submit retries.
    pub fn submit_retries(&self) -> u64 {
        self.submit_retries
    }
}

/// A structured record of a fetched-but-not-submitted attestation. Constructing and emitting one
/// (never dropping silently) is the §8.4 obligation; the concrete log/alert sink is wired in a
/// later slice. Fields are private with read-only accessors; build one via [`Self::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectionRecord {
    payload_id: String,
    reason: String,
}

impl RejectionRecord {
    /// Builds a rejection record from an attestation identifier (e.g. its `messageHash`, so the
    /// drop is traceable) and a human-readable reason (typically a `RelayerError` via `Display`).
    pub fn new(payload_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            payload_id: payload_id.into(),
            reason: reason.into(),
        }
    }

    /// The dropped attestation's identifier.
    pub fn payload_id(&self) -> &str {
        &self.payload_id
    }

    /// The reason the attestation was not submitted.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Emits a rejection record. Stub: the structured emission is wired with the observability backend
/// in a later slice; the record is surfaced here (not dropped) so the never-silently-drop rule is
/// preserved by construction.
pub fn log_rejection(record: &RejectionRecord) {
    let _ = record;
}

/// One thing that happened to an attestation on its way through the Circle half. The §8.4 failure
/// catalog maps one-to-one onto these three shapes, so every row of that table has an observable
/// emission and none can be "handled" by dropping it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayerEvent {
    /// A TRANSIENT failure is being retried — the attestation is NOT lost. A 404 (Circle has not
    /// published it yet), a 429, a 5xx, or a transport failure, each attempt logged with the status
    /// and attempt number so a stuck deposit is visible long before it is fatal.
    Pending {
        /// The Circle endpoint, e.g. `GET /v1/attestations/{depositMessageHash}`.
        endpoint: String,
        /// The HTTP status, when the failure had one (a transport failure does not).
        status: Option<u16>,
        /// 1-based attempt number that just failed.
        attempt: u32,
        /// The failure, rendered.
        reason: String,
    },
    /// An operator must look: a permanent rejection, a transient failure that crossed the alert
    /// threshold, or a retry budget that ran out.
    Alert { endpoint: String, reason: String },
    /// Permanently refused — a 400, a schema-decode failure, a `messageHash` that does not bind its
    /// payload, a malformed request parameter. It will never be submitted, and it is recorded here
    /// with its reason rather than dropped.
    Rejected { endpoint: String, reason: String },
}

/// Where [`RelayerEvent`]s go. Implementations must be cheap and non-blocking (the client emits
/// while holding no lock, but it does emit on the request path).
pub trait EventSink: fmt::Debug + Send + Sync {
    fn emit(&self, event: RelayerEvent);
}

/// The default sink: drops events. It exists so a `CircleClient` can be constructed before the
/// monitoring backend exists (this slice) — NOT as a licence to run production without one. It is
/// the only place in the relayer where an event may be discarded, and it is opt-out by installing a
/// real sink.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSink;

impl EventSink for NoopSink {
    fn emit(&self, _event: RelayerEvent) {}
}
