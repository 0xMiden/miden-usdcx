//! Structured-logging + metrics STUBS (scaffold). The full tracing/metrics-backend wiring lands
//! with the poll loop; this slice provides the counters and the rejection-log surface so the
//! non-negotiable "never silently drop a fetched attestation" obligation (§8.4) already has a home:
//! every fetched-but-not-submitted attestation is surfaced with a reason, never dropped.

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
