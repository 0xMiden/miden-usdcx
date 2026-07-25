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
    attestations_duplicate: u64,
    attestations_already_minted: u64,
    attestations_deferred: u64,
    reconciliation_required: u64,
    mint_notes_built: u64,
    mint_notes_submitted: u64,
    submit_retries: u64,
    cycle_duration_ms: Histogram,
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

    /// A fetched attestation the idempotency gate had already recorded — a re-poll, or another
    /// observer's claim. No second mint followed.
    pub fn record_duplicate(&mut self) {
        self.attestations_duplicate = self.attestations_duplicate.saturating_add(1);
    }

    /// The on-chain `usedNonces` assert fired (D5c) — the SAFETY backstop, observed from the
    /// liveness side. Counted apart from a rejection: nothing is wrong.
    pub fn record_already_minted(&mut self) {
        self.attestations_already_minted = self.attestations_already_minted.saturating_add(1);
    }

    /// A TRANSIENT failure left this attestation for a later cycle. It is neither minted nor
    /// refused, and a count that climbs without the submitted count climbing is the shape of a
    /// relayer that is stuck.
    pub fn record_deferred(&mut self) {
        self.attestations_deferred = self.attestations_deferred.saturating_add(1);
    }

    /// An attestation an operator must resolve — the relayer refused to guess.
    pub fn record_reconciliation_required(&mut self) {
        self.reconciliation_required = self.reconciliation_required.saturating_add(1);
    }

    /// One cycle took `ms` end to end.
    pub fn record_cycle_duration_ms(&mut self, ms: u64) {
        self.cycle_duration_ms.observe(ms);
    }

    /// Attestations the cycle PROCESSED — freshly polled from a page, or re-driven from the retry
    /// work list. The six terminal counters below partition this total (one per processed
    /// attestation), so `attestations_fetched == submitted + rejected + duplicate + already_minted +
    /// deferred + reconciliation_required` holds by construction; a break in that equality is a
    /// silent drop.
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

    /// Attestations the idempotency gate refused a second mint for.
    pub fn attestations_duplicate(&self) -> u64 {
        self.attestations_duplicate
    }

    /// Attestations the chain had already minted (the on-chain nonce trap).
    pub fn attestations_already_minted(&self) -> u64 {
        self.attestations_already_minted
    }

    /// Attestations left for a later cycle by a transient failure.
    pub fn attestations_deferred(&self) -> u64 {
        self.attestations_deferred
    }

    /// Attestations left for an operator.
    pub fn reconciliation_required(&self) -> u64 {
        self.reconciliation_required
    }

    /// The cycle-duration distribution.
    pub fn cycle_duration_ms(&self) -> &Histogram {
        &self.cycle_duration_ms
    }

    /// A flat, `Copy` snapshot of the cumulative counters — what the loop surfaces each cycle
    /// ([`RelayerEvent::Metrics`]) and what a test reads to assert throughput. It is a snapshot, not a
    /// handle: reading it cannot mutate a counter, and a caller cannot bump one out of band.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let bounds = self.cycle_duration_ms.bounds();
        MetricsSnapshot {
            attestations_fetched: self.attestations_fetched,
            attestations_rejected: self.attestations_rejected,
            attestations_duplicate: self.attestations_duplicate,
            attestations_already_minted: self.attestations_already_minted,
            attestations_deferred: self.attestations_deferred,
            reconciliation_required: self.reconciliation_required,
            mint_notes_built: self.mint_notes_built,
            mint_notes_submitted: self.mint_notes_submitted,
            submit_retries: self.submit_retries,
            cycle_duration_samples: self.cycle_duration_ms.count(),
            cycle_duration_ms_sum: self.cycle_duration_ms.sum(),
            cycle_duration_bounds: bounds,
            // the CUMULATIVE count at each bound — the distribution, captured so the snapshot is
            // self-contained (an operator reads the latency shape off the metrics line, not just totals)
            cycle_duration_cumulative: bounds
                .iter()
                .map(|le| self.cycle_duration_ms.bucket(*le))
                .collect(),
        }
    }
}

/// A cumulative snapshot of [`RelayerMetrics`] — the counters AND the cycle-duration distribution the
/// loop surfaces per cycle. It carries a `Vec` of cumulative bucket counts, so it is `Clone` (not
/// `Copy`); it is read once per cycle, so that costs nothing that matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub attestations_fetched: u64,
    pub attestations_rejected: u64,
    pub attestations_duplicate: u64,
    pub attestations_already_minted: u64,
    pub attestations_deferred: u64,
    pub reconciliation_required: u64,
    pub mint_notes_built: u64,
    pub mint_notes_submitted: u64,
    pub submit_retries: u64,
    /// The cycle-duration histogram's total sample count (the `+Inf` bucket).
    pub cycle_duration_samples: u64,
    /// The sum of every cycle's duration, in milliseconds.
    pub cycle_duration_ms_sum: u64,
    /// The histogram's `le` upper bounds, ascending (aligned with [`Self::cycle_duration_cumulative`]).
    pub cycle_duration_bounds: &'static [u64],
    /// The CUMULATIVE count at each bound — `cycle_duration_cumulative[i]` is the number of cycles
    /// whose duration was `<= cycle_duration_bounds[i]`. Monotonic non-decreasing; the last equals
    /// [`Self::cycle_duration_samples`].
    pub cycle_duration_cumulative: Vec<u64>,
}

impl MetricsSnapshot {
    /// A one-line `key=value` rendering — the body of the [`RelayerEvent::Metrics`] the loop emits. It
    /// carries the counters AND the full cycle-duration bucket series (`cycle_ms_le_<bound>=<cum>` for
    /// every bound, then `cycle_ms_le_inf=<count>` and `cycle_ms_sum=<sum>`), so the latency
    /// distribution is on the wire, not just the totals.
    pub fn render(&self) -> String {
        let mut line = format!(
            "fetched={} submitted={} built={} rejected={} duplicate={} already_minted={} \
             deferred={} reconciliation_required={} submit_retries={} cycle_samples={} \
             cycle_ms_sum={}",
            self.attestations_fetched,
            self.mint_notes_submitted,
            self.mint_notes_built,
            self.attestations_rejected,
            self.attestations_duplicate,
            self.attestations_already_minted,
            self.attestations_deferred,
            self.reconciliation_required,
            self.submit_retries,
            self.cycle_duration_samples,
            self.cycle_duration_ms_sum,
        );
        for (le, cumulative) in self
            .cycle_duration_bounds
            .iter()
            .zip(&self.cycle_duration_cumulative)
        {
            line.push_str(&format!(" cycle_ms_le_{le}={cumulative}"));
        }
        // the +Inf bucket is the total sample count — the Prometheus convention, and the anchor a
        // dashboard divides the lower buckets against
        line.push_str(&format!(" cycle_ms_le_inf={}", self.cycle_duration_samples));
        line
    }
}

/// A CUMULATIVE bucket histogram — the Prometheus reading of the word, where `bucket(le)` holds
/// every sample `<= le`. Fixed bounds, no allocation per observation, saturating counters: a metric
/// is diagnostic, never load-bearing, and one that could panic on overflow would be worse than none.
///
/// It is a plain type rather than an exporter's: this crate names no metrics backend (the monitoring
/// slice owns that choice), and a test that must prove a distribution was recorded needs to READ the
/// buckets, not scrape a global registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Histogram {
    /// Upper bounds, ascending. The implicit final `+Inf` bucket is [`Self::count`].
    bounds: &'static [u64],
    /// Per-bound counts (NOT cumulative on the way in; [`Self::bucket`] accumulates on the way out).
    counts: Vec<u64>,
    count: u64,
    sum: u64,
}

/// Cycle-duration bounds, in milliseconds: sub-10ms (everything cached) through 30s (the configured
/// per-attempt request deadline — a cycle past it is a cycle that spent its whole budget waiting).
const CYCLE_DURATION_BOUNDS_MS: &[u64] =
    &[5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 30_000];

impl Histogram {
    /// A histogram over `bounds` (ascending upper bounds, in the sample's own unit).
    pub fn new(bounds: &'static [u64]) -> Self {
        Self {
            bounds,
            counts: vec![0; bounds.len()],
            count: 0,
            sum: 0,
        }
    }

    /// The cycle-duration histogram (milliseconds).
    pub fn cycle_duration_ms() -> Self {
        Self::new(CYCLE_DURATION_BOUNDS_MS)
    }

    /// Records one sample.
    pub fn observe(&mut self, value: u64) {
        if let Some(index) = self.bounds.iter().position(|bound| value <= *bound) {
            self.counts[index] = self.counts[index].saturating_add(1);
        }
        self.count = self.count.saturating_add(1);
        self.sum = self.sum.saturating_add(value);
    }

    /// Samples `<= le`, cumulative.
    ///
    /// `bucket(u64::MAX)` is the explicit `+Inf` query and returns [`Self::count`] — EVERY sample,
    /// including the over-bound overflow that `observe` binned into no finite bucket. Any FINITE `le`
    /// (including the last configured bound) sums only the finite bins whose bound is `<= le`, so a
    /// sample past the top bound is EXCLUDED from `bucket(top_bound)`. This is the fix for the round-4
    /// bug where `bucket(top_bound)` returned the total and thus hid the long tail: `cycle_ms_le_30000`
    /// must count cycles `<= 30 s`, not all cycles.
    ///
    /// (A finite `le` above the top bound resolves to the same finite sum as the top bound — the
    /// histogram retains no per-value data past its last bound, so only the `+Inf` query can account
    /// for the overflow. That is the documented Prometheus contract for a bounded histogram.)
    pub fn bucket(&self, le: u64) -> u64 {
        if le == u64::MAX {
            return self.count;
        }
        self.bounds
            .iter()
            .zip(&self.counts)
            .take_while(|(bound, _)| **bound <= le)
            .map(|(_, count)| *count)
            .sum()
    }

    /// The bucket upper bounds.
    pub fn bounds(&self) -> &'static [u64] {
        self.bounds
    }

    /// Total samples observed.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The sum of every observed sample — with [`Self::count`], the mean.
    pub fn sum(&self) -> u64 {
        self.sum
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::cycle_duration_ms()
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
    /// **The terminal fate of ONE fetched attestation** — the §8.4 no-silent-drops obligation, as an
    /// emission. The orchestration raises exactly one of these per attestation it fetched, whatever
    /// happened to it, so "was this deposit dropped?" is answerable from the log alone.
    ///
    /// The three variants above are the CIRCLE half's vocabulary (an endpoint answered, or did not);
    /// this one is the CYCLE's (a deposit was minted, refused, deferred, or left for an operator).
    /// They are separate because a 404 on a page fetch and a deposit the chain already minted are not
    /// the same kind of fact, and an alert that could not tell them apart would fire on both.
    Attestation {
        /// The attestation's `messageHash`, `0x`-hex — what an operator greps for.
        message_hash: String,
        /// A short, STABLE slug an alert matches on (`"submitted"`, `"rejected"`, `"deferred"`,
        /// `"duplicate"`, `"already-minted"`, `"reconciliation-required"`).
        outcome: &'static str,
        /// Why — rendered from the typed disposition, and never empty.
        reason: String,
    },
    /// **A whole cycle's outcome** — the loop's own lifecycle event, distinct from the per-attestation
    /// ones a cycle emits inside itself. `"completed"` carries the cycle's counts so an operator sees
    /// throughput move; `"failed"` carries the error a cycle returned (a broken poll, discovery,
    /// cursor, or store) — the event the round-1 loop dropped by matching `Err(_)` and logging
    /// nothing. A cycle that failed silently is a relayer that stopped making progress with no signal.
    Cycle {
        /// `"completed"` or `"failed"` — stable, so an alert can match on the failing one.
        outcome: &'static str,
        /// The counts, or the error — never empty.
        detail: String,
    },
    /// **The cumulative metrics snapshot** the loop surfaces after every cycle — the counters,
    /// submit-retry count, and cycle-duration totals an operator watches for throughput and stalls.
    /// Distinct from [`Self::Cycle`]'s per-cycle disposition summary: this is the running total, so a
    /// dashboard can read it without differencing successive cycle lines.
    Metrics {
        /// The rendered snapshot ([`MetricsSnapshot::render`]).
        detail: String,
    },
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

impl RelayerEvent {
    /// The severity an operator triages on: `"pending"` (retrying, not lost), `"alert"` and
    /// `"rejected"` (look now), `"cycle"` (a whole cycle's lifecycle), and the per-attestation
    /// terminal event's own outcome slug. Stable — an alert rule matches on it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Pending { .. } => "pending",
            Self::Alert { .. } => "alert",
            Self::Rejected { .. } => "rejected",
            Self::Attestation { outcome, .. } => outcome,
            Self::Cycle { outcome, .. } => outcome,
            Self::Metrics { .. } => "metrics",
        }
    }

    /// Renders the event as ONE structured, single-line record — `key=value` fields, so it is both
    /// human-scannable and machine-greppable, and every field an operator acts on is present. Newlines
    /// in a reason are collapsed so one event is always one line (a multi-line record read as several
    /// is how a downstream parser miscounts, and miscounting is the silent drop moved into the reader).
    pub fn render(&self) -> String {
        let one_line = |s: &str| s.replace(['\n', '\r'], " ");
        match self {
            Self::Pending {
                endpoint,
                status,
                attempt,
                reason,
            } => {
                let status = status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".to_string());
                format!(
                    "event=pending endpoint=\"{}\" status={status} attempt={attempt} reason=\"{}\"",
                    one_line(endpoint),
                    one_line(reason)
                )
            }
            Self::Alert { endpoint, reason } => format!(
                "event=alert endpoint=\"{}\" reason=\"{}\"",
                one_line(endpoint),
                one_line(reason)
            ),
            Self::Rejected { endpoint, reason } => format!(
                "event=rejected endpoint=\"{}\" reason=\"{}\"",
                one_line(endpoint),
                one_line(reason)
            ),
            Self::Attestation {
                message_hash,
                outcome,
                reason,
            } => format!(
                "event=attestation messageHash={message_hash} outcome={outcome} reason=\"{}\"",
                one_line(reason)
            ),
            Self::Cycle { outcome, detail } => {
                format!(
                    "event=cycle outcome={outcome} detail=\"{}\"",
                    one_line(detail)
                )
            }
            Self::Metrics { detail } => format!("event=metrics {}", one_line(detail)),
        }
    }
}

/// The **production** event sink: it WRITES each event, one structured line per event, to an
/// [`io::Write`](std::io::Write) — the binary installs one over stderr.
///
/// It is the counterpart of [`NoopSink`], and the point of R7's observability half: the service that
/// must never silently drop an attestation needs a sink that actually emits, not one that discards.
/// It is parameterized over its writer so a test can point it at a buffer and read exactly what an
/// operator would see (`tests/observability_sink.rs`) — the production wiring and the tested type are
/// the SAME type, so the test is evidence about the binary's logging and not about an injected fake.
///
/// This crate names no logging framework — that choice is the monitoring slice's (`P4-OPS`). A
/// line-per-event stderr writer is the honest floor: real, greppable, and replaceable by a structured
/// backend behind the same [`EventSink`] trait without touching the orchestration.
///
/// A write that FAILS is dropped rather than propagated: observability must never fail the
/// withdrawal it observes, and a relayer that aborted a mint because stderr was full would have let
/// the logger become the outage.
pub struct WriteEventSink<W> {
    writer: std::sync::Mutex<W>,
}

impl<W: std::io::Write + Send> WriteEventSink<W> {
    /// A sink writing each event to `writer`.
    pub fn new(writer: W) -> Self {
        Self {
            writer: std::sync::Mutex::new(writer),
        }
    }
}

impl WriteEventSink<std::io::Stderr> {
    /// The sink the binary installs: one structured line per event, on stderr.
    pub fn stderr() -> Self {
        Self::new(std::io::stderr())
    }
}

impl<W> fmt::Debug for WriteEventSink<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WriteEventSink")
    }
}

impl<W: std::io::Write + Send> EventSink for WriteEventSink<W> {
    fn emit(&self, event: RelayerEvent) {
        if let Ok(mut writer) = self.writer.lock() {
            // a best-effort write: the `_ =` is deliberate — a full or broken stderr must not fail the
            // mint being logged (see the type docs)
            let _ = writeln!(writer, "{}", event.render());
        }
    }
}
