//! **The cycle-duration histogram, surfaced AND correct at the top bound** (round-4 finding 1 +
//! round-5 finding 1).
//!
//! Round 4 surfaced the bucket series, but `Histogram::bucket` returned the TOTAL count for any `le`
//! at or above the last finite bound — so `cycle_ms_le_30000` silently included cycles LONGER than 30
//! seconds and was always identical to `cycle_ms_le_inf`, hiding exactly the long-tail stalls the
//! histogram exists to expose. The finite buckets now sum only the samples actually binned (≤ their
//! bound); the total (`+Inf`) is returned ONLY for the explicit `u64::MAX` query. These tests use an
//! OVER-BOUND sample so the two genuinely differ.

use xreserve_deposit_relayer::observability::{Histogram, RelayerMetrics};

/// The last finite bound (30 s), and a sample well past it.
const TOP_BOUND_MS: u64 = 30_000;
const OVER_BOUND_MS: u64 = 45_000;

/// **The adversarial overflow case, at the `Histogram` level.** A sample above the top bound is in the
/// `+Inf` total but in NO finite bucket — so `bucket(TOP_BOUND)` must EXCLUDE it while `bucket(u64::MAX)`
/// includes it. Round 4 returned the total for both, collapsing the long tail.
#[test]
fn the_top_finite_bucket_excludes_over_bound_samples() {
    let mut h = Histogram::cycle_duration_ms();
    h.observe(3); // a fast cycle
    h.observe(OVER_BOUND_MS); // a 45s stall — past the top bound

    assert_eq!(
        h.bucket(TOP_BOUND_MS),
        1,
        "le=30000 must count only the samples <= 30s (the 3ms one), NOT the 45s stall"
    );
    assert_eq!(
        h.bucket(u64::MAX),
        2,
        "the +Inf query must count every sample, including the over-bound stall"
    );
    assert_eq!(h.count(), 2, "both samples are in the total");
    assert!(
        h.bucket(TOP_BOUND_MS) < h.bucket(u64::MAX),
        "the top finite bucket must be strictly below +Inf when a sample overflows — otherwise the \
         long tail is hidden"
    );
}

/// The exported snapshot carries the SAME corrected semantics: the top finite cumulative excludes the
/// over-bound sample, and `cycle_duration_samples` (the `+Inf`) includes it.
#[test]
fn the_snapshot_top_bucket_excludes_over_bound_samples() {
    let mut metrics = RelayerMetrics::new();
    metrics.record_cycle_duration_ms(3);
    metrics.record_cycle_duration_ms(4_000);
    metrics.record_cycle_duration_ms(OVER_BOUND_MS);

    let snap = metrics.snapshot();
    assert_eq!(snap.cycle_duration_samples, 3, "+Inf counts all three");
    assert_eq!(snap.cycle_duration_ms_sum, 3 + 4_000 + OVER_BOUND_MS);

    let bounds = snap.cycle_duration_bounds;
    let cumulative = &snap.cycle_duration_cumulative;
    assert!(
        cumulative.windows(2).all(|w| w[0] <= w[1]),
        "a cumulative histogram is non-decreasing: {cumulative:?}"
    );
    let at = |le: u64| cumulative[bounds.iter().position(|b| *b == le).expect("bound")];
    assert_eq!(at(5), 1, "only the 3ms sample is <= 5ms");
    assert_eq!(at(5_000), 2, "the 3ms and 4000ms samples are <= 5000ms");
    assert_eq!(
        at(TOP_BOUND_MS),
        2,
        "the top finite bucket excludes the 45s stall"
    );
    assert_eq!(
        *cumulative.last().unwrap(),
        2,
        "the top finite cumulative is strictly below the {} total samples — the long tail is visible",
        snap.cycle_duration_samples
    );
    assert!(
        *cumulative.last().unwrap() < snap.cycle_duration_samples,
        "the top finite bucket must not equal the total when a sample overflows"
    );
}

/// `render` emits the corrected series: the top finite bound and `+Inf` differ when a sample overflows.
#[test]
fn the_render_distinguishes_the_top_bound_from_inf() {
    let mut metrics = RelayerMetrics::new();
    metrics.record_cycle_duration_ms(3);
    metrics.record_cycle_duration_ms(OVER_BOUND_MS);

    let line = metrics.snapshot().render();
    assert!(line.contains("cycle_ms_le_5=1"), "{line}");
    assert!(
        line.contains("cycle_ms_le_30000=1"),
        "the top finite bucket must exclude the 45s stall: {line}"
    );
    assert!(
        line.contains("cycle_ms_le_inf=2"),
        "the +Inf must include the 45s stall: {line}"
    );
    assert!(
        line.contains(&format!("cycle_ms_sum={}", 3 + OVER_BOUND_MS)),
        "{line}"
    );
}

/// All-under-bound samples still behave: every finite bucket at/above the max sample equals the total.
#[test]
fn samples_under_the_top_bound_fill_the_finite_buckets() {
    let mut h = Histogram::cycle_duration_ms();
    h.observe(3);
    h.observe(4_000);
    assert_eq!(h.bucket(5), 1);
    assert_eq!(h.bucket(5_000), 2);
    assert_eq!(
        h.bucket(TOP_BOUND_MS),
        2,
        "with no overflow, the top finite bucket holds every sample"
    );
    assert_eq!(h.bucket(u64::MAX), 2);
}

/// An empty histogram renders zeros across the whole series — a dashboard scraping at startup finds
/// the keys, not a gap.
#[test]
fn an_empty_histogram_still_renders_the_series() {
    let line = RelayerMetrics::new().snapshot().render();
    assert!(line.contains("cycle_ms_le_inf=0"), "{line}");
    assert!(line.contains("cycle_ms_sum=0"), "{line}");
    assert!(line.contains("cycle_ms_le_5=0"), "{line}");
    assert!(line.contains("cycle_ms_le_30000=0"), "{line}");
}
