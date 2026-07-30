//! **Recovery-policy validation.**
//!
//! The stale-claim threshold is validated STRICTLY beyond the computed submit envelope
//! (`max_retry_attempts × submit_deadline_ms + exponential backoff`), so a live driver can never be
//! reclaimed while its submit is legitimately in flight. Three gaps a looser suite would leave are
//! closed here:
//!
//! * the envelope's BACKOFF term is now exercised with NON-ZERO `backoff_base_ms` and asserted
//!   exactly (a mutation that drops the backoff contribution must fail here);
//! * a ZERO `submit_deadline_ms` — which would make every submit time out instantly and defer every
//!   deposit forever — is refused with a specific typed error;
//! * `RecoveryPolicy::new` enforces its documented ABSOLUTE floor even for a caller-supplied
//!   minimum below it.
//!
//! Every negative case asserts the SPECIFIC error and its relevant fields (
//! assert-specific-error-in-tests), not a bare `is_err()`.

use assert_matches::assert_matches;
use xreserve_deposit_relayer::config::{RecoveryPolicy, RelayerConfig};
use xreserve_deposit_relayer::error::RelayerError;

/// A config with every recovery-relevant knob set — INCLUDING `backoff_base_ms`, so the envelope's
/// backoff term is exercised rather than zeroed away.
fn config_with(
    retry_batch_size: i64,
    stale_claim_secs: i64,
    max_retry_attempts: u32,
    submit_deadline_ms: u64,
    backoff_base_ms: u64,
) -> RelayerConfig {
    let mut value = serde_json::to_value(RelayerConfig::default()).expect("serialize default");
    value["retry_batch_size"] = serde_json::json!(retry_batch_size);
    value["stale_claim_secs"] = serde_json::json!(stale_claim_secs);
    value["max_retry_attempts"] = serde_json::json!(max_retry_attempts);
    value["submit_deadline_ms"] = serde_json::json!(submit_deadline_ms);
    value["backoff_base_ms"] = serde_json::json!(backoff_base_ms);
    serde_json::from_value(value).expect("deserialize")
}

/// The package default is a VALID recovery policy — the positive control.
#[test]
fn the_default_config_yields_a_valid_recovery_policy() {
    let policy = RelayerConfig::default()
        .recovery_policy()
        .expect("the package defaults must be a valid recovery policy");
    assert!(policy.retry_batch_size() >= 1);
    assert!(policy.stale_claim_secs() >= RecoveryPolicy::MIN_STALE_CLAIM_SECS);
}

/// `retry_batch_size = 0` is refused with the SPECIFIC error and field.
#[test]
fn a_zero_retry_batch_size_is_refused() {
    let err = config_with(0, 10_000, 3, 1_000, 0)
        .recovery_policy()
        .expect_err("a zero retry batch strands every retry");
    assert_matches!(
        err,
        RelayerError::BadRecoveryPolicy {
            retry_batch_size: 0,
            ..
        }
    );
}

/// `stale_claim_secs = 0` is refused with the SPECIFIC error and field.
#[test]
fn a_zero_stale_claim_threshold_is_refused() {
    let err = config_with(100, 0, 3, 1_000, 0)
        .recovery_policy()
        .expect_err("a zero stale threshold races live submits");
    assert_matches!(
        err,
        RelayerError::BadRecoveryPolicy {
            stale_claim_secs: 0,
            ..
        }
    );
}

/// **The envelope INCLUDES the exponential backoff — exactly.** 3 attempts × 30 s + backoff (`5 s ·
/// (2^0 + 2^1)` capped, upper-bounded as 2 gaps × `5 s · 2^2` = 40 s) = 130 s. This value is what
/// the threshold is validated against; a mutation that drops the backoff term makes it 90 s, so
/// this exact assertion fails.
#[test]
fn the_submit_envelope_includes_the_backoff_term_exactly() {
    let with_backoff = config_with(100, 10_000, 3, 30_000, 5_000).submit_worst_case_secs();
    let without_backoff = config_with(100, 10_000, 3, 30_000, 0).submit_worst_case_secs();

    assert_eq!(
        without_backoff, 90,
        "3 attempts × 30s with no backoff is a 90s envelope"
    );
    assert_eq!(
        with_backoff, 130,
        "the same config with 5s backoff base must add the backoff term (40s) → 130s"
    );
    assert!(
        with_backoff > without_backoff,
        "the backoff term must widen the envelope"
    );
}

/// **The cross-field boundary WITH backoff.** With the 130 s envelope above, a threshold at or
/// below it is refused (the error names 131 as the required minimum) and one second beyond is
/// accepted. Crucially a threshold of 100 s — which WOULD be accepted if the envelope ignored
/// backoff (90 s) — is REFUSED, so dropping the backoff term is caught here too.
#[test]
fn the_stale_threshold_must_exceed_the_backoff_inclusive_envelope() {
    let attempts = 3;
    let deadline = 30_000;
    let backoff = 5_000;
    let envelope = 130;

    // exactly at the envelope — refused, required minimum is envelope + 1
    assert_matches!(
        config_with(100, envelope as i64, attempts, deadline, backoff).recovery_policy(),
        Err(RelayerError::BadRecoveryPolicy { stale_claim_secs, required_min_stale_secs, .. })
            if stale_claim_secs == envelope && required_min_stale_secs == envelope + 1
    );

    // 100 s — inside the backoff-inclusive envelope (130), though ABOVE the backoff-free one (90).
    // This is the case that catches a dropped backoff term.
    assert_matches!(
        config_with(100, 100, attempts, deadline, backoff).recovery_policy(),
        Err(RelayerError::BadRecoveryPolicy { stale_claim_secs: 100, required_min_stale_secs, .. })
            if required_min_stale_secs == envelope + 1
    );

    // one second beyond the envelope — accepted
    let policy = config_with(100, (envelope + 1) as i64, attempts, deadline, backoff)
        .recovery_policy()
        .expect("a threshold strictly beyond the backoff-inclusive envelope is safe");
    assert_eq!(policy.stale_claim_secs(), envelope + 1);
}

/// **A zero submit deadline is refused** with a specific typed error. A 0 ms deadline makes
/// `Duration::from_millis(0)` time out every async submit instantly, deferring every deposit to
/// `Failed` forever — the same silent-liveness class the validated policy exists to reject.
#[test]
fn a_zero_submit_deadline_is_refused() {
    let err = config_with(100, 10_000, 3, 0, 0)
        .recovery_policy()
        .expect_err("a zero submit deadline defers every deposit forever");
    assert_matches!(
        err,
        RelayerError::BadSubmitDeadline {
            submit_deadline_ms: 0
        }
    );

    // the smallest non-zero deadline is accepted (with a valid stale threshold)
    config_with(100, RecoveryPolicy::MIN_STALE_CLAIM_SECS as i64, 3, 1, 0)
        .recovery_policy()
        .expect("a 1ms deadline is a runnable (if aggressive) policy");
}

/// Below the ABSOLUTE floor is refused even when the submit envelope is tiny.
#[test]
fn the_absolute_floor_is_enforced_when_the_envelope_is_small() {
    // envelope = 1 attempt × 1 s = 1 s, so the binding minimum is the absolute floor (60 s)
    let below = config_with(
        100,
        (RecoveryPolicy::MIN_STALE_CLAIM_SECS - 1) as i64,
        1,
        1_000,
        0,
    )
    .recovery_policy()
    .expect_err("below the absolute floor is refused");
    assert_matches!(
        below,
        RelayerError::BadRecoveryPolicy { required_min_stale_secs, .. }
            if required_min_stale_secs == RecoveryPolicy::MIN_STALE_CLAIM_SECS
    );

    config_with(
        100,
        RecoveryPolicy::MIN_STALE_CLAIM_SECS as i64,
        1,
        1_000,
        0,
    )
    .recovery_policy()
    .expect("at the absolute floor with a tiny envelope is accepted");
}

/// `RecoveryPolicy::new` enforces its documented ABSOLUTE floor even when the caller supplies a
/// smaller minimum — it must not be a hole in the validated type's invariant that
/// `stale_claim_secs() >= 60`.
#[test]
fn the_constructor_enforces_the_absolute_floor_regardless_of_the_caller_minimum() {
    // the caller passes a minimum of 0, but the floor (60) still binds
    assert_matches!(
        RecoveryPolicy::new(1, 0, 0),
        Err(RelayerError::BadRecoveryPolicy { stale_claim_secs: 0, required_min_stale_secs, .. })
            if required_min_stale_secs == RecoveryPolicy::MIN_STALE_CLAIM_SECS
    );
    assert_matches!(
        RecoveryPolicy::new(1, RecoveryPolicy::MIN_STALE_CLAIM_SECS - 1, 0),
        Err(RelayerError::BadRecoveryPolicy { required_min_stale_secs, .. })
            if required_min_stale_secs == RecoveryPolicy::MIN_STALE_CLAIM_SECS
    );
    // at the floor with a caller minimum of 0 — accepted, and the accessor upholds its >= 60 invariant
    let policy = RecoveryPolicy::new(1, RecoveryPolicy::MIN_STALE_CLAIM_SECS, 0)
        .expect("at the absolute floor is accepted");
    assert!(policy.stale_claim_secs() >= RecoveryPolicy::MIN_STALE_CLAIM_SECS);
}

/// `RecoveryPolicy::new` still enforces a caller minimum ABOVE the floor, with the specific error.
#[test]
fn the_constructor_enforces_a_caller_minimum_above_the_floor() {
    let min = 200; // above the absolute floor
    assert!(RecoveryPolicy::new(1, min, min).is_ok());
    assert_matches!(
        RecoveryPolicy::new(0, min, min),
        Err(RelayerError::BadRecoveryPolicy {
            retry_batch_size: 0,
            ..
        })
    );
    assert_matches!(
        RecoveryPolicy::new(100, min - 1, min),
        Err(RelayerError::BadRecoveryPolicy { stale_claim_secs, required_min_stale_secs, .. })
            if stale_claim_secs == min - 1 && required_min_stale_secs == min
    );
}
