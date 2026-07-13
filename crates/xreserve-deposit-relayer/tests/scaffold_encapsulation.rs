//! `tests/scaffold_encapsulation.rs` — the scaffold data types (`RelayerConfig`, `RelayerMetrics`,
//! `RejectionRecord`) are ENCAPSULATED: private fields, read-only accessors, and controlled
//! construction (per the repo's private-fields-with-accessors + validate-in-constructor checklists).
//! These tests exercise the encapsulated public APIs so a regression in a constructor, a
//! mutator→field mapping, or an accessor is caught (they are not tautological: the metrics case
//! would fail if any `record_*` mutator touched the wrong counter).

use xreserve_deposit_relayer::config::RelayerConfig;
use xreserve_deposit_relayer::observability::{RejectionRecord, RelayerMetrics};

#[test]
fn config_default_exposes_documented_values_via_accessors() {
    let cfg = RelayerConfig::default();
    // CIR-API-4 rate ceilings and the Q-API-AUTH "no credential embedded" posture, read-only.
    assert_eq!(cfg.rate_qps_per_ip(), 5);
    assert_eq!(cfg.rate_qps_global(), 35);
    assert_eq!(cfg.api_auth_token(), None);
    assert!(cfg.circle_base_url().starts_with("https://"));
    assert_eq!(cfg.xusdc_identifier(), &[0u8; 32]);
}

#[test]
fn config_serde_round_trips() {
    let cfg = RelayerConfig::default();
    let json = serde_json::to_string(&cfg).expect("config serializes");
    let back: RelayerConfig = serde_json::from_str(&json).expect("config deserializes");
    assert_eq!(cfg, back, "config round-trips through serde");
}

#[test]
fn metrics_start_at_zero_and_each_mutator_targets_its_own_counter() {
    let mut m = RelayerMetrics::new();
    assert_eq!(m.attestations_fetched(), 0);
    assert_eq!(m.attestations_rejected(), 0);
    assert_eq!(m.mint_notes_built(), 0);
    assert_eq!(m.mint_notes_submitted(), 0);
    assert_eq!(m.submit_retries(), 0);

    // Distinct call counts per counter so a mutator wired to the wrong field is caught.
    m.record_fetched();
    m.record_fetched();
    m.record_fetched();
    m.record_rejected();
    m.record_rejected();
    m.record_note_built();
    m.record_note_submitted();
    m.record_submit_retry();

    assert_eq!(m.attestations_fetched(), 3);
    assert_eq!(m.attestations_rejected(), 2);
    assert_eq!(m.mint_notes_built(), 1);
    assert_eq!(m.mint_notes_submitted(), 1);
    assert_eq!(m.submit_retries(), 1);
}

#[test]
fn rejection_record_round_trips_through_accessors() {
    // A fetched-but-not-submitted attestation is surfaced with a traceable id + reason (§8.4).
    let rec = RejectionRecord::new("0xdeadbeef", "deposit intent magic mismatch");
    assert_eq!(rec.payload_id(), "0xdeadbeef");
    assert_eq!(rec.reason(), "deposit intent magic mismatch");
}
