//! `tests/deferred_dependencies_doc.rs` — guards the operator-ratified reqwest deferral.
//!
//! reqwest (the Circle HTTP client) cannot be resolved under this repository's offline `--locked`
//! gate from the pinned cache, so — by explicit operator decision (round 5 escalation → round 6
//! ratification) — it is deferred to the Circle-facing slice. This test keeps that decision
//! DISCOVERABLE and DURABLE: it fails if `DEFERRED-DEPENDENCIES.md` goes missing or loses its
//! required content, if the `Cargo.toml` comment stops cross-referencing it, or if reqwest (or any
//! other crates.io dependency line) is silently re-added to this slice.

use std::path::Path;

/// The relayer crate's manifest directory (baked at compile time), so the guard reads the exact
/// files this crate ships regardless of the invoking CWD.
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn read_crate_file(rel: &str) -> String {
    let path = Path::new(MANIFEST_DIR).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The deferral record exists and carries the three operator-required elements: (a) WHAT + WHY,
/// (b) WHICH slice introduces it, (c) HOW it is provisioned offline there.
#[test]
fn deferred_dependencies_doc_exists_and_is_complete() {
    let doc = read_crate_file("DEFERRED-DEPENDENCIES.md");
    assert!(
        !doc.trim().is_empty(),
        "DEFERRED-DEPENDENCIES.md must not be empty"
    );
    let lower = doc.to_lowercase();

    // (a) names the deferred dependency and WHY it is deferred (the offline --locked gate cannot
    //     resolve it from the pinned cache).
    assert!(
        lower.contains("reqwest"),
        "must name the deferred dependency reqwest"
    );
    assert!(
        lower.contains("offline") && lower.contains("--locked"),
        "must state the offline `--locked` gate as the reason"
    );
    assert!(
        lower.contains("pinned cache") || lower.contains("crates.io"),
        "must state the pinned-cache / registry-resolution reason"
    );

    // (b) the slice that will introduce it.
    assert!(
        lower.contains("circle"),
        "must name the Circle-facing slice that introduces reqwest"
    );

    // (c) HOW it will be provisioned offline there (pre-seeded cargo cache or vendoring).
    assert!(
        lower.contains("vendor") || lower.contains("seed"),
        "must state the offline provisioning path (vendoring or a pre-seeded cache)"
    );
}

/// The `Cargo.toml` reqwest comment block cross-references the deferral record, AND reqwest is not
/// silently re-added as a real dependency (the operator decision: no reqwest / crates.io dep here).
#[test]
fn cargo_manifest_cross_references_deferral_and_omits_reqwest_dep() {
    let manifest = read_crate_file("Cargo.toml");
    assert!(
        manifest.contains("DEFERRED-DEPENDENCIES.md"),
        "the reqwest comment block in Cargo.toml must cross-reference DEFERRED-DEPENDENCIES.md"
    );

    // No non-comment line may declare a reqwest dependency (in any `reqwest = ...` form).
    let declares_reqwest = manifest
        .lines()
        .map(str::trim_start)
        .any(|line| !line.starts_with('#') && line.starts_with("reqwest"));
    assert!(
        !declares_reqwest,
        "reqwest must NOT be a declared dependency in this slice (deferred to the Circle-facing slice)"
    );
}
