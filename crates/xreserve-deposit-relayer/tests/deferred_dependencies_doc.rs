//! `tests/deferred_dependencies_doc.rs` — guards the reqwest deferral **and its discharge**.
//!
//! reqwest (the Circle HTTP client) could not be resolved under this repository's offline
//! `--locked` gate from the pinned cache, so — by explicit operator decision — it was deferred to
//! the Circle-facing slice, with `DEFERRED-DEPENDENCIES.md` recording WHAT / WHY / WHICH-slice /
//! HOW.
//!
//! **This IS that slice**, and the deferral is discharged: the cache carries `reqwest 0.13.4`
//! and its closure, so the dependency is declared and the offline gate still passes. The guard
//! therefore flipped WITH the decision it guards — it no longer asserts reqwest's ABSENCE (that
//! would now be asserting the deferral was never discharged, i.e. that this slice does not exist);
//! it asserts the DISCHARGE is real and stays offline-correct:
//!
//! * the record still exists and still carries the four required elements (what / why / which slice
//!   / how) — the reason the earlier slices carry no reqwest must not be lost, and the next
//!   dependency that hits the offline gate must find the playbook;
//! * the record states the discharge, so nobody re-defers a dependency that is already here;
//! * reqwest IS declared, `default-features = false`, with reqwest **0.13's** feature names — the
//!   0.12 name `rustls-tls` would silently pull the default TLS backend and break the offline gate;
//! * the offline-hostile mock-server crates (`wiremock` / `httpmock` / `mockito`, absent from the
//!   pinned cache) are NOT declared — the mock is built from cached `axum` + `tokio`.

use std::path::Path;

/// The relayer crate's manifest directory (baked at compile time), so the guard reads the exact
/// files this crate ships regardless of the invoking CWD.
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn read_crate_file(rel: &str) -> String {
    let path = Path::new(MANIFEST_DIR).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The workspace manifest, where the shared dependency versions are pinned.
fn read_workspace_manifest() -> String {
    let path = Path::new(MANIFEST_DIR).join("../..").join("Cargo.toml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The deferral record exists and carries the operator-required elements: (a) WHAT + WHY, (b) WHICH
/// slice introduces it, (c) HOW it is provisioned offline there — and now (d) that it is
/// DISCHARGED.
#[test]
fn deferred_dependencies_doc_exists_and_is_complete() {
    let doc = read_crate_file("DEFERRED-DEPENDENCIES.md");
    assert!(
        !doc.trim().is_empty(),
        "DEFERRED-DEPENDENCIES.md must not be empty"
    );
    let lower = doc.to_lowercase();

    // (a) names the deferred dependency and WHY it was deferred (the offline --locked gate could not
    //     resolve it from the pinned cache). The WHY outlives the deferral: it is the rule every
    //     future dependency must clear.
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

    // (b) the slice that introduces it.
    assert!(
        lower.contains("circle"),
        "must name the Circle-facing slice that introduces reqwest"
    );

    // (c) HOW it is provisioned offline there (pre-seeded cargo cache or vendoring).
    assert!(
        lower.contains("vendor") || lower.contains("seed"),
        "must state the offline provisioning path (vendoring or a pre-seeded cache)"
    );

    // (d) and that the deferral has been DISCHARGED by this slice — so a later reader does not
    //     re-defer a dependency that is already declared and resolving offline.
    assert!(
        lower.contains("discharged"),
        "the record must state that the deferral is DISCHARGED in the Circle-facing slice"
    );
}

/// The `Cargo.toml` comment block still cross-references the record, and reqwest is now declared —
/// with the feature set that keeps the offline gate green.
#[test]
fn cargo_manifest_cross_references_the_record_and_declares_reqwest_offline_correctly() {
    let manifest = read_crate_file("Cargo.toml");
    assert!(
        manifest.contains("DEFERRED-DEPENDENCIES.md"),
        "the reqwest comment block in Cargo.toml must cross-reference DEFERRED-DEPENDENCIES.md"
    );

    // the crate consumes reqwest from the workspace table (single version pin for every service)
    let declares_reqwest = manifest
        .lines()
        .map(str::trim_start)
        .any(|line| !line.starts_with('#') && line.starts_with("reqwest"));
    assert!(
        declares_reqwest,
        "the Circle-facing slice MUST declare reqwest — the deferral is discharged here"
    );

    let workspace = read_workspace_manifest();
    let reqwest_pin = workspace
        .lines()
        .map(str::trim_start)
        .find(|line| !line.starts_with('#') && line.starts_with("reqwest"))
        .expect("reqwest is pinned once, in the root [workspace.dependencies]");

    // reqwest 0.13 feature names — `rustls-tls` is the 0.12 name and does NOT exist in 0.13; using
    // it would fall back to the default TLS backend, which is not in the pinned offline cache.
    assert!(
        reqwest_pin.contains("default-features = false"),
        "reqwest must not pull its default features (system OpenSSL / default TLS): {reqwest_pin}"
    );
    for feature in ["\"rustls\"", "\"json\"", "\"query\""] {
        assert!(
            reqwest_pin.contains(feature),
            "reqwest must declare the 0.13 feature {feature}: {reqwest_pin}"
        );
    }
    assert!(
        !reqwest_pin.contains("rustls-tls"),
        "`rustls-tls` is reqwest 0.12's TLS feature name; 0.13's is `rustls`: {reqwest_pin}"
    );
}

/// The offline gate still binds: the mock Circle server must be built from crates that ARE in the
/// pinned cache. `wiremock` / `httpmock` / `mockito` are not, and adding one would break every
/// `--locked --offline` command — the exact failure this record exists to prevent.
#[test]
fn no_offline_hostile_mock_server_crate_is_declared() {
    let manifest = read_crate_file("Cargo.toml");
    let workspace = read_workspace_manifest();

    for crate_name in ["wiremock", "httpmock", "mockito"] {
        for (label, text) in [("crate", &manifest), ("workspace", &workspace)] {
            let declared = text
                .lines()
                .map(str::trim_start)
                .any(|line| !line.starts_with('#') && line.starts_with(crate_name));
            assert!(
                !declared,
                "`{crate_name}` is not in the pinned offline cache and must not be declared in the \
                 {label} manifest — the mock Circle server is built from axum + tokio"
            );
        }
    }
}
