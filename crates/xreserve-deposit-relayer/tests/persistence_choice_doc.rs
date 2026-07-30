//! `tests/persistence_choice_doc.rs` — guards the RECORDED persistence choice of the idempotency
//! seam.
//!
//! The component spec leaves the store's persistence technology `RIV` (requires implementer's
//! validation), so the slice that implements the seam must CHOOSE one and record the choice — what
//! was picked, what it was picked over, and the property that decided it. `PERSISTENCE-CHOICE.md`
//! is that record; this guard keeps it from drifting away from the manifest it describes (a
//! document that says "SQLite" while the crate has quietly moved to a JSON file is worse than no
//! document).
//!
//! It asserts the two ends agree, not the prose in between: the record names the chosen engine, the
//! alternatives it weighed, and the durability property that ruled the cache-only options out — and
//! the crate actually declares that engine, with the feature set that keeps the offline `--locked`
//! gate green.

use std::path::Path;

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn read_crate_file(rel: &str) -> String {
    let path = Path::new(MANIFEST_DIR).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn read_workspace_manifest() -> String {
    let path = Path::new(MANIFEST_DIR).join("../..").join("Cargo.toml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The record exists and carries what a later reader needs: the chosen engine, the alternatives it
/// was chosen over, and WHY — the atomic claim and the durable cursor, the two properties a
/// cache-only store cannot give.
#[test]
fn the_persistence_choice_is_recorded_with_its_rationale() {
    let doc = read_crate_file("PERSISTENCE-CHOICE.md");
    assert!(
        !doc.trim().is_empty(),
        "PERSISTENCE-CHOICE.md must not be empty"
    );
    let lower = doc.to_lowercase();

    // (a) the chosen engine, named.
    assert!(
        lower.contains("sqlite") && lower.contains("rusqlite"),
        "the record must name the chosen engine (SQLite, via rusqlite)"
    );

    // (b) the alternatives it was weighed against — the choice is only a choice if the losers are
    //     named (and the offline-hostile ones are the trap a later slice would otherwise re-walk).
    for alternative in ["serde_json", "bincode", "sled"] {
        assert!(
            lower.contains(alternative),
            "the record must weigh the `{alternative}` alternative"
        );
    }

    // (c) the properties that decided it: an ATOMIC claim (check-then-insert as one step) and a
    //     cursor that survives a restart. Losing either is the failure the seam exists to prevent.
    assert!(
        lower.contains("atomic"),
        "the record must state the atomic-claim property that decided the choice"
    );
    assert!(
        lower.contains("restart"),
        "the record must state the restart-durability property that decided the choice"
    );
    assert!(
        lower.contains("cache"),
        "the record must state why a cache-only store is not acceptable (the cursor must not be \
         lost)"
    );

    // (d) the sharp edge the choice brings with it: SQLite's ephemeral databases are spelled as
    //     ordinary FILENAMES, so choosing SQLite means the constructor must refuse them. A record
    //     that recommended SQLite without naming this trap would be handing the next slice (the
    //     listener, which needs the same durable cursor) a store that an operator's config can
    //     silently turn back into a cache.
    assert!(
        lower.contains(":memory:") && lower.contains("mode=memory"),
        "the record must name the ephemeral SQLite spellings the store has to refuse (`:memory:`, a \
         `mode=memory` uri)"
    );
    assert!(
        lower.contains("pragma_database_list") || lower.contains("database_list"),
        "the record must state HOW durability is enforced (asking SQLite where the database landed)"
    );
}

/// The manifests agree with the record: the engine is declared, pinned ONCE in the workspace table,
/// and built from the vendored amalgamation (`bundled`) so the offline gate does not depend on a
/// system libsqlite3 that may not be linkable.
#[test]
fn the_manifests_declare_the_recorded_engine() {
    let manifest = read_crate_file("Cargo.toml");
    assert!(
        manifest.contains("PERSISTENCE-CHOICE.md"),
        "the rusqlite declaration in Cargo.toml must cross-reference PERSISTENCE-CHOICE.md"
    );

    let declares_rusqlite = manifest
        .lines()
        .map(str::trim_start)
        .any(|line| !line.starts_with('#') && line.starts_with("rusqlite"));
    assert!(
        declares_rusqlite,
        "the crate must declare the recorded persistence engine (rusqlite)"
    );

    let workspace = read_workspace_manifest();
    let pin = workspace
        .lines()
        .map(str::trim_start)
        .find(|line| !line.starts_with('#') && line.starts_with("rusqlite"))
        .expect("rusqlite is pinned once, in the root [workspace.dependencies]");
    assert!(
        pin.contains("\"bundled\""),
        "rusqlite must be `bundled` — a system-linked SQLite is not guaranteed to be linkable in \
         the offline gate's environment, and would let the host's SQLite version drift under the \
         store: {pin}"
    );
}

/// The offline-hostile durable stores stay out. `sled` / `redb` / `sqlx` are NOT in the pinned
/// cargo cache: declaring one would break every `--locked --offline` command in the repository —
/// the same wall `DEFERRED-DEPENDENCIES.md` was written about.
#[test]
fn no_offline_hostile_store_crate_is_declared() {
    let manifest = read_crate_file("Cargo.toml");
    let workspace = read_workspace_manifest();

    for crate_name in ["sled", "redb", "sqlx"] {
        for (label, text) in [("crate", &manifest), ("workspace", &workspace)] {
            let declared = text
                .lines()
                .map(str::trim_start)
                .any(|line| !line.starts_with('#') && line.starts_with(crate_name));
            assert!(
                !declared,
                "`{crate_name}` is not in the pinned offline cache and must not be declared in the \
                 {label} manifest — the idempotency store is built on the cached rusqlite"
            );
        }
    }
}
