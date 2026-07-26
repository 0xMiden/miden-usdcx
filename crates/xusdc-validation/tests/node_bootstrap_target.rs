//! Round-8: harden the v16 real-node bootstrap against a read-only / cross-owned external node
//! checkout — the documented LNV D/E, G/J, and live-sanity blocker.
//!
//! `scripts/start-test-node.sh` builds the genesis tool with `cargo build --release -p
//! test-node-genesis --bin gen-genesis` (no `--target-dir`) and resolves it at
//! `${CARGO_TARGET_DIR:-$ROOT/target}/release/gen-genesis`. Left at its default, that build writes
//! into the EXTERNAL client-repo `target/`, which in a restricted sandbox is read-only / owned by a
//! different user — so bootstrap dies with `failed to open .../target/release/.cargo-build-lock:
//! Permission denied` BEFORE any row assertion runs. `stack::node_build_target_dir` computes a
//! WRITABLE, harness-owned cargo target under the per-run `run_root` (honoring an explicit
//! caller-provisioned override), and the bootstrap invocation pins `CARGO_TARGET_DIR` to it so the
//! gen-genesis build never touches the external checkout. (The script's `cargo install` step uses an
//! explicit `--target-dir` and is unaffected.)

use std::path::PathBuf;

use xusdc_validation::stack::node_build_target_dir;

const RUN_ROOT: &str = "/var/tmp/lnv/blk/r8";

#[test]
fn defaults_to_a_writable_subdir_under_run_root() {
    let run_root = PathBuf::from(RUN_ROOT);
    let dir = node_build_target_dir(&run_root, None);
    assert!(
        dir.starts_with(&run_root),
        "the gen-genesis build target must live UNDER the writable per-run root, got {}",
        dir.display()
    );
    assert_ne!(
        dir, run_root,
        "it must be a DEDICATED subdir, not run_root itself (so node artifacts don't collide with \
         the harness's own run files)"
    );
}

#[test]
fn never_targets_the_cross_owned_external_checkout() {
    // The exact regression the LNV bootstrap hit: building gen-genesis into the external client-repo
    // target, whose `.cargo-build-lock` is not writable in the audit/builder sandbox.
    let run_root = PathBuf::from(RUN_ROOT);
    let dir = node_build_target_dir(&run_root, None)
        .to_string_lossy()
        .into_owned();
    for external in ["miden-client-v16", "MIDEN_V16_NODE_DIR"] {
        assert!(
            !dir.contains(external),
            "the default gen-genesis build target must NOT point into the cross-owned external node \
             checkout (`{external}`) — that is the `.cargo-build-lock: Permission denied` bootstrap \
             failure; got {dir}"
        );
    }
}

#[test]
fn honors_an_explicit_writable_override_but_ignores_a_blank_one() {
    let run_root = PathBuf::from(RUN_ROOT);
    // An operator who provisions a writable CARGO_TARGET_DIR keeps control of it.
    assert_eq!(
        node_build_target_dir(&run_root, Some("/writable/custom-target")),
        PathBuf::from("/writable/custom-target"),
        "an explicit, non-empty CARGO_TARGET_DIR override is honored as-is"
    );
    // A blank / whitespace-only override is meaningless — fall back to the safe writable default so
    // an empty env var can't silently send the build back to `$ROOT/target` (the external checkout).
    assert_eq!(
        node_build_target_dir(&run_root, Some("   ")),
        node_build_target_dir(&run_root, None),
        "a blank override must fall back to the safe writable default, not the external checkout"
    );
    assert_eq!(
        node_build_target_dir(&run_root, Some("")),
        node_build_target_dir(&run_root, None)
    );
}
