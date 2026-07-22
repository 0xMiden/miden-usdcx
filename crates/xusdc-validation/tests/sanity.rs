//! Live E2E driver for the v16 sanity gate — `#[ignore]`d in the default (offline) suite because it
//! requires a RUNNING Miden node (the four v16 services on RPC 57291). The PURE-logic unit tests for
//! the sanity module live in `src/sanity/tests.rs` and DO run in the offline gate.
//!
//! Run it against a running node (RELEASE — debug proving is minutes/tx):
//! ```bash
//! # in the v16 client repo: ./scripts/start-test-node.sh --background
//! cargo test --release -p xusdc-validation --test sanity -- --ignored --nocapture
//! ```
//! The equivalent binary (`sanity_e2e`) is the canonical entry point + record writer; this test is
//! the harness twin (operator-run), mirroring the LNV `rows_*` live tests.

use anyhow::Result;
use std::path::PathBuf;

use xusdc_validation::sanity::{run_sanity, SanityConfig};

fn rpc_url() -> String {
    std::env::var("SANITY_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:57291".to_string())
}

#[tokio::test]
#[ignore = "requires a running v16 node (operator-run); see the module docs"]
async fn sanity_e2e_live() -> Result<()> {
    let run_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../local-node-data/sanity/test-run");
    let faucet_id = std::env::var("SANITY_FAUCET_ID")
        .ok()
        .map(|h| miden_protocol::account::AccountId::from_hex(&h))
        .transpose()
        .map_err(|e| anyhow::anyhow!("SANITY_FAUCET_ID: {e}"))?;

    let cfg = SanityConfig {
        rpc_url: rpc_url(),
        faucet_id,
        run_root,
        attester_secret: None,
        node_log_dir: std::env::var("SANITY_NODE_LOG_DIR").ok().map(PathBuf::from),
    };
    let report = run_sanity(&cfg, "miden-node 0.16.0-alpha.2 (test)").await?;

    for c in &report.checks {
        println!(
            "{} {}: {}",
            if c.pass { "PASS" } else { "FAIL" },
            c.id,
            c.detail
        );
    }
    assert!(
        report.all_passed(),
        "{} core sanity assertion(s) FAILED — deploy BLOCKED",
        report.failures().len()
    );
    // A local (no --faucet-id) run is the FULL gate — it must include the destructive admin surface.
    // (A `--faucet-id` re-check is non-destructive by design and does NOT run admin.)
    assert!(
        report.checks.iter().any(|c| c.area == "admin"),
        "the local full gate must exercise the admin surface"
    );
    Ok(())
}

/// The checked-in VALIDATION-RECORD-SANITY.md must be an HONEST artifact of the CURRENT design: it
/// contains the admin surface, so under the new model it can ONLY be a FRESH-deploy LOCAL full gate
/// (the sole mode that runs admin). It must therefore be labeled a fresh LOCAL deploy, reproduce with
/// the fresh-deploy command, and — critically — must NOT advertise any REMOTE destructive-admin path
/// (`--credentials`, a "DEVNET full re-run", or admin against a deployed faucet). Offline guard for
/// the round-10 "no destructive admin on the devnet path" correction; runs in the default suite.
#[test]
fn checked_in_record_is_an_honest_fresh_deploy_full_gate() {
    let record = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("VALIDATION-RECORD-SANITY.md"),
    )
    .expect("reading the checked-in VALIDATION-RECORD-SANITY.md");

    // The record HAS the admin surface, so it must be the fresh-deploy LOCAL full gate on loopback.
    assert!(
        record.contains("RPC `http://127.0.0.1:57291`"),
        "the full-gate record runs on a loopback node"
    );
    assert!(record.contains("a FRESH production faucet deployed on the running LOCAL node"));
    assert!(record.contains("**This record** was produced by the FRESH-deploy LOCAL full gate"));
    assert!(
        record.contains("--bin sanity_e2e -- --rpc-url http://127.0.0.1:57291"),
        "reproduces with the fresh-deploy command"
    );

    // It must NOT advertise or require ANY remote destructive-admin path against a deployed faucet.
    for forbidden in [
        "--credentials",
        "DEVNET existing-faucet FULL re-run",
        "DEVNET re-run",
        "existing-faucet FULL re-run",
        "--deploy-only",
    ] {
        assert!(
            !record.contains(forbidden),
            "the record must not advertise the removed remote-admin path: '{forbidden}'"
        );
    }
}
