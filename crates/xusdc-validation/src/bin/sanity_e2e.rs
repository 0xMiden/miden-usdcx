//! `sanity_e2e` — the v16 E2E sanity gate binary.
//!
//! Drives core faucet functionality against a REAL running Miden node and asserts fund-correctness
//! end-to-end (the P0 scale-0 identity, mint/burn amounts + destinations, replay, supply-cap,
//! attestation gates, DC-8 burn-evidence, clean node logs).
//!
//! **Two modes.** A FRESH local deploy (no `--faucet-id`, loopback only) runs the WHOLE matrix
//! including the DESTRUCTIVE admin surface, always against a faucet we own and throw away with the
//! test node. Targeting an ALREADY-deployed faucet (`--faucet-id`, LOCAL or DEVNET) runs ONLY the
//! non-destructive fund-correctness subset (scale-0 mints, the attestation/replay/cap negatives, the
//! burn arc) with the operator's allowlisted attester secret — it NEVER mutates the deployed faucet
//! (no pause / policy change / ownership transfer). That subset is the INTENDED, COMPLETE devnet gate.
//!
//! ```text
//! # LOCAL full gate — deploys a fresh faucet on the LOCAL node + runs admin; scans the node logs:
//! #   in the v16 client repo: ./scripts/start-test-node.sh --background   (RPC 127.0.0.1:57291)
//! cargo run --release --locked -p xusdc-validation --bin sanity_e2e -- --rpc-url http://127.0.0.1:57291
//!
//! # DEVNET (or local existing-faucet) — non-destructive re-check against a deployed faucet
//! # (the allowlisted attester secret is read from a FILE / env, NEVER argv):
//! SANITY_ATTESTER_SECRET=$(cat allowlisted-attester.hex) cargo run --release --locked \
//!     -p xusdc-validation --bin sanity_e2e -- --rpc-url https://rpc.devnet.miden.io --faucet-id <ID>
//! ```
//!
//! Exit 0 = every core assertion PASSED (record PENDING HUMAN ACCEPTANCE). Exit non-zero = at least
//! one assertion FAILED — a surfaced finding that BLOCKS the deploy.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use miden_protocol::account::AccountId;
use xusdc_validation::sanity::{is_loopback, render_sanity_record, run_sanity, SanityConfig};

const DEFAULT_NODE_VERSION: &str =
    "miden-node 0.16.0-alpha.2 (v16 start-test-node.sh cached binaries)";
const DEFAULT_RPC_URL: &str = "http://127.0.0.1:57291";
/// Where `start-test-node.sh` writes the v16 node's service logs (override with `MIDEN_V16_NODE_DIR`
/// or `--node-log-dir`). Only used for the LOCAL clean-log gate.
const DEFAULT_V16_NODE_DIR: &str = "/home/agent/work/miden-client-v16";

struct Args {
    rpc_url: String,
    faucet_id: Option<AccountId>,
    attester_secret: Option<[u8; 32]>,
    node_log_dir: Option<PathBuf>,
    node_version: String,
    run_root: PathBuf,
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        bail!("expected 64 hex chars (32 bytes), got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .with_context(|| format!("invalid hex at byte {i}"))?;
    }
    Ok(out)
}

fn parse_args() -> Result<Args> {
    let mut rpc_url = DEFAULT_RPC_URL.to_string();
    let mut faucet_id = None;
    let mut attester_secret = None;
    let mut node_log_dir: Option<PathBuf> = None;
    let mut node_version = DEFAULT_NODE_VERSION.to_string();
    let mut run_root: Option<PathBuf> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--rpc-url" => rpc_url = it.next().context("--rpc-url needs a value")?,
            "--faucet-id" => {
                let v = it.next().context("--faucet-id needs a value")?;
                faucet_id = Some(
                    AccountId::from_hex(&v)
                        .map_err(|e| anyhow::anyhow!("parsing --faucet-id '{v}': {e}"))?,
                );
            }
            "--attester-secret-file" => {
                // The secret is read from a FILE (or the SANITY_ATTESTER_SECRET env var), never from
                // argv — a mint-authorizing scalar must not land in the process list or shell history.
                let path = it.next().context("--attester-secret-file needs a path")?;
                let hex = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading the attester secret from {path}"))?;
                attester_secret =
                    Some(parse_hex32(hex.trim()).context("parsing the attester secret file")?);
            }
            "--node-log-dir" => {
                node_log_dir = Some(PathBuf::from(
                    it.next().context("--node-log-dir needs a value")?,
                ));
            }
            "--node-version" => node_version = it.next().context("--node-version needs a value")?,
            "--run-root" => {
                run_root = Some(PathBuf::from(
                    it.next().context("--run-root needs a value")?,
                ))
            }
            "-h" | "--help" => {
                println!(
                    "sanity_e2e — v16 E2E faucet sanity gate\n\n\
                     Two modes: OMIT --faucet-id on a LOCAL node to deploy a FRESH faucet + run the\n\
                     WHOLE matrix incl. the destructive admin surface (against a faucet we own/throw\n\
                     away). Pass --faucet-id (LOCAL or DEVNET) to run ONLY the non-destructive\n\
                     fund-correctness subset against an ALREADY-deployed faucet — it NEVER mutates it\n\
                     (no admin), and is the intended COMPLETE devnet gate. Fresh deploy is refused\n\
                     against a non-loopback RPC (devnet deployment is OUT OF SCOPE).\n\n\
                     --rpc-url <URL>          node RPC (default {DEFAULT_RPC_URL})\n\
                     --faucet-id <HEX>        target an ALREADY-deployed faucet (non-destructive subset; needs its\n\
                                              allowlisted attester secret via --attester-secret-file / SANITY_ATTESTER_SECRET).\n\
                                              OMIT only on a LOCAL node to deploy + full-test a fresh faucet (the local gate)\n\
                     --attester-secret-file <PATH>  the deployed faucet's allowlisted attester secret (hex; with --faucet-id;\n\
                                              or set SANITY_ATTESTER_SECRET) — never on argv\n\
                     --node-log-dir <DIR>     the running node's service-log dir for the clean-log gate (local)\n\
                     --node-version <STR>     node version stamped in the record\n\
                     --run-root <DIR>         scratch dir for the client store/keystore (gitignored)\n"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument '{other}' (try --help)"),
        }
    }

    // Env fallback for the attester secret (never on argv).
    if attester_secret.is_none() {
        if let Ok(hex) = std::env::var("SANITY_ATTESTER_SECRET") {
            attester_secret =
                Some(parse_hex32(hex.trim()).context("parsing SANITY_ATTESTER_SECRET")?);
        }
    }

    let run_root = run_root.unwrap_or_else(|| {
        let label = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        repo_root()
            .join("local-node-data")
            .join("sanity")
            .join(format!("run-{label}"))
    });

    // The clean-log gate scans the node's service logs — only meaningful for a LOOPBACK node whose
    // logs are on this box (a remote devnet node has no local logs). Default to the v16 node's log
    // dir only for a loopback RPC.
    let loopback = is_loopback(&rpc_url);
    if node_log_dir.is_none() && loopback {
        let node_dir = std::env::var("MIDEN_V16_NODE_DIR")
            .unwrap_or_else(|_| DEFAULT_V16_NODE_DIR.to_string());
        node_log_dir = Some(PathBuf::from(node_dir).join("target/test-node/data/logs"));
    }

    Ok(Args {
        rpc_url,
        faucet_id,
        attester_secret,
        node_log_dir,
        node_version,
        run_root,
    })
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("."))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    println!(
        "xUSDC v16 E2E sanity gate\n  node: {}\n  rpc:  {}\n  faucet: {}\n  run root: {}\n  node logs: {}\n",
        args.node_version,
        args.rpc_url,
        args.faucet_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "<deploy fresh>".to_string()),
        args.run_root.display(),
        args.node_log_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<none (devnet)>".to_string()),
    );

    let cfg = SanityConfig {
        rpc_url: args.rpc_url,
        faucet_id: args.faucet_id,
        run_root: args.run_root.clone(),
        attester_secret: args.attester_secret,
        node_log_dir: args.node_log_dir,
    };

    // ENFORCE the fresh-deploy locality boundary: deploying a fresh faucet (a run with no --faucet-id)
    // is a LOCAL-only action. Against a remote/devnet RPC it is REFUSED — devnet deployment is OUT OF
    // SCOPE; the operator must TARGET the already-deployed faucet with --faucet-id.
    let deploys_fresh = cfg.faucet_id.is_none();
    if deploys_fresh && !is_loopback(&cfg.rpc_url) {
        bail!(
            "REFUSED: deploying a fresh faucet is a LOCAL-only action, but --rpc-url '{}' is not a \
             loopback node. Devnet deployment is OUT OF SCOPE. Target the ALREADY-deployed faucet \
             instead with --faucet-id <HEX> (the non-destructive re-check).",
            cfg.rpc_url
        );
    }

    let report = run_sanity(&cfg, &args.node_version)
        .await
        .context("running the sanity suite")?;

    let record_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("VALIDATION-RECORD-SANITY.md");
    std::fs::write(&record_path, render_sanity_record(&report))
        .with_context(|| format!("writing {}", record_path.display()))?;

    println!("\n=== SUMMARY ===");
    let passed = report.checks.iter().filter(|c| c.pass).count();
    println!("{passed}/{} checks passed", report.checks.len());
    println!("record: {}", record_path.display());

    if report.all_passed() {
        println!(
            "\nALL CORE FUNCTIONALITY PASSED — record written PENDING HUMAN ACCEPTANCE (the gate \
             verdict is a human decision; the deploy proceeds only after a human accepts)."
        );
        Ok(())
    } else {
        for c in report.failures() {
            eprintln!("FAIL {} ({}): {} — {}", c.id, c.area, c.what, c.detail);
        }
        bail!(
            "sanity gate: {} core assertion(s) FAILED — deploy BLOCKED; see {}",
            report.failures().len(),
            record_path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use xusdc_validation::sanity::is_loopback;

    #[test]
    fn loopback_hosts_allow_fresh_deploy() {
        for url in [
            "http://127.0.0.1:57291",
            "http://127.0.0.1",
            "http://localhost:57291",
            "https://LOCALHOST",
            "http://[::1]:57291",
            "127.0.0.1:57291",
        ] {
            assert!(is_loopback(url), "{url} must be treated as loopback");
        }
    }

    #[test]
    fn remote_and_spoofed_hosts_refuse_fresh_deploy() {
        for url in [
            "https://rpc.devnet.miden.io",
            "https://rpc.devnet.miden.io:443",
            // Substring spoofs: the loopback marker is NOT the actual host.
            "http://127.0.0.1.evil.com:80",
            "http://localhost.evil.com",
            "http://evil.com/127.0.0.1",
        ] {
            assert!(!is_loopback(url), "{url} must be treated as REMOTE");
        }
    }
}
