//! Lifecycle of the **v16** local Miden node stack.
//!
//! The v16 node is multi-service and has no `bundled` mode; its authoritative bring-up is the client
//! repo's `scripts/start-test-node.sh`, which installs (cached) and starts the four v0.16.0-alpha.2
//! services in order — `miden-validator`, `miden-node` (sequencer), `miden-ntx-builder`,
//! `miden-remote-prover` — on RPC `57291`, generating a fresh isolated genesis each time. This module
//! DELEGATES to that script (and `stop-test-node.sh`) rather than re-implementing the v0.15-era
//! four-process bootstrap in Rust: the script is the single source of truth for the v16 node CLI, so
//! the harness cannot drift from it. The client-repo directory is [`StackConfig::client_repo_dir`]
//! (env `MIDEN_V16_NODE_DIR`, default the provisioned path).
//!
//! [`NodeStack`] runs the script on [`bootstrap_and_start`](NodeStack::bootstrap_and_start), verifies
//! the RPC is accepting connections, and tears the node down on drop (unless kept) — port 57291 MUST
//! be free when a run ends. The service logs live under `<client_repo>/target/test-node/data/logs`
//! ([`StackConfig::log_dir`]).

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::config::StackConfig;

/// How long to wait for the sequencer RPC to accept connections after `start-test-node.sh` returns.
const RPC_READY_TIMEOUT: Duration = Duration::from_secs(60);
/// How long to wait for the RPC port to free after `stop-test-node.sh`.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// The four v16 node services (log basenames the script writes under the node data-log dir).
pub const V16_SERVICES: [&str; 4] = ["validator", "sequencer", "ntx-builder", "prover"];

/// One v16 node service and where its log is archived.
pub struct Service {
    pub name: &'static str,
    pub log_path: PathBuf,
}

/// The running v16 node (managed by the client-repo script). Dropping it tears the node down
/// (unless kept).
pub struct NodeStack {
    pub config: StackConfig,
    keep_on_drop: bool,
    running: bool,
}

fn port_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}")
            .parse()
            .expect("loopback address parses"),
        Duration::from_millis(250),
    )
    .is_ok()
}

/// The cargo target directory the v16 node-bootstrap script builds `gen-genesis` into.
///
/// `scripts/start-test-node.sh` runs `cargo build --release -p test-node-genesis --bin gen-genesis`
/// (no `--target-dir`) and resolves the binary at `${CARGO_TARGET_DIR:-$ROOT/target}/release/
/// gen-genesis`. Left at its default that build writes into the EXTERNAL client-repo `target/`,
/// which in a restricted sandbox is read-only / owned by another user — bootstrap then dies with
/// `failed to open .../target/release/.cargo-build-lock: Permission denied` BEFORE any node service
/// starts (the LNV real-node bootstrap blocker documented across rounds 4-8). This redirects the
/// build into a WRITABLE, harness-owned dir under the per-run `run_root`, so it never touches the
/// external checkout. A non-empty caller-set `CARGO_TARGET_DIR` (an operator-provisioned writable
/// target) is honored as-is; a blank one falls back to the safe default. The script's `cargo
/// install` step uses an explicit `--target-dir` and is unaffected by this variable.
pub fn node_build_target_dir(run_root: &Path, caller_override: Option<&str>) -> PathBuf {
    match caller_override {
        Some(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => run_root.join("node-cargo-target"),
    }
}

/// Runs a client-repo node script (`start-test-node.sh` / `stop-test-node.sh`) from the client-repo
/// dir with the node toolchain on `PATH`, a writable `TMPDIR`, and a writable `CARGO_TARGET_DIR`
/// (see [`node_build_target_dir`] — so the `gen-genesis` build never touches the cross-owned
/// external checkout target).
fn run_node_script(config: &StackConfig, script: &str, extra_arg: Option<&str>) -> Result<()> {
    let script_path = config.client_repo_dir.join("scripts").join(script);
    if !script_path.exists() {
        bail!(
            "the v16 node script {} does not exist — set MIDEN_V16_NODE_DIR to the client repo \
             (currently {})",
            script_path.display(),
            config.client_repo_dir.display()
        );
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/agent".to_string());
    let path = format!(
        "{home}/.cargo/bin:{}",
        std::env::var("PATH").unwrap_or_default()
    );
    let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| format!("{home}/tmp"));
    // Redirect the script's `gen-genesis` release build off the (often read-only / cross-owned)
    // external checkout target and into a writable, harness-owned dir under `run_root` — otherwise
    // bootstrap dies on `.cargo-build-lock: Permission denied` before any node service starts.
    let caller_target = std::env::var("CARGO_TARGET_DIR").ok();
    let target_dir = node_build_target_dir(&config.run_root, caller_target.as_deref());
    std::fs::create_dir_all(&target_dir).ok();
    let mut cmd = Command::new("bash");
    cmd.arg(&script_path)
        .current_dir(&config.client_repo_dir)
        .env("PATH", path)
        .env("TMPDIR", tmpdir)
        .env("CARGO_TARGET_DIR", &target_dir);
    if let Some(a) = extra_arg {
        cmd.arg(a);
    }
    let status = cmd
        .status()
        .with_context(|| format!("running {}", script_path.display()))?;
    if !status.success() {
        bail!("{} exited with {status}", script_path.display());
    }
    Ok(())
}

impl NodeStack {
    /// Brings up a FRESH v16 node via `start-test-node.sh --background` and waits until the sequencer
    /// RPC accepts connections. Fails if the RPC port is already in use.
    pub fn bootstrap_and_start(config: &StackConfig) -> Result<Self> {
        if port_open(config.rpc_port) {
            bail!(
                "port {} is already in use — a previous node is still running; stop it before a \
                 fresh run",
                config.rpc_port
            );
        }
        // The script installs (cached) + starts the four v16 services and returns once RPC is ready.
        run_node_script(config, "start-test-node.sh", Some("--background"))
            .context("starting the v16 node via start-test-node.sh --background")?;

        let mut stack = Self {
            config: config.clone(),
            keep_on_drop: false,
            running: true,
        };
        let deadline = Instant::now() + RPC_READY_TIMEOUT;
        while !port_open(stack.config.rpc_port) {
            if Instant::now() > deadline {
                stack.stop().ok();
                bail!(
                    "the v16 sequencer RPC did not accept connections on port {} within {:?}",
                    stack.config.rpc_port,
                    RPC_READY_TIMEOUT
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(stack)
    }

    /// Marks the node to be left RUNNING on drop (supervised inspection via `lnv_stack up`).
    pub fn keep_on_drop(&mut self) {
        self.keep_on_drop = true;
    }

    /// Stops the v16 node via `stop-test-node.sh` and verifies the RPC port is free again. Idempotent.
    pub fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }
        run_node_script(&self.config, "stop-test-node.sh", None)
            .context("stopping the v16 node via stop-test-node.sh")?;
        self.running = false;
        let deadline = Instant::now() + STOP_TIMEOUT;
        while port_open(self.config.rpc_port) {
            if Instant::now() > deadline {
                bail!(
                    "port {} is still open after stop-test-node.sh — a foreign process holds it",
                    self.config.rpc_port
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    /// The four v16 services with their archived log paths (under the node data-log dir).
    pub fn services(&self) -> Vec<Service> {
        let log_dir = self.config.log_dir();
        V16_SERVICES
            .iter()
            .map(|name| Service {
                name,
                log_path: log_dir.join(format!("{name}.log")),
            })
            .collect()
    }
}

impl Drop for NodeStack {
    fn drop(&mut self) {
        if !self.keep_on_drop {
            let _ = self.stop();
        }
    }
}

/// Stops a kept v16 node (the `lnv_stack down` path) via `stop-test-node.sh`, without owning a
/// [`NodeStack`] handle.
pub fn stop_node(config: &StackConfig) -> Result<()> {
    run_node_script(config, "stop-test-node.sh", None)
        .context("stopping the v16 node via stop-test-node.sh")
}
