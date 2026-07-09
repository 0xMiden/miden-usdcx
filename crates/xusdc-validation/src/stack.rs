//! Lifecycle of the pinned local Miden node stack (`miden-node v0.15.1`).
//!
//! v0.15.1 ships NO `bundled` mode — the local chain is THREE services plus the tx prover the
//! ntx-builder requires, each a separate installed binary (`/usr/local/bin`):
//!
//! 1. `miden-validator bootstrap` — builds + signs the LOCAL genesis block (`genesis.dat`) and
//!    initializes the validator db. Uses the binary's default, predefined dev validator key
//!    (`0101…01`, documented in `--help`), so the genesis procedure is deterministic without a
//!    key ceremony. NEVER `--network devnet|testnet` — the gate requires an isolated local chain.
//! 2. `miden-node bootstrap --file` + `miden-ntx-builder bootstrap --file` — initialize the
//!    sequencer's and ntx-builder's stores from that SAME trusted genesis file.
//! 3. Start order: tx prover → validator → ntx-builder → sequencer (the sequencer dials both
//!    service URLs at startup).
//!
//! The sequencer is started with `--rpc.network-tx-auth-header-value` and the ntx-builder with
//! the matching `--rpc.auth-header-value`: at v0.15.1 the user RPC rejects post-deployment
//! transactions against network accounts, and only a submitter presenting the shared
//! `x-miden-network-tx-auth` token may submit them — without the token the stack's own
//! network-transaction pipeline would be inert.
//!
//! Every service's stdout+stderr is captured to `<run_root>/logs/<service>.log` (gitignored;
//! excerpts go in the validation record). [`NodeStack`] kills all children on drop unless
//! explicitly kept — port 57291 MUST be free when a run ends.

use std::fs::{self, File};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::config::StackConfig;

/// How long to wait for the sequencer RPC to accept TCP connections after start.
const RPC_READY_TIMEOUT: Duration = Duration::from_secs(60);
/// How long to wait for a service to exit after SIGTERM before SIGKILL.
const TERM_GRACE: Duration = Duration::from_secs(10);

/// One spawned stack service.
pub struct Service {
    pub name: &'static str,
    pub child: Child,
    pub log_path: PathBuf,
}

/// The running four-process stack. Dropping it tears everything down (unless kept).
pub struct NodeStack {
    pub config: StackConfig,
    services: Vec<Service>,
    keep_on_drop: bool,
}

/// Runs a bootstrap-style command to completion, teeing output to a log file.
fn run_to_completion(name: &str, log_dir: &Path, mut cmd: Command) -> Result<()> {
    let log_path = log_dir.join(format!("bootstrap-{name}.log"));
    let log = File::create(&log_path)
        .with_context(|| format!("creating {}", log_path.display()))?;
    let err_log = log.try_clone().context("cloning the log handle")?;
    let status = cmd
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err_log))
        .status()
        .with_context(|| format!("spawning the {name} bootstrap"))?;
    if !status.success() {
        bail!(
            "{name} bootstrap failed with {status}; log: {}",
            log_path.display()
        );
    }
    Ok(())
}

/// Spawns a long-running service with stdout+stderr captured to its log file.
fn spawn_service(name: &'static str, log_dir: &Path, mut cmd: Command) -> Result<Service> {
    let log_path = log_dir.join(format!("{name}.log"));
    let log = File::create(&log_path)
        .with_context(|| format!("creating {}", log_path.display()))?;
    let err_log = log.try_clone().context("cloning the log handle")?;
    let child = cmd
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err_log))
        .spawn()
        .with_context(|| format!("spawning {name}"))?;
    Ok(Service { name, child, log_path })
}

fn port_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().expect("loopback address parses"),
        Duration::from_millis(250),
    )
    .is_ok()
}

impl NodeStack {
    /// Bootstraps a FRESH isolated local chain under `config.run_root` (fails if the run root
    /// already holds one) and starts all four services, waiting until the sequencer RPC accepts
    /// connections. Returns the running stack.
    pub fn bootstrap_and_start(config: &StackConfig) -> Result<Self> {
        let root = &config.run_root;
        if root.join("genesis").exists() {
            bail!(
                "run root {} already holds a chain — every LNV run starts from a FRESH genesis",
                root.display()
            );
        }
        // The RPC port must be free BEFORE we start: a leftover node would poison the run.
        if port_open(config.rpc_port) {
            bail!(
                "port {} is already in use — a previous node stack is still running; stop it \
                 before starting a fresh run",
                config.rpc_port
            );
        }

        let genesis_dir = root.join("genesis");
        let accounts_dir = root.join("genesis-accounts");
        let validator_dir = root.join("validator");
        let node_dir = root.join("node");
        let ntx_dir = root.join("ntx-builder");
        let log_dir = config.log_dir();
        for dir in [&genesis_dir, &accounts_dir, &validator_dir, &node_dir, &ntx_dir, &log_dir] {
            fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }

        // 1. LOCAL genesis: build + sign genesis.dat with the documented default dev validator
        //    key. Isolated by construction — no devnet/testnet coupling.
        let mut cmd = Command::new("miden-validator");
        cmd.args(["bootstrap", "--genesis-block-directory"])
            .arg(&genesis_dir)
            .arg("--accounts-directory")
            .arg(&accounts_dir)
            .arg("--data-directory")
            .arg(&validator_dir);
        run_to_completion("validator", &log_dir, cmd)?;

        let genesis_file = genesis_dir.join("genesis.dat");
        if !genesis_file.exists() {
            bail!(
                "validator bootstrap produced no {} — cannot seed the sequencer/ntx stores",
                genesis_file.display()
            );
        }

        // 2. Seed the sequencer + ntx-builder stores from the SAME trusted genesis file.
        let mut cmd = Command::new("miden-node");
        cmd.args(["bootstrap", "--data-directory"])
            .arg(&node_dir)
            .arg("--file")
            .arg(&genesis_file);
        run_to_completion("node", &log_dir, cmd)?;

        let mut cmd = Command::new("miden-ntx-builder");
        cmd.args(["bootstrap", "--data-directory"])
            .arg(&ntx_dir)
            .arg("--file")
            .arg(&genesis_file);
        run_to_completion("ntx-builder", &log_dir, cmd)?;

        // 3. Start the services: prover → validator → ntx-builder → sequencer.
        let mut services = Vec::new();

        let mut cmd = Command::new("miden-remote-prover");
        cmd.args(["--kind", "transaction", "--port", &config.tx_prover_port.to_string()]);
        services.push(spawn_service("tx-prover", &log_dir, cmd)?);

        let mut cmd = Command::new("miden-validator");
        cmd.args(["start", "--listen"])
            .arg(format!("127.0.0.1:{}", config.validator_port))
            .arg("--data-directory")
            .arg(&validator_dir);
        services.push(spawn_service("validator", &log_dir, cmd)?);

        let mut cmd = Command::new("miden-ntx-builder");
        cmd.args(["start", "--listen"])
            .arg(format!("127.0.0.1:{}", config.ntx_builder_port))
            .arg("--rpc.url")
            .arg(config.rpc_url())
            .arg("--rpc.auth-header-value")
            .arg(&config.network_tx_auth_token)
            .arg("--tx-prover.url")
            .arg(config.tx_prover_url())
            .arg("--data-directory")
            .arg(&ntx_dir);
        services.push(spawn_service("ntx-builder", &log_dir, cmd)?);

        let mut cmd = Command::new("miden-node");
        cmd.args(["sequencer", "--data-directory"])
            .arg(&node_dir)
            .arg("--rpc.listen")
            .arg(format!("127.0.0.1:{}", config.rpc_port))
            .arg("--validator.url")
            .arg(config.validator_url())
            .arg("--ntx-builder.url")
            .arg(config.ntx_builder_url())
            .arg("--rpc.network-tx-auth-header-value")
            .arg(&config.network_tx_auth_token);
        services.push(spawn_service("sequencer", &log_dir, cmd)?);

        let mut stack = Self {
            config: config.clone(),
            services,
            keep_on_drop: false,
        };

        // Readiness: the sequencer RPC accepting TCP connections. Fail fast if any service
        // already died (bad flags, port clash) rather than waiting out the timeout.
        let deadline = Instant::now() + RPC_READY_TIMEOUT;
        loop {
            let mut startup_death: Option<(String, String)> = None;
            for service in &mut stack.services {
                if let Some(status) = service
                    .child
                    .try_wait()
                    .with_context(|| format!("polling {}", service.name))?
                {
                    startup_death = Some((
                        format!("{} exited at startup with {status}", service.name),
                        service.log_path.display().to_string(),
                    ));
                    break;
                }
            }
            if let Some((what, log)) = startup_death {
                stack.stop().ok();
                bail!("{what}; log: {log}");
            }
            if port_open(stack.config.rpc_port) {
                break;
            }
            if Instant::now() > deadline {
                stack.stop().ok();
                bail!(
                    "the sequencer RPC did not accept connections on port {} within {:?}",
                    stack.config.rpc_port,
                    RPC_READY_TIMEOUT
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }

        Ok(stack)
    }

    /// Marks the stack to be left RUNNING on drop (supervised inspection via `lnv_stack up`).
    pub fn keep_on_drop(&mut self) {
        self.keep_on_drop = true;
    }

    /// Stops all services (reverse start order: sequencer first, prover last), waits for exit,
    /// and verifies the RPC port is free again. Idempotent.
    pub fn stop(&mut self) -> Result<()> {
        for service in self.services.iter_mut().rev() {
            // Already exited?
            if service.child.try_wait().ok().flatten().is_some() {
                continue;
            }
            // SIGTERM for a clean shutdown; escalate to SIGKILL after the grace window.
            let pid = service.child.id().to_string();
            let _ = Command::new("kill").arg(&pid).status();
            let deadline = Instant::now() + TERM_GRACE;
            loop {
                match service.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() > deadline => {
                        let _ = service.child.kill();
                        let _ = service.child.wait();
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                    Err(_) => break,
                }
            }
        }
        // The next run (ours or the auditor's) needs the RPC port back.
        let deadline = Instant::now() + TERM_GRACE;
        while port_open(self.config.rpc_port) {
            if Instant::now() > deadline {
                bail!(
                    "port {} is still open after stopping the stack — a foreign process holds it",
                    self.config.rpc_port
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    /// The spawned services (name, pid, log path) for the evidence manifest.
    pub fn services(&self) -> &[Service] {
        &self.services
    }
}

impl Drop for NodeStack {
    fn drop(&mut self) {
        if !self.keep_on_drop {
            let _ = self.stop();
        }
    }
}
