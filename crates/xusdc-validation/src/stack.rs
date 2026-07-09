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

use std::path::PathBuf;
use std::process::Child;

use anyhow::Result;

use crate::config::StackConfig;

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

impl NodeStack {
    /// Bootstraps a FRESH isolated local chain under `config.run_root` (fails if the run root
    /// already holds one) and starts all four services, waiting until the sequencer RPC accepts
    /// connections. Returns the running stack.
    pub fn bootstrap_and_start(config: &StackConfig) -> Result<Self> {
        let _ = config;
        todo!("LNV-1 driver: bootstrap genesis + start validator/ntx-builder/sequencer/prover")
    }

    /// Marks the stack to be left RUNNING on drop (supervised inspection via `lnv_stack up`).
    pub fn keep_on_drop(&mut self) {
        self.keep_on_drop = true;
    }

    /// Stops all services (reverse start order), waits for exit, and verifies the RPC port is
    /// free again. Idempotent.
    pub fn stop(&mut self) -> Result<()> {
        todo!("LNV-1 driver: stop the stack")
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
