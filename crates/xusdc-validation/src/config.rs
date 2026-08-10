//! Run + stack configuration for the LNV harness.
//!
//! Every port is fixed and loopback-only for reproducibility (recorded in the validation record):
//! the auditors reproduce the gate from a fresh node with the same wiring. All node data
//! directories, stores, keystores, and full logs live under the gitignored
//! `local-node-data/` repo root (evidence excerpts go in the record; full logs stay out of git).

use std::path::{Path, PathBuf};

use miden_protocol::Word;
use xusdc_encoding::xreserve::encoding::bytes32_to_storage_map_key;

// The v16 node's ACTUAL loopback ports, exactly as the client repo's `start-test-node.sh` binds
// them (script lines 33-37). The harness only ever dials the sequencer RPC (57291); the other three
// are the script's internal service ports — recorded truthfully in the evidence so a reproduction
// frees the right ports, never the old harness-assigned 57292–57294 (which nothing binds).
/// Sequencer public RPC port — the standard local Miden RPC port the pinned
/// `miden-client 0.16.0-alpha.1` `for_localhost()` preset also expects.
pub const RPC_PORT: u16 = 57291;
/// Validator gRPC port (`start-test-node.sh` binds `127.0.0.1:50101`).
pub const VALIDATOR_PORT: u16 = 50101;
/// ntx-builder gRPC port (`start-test-node.sh` binds `127.0.0.1:50301`).
pub const NTX_BUILDER_PORT: u16 = 50301;
/// Remote tx-prover port (`start-test-node.sh` binds `127.0.0.1:50051`).
pub const TX_PROVER_PORT: u16 = 50051;

/// The shared network-transaction authorization token. v0.15.1 rejects post-deployment
/// user-RPC transactions against network accounts ("Network transactions may not be submitted by
/// users yet"); the sequencer accepts them only from a submitter presenting this value in the
/// `x-miden-network-tx-auth` metadata header. The harness starts the sequencer with this token and
/// hands it to the ntx-builder, making the local stack's network-transaction path fully
/// operational (row K exercises it; rows A/B do not depend on it).
pub const NETWORK_TX_AUTH_TOKEN: &str = "lnv-local-network-tx-auth";

/// The domain-config parameters of a run. Since the Wave-1 S1 recomposition the three fields
/// `domain`/`source_domain`/`xreserve_contract` are BUILD-SEEDED via the builder's required
/// `with_domain_config` (DEC-4), and ONLY the `identifier` is committed post-deploy by the owner's
/// `identifier_init` note (the minimized replacement of the former four-field `domain_init`).
/// LOCAL TEST values (Circle's real domain assignment is DEV-gated and stays OPEN — these exist to
/// prove the seed/write/read-back path, not to bind a real domain).
#[derive(Debug, Clone)]
pub struct DomainParams {
    /// `domain` (u32) — the Miden-side domain id, element 0 of the domain slot.
    pub domain: u32,
    /// `source_domain` (u32) — the native-USDC source domain id.
    pub source_domain: u32,
    /// `xreserve_contract` — the raw bytes32, stored as 8 u32-LE packed felts across two slots.
    pub xreserve_contract: [u8; 32],
    /// `identifier` — a LEGACY raw bytes32 value. It is NO LONGER the faucet's identifier: since the
    /// R2 identifier-binding fix the identifier is DERIVED from the faucet's own id at init
    /// (`XReserveIdentifierInitNote::identifier_for(faucet_id)`, the account-id fixpoint), never from
    /// this field. Retained only so `DomainParams` stays fully populated for the record/fixtures.
    pub identifier_bytes: [u8; 32],
}

impl DomainParams {
    /// The LEGACY vector-token identifier as the canonical `bytes32_to_storage_map_key` Word. NOT the faucet's
    /// actual identifier (that is the own-id fixpoint `identifier_for(faucet_id)`, derived at init) —
    /// retained only for record/fixture completeness; the fresh-init assertions compute the own-id
    /// key from `account.id()` directly.
    pub fn identifier_word(&self) -> Word {
        bytes32_to_storage_map_key(&self.identifier_bytes).into()
    }

    /// The fixed LNV-1 test parameters (recorded in the evidence; values are arbitrary non-zero
    /// patterns chosen to make read-back mismatches loud).
    pub fn lnv1() -> Self {
        Self {
            domain: 1313,
            source_domain: 7,
            xreserve_contract: [0xC1; 32],
            identifier_bytes: [0x1D; 32],
        }
    }

    /// A SECOND, everywhere-different parameter set for the init-once negative: the second
    /// `identifier_init` note carries THIS set's identifier — if the reinit gate ever failed and
    /// the second identifier were written, the read-back assertion would mismatch loudly. (The
    /// other three fields stay everywhere-different too, documenting that no runtime writer for
    /// them exists at all post-recomposition.)
    pub fn lnv1_reinit_attempt() -> Self {
        Self {
            domain: 9999,
            source_domain: 42,
            xreserve_contract: [0xEE; 32],
            identifier_bytes: [0x2A; 32],
        }
    }
}

/// The provisioned v16 client-repo path (holds `scripts/start-test-node.sh`); override with
/// `MIDEN_V16_NODE_DIR`.
pub const DEFAULT_V16_NODE_DIR: &str = "/home/agent/work/miden-client-v16";

/// Where the v16 node lives + how the harness reaches it. The node itself is brought up by the
/// client repo's `start-test-node.sh` (see [`crate::stack`]); `run_root` holds only the client
/// store/keystore/evidence.
#[derive(Debug, Clone)]
pub struct StackConfig {
    /// Root directory of this run (gitignored): client store, keystore, evidence.
    pub run_root: PathBuf,
    /// The v16 client-repo dir whose `scripts/start-test-node.sh` brings up the node.
    pub client_repo_dir: PathBuf,
    pub rpc_port: u16,
    /// Nominal loopback ports (evidence metadata; the v16 node's real internal ports are the
    /// script's own — the harness only ever talks to `rpc_port`).
    pub validator_port: u16,
    pub ntx_builder_port: u16,
    pub tx_prover_port: u16,
    /// The shared `x-miden-network-tx-auth` token (the v16 script wires it into the sequencer +
    /// ntx-builder; the harness never presents it).
    pub network_tx_auth_token: String,
}

impl StackConfig {
    pub fn new(run_root: PathBuf) -> Self {
        let client_repo_dir = std::env::var("MIDEN_V16_NODE_DIR")
            .unwrap_or_else(|_| DEFAULT_V16_NODE_DIR.to_string())
            .into();
        Self {
            run_root,
            client_repo_dir,
            rpc_port: RPC_PORT,
            validator_port: VALIDATOR_PORT,
            ntx_builder_port: NTX_BUILDER_PORT,
            tx_prover_port: TX_PROVER_PORT,
            network_tx_auth_token: NETWORK_TX_AUTH_TOKEN.to_string(),
        }
    }

    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }
    pub fn validator_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.validator_port)
    }
    pub fn ntx_builder_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ntx_builder_port)
    }
    pub fn tx_prover_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.tx_prover_port)
    }
    /// The v16 node's service-log directory (`start-test-node.sh` writes
    /// `validator/sequencer/ntx-builder/prover.log` here).
    pub fn log_dir(&self) -> PathBuf {
        self.client_repo_dir.join("target/test-node/data/logs")
    }
}

/// Full LNV-1 run configuration.
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub stack: StackConfig,
    /// The faucet's `max_supply` at build (mutable post-deploy via `set_max_supply`).
    pub max_supply: u64,
    /// The run's domain params: the three build-seeded fields + the identifier the FIRST
    /// (succeeding) `identifier_init` commits.
    pub domain_params: DomainParams,
    /// The everywhere-different params whose identifier the SECOND (rejected) `identifier_init`
    /// carries.
    pub reinit_params: DomainParams,
    /// Keep the node stack running after the run (supervised/manual inspection); default false —
    /// the stack MUST be torn down so port 57291 is free for the next run.
    pub keep_stack: bool,
}

impl RunConfig {
    /// A fresh run rooted under `local-node-data/lnv1/<label>` in the repo (gitignored) — the
    /// historical single-slice layout the LNV-1..4 binaries use.
    pub fn fresh(repo_root: &Path, label: &str) -> Self {
        Self::fresh_under(repo_root, "lnv1", label)
    }

    /// A fresh run rooted under `local-node-data/<track>/<label>` (gitignored). The LNV-5
    /// consolidated gate runs under the `lnv5` track.
    pub fn fresh_under(repo_root: &Path, track: &str, label: &str) -> Self {
        let run_root = repo_root.join("local-node-data").join(track).join(label);
        Self {
            stack: StackConfig::new(run_root),
            max_supply: 1_000_000_000_000,
            domain_params: DomainParams::lnv1(),
            reinit_params: DomainParams::lnv1_reinit_attempt(),
            keep_stack: false,
        }
    }
}

/// The repo root, resolved from this crate's manifest dir (`crates/xusdc-validation` → two up).
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the crate lives two levels under the repo root")
}
