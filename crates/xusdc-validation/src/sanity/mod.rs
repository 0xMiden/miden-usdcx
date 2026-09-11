//! Runs faucet checks against an existing node.
//! With no faucet ID, deploys a disposable local faucet and includes administrative changes.
//! With a supplied faucet ID, runs mint, burn, and rejection checks without administrative changes.
//! Successful transactions commit through the network transaction builder; rejection probes
//! execute locally.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use miden_client::rpc::NodeRpcClient;
use miden_client::store::TransactionFilter;
use miden_client::transaction::{TransactionId, TransactionRequestBuilder, TransactionStatus};
use miden_protocol::account::AccountId;
use miden_protocol::Word;
use miden_standards::interop::eth::EthEmbeddedAccountId;

use xusdc_encoding::note::xreserve_admin::XReserveIdentifierInitNote;
use xusdc_encoding::xreserve::encoding::bytes32_to_storage_map_key;

use crate::actors::{create_actors, Actors, AttesterKey};
use crate::client::{os_seed, HarnessClient};
use crate::deploy::build_faucet_account;
use crate::mintburn;

mod admin;
mod admin_restore;
mod checks;
mod driver;
mod evidence;
mod net;
mod record;
#[cfg(test)]
mod tests;

pub use checks::{assert_attester_consumable, assert_burn_note_structure};
pub use record::render_sanity_record;

use driver::SanityDriver;

// MANDATED AMOUNTS (xUSDC 6-decimal smallest units; scale-0 identity ⇒ raw == minted units)
// ================================================================================================

/// The round-number mint: a Circle-format deposit of 100 xUSDC.
pub const MINT_ROUND_UNITS: u64 = 100_000_000;
/// The NON-round mint: the P0 regression probe — any residual 10^6 rescale would corrupt it.
pub const MINT_NONROUND_UNITS: u64 = 123_456_789;
/// The mandated burn: 50 xUSDC.
pub const BURN_UNITS: u64 = 50_000_000;
/// The faucet's deploy-time max supply (mutable via `set_max_supply`). Comfortably above the mints.
pub const DEPLOY_MAX_SUPPLY: u64 = 1_000_000_000_000;
/// The `set_max_supply` target the admin check writes and reads back (proves cap mutability).
pub const RAISED_MAX_SUPPLY: u64 = 3_000_000_000_000;
/// The raised `min_burn_size`; a burn below it must reject.
pub const RAISED_MIN_BURN: u64 = BURN_UNITS + 1;
/// The lowered `min_burn_size` restored so the mandated 50 xUSDC burn passes.
pub const LOWERED_MIN_BURN: u64 = 1;

/// Bounded wait for a submitted (regular-account) tx to commit (deploy path).
const TX_COMMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(240);

// CONFIG + REPORT
// ================================================================================================

/// Sanity-run configuration. `faucet_id = None` ⇒ deploy a FRESH production faucet on a LOCAL node and
/// run the FULL suite incl. the destructive admin surface (the local gate — the ONLY place the admin
/// surface runs). `Some(id)` ⇒ target an already-deployed faucet (local OR devnet) and run ONLY the
/// non-destructive fund-correctness subset (mint / burn / attestation / replay / cap) — NO admin, so a
/// deployed faucet is never mutated. The existing-faucet path requires `attester_secret`.
#[derive(Debug, Clone)]
pub struct SanityConfig {
    /// The node RPC URL (`http://127.0.0.1:57291` locally; the devnet RPC for the re-check).
    pub rpc_url: String,
    /// A pre-deployed faucet to target (non-destructive subset); `None` deploys a fresh one (local
    /// full gate).
    pub faucet_id: Option<AccountId>,
    /// Scratch root for the client store, keystore, and actor secrets (gitignored).
    pub run_root: PathBuf,
    /// The deployed faucet's ALREADY-ALLOWLISTED attester secret scalar (existing-faucet re-check
    /// only; the operator supplies the real key so the mint checks authenticate). `None` ⇒ generate a
    /// throwaway key (local full gate).
    pub attester_secret: Option<[u8; 32]>,
    /// The running node's service-log directory to scan for the clean-log gate (local only; a remote
    /// devnet node has no local logs, so `None` skips it).
    pub node_log_dir: Option<PathBuf>,
}

/// One recorded assertion outcome (pass or fail).
#[derive(Debug, Clone)]
pub struct Check {
    pub id: String,
    pub area: String,
    pub what: String,
    pub pass: bool,
    pub detail: String,
}

/// The full sanity report — every check plus the run identities.
#[derive(Debug, Clone)]
pub struct SanityReport {
    pub rpc_url: String,
    pub node_version: String,
    pub deployed_fresh: bool,
    /// Whether the node RPC is a LOOPBACK/local node (vs a remote/devnet node), derived from the RPC
    /// URL ([`is_loopback`]). Tracked SEPARATELY from `deployed_fresh` so a caller-supplied faucet
    /// exercised on localhost is rendered as a LOCAL re-run, NEVER mislabeled as a DEVNET run.
    pub local_node: bool,
    pub faucet_id: String,
    pub owner_id: String,
    pub recipient_id: String,
    pub holder_id: String,
    pub attester_commitment_hex: String,
    /// Whether the mint attester was OPERATOR-SUPPLIED (an already-allowlisted deployed-faucet key,
    /// on the existing-faucet re-run) vs a LOCAL THROWAWAY key the harness generated + allowlisted
    /// (fresh deploy). Drives the record's provenance label so a supplied key is not mislabeled as a
    /// local test key. For the LOCAL throwaway key the harness can assert it is not a Circle key; for
    /// an OPERATOR-SUPPLIED key this run makes NO origin claim — provenance is the operator's
    /// responsibility (see [`render_sanity_record`]).
    pub attester_supplied: bool,
    pub checks: Vec<Check>,
}

impl SanityReport {
    /// Whether no check failed.
    pub fn all_passed(&self) -> bool {
        self.failures().is_empty()
    }
    /// The failing checks (executed and did not hold — the surfaced findings that BLOCK the deploy).
    pub fn failures(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| !c.pass).collect()
    }
}

/// Accumulates checks during the run.
pub(crate) struct Ledger {
    pub(crate) checks: Vec<Check>,
}

impl Ledger {
    fn new() -> Self {
        Self { checks: Vec::new() }
    }
    pub(crate) fn record(&mut self, id: &str, area: &str, what: &str, pass: bool, detail: String) {
        println!(
            "  [{}] {id}: {what} — {detail}",
            if pass { "PASS" } else { "FAIL" }
        );
        self.checks.push(Check {
            id: id.to_string(),
            area: area.to_string(),
            what: what.to_string(),
            pass,
            detail,
        });
    }
}

// THE ORCHESTRATOR
// ================================================================================================

/// Whether `rpc_url` points at a LOOPBACK node on this box — the only place a fresh deploy is allowed,
/// and the discriminator that labels the run's ENVIRONMENT (local vs devnet) in the record. Extracts
/// the exact host (strips scheme, path, and `:port`) and exact-matches a loopback host, so a spoof
/// like `http://127.0.0.1.evil.com` (host `127.0.0.1.evil.com`) is correctly treated as REMOTE.
pub fn is_loopback(rpc_url: &str) -> bool {
    let after_scheme = rpc_url.rsplit("://").next().unwrap_or(rpc_url);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal `[::1]:port` → `::1`.
        rest.split(']').next().unwrap_or(rest)
    } else {
        // `host:port` → `host` (rsplit so a bare `host` with no port is left intact).
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    matches!(
        host.to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost" | "::1"
    )
}

/// The validated run mode, decided PURELY from the config (node-free). `deployed_fresh` ⇒ we deploy a
/// faucet we own and run the FULL suite incl. the DESTRUCTIVE admin surface; otherwise we target an
/// already-deployed faucet and run ONLY the non-destructive subset. `run_admin == deployed_fresh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunMode {
    pub(crate) deployed_fresh: bool,
    pub(crate) local_node: bool,
    pub(crate) run_admin: bool,
}

/// Decides + VALIDATES the run mode, enforcing the LOCALITY INVARIANT: a FRESH deploy — which runs the
/// destructive admin suite against a faucet we create — is a LOCAL-only action, so a fresh deploy
/// against a NON-loopback (remote/devnet) RPC is REFUSED. This is the single authority every caller
/// goes through ([`run_sanity`], and via it the live integration test), so NO direct caller can
/// fresh-deploy + mutate a remote/devnet faucet — the CLI's own check is defense-in-depth on top.
/// Pure + node-free (no RPC), so it is unit-tested without a node.
pub(crate) fn decide_run_mode(faucet_id: Option<AccountId>, rpc_url: &str) -> Result<RunMode> {
    let deployed_fresh = faucet_id.is_none();
    let local_node = is_loopback(rpc_url);
    if deployed_fresh && !local_node {
        bail!(
            "REFUSED: a fresh deploy + the DESTRUCTIVE admin suite is a LOCAL-only action, but \
             rpc_url '{rpc_url}' is not a loopback node. Devnet deployment is OUT OF SCOPE — target \
             an ALREADY-deployed faucet with a faucet id (the non-destructive re-check) instead."
        );
    }
    Ok(RunMode {
        deployed_fresh,
        local_node,
        run_admin: deployed_fresh,
    })
}

/// Runs the whole sanity suite against the node at `cfg.rpc_url`, returning the populated report.
/// A HARD infra failure (node unreachable, a positive consumption that never commits) bails; an
/// assertion that does not hold is RECORDED (`pass = false`) so the binary surfaces every finding.
pub async fn run_sanity(cfg: &SanityConfig, node_version: &str) -> Result<SanityReport> {
    // Decide + VALIDATE the mode FIRST — before ANY RPC / filesystem / deploy work — so a remote
    // fresh-deploy (which would run the destructive admin suite against a faucet on a remote/devnet
    // node) is refused here, for EVERY caller of run_sanity, not just the CLI.
    let RunMode {
        deployed_fresh,
        local_node,
        run_admin,
    } = decide_run_mode(cfg.faucet_id, &cfg.rpc_url)?;

    std::fs::create_dir_all(&cfg.run_root)
        .with_context(|| format!("creating the run root {}", cfg.run_root.display()))?;

    let mut hc = net::build_client_at(&cfg.rpc_url, &cfg.run_root).await?;
    hc.client.sync_state().await.context("initial sync")?;

    // The attester that signs POSITIVE mints: the operator-supplied allowlisted key (existing
    // faucet), else a fresh throwaway key allowlisted on the fresh deploy (local).
    let supplied_attester = match &cfg.attester_secret {
        Some(scalar) => Some(
            AttesterKey::from_secret_scalar(scalar, &cfg.run_root, "supplied")
                .context("loading the supplied attester secret")?,
        ),
        None => None,
    };
    if !deployed_fresh && supplied_attester.is_none() {
        bail!(
            "the existing-faucet re-check (--faucet-id) requires the deployed faucet's \
             ALREADY-ALLOWLISTED attester secret via --attester-secret-file <PATH> / \
             SANITY_ATTESTER_SECRET — never on argv"
        );
    }

    // Actors are ALWAYS fresh harness wallets (never Circle keys). On the fresh-deploy path they are
    // the faucet's own roles; on the existing-faucet subset the admin surface never runs, so the
    // owner/DOM_PAUSER wallets are simply unused for mutation.
    let actors = create_actors(&mut hc, &cfg.run_root)
        .await
        .context("creating local test actors (never Circle keys)")?;

    let owner_id = actors.owner.id();
    let recipient_id = actors.recipient.id();
    let holder_id = actors.holder.id();
    // The relayer that emits mint notes is permissionless — any wallet. Use the manager wallet.
    let relayer_id = actors.manager.id();
    // Provenance for the record: a supplied attester is the deployed faucet's already-allowlisted
    // key; otherwise it is a local throwaway the harness generated + allowlisted.
    let attester_supplied = supplied_attester.is_some();
    let mint_attester: &AttesterKey = supplied_attester.as_ref().unwrap_or(&actors.attester);

    let faucet_id = match cfg.faucet_id {
        Some(id) => {
            register_existing_faucet(&mut hc, id).await?;
            id
        }
        None => deploy_fresh_faucet(&mut hc, &actors).await?,
    };

    let mut d = SanityDriver {
        hc,
        faucet_id,
        // Fresh-LOCAL: the fresh faucet's identifier is the own-id fixpoint the `identifier_init`
        // note derives (`identifier_for(faucet_id)`), so mints must carry `remoteToken =
        // EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()` — the OWN-ID config, not the vector token. `remoteDomain`
        // already equals the build-seed MINT_DOMAIN. Existing-faucet: resolved from the DEPLOYED
        // faucet below (same own-id shape, read from chain).
        mint_config: Some(mintburn::MintDomainConfig::for_deployed_faucet(
            mintburn::MINT_DOMAIN,
            faucet_id,
        )),
    };
    if !deployed_fresh {
        d.mint_config = Some(resolve_deployed_mint_config(&mut d, faucet_id).await?);
    }
    let mut led = Ledger::new();

    // A fresh deploy allowlists its throwaway attester; an existing faucet's supplied attester is
    // ALREADY allowlisted (do not re-add).
    if deployed_fresh {
        admin::allowlist_attester(&mut d, owner_id, mint_attester).await?;
    }

    // 1. MINT — scale-0 identity, round + non-round.
    checks::mint_and_assert(
        &mut d,
        &mut led,
        relayer_id,
        mint_attester,
        recipient_id,
        MINT_ROUND_UNITS,
        checks::SALT_MINT_ROUND,
        "MINT-ROUND",
        "100 xUSDC (round)",
    )
    .await?;
    checks::mint_and_assert(
        &mut d,
        &mut led,
        relayer_id,
        mint_attester,
        recipient_id,
        MINT_NONROUND_UNITS,
        checks::SALT_MINT_NONROUND,
        "MINT-NONROUND",
        "123.456789 xUSDC (P0 regression)",
    )
    .await?;

    // 2. Attestation + fund-safety negatives.
    checks::negatives_suite(
        &mut d,
        &mut led,
        relayer_id,
        mint_attester,
        &actors.attester_b,
        recipient_id,
    )
    .await?;

    checks::burn_and_assert(&mut d, &mut led, mint_attester, relayer_id, holder_id).await?;

    // 4. Admin surface — DESTRUCTIVE (pause/unpause, attester rotation, min/max setters, owner-gating,
    //    2-step ownership + restore). Runs ONLY on a FRESH deploy — a faucet we own and throw away with
    //    the local node. Against an already-deployed faucet (local OR devnet) it NEVER runs, so a
    //    deployed faucet is never mutated; that non-destructive subset is the INTENDED complete matrix.
    if run_admin {
        admin::admin_suite(
            &mut d,
            &mut led,
            &actors,
            mint_attester,
            relayer_id,
            recipient_id,
        )
        .await?;
    }

    // 5. Clean-node-log gate (local only; a remote devnet node has no local logs).
    if let Some(log_dir) = &cfg.node_log_dir {
        log_check(&mut led, log_dir);
    }

    Ok(SanityReport {
        rpc_url: cfg.rpc_url.clone(),
        node_version: node_version.to_string(),
        deployed_fresh,
        local_node,
        faucet_id: faucet_id.to_string(),
        owner_id: owner_id.to_string(),
        recipient_id: recipient_id.to_string(),
        holder_id: holder_id.to_string(),
        attester_commitment_hex: mint_attester.commitment_hex.clone(),
        attester_supplied,
        checks: led.checks,
    })
}

/// The clean-node-log gate: scans the run's service logs (the same classifier + expected-pattern
/// table the LNV row-L gate uses) and records a PASS iff there are ZERO unexpected ERROR lines, ZERO
/// panics, and ZERO untriaged WARN lines.
fn log_check(led: &mut Ledger, log_dir: &Path) {
    use crate::rows_kl::{scan_logs, EXPECTED_LOG_LINES};
    use crate::stack::V16_SERVICES;
    let what = "the node's four v16 service logs are present, non-empty, and free of unexpected ERROR / panic / untriaged-WARN lines";
    match scan_logs(log_dir, EXPECTED_LOG_LINES) {
        Ok(l) => {
            // Completeness: every required v16 service log must be present AND non-empty — otherwise
            // the gate would pass vacuously on a missing/zero-byte log set (fail-open).
            let mut missing = Vec::new();
            for svc in V16_SERVICES {
                match l.scanned.iter().find(|s| s.service == svc) {
                    None => missing.push(format!("{svc} (absent)")),
                    Some(s) if s.bytes == 0 || s.lines == 0 => {
                        missing.push(format!("{svc} (empty)"))
                    }
                    Some(_) => {}
                }
            }
            let flagged_clean = l.unexpected_errors.is_empty()
                && l.panics.is_empty()
                && l.untriaged_warnings.is_empty();
            let pass = missing.is_empty() && flagged_clean;
            let detail = if pass {
                format!(
                    "all {} required service logs present + non-empty; 0 unexpected ERROR, 0 panic, 0 untriaged WARN ({} triaged-WARN lines)",
                    V16_SERVICES.len(),
                    l.triaged_warnings.len()
                )
            } else if !missing.is_empty() {
                format!("INCOMPLETE service-log set: {}", missing.join(", "))
            } else {
                let flagged: Vec<String> = l
                    .panics
                    .iter()
                    .chain(l.unexpected_errors.iter())
                    .chain(l.untriaged_warnings.iter())
                    .take(5)
                    .map(|f| format!("[{}] {}", f.service, f.line))
                    .collect();
                format!(
                    "UNCLEAN: {} unexpected ERROR, {} panic, {} untriaged WARN; e.g. {}",
                    l.unexpected_errors.len(),
                    l.panics.len(),
                    l.untriaged_warnings.len(),
                    flagged.join(" | ")
                )
            };
            led.record("NODE-LOGS-CLEAN", "logs", what, pass, detail);
        }
        Err(e) => led.record(
            "NODE-LOGS-CLEAN",
            "logs",
            what,
            false,
            format!("could not scan {}: {e:#}", log_dir.display()),
        ),
    }
}

/// Resolves the DEPLOYED faucet's mint domain config for the `--faucet-id` re-check (the thin
/// slot-read adapter; the node-free logic lives in [`mintburn::MintDomainConfig`]). Reads the on-chain
/// `domain` and pairs it with `remote_token = EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()` — the two fields the
/// structural validation mint gate compares. Then VERIFIES the faucet's stored identifier key equals
/// `bytes32_to_storage_map_key(EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32())`: if it does not, the deployed
/// identifier is NOT `EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()` and every mint would be rejected at structural validation, so we
/// bail HERE with an explicit message instead of letting the operator hit the 300s path-N timeout (the
/// A6 failure mode). The `domain` compare cannot be pre-verified the same way (the mint payload IS what
/// establishes the domain), so a wrong stored domain is caught by the resolved config making the mint
/// carry exactly it.
async fn resolve_deployed_mint_config(
    d: &mut SanityDriver,
    faucet_id: AccountId,
) -> Result<mintburn::MintDomainConfig> {
    let faucet = d.fetch_faucet().await?;
    let domain = driver::domain_config(&faucet)?;
    let config = mintburn::MintDomainConfig::for_deployed_faucet(domain, faucet_id);
    let stored_identifier = driver::identifier_config(&faucet)?;
    let expected_identifier: Word = bytes32_to_storage_map_key(&config.remote_token).into();
    if stored_identifier != expected_identifier {
        bail!(
            "the deployed faucet {faucet_id}'s stored identifier key {stored_identifier:?} does not \
             match bytes32_to_storage_map_key(EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()) {expected_identifier:?}: \
             the mint gate (structural validation) would reject every mint with WRONG_IDENTIFIER. The --faucet-id \
             re-check requires the identifier A5's identifier_init set from EthEmbeddedAccountId::from_account_id(faucet.id()).to_bytes32()."
        );
    }
    println!("resolved deployed-faucet mint config: domain={domain}, identifier verified");
    Ok(config)
}

/// Registers a deployed faucet (existing-faucet re-check) with the client so the client-side negative
/// probes can execute against its committed state.
async fn register_existing_faucet(hc: &mut HarnessClient, id: AccountId) -> Result<()> {
    let account = hc
        .rpc
        .get_account_details(id)
        .await
        .map_err(|e| anyhow::anyhow!("GetAccount({id}) for the supplied --faucet-id: {e}"))?
        .with_context(|| format!("the node does not recognize the supplied faucet {id}"))?;
    hc.client
        .add_account(&account, true)
        .await
        .with_context(|| format!("registering the supplied faucet {id} with the client"))?;
    Ok(())
}

/// Deploys the harness faucet and registers it with the client.
async fn deploy_fresh_faucet(hc: &mut HarnessClient, actors: &Actors) -> Result<AccountId> {
    let owner_id = actors.owner.id();
    let domain = mintburn::lnv2_domain_params();
    let faucet = build_faucet_account(
        owner_id,
        actors.pauser.id(),
        actors.manager.id(),
        actors.blk_manager.id(),
        DEPLOY_MAX_SUPPLY,
        &domain,
        os_seed(),
    )?;
    let faucet_id = faucet.id();
    println!("deploying fresh faucet {faucet_id}");

    let note1 = XReserveIdentifierInitNote::create(owner_id, faucet_id, hc.client.rng())
        .context("building the identifier_init note")?;

    let emit1 = TransactionRequestBuilder::new()
        .own_output_notes(vec![note1.clone()])
        .build()
        .context("building the owner identifier_init emit")?;
    let emit1_tx = hc
        .client
        .submit_new_transaction(owner_id, emit1)
        .await
        .context("submitting the owner identifier_init emit")?;
    wait_commit_bare(hc, emit1_tx).await?;

    hc.client
        .add_account(&faucet, false)
        .await
        .context("registering the new faucet account with the client")?;
    let deploy = TransactionRequestBuilder::new()
        .input_notes(vec![(note1, None)])
        .build()
        .context("building the deploy request")?;
    let deploy_tx = hc
        .client
        .submit_new_transaction(faucet_id, deploy)
        .await
        .context("submitting the faucet deploy (+identifier_init) transaction")?;
    wait_commit_bare(hc, deploy_tx).await?;
    println!("faucet deployed + identifier_init committed");
    Ok(faucet_id)
}

/// Bare tx-commit wait used before the [`SanityDriver`] exists (during deploy).
async fn wait_commit_bare(hc: &mut HarnessClient, tx_id: TransactionId) -> Result<u32> {
    use std::time::Instant;
    let deadline = Instant::now() + TX_COMMIT_TIMEOUT;
    loop {
        hc.client
            .sync_state()
            .await
            .context("sync while waiting for a tx")?;
        let record = hc
            .client
            .get_transactions(TransactionFilter::Ids(vec![tx_id]))
            .await?
            .pop()
            .with_context(|| format!("tx {tx_id} not tracked"))?;
        match record.status {
            TransactionStatus::Committed { block_number, .. } => return Ok(block_number.as_u32()),
            TransactionStatus::Discarded(cause) => bail!("tx {tx_id} DISCARDED: {cause:?}"),
            TransactionStatus::Pending => {
                if Instant::now() > deadline {
                    bail!("tx {tx_id} did not commit within {TX_COMMIT_TIMEOUT:?}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }
}
