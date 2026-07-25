//! LNV-1 test suite — matrix rows A (deploy + recognize) and B (`domain_init` init-once),
//! written TEST-FIRST against the assertion suite + driver API.
//!
//! Two layers:
//! 1. **The real-node E2E** (`lnv1_rows_ab_against_real_local_node`): boots a FRESH local
//!    v0.15.1 stack, deploys the production faucet via path C, drives `domain_init` #1/#2, and
//!    judges the observations with the row-A/B assertion suite. This is the gate run for this
//!    slice; it needs the pinned node binaries installed (`miden-node`/`miden-validator`/
//!    `miden-ntx-builder`/`miden-remote-prover`) and free loopback ports 57291–57294. It is
//!    `#[ignore]`d in the DEFAULT suite because it requires loopback LISTENER binds, which
//!    hermetic audit sandboxes deny (`Operation not permitted` on bind) — run it explicitly:
//!    `cargo test -p xusdc-validation --locked -- --include-ignored` (or the `lnv1_rows_ab`
//!    binary). The full-matrix gate claim ("rows A/B pass on a REAL node") rides ONLY on such real
//!    runs plus the LNV-1 human supervision gate — a green DEFAULT suite is NEVER the gate.
//! 2. **Assertion negatives** (no node, sandbox-safe — the default suite): synthetic
//!    observations built from REAL production-composition accounts, each proving one row-check
//!    actually rejects the state it exists to reject — a silently-weakened assertion suite
//!    fails these.

use anyhow::Result;
use miden_protocol::account::{
    Account, AccountBuilder, AccountId, AccountIdVersion, AccountType, AssetCallbackFlag,
};
use miden_standards::account::auth::AuthNetworkAccount;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_validation::assertions::{assert_row_a, assert_row_b, ERR_DOMAIN_REINIT_TEXT};
use xusdc_validation::config::{repo_root, DomainParams, RunConfig};
use xusdc_validation::deploy::{build_xreserve_component_seeded, production_components};
use xusdc_validation::evidence::write_evidence;
use xusdc_validation::observations::RowsAbObservations;
use xusdc_validation::rows_ab::run_rows_ab;

const MAX_SUPPLY: u64 = 1_000_000_000_000;

// ── synthetic-fixture helpers ────────────────────────────────────────────────────────────────

fn wallet_id(seed: u8) -> AccountId {
    // v16: `AccountId::dummy` gained an `AssetCallbackFlag` param (#3167 / MIGRATION-V16-ALPHA2.md
    // S6). These synthetic wallets register no transfer policy, so the flag is `Disabled`.
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// A production-shaped faucet `Account` with nonce 1 (as if deployed), optionally with the five
/// domain-config slots pre-seeded (`Some(params)` = post-init shape) and an optional REPLACEMENT
/// auth component (`None` = the frozen production auth).
fn synthetic_deployed_faucet(
    domain: Option<&DomainParams>,
    auth_override: Option<AuthNetworkAccount>,
) -> Result<Account> {
    let xreserve = build_xreserve_component_seeded(domain)?;
    let components = production_components(
        xreserve,
        wallet_id(1),
        wallet_id(2),
        wallet_id(3),
        MAX_SUPPLY,
    )?;
    let auth = match auth_override {
        Some(auth) => auth,
        None => XReserveStablecoinBuilder::auth_component()?,
    };
    let account = AccountBuilder::new([7u8; 32])
        .account_type(AccountType::Public)
        .with_auth_component(auth)
        .with_components(components)
        .build_existing()?;
    Ok(account)
}

/// A green-shaped observation set around `deployed`/`after_reinit` (callers then break exactly
/// the one surface their test targets).
fn synthetic_obs(deployed: Option<Account>, after_reinit: Option<Account>) -> RowsAbObservations {
    let faucet_id = deployed
        .as_ref()
        .or(after_reinit.as_ref())
        .map(Account::id)
        .unwrap_or_else(|| wallet_id(9));
    RowsAbObservations {
        main_commit: "synthetic".to_string(),
        faucet_id,
        deployed,
        deploy_tx_id: "0xsynthetic".to_string(),
        deploy_block: 1,
        owner_id: wallet_id(1),
        domain_params: DomainParams::lnv1(),
        reinit_params: DomainParams::lnv1_reinit_attempt(),
        first_note_id: "0xnote1".to_string(),
        second_note_id: "0xnote2".to_string(),
        reinit_error: Some(format!("executor trap: {ERR_DOMAIN_REINIT_TEXT}")),
        after_reinit,
        second_note_consumed: false,
    }
}

/// The fully green synthetic shape (post-init faucet, reinit rejected, nothing changed).
fn green_obs() -> Result<RowsAbObservations> {
    let params = DomainParams::lnv1();
    let deployed = synthetic_deployed_faucet(Some(&params), None)?;
    let after = synthetic_deployed_faucet(Some(&params), None)?;
    Ok(synthetic_obs(Some(deployed), Some(after)))
}

// ── row A negatives ──────────────────────────────────────────────────────────────────────────

/// Row A must reject a node that does not recognize the deployed account.
#[test]
fn row_a_rejects_unrecognized_account() -> Result<()> {
    let obs = synthetic_obs(None, None);
    let err = assert_row_a(&obs).expect_err("row A must fail when GetAccount returns nothing");
    assert!(
        format!("{err:#}").contains("GetAccount"),
        "the failure must name the missing GetAccount recognition, got: {err:#}"
    );
    Ok(())
}

/// Row A must reject an on-chain allowlist that lost exactly one root of the frozen production set
/// — an exact-set check, not a non-empty check. The fixture size is derived from the frozen set
/// (owned by `XReserveStablecoinBuilder`) so this tripwire tracks it without a magic number.
#[test]
fn row_a_rejects_a_thinned_allowlist() -> Result<()> {
    let full = XReserveStablecoinBuilder::allowed_note_scripts();
    let mut thinned = full.clone();
    let dropped = *thinned.iter().next().expect("the frozen set is non-empty");
    thinned.remove(&dropped);
    assert_eq!(
        thinned.len(),
        full.len() - 1,
        "the thinned fixture drops exactly one root"
    );
    let auth = AuthNetworkAccount::with_allowed_notes(thinned)?;

    let params = DomainParams::lnv1();
    let account = synthetic_deployed_faucet(Some(&params), Some(auth))?;
    let obs = synthetic_obs(Some(account), None);
    let err = assert_row_a(&obs).expect_err("row A must fail on a thinned allowlist");
    assert!(
        format!("{err:#}").contains("allowlist"),
        "the failure must name the allowlist, got: {err:#}"
    );
    Ok(())
}

/// Row A on the green synthetic shape still requires a REAL green E2E for the on-chain claim —
/// but the assertion suite itself must accept the correct shape (guards against an
/// always-failing suite).
#[test]
fn row_a_accepts_the_production_shape() -> Result<()> {
    let obs = green_obs()?;
    assert_row_a(&obs)?;
    Ok(())
}

// ── row B negatives ──────────────────────────────────────────────────────────────────────────

/// Row B must reject an UNINITIALIZED domain config (empty slots = domain_init never executed).
#[test]
fn row_b_rejects_uninitialized_domain_config() -> Result<()> {
    let deployed = synthetic_deployed_faucet(None, None)?;
    let after = synthetic_deployed_faucet(None, None)?;
    let obs = synthetic_obs(Some(deployed), Some(after));
    let err = assert_row_b(&obs).expect_err("row B must fail when the domain slots are empty");
    assert!(
        format!("{err:#}").contains("read-back"),
        "the failure must name the read-back mismatch, got: {err:#}"
    );
    Ok(())
}

/// Row B must reject a run whose second domain_init did NOT fail (init-once did not hold).
#[test]
fn row_b_requires_a_reinit_failure() -> Result<()> {
    let mut obs = green_obs()?;
    obs.reinit_error = None;
    let err = assert_row_b(&obs).expect_err("row B must fail when the reinit attempt succeeded");
    assert!(
        format!("{err:#}").contains("did not fail"),
        "the failure must say the attempt did not fail, got: {err:#}"
    );
    Ok(())
}

/// Row B must reject a reinit failure with the WRONG error (only the init-once gate counts —
/// e.g. an RPC-layer rejection is NOT the on-chain init-once semantics).
#[test]
fn row_b_requires_the_exact_reinit_gate_error() -> Result<()> {
    let mut obs = green_obs()?;
    obs.reinit_error = Some("Network transactions may not be submitted by users yet".to_string());
    let err = assert_row_b(&obs).expect_err("row B must fail on a non-gate failure");
    assert!(
        format!("{err:#}").contains(ERR_DOMAIN_REINIT_TEXT),
        "the failure must name the expected gate error, got: {err:#}"
    );
    Ok(())
}

/// Row B must reject any write of the SECOND note's params (the init-once gate leaked).
#[test]
fn row_b_rejects_second_params_written() -> Result<()> {
    let first = DomainParams::lnv1();
    let second = DomainParams::lnv1_reinit_attempt();
    let deployed = synthetic_deployed_faucet(Some(&first), None)?;
    // After the "attempt", storage suddenly holds the SECOND note's params.
    let after = synthetic_deployed_faucet(Some(&second), None)?;
    let obs = synthetic_obs(Some(deployed), Some(after));
    let err = assert_row_b(&obs)
        .expect_err("row B must fail when the second note's params reached storage");
    assert!(
        format!("{err:#}").contains("post-reinit-attempt"),
        "the failure must name the post-attempt state, got: {err:#}"
    );
    Ok(())
}

/// Row B must reject an on-chain consumption of the second note within the watch window.
#[test]
fn row_b_rejects_a_consumed_second_note() -> Result<()> {
    let mut obs = green_obs()?;
    obs.second_note_consumed = true;
    let err = assert_row_b(&obs).expect_err("row B must fail when note #2 was consumed");
    assert!(
        format!("{err:#}").contains("consumed"),
        "the failure must name the consumption, got: {err:#}"
    );
    Ok(())
}

/// The green synthetic shape passes row B (guards against an always-failing suite).
#[test]
fn row_b_accepts_the_initialized_shape() -> Result<()> {
    let obs = green_obs()?;
    assert_row_b(&obs)?;
    Ok(())
}

// ── the real-node E2E (the gate run for this slice) ──────────────────────────────────────────

/// Rows A + B against a REAL fresh local node: bootstrap genesis, start
/// validator/ntx-builder/sequencer/prover, deploy the production faucet (its first transaction
/// consumes the owner's `domain_init` — the first admin note), verify recognition + read-backs,
/// prove init-once, tear down. Writes `evidence.json` under the gitignored run root either way.
///
/// Ignored by default (NOT optional for the gate): it must bind loopback listener sockets for
/// the four node services, which hermetic audit sandboxes forbid. The gate record requires this
/// test green via `-- --include-ignored` on a network-enabled box; the default suite's green
/// carries no real-node claim.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real-node E2E: needs the v0.15.1 node binaries + loopback listener binds (denied in \
            sandboxed audit environments); run with `-- --include-ignored` or the lnv1_rows_ab \
            binary — the §11.2 gate claim rides on real runs + the human gate, never on the \
            default suite"]
async fn lnv1_rows_ab_against_real_local_node() -> Result<()> {
    let label = format!(
        "test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the epoch")
            .as_secs()
    );
    let cfg = RunConfig::fresh(&repo_root(), &label);

    let obs = run_rows_ab(&cfg).await?;
    let row_a = assert_row_a(&obs);
    let row_b = assert_row_b(&obs);
    let evidence = write_evidence(&cfg, &obs, &row_a, &row_b)?;
    println!("LNV-1 evidence: {}", evidence.display());

    row_a?;
    row_b?;
    Ok(())
}
