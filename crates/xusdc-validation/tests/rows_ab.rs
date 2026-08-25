//! LNV-1 test suite — matrix row A (deploy + recognize), written TEST-FIRST against the assertion
//! suite + driver API.
//!
//! Two layers:
//! 1. **The real-node E2E** (`lnv1_rows_ab_against_real_local_node`): boots a FRESH local v16 stack,
//!    deploys the production faucet via path C, and judges the observations with the row-A assertion
//!    suite. This is the gate run for this slice; it needs the node toolchain installed and free
//!    loopback ports. It is `#[ignore]`d in the DEFAULT suite because it requires loopback LISTENER
//!    binds, which hermetic audit sandboxes deny (`Operation not permitted` on bind) — run it
//!    explicitly: `cargo test -p xusdc-validation --locked -- --include-ignored` (or the
//!    `lnv1_rows_ab` binary). The full-matrix gate claim ("row A passes on a REAL node") rides ONLY
//!    on such real runs plus the LNV-1 human supervision gate — a green DEFAULT suite is NEVER the
//!    gate.
//! 2. **Assertion negatives** (no node, sandbox-safe — the default suite): synthetic
//!    observations built from REAL production-composition accounts, each proving one row-check
//!    actually rejects the state it exists to reject — a silently-weakened assertion suite
//!    fails these.

use anyhow::Result;
use miden_protocol::account::{
    Account, AccountBuilder, AccountId, AccountIdVersion, AccountType, AssetCallbackFlag,
};
use miden_protocol::block::FeeParameters;
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::Felt;
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::tx_script::ExpirationTransactionScript;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_encoding::xreserve::encoding::{
    DepositIntent, EncodingError, ForeignChainAddress, MintIntent,
};
use xusdc_validation::assertions::assert_row_a;
use xusdc_validation::config::{repo_root, DomainParams, RunConfig};
use xusdc_validation::deploy::{build_faucet_account, production_components};
use xusdc_validation::evidence::write_evidence;
use xusdc_validation::mintburn;
use xusdc_validation::observations::RowsAbObservations;
use xusdc_validation::rows_ab::run_rows_ab;

const MAX_SUPPLY: u64 = 1_000_000_000_000;

/// The raw uint256 amount and fee ceiling the identity-binding fixture's deposit intent carries.
/// Neither is read by the structural gate; they only have to be a well-formed pair.
const MINT_AMOUNT_RAW: u64 = 100;
const MINT_MAX_FEE_RAW: u64 = 1;

// ── synthetic-fixture helpers ────────────────────────────────────────────────────────────────

fn wallet_id(seed: u8) -> AccountId {
    // These synthetic wallets register no transfer policy, so the flag is `Disabled`.
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// Fee parameters for the synthetic fixtures. A real run reads these from the chain it deploys to;
/// the row-A checks do not read the fee schedule, only the composition around it.
fn fee_parameters() -> FeeParameters {
    FeeParameters::new(wallet_id(5), 0)
}

/// A production-shaped faucet `Account` with nonce 1 (as if deployed), its four domain-config fields
/// build-seeded from `build_seed` (the builder REQUIRES them — they exist from construction and have
/// no runtime writer). `auth_override` optionally REPLACES the frozen production auth.
fn synthetic_deployed_faucet(
    build_seed: &DomainParams,
    auth_override: Option<AuthNetworkAccount>,
) -> Result<Account> {
    let components = production_components(
        wallet_id(1),
        wallet_id(2),
        wallet_id(3),
        wallet_id(4),
        MAX_SUPPLY,
        build_seed,
        fee_parameters(),
    )?;
    let auth = match auth_override {
        Some(auth) => auth,
        None => XReserveStablecoinBuilder::auth_component(fee_parameters())?,
    };
    Ok(AccountBuilder::new([7u8; 32])
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_components(auth)
        .with_components(components)
        .build_existing()?)
}

/// A green-shaped observation set around `deployed` (callers then break exactly the one surface
/// their test targets).
fn synthetic_obs(deployed: Option<Account>) -> RowsAbObservations {
    let faucet_id = deployed
        .as_ref()
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
    }
}

/// The fully green synthetic shape (a deployed faucet carrying the run's build seed).
fn green_obs() -> Result<RowsAbObservations> {
    let params = DomainParams::lnv1();
    Ok(synthetic_obs(Some(synthetic_deployed_faucet(
        &params, None,
    )?)))
}

// ── row A negatives ──────────────────────────────────────────────────────────────────────────

/// Row A must reject a node that does not recognize the deployed account.
#[test]
fn row_a_rejects_unrecognized_account() -> Result<()> {
    let obs = synthetic_obs(None);
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
    // The production auth shape with ONLY the note set thinned: same fee manager, same one-root
    // tx-script allowlist, so the row fails on the note allowlist and nothing else.
    let fee_policy_manager = FeePolicyManager::builder()
        .fee_faucet_id(fee_parameters().fee_faucet_id())
        .active_fee_policy(BasicConstantFeePolicy::new().into())
        .build();
    let auth = AuthNetworkAccount::custom(thinned, fee_policy_manager)?
        .with_allowed_tx_scripts([ExpirationTransactionScript::script_root()]);

    let params = DomainParams::lnv1();
    let account = synthetic_deployed_faucet(&params, Some(auth))?;
    let obs = synthetic_obs(Some(account));
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

// ── row A domain-config read-back negative ───────────────────────────────────────────────────

/// Row A must reject a faucet whose on-chain domain config does not match the run's build seed —
/// the read-back is an equality check against the deploy parameters, not a presence check.
#[test]
fn row_a_rejects_a_domain_config_read_back_mismatch() -> Result<()> {
    // Deployed with an everywhere-different seed; the observation still claims the run's params.
    let other = DomainParams {
        domain: 9999,
        source_domain: 42,
        xreserve_contract: ForeignChainAddress::new([0xEE; 32]),
    };
    let account = synthetic_deployed_faucet(&other, None)?;
    let obs = synthetic_obs(Some(account));
    let err =
        assert_row_a(&obs).expect_err("row A must fail on a domain-config read-back mismatch");
    assert!(
        format!("{err:#}").contains("read-back"),
        "the failure must name the read-back mismatch, got: {err:#}"
    );
    Ok(())
}

// ── the deploy path itself, driven in memory ─────────────────────────────────────────────────

/// The account the harness actually deploys — `deploy::build_faucet_account`, the thin delegation to
/// `XReserveStablecoinBuilder` — put through row A's production-shape assertions without a node.
///
/// The MASM is assembled at build time and embedded in the shipped component, so the whole
/// composition resolves in memory; the only thing the real deploy adds is the scriptless, noteless
/// first transaction, whose entire effect on the account is the nonce bump `AuthNetworkAccount`
/// authorizes. Reproducing exactly that bump here is what lets row A judge the REAL deploy output
/// rather than a fixture rebuilt from the same components.
///
/// The pre-bump assertions pin the two properties only a NEW account can carry: it is new (nonce 0,
/// so the deploy transaction has something to commit) and its id was derived with asset callbacks
/// ENABLED. That flag is immutable in the id, and xUSDC is a policed asset, so a composition that
/// derived it Disabled would silently skip the transfer-policy callbacks on a live faucet.
#[test]
fn the_deploy_construction_produces_the_row_a_production_shape() -> Result<()> {
    let params = DomainParams::lnv1();
    let mut faucet = build_faucet_account(
        wallet_id(1),
        wallet_id(2),
        wallet_id(3),
        wallet_id(4),
        MAX_SUPPLY,
        &params,
        fee_parameters(),
        [0x5eu8; 32],
    )?;

    assert!(
        faucet.is_new(),
        "the deploy path must produce a NEW account for its first transaction to materialize"
    );
    assert_eq!(
        faucet.id().asset_callback_flag(),
        AssetCallbackFlag::Enabled,
        "xUSDC is policed: the id must be derived with asset callbacks enabled"
    );

    // The deploy transaction's whole effect on the account: `AuthNetworkAccount` authorizes a
    // scriptless, noteless first transaction, which bumps the nonce 0 → 1.
    faucet.increment_nonce(Felt::from(1u32))?;

    let obs = RowsAbObservations {
        faucet_id: faucet.id(),
        deployed: Some(faucet),
        domain_params: params,
        ..synthetic_obs(None)
    };
    assert_row_a(&obs)?;
    Ok(())
}

// ── row A: the faucet-identity binding of a mint ─────────────────────────────────────────────

/// The faucet's identifier IS its own account id — there is no identifier slot and no init note — so
/// a mint names the faucet through the deposit intent's `remoteToken`, and the binding is enforced
/// in the Rust structural gate before any note exists: `MintIntent::from_deposit_intent` returns
/// [`EncodingError::RemoteTokenMismatch`] for an intent addressed to a different faucet.
///
/// This is deliberately NOT an on-chain assertion. The rebuild OVERWRITES `remoteToken` with the
/// faucet's own id read from the kernel, so on chain a foreign token can only ever surface as a
/// signature mismatch — a row-E shape, not an identity check. The positive control below pins that
/// the same payload addressed to this faucet passes, so the negative cannot hold vacuously.
#[test]
fn row_a_rejects_a_deposit_intent_addressed_to_another_faucet() -> Result<()> {
    let faucet = synthetic_deployed_faucet(&DomainParams::lnv1(), None)?.id();
    let other_faucet = wallet_id(0x3b);
    assert_ne!(
        faucet, other_faucet,
        "the fixture must address a genuinely different faucet"
    );
    let recipient = wallet_id(6);

    let elsewhere = mintburn::mint_payload_own_id(
        other_faucet,
        mintburn::BASE_VECTOR,
        recipient,
        MINT_AMOUNT_RAW,
        MINT_MAX_FEE_RAW,
        0x21,
    );
    let intent = DepositIntent::read_from_bytes(&elsewhere).expect("the payload decodes");
    let err = MintIntent::from_deposit_intent(&intent, faucet, mintburn::MINT_DOMAIN)
        .expect_err("a deposit intent naming another faucet must be refused");
    assert!(
        matches!(err, EncodingError::RemoteTokenMismatch),
        "the refusal must be the remoteToken gate, got: {err:?}"
    );

    let here = mintburn::mint_payload_own_id(
        faucet,
        mintburn::BASE_VECTOR,
        recipient,
        MINT_AMOUNT_RAW,
        MINT_MAX_FEE_RAW,
        0x21,
    );
    let intent = DepositIntent::read_from_bytes(&here).expect("the payload decodes");
    MintIntent::from_deposit_intent(&intent, faucet, mintburn::MINT_DOMAIN)
        .expect("an intent addressed to this faucet must be accepted");
    Ok(())
}

// ── the real-node E2E (the gate run for this slice) ──────────────────────────────────────────

/// Row A against a REAL fresh local node: bootstrap genesis, start
/// validator/ntx-builder/sequencer/prover, deploy the production faucet (its first transaction is
/// scriptless and noteless; all four domain-config fields are build-seeded), verify recognition +
/// read-backs, tear down. Writes `evidence.json` under the gitignored run root either way.
///
/// Ignored by default (NOT optional for the gate): it must bind loopback listener sockets for
/// the four node services, which hermetic audit sandboxes forbid. The gate record requires this
/// test green via `-- --include-ignored` on a network-enabled box; the default suite's green
/// carries no real-node claim.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real-node E2E: needs the v16 node toolchain + loopback listener binds (denied in \
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
    let evidence = write_evidence(&cfg, &obs, &row_a)?;
    println!("LNV-1 evidence: {}", evidence.display());

    row_a?;
    Ok(())
}
