//! Tests deployment and configuration.
//! Synthetic fixtures exercise the assertions offline. Ignored integration tests require a local node.

use anyhow::Result;
use miden_protocol::account::{
    Account, AccountBuilder, AccountId, AccountIdVersion, AccountType, AssetCallbackFlag,
    StorageSlotName,
};
use miden_protocol::Word;
use miden_standards::account::auth::AuthNetworkAccount;
use xusdc_encoding::account::xreserve::{XReserveStablecoinBuilder, IDENTIFIER_CONFIG_SLOT_LABEL};
use xusdc_encoding::note::xreserve_admin::XReserveIdentifierInitNote;
use xusdc_validation::assertions::{assert_row_a, assert_row_b, ERR_IDENTIFIER_REINIT_TEXT};
use xusdc_validation::config::{repo_root, DomainParams, RunConfig};
use xusdc_validation::deploy::{build_xreserve_component_seeded, production_components};
use xusdc_validation::evidence::write_evidence;
use xusdc_validation::observations::RowsAbObservations;
use xusdc_validation::rows_ab::run_rows_ab;

const MAX_SUPPLY: u64 = 1_000_000_000_000;

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

/// The identifier-slot shape of a synthetic post-deploy faucet. The identifier is BOUND to the
/// faucet id (the R2 identifier-binding fix): it is DERIVED from the id, never caller-chosen. This
/// mirrors the real deploy — the account id is fixed by the EMPTY-identifier component, then
/// `identifier_init` writes the own-id key into the (immutable-id) account.
#[derive(Clone, Copy)]
enum Identifier {
    /// Empty slot — `identifier_init` never executed.
    Uninitialized,
    /// The own-id fixpoint key `identifier_for(faucet_id)` — the correct post-init shape.
    OwnId,
    /// An explicit WRONG value in the slot — a corrupted / breached identifier (a negative fixture).
    Wrong(Word),
}

/// A production-shaped faucet `Account` with nonce 1 (as if deployed). The three build-seeded fields
/// always come from `build_seed` (the recomposed builder REQUIRES them — they exist from
/// construction and have no runtime writer). `auth_override` optionally REPLACES the frozen
/// production auth. The identifier slot is written POST-BUILD per `identifier`: the account id is
/// derived from the EMPTY-identifier component (exactly as the real deploy fixes it), then the
/// identifier is set into the account whose id is now immutable — the faithful twin of the
/// post-deploy `identifier_init` write (which cannot be a build seed: the own-id key is a fixpoint of
/// the id the build produces).
fn synthetic_deployed_faucet(
    identifier: Identifier,
    build_seed: &DomainParams,
    auth_override: Option<AuthNetworkAccount>,
) -> Result<Account> {
    // Ship the identifier EMPTY so the id is derived from the empty-identifier component (as the real
    // deploy does); the builder still seeds domain/source_domain/xreserve_contract from `build_seed`.
    let xreserve = build_xreserve_component_seeded(None)?;
    let components = production_components(
        xreserve,
        wallet_id(1),
        wallet_id(2),
        wallet_id(3),
        wallet_id(4),
        MAX_SUPPLY,
        build_seed,
    )?;
    let auth = match auth_override {
        Some(auth) => auth,
        None => XReserveStablecoinBuilder::auth_component()?,
    };
    let mut account = AccountBuilder::new([7u8; 32])
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_auth_component(auth)
        .with_components(components)
        .build_existing()?;

    // Post-build identifier write — the id is fixed now, so this is the exact post-deploy
    // `identifier_init` shape (the own-id key, or a negative value, without changing the id).
    let value = match identifier {
        Identifier::Uninitialized => None,
        Identifier::OwnId => Some(XReserveIdentifierInitNote::identifier_for(account.id())),
        Identifier::Wrong(word) => Some(word),
    };
    if let Some(word) = value {
        let slot = StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)?;
        account.storage_mut().set_item(&slot, word)?;
    }
    Ok(account)
}

/// A foreign own-id identifier (a DIFFERENT account's key) — guaranteed distinct from any faucet's
/// own-id key, so it is a valid "wrong identifier" negative for the post-reinit read-back.
fn foreign_identifier() -> Word {
    XReserveIdentifierInitNote::identifier_for(wallet_id(9))
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
        reinit_error: Some(format!("executor trap: {ERR_IDENTIFIER_REINIT_TEXT}")),
        after_reinit,
        second_note_consumed: false,
    }
}

/// The fully green synthetic shape (post-init faucet, reinit rejected, nothing changed).
fn green_obs() -> Result<RowsAbObservations> {
    let params = DomainParams::lnv1();
    let deployed = synthetic_deployed_faucet(Identifier::OwnId, &params, None)?;
    let after = synthetic_deployed_faucet(Identifier::OwnId, &params, None)?;
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
    let account = synthetic_deployed_faucet(Identifier::OwnId, &params, Some(auth))?;
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

/// Row B must reject an UNINITIALIZED identifier (an empty identifier slot = identifier_init never
/// executed; the three build-seeded fields exist from construction — Wave-1 S1).
#[test]
fn row_b_rejects_uninitialized_identifier() -> Result<()> {
    let params = DomainParams::lnv1();
    let deployed = synthetic_deployed_faucet(Identifier::Uninitialized, &params, None)?;
    let after = synthetic_deployed_faucet(Identifier::Uninitialized, &params, None)?;
    let obs = synthetic_obs(Some(deployed), Some(after));
    let err = assert_row_b(&obs).expect_err("row B must fail when the identifier slot is empty");
    assert!(
        format!("{err:#}").contains("read-back"),
        "the failure must name the read-back mismatch, got: {err:#}"
    );
    Ok(())
}

/// Row B must reject a run whose second identifier_init did NOT fail (init-once did not hold).
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
        format!("{err:#}").contains(ERR_IDENTIFIER_REINIT_TEXT),
        "the failure must name the expected gate error, got: {err:#}"
    );
    Ok(())
}

/// Row B must reject any post-reinit identifier that is NOT the own-id key (a leaked / corrupted
/// slot). Post-recomposition the second `identifier_init` derives the SAME own-id key as the first,
/// so a breach cannot present as a distinct "second identifier" — it shows up as ANY identifier !=
/// `identifier_for(faucet_id)`, which the post-attempt read-back catches.
#[test]
fn row_b_rejects_wrong_post_reinit_identifier() -> Result<()> {
    let params = DomainParams::lnv1();
    let deployed = synthetic_deployed_faucet(Identifier::OwnId, &params, None)?;
    // The breached shape: a FOREIGN identifier (a different account's own-id key) in the slot after
    // the rejected reinit — it must NOT equal this faucet's own-id key.
    let after = synthetic_deployed_faucet(Identifier::Wrong(foreign_identifier()), &params, None)?;
    let obs = synthetic_obs(Some(deployed), Some(after));
    let err = assert_row_b(&obs)
        .expect_err("row B must fail when the post-reinit identifier is not the own-id key");
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
/// consumes the owner's `identifier_init` — the first admin note; the other three domain-config
/// fields are build-seeded), verify recognition + read-backs, prove init-once, tear down. Writes
/// `evidence.json` under the gitignored run root either way.
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
