//! Offline unit tests for the sanity gate's PURE logic (no node): the scale-0 identity parity, the
//! URL parser, the error-code matcher, the burn-note structural assertion (accept + SPECIFIC
//! rejections), the attester-consumability proof (accept + a foreign-tag REJECT), and the record
//! renderer's verdict logic. The live E2E driver is `tests/sanity.rs` (`#[ignore]`d, operator-run).

use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::{Felt, Word};

use withdrawal_listener_attester::config::ListenerConfig;
use withdrawal_listener_attester::error::DiscoveryReject;
use withdrawal_listener_attester::validate::{
    validate_discovery, DiscoveredDetails, DiscoveryRecord,
};
use xusdc_encoding::note::xreserve_burn::{XReserveBurnNote, FIXED_XUSDC_BURN_TAG};

use super::admin_restore::{
    plan_ownership_restore, reconcile_ownership, OwnershipOutcome, OwnershipRestore,
    MAX_OWNERSHIP_RECONCILE_ATTEMPTS,
};
use super::checks::{
    assert_attester_consumable, assert_burn_note_structure, burn_items, err_code_for, truncate,
};
use super::net::parse_url_parts;
use super::{
    Check, SanityReport, BURN_UNITS, DEPLOY_MAX_SUPPLY, MINT_NONROUND_UNITS, MINT_ROUND_UNITS,
};
use crate::mintburn;

// The A6 `--faucet-id` mint-config tests live in a dedicated submodule (`sanity/tests/a6.rs`) to keep
// this file under the BUILDER-GATES G3 size ceiling; they reuse this module's `dummy_id` / `faucet_id`
// / `rng` fixtures below.
mod a6;

fn dummy_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// Builds a public faucet ID using the harness configuration.
fn faucet_id(seed: u8) -> AccountId {
    crate::deploy::build_faucet_account(
        dummy_id(1),
        dummy_id(2),
        dummy_id(3),
        dummy_id(4),
        DEPLOY_MAX_SUPPLY,
        &mintburn::lnv2_domain_params(),
        [seed; 32],
    )
    .expect("building an offline production faucet")
    .id()
}

fn rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::new_unchecked(seed),
        Felt::new_unchecked(seed ^ 0xa5a5),
        Felt::new_unchecked(seed.wrapping_mul(2654435761)),
        Felt::new_unchecked(seed.wrapping_add(0x1234_5678)),
    ]))
}

/// The P0 scale-0 identity parity: the harness mirror equals the shipped `DEPOSIT_SCALE_EXP = 0`, so
/// minted units == the raw 6-decimal deposit amount for BOTH mandated amounts.
#[test]
fn scale0_identity_parity() {
    assert_eq!(
        mintburn::SCALE_EXP,
        0,
        "the harness scale must mirror DEPOSIT_SCALE_EXP = 0"
    );
    for amount in [
        MINT_ROUND_UNITS,
        MINT_NONROUND_UNITS,
        BURN_UNITS,
        1,
        999_999_999,
    ] {
        assert_eq!(
            mintburn::reduced(amount),
            amount,
            "reduced must be identity"
        );
        assert_eq!(
            mintburn::raw_for_units(amount),
            amount,
            "raw_for_units must be identity"
        );
    }
    assert_eq!(MINT_ROUND_UNITS, 100 * 1_000_000);
}

#[test]
fn url_parser_handles_loopback_and_devnet() {
    let (s, h, p) = parse_url_parts("http://127.0.0.1:57291").unwrap();
    assert_eq!(
        (s.as_str(), h.as_str(), p),
        ("http", "127.0.0.1", Some(57291))
    );
    let (s, h, p) = parse_url_parts("https://rpc.devnet.miden.io").unwrap();
    assert_eq!(
        (s.as_str(), h.as_str(), p),
        ("https", "rpc.devnet.miden.io", None)
    );
    let (s, h, p) = parse_url_parts("localhost:57291").unwrap();
    assert_eq!(
        (s.as_str(), h.as_str(), p),
        ("http", "localhost", Some(57291))
    );
    assert!(parse_url_parts("http://127.0.0.1:not-a-port").is_err());
}

#[test]
fn err_code_is_deterministic_and_nonzero() {
    // The same message hashes to the same code; distinct messages differ.
    let a = err_code_for("the contract is paused");
    let b = err_code_for("the contract is paused");
    let c = err_code_for("deposit intent nonce has already been used");
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, 0);
}

#[test]
fn truncate_is_utf8_safe() {
    let s = "ünïcödé error message with accents";
    let _ = truncate(s, 5); // must not panic on a multi-byte boundary
    assert_eq!(truncate("short", 100), "short");
    assert!(truncate("0123456789", 4).starts_with("0123"));
}

/// The structural assertion ACCEPTS a correct burn note and REJECTS with a SPECIFIC reason for the
/// wrong faucet target and a wrong claimed amount (never a generic is_err).
#[test]
fn burn_note_structure_accept_and_specific_rejects() {
    let faucet = faucet_id(7);
    let other = faucet_id(8);
    let sender = dummy_id(9);
    let items = burn_items(BURN_UNITS).unwrap();

    let good = XReserveBurnNote::create(sender, faucet, items.clone(), &mut rng(1)).unwrap();
    let detail = assert_burn_note_structure(&good, faucet, &items)
        .expect("a correct burn note must pass the structural assertion");
    assert!(detail.contains("0x4255524E"));

    // Wrong faucet target → a SPECIFIC "targets … != faucet" rejection.
    let err = assert_burn_note_structure(&good, other, &items)
        .expect_err("the wrong faucet target must be rejected");
    assert!(
        err.contains("targets"),
        "expected a target-mismatch reason, got: {err}"
    );

    // Wrong claimed amount → a SPECIFIC amount-mismatch rejection.
    let wrong_items = burn_items(BURN_UNITS + 1).unwrap();
    let err = assert_burn_note_structure(&good, faucet, &wrong_items)
        .expect_err("a wrong claimed amount must be rejected");
    assert!(
        err.contains("amount"),
        "expected an amount-mismatch reason, got: {err}"
    );
}

/// The attester-consumability proof ACCEPTS a correct burn note (its OWN validate_discovery +
/// decode) and REJECTS a discovery record carrying a FOREIGN tag (the attester would not discover it).
#[test]
fn attester_consumable_accept_and_foreign_tag_reject() {
    let faucet = faucet_id(11);
    let sender = dummy_id(12);
    let items = burn_items(BURN_UNITS).unwrap();
    let note = XReserveBurnNote::create(sender, faucet, items, &mut rng(2)).unwrap();

    // ACCEPT: the real burn note resolves.
    let detail = assert_attester_consumable(&note, faucet)
        .expect("the attester must find + decode a correct burn note");
    assert!(detail.contains(&BURN_UNITS.to_string()));

    // REJECT: the attester's exact-tag discovery refuses a note under a FOREIGN tag.
    let items_felts = note.recipient().storage().items().to_vec();
    let foreign_tag = FIXED_XUSDC_BURN_TAG ^ 0x1;
    let record = DiscoveryRecord::new(
        foreign_tag,
        Some(DiscoveredDetails::from_metadata(
            items_felts,
            note.metadata(),
        )),
    );
    let cfg = ListenerConfig::builder()
        .burn_tag(FIXED_XUSDC_BURN_TAG)
        .faucet_id(faucet)
        .build()
        .unwrap();
    // The SPECIFIC variant, with the expected + actual tags (not a generic is_err).
    match validate_discovery(&record, &cfg) {
        Err(DiscoveryReject::TagMismatch { expected, actual }) => {
            assert_eq!(
                expected, FIXED_XUSDC_BURN_TAG,
                "expected tag is the burn tag"
            );
            assert_eq!(actual, foreign_tag, "actual tag is the foreign one");
        }
        other => panic!("expected DiscoveryReject::TagMismatch, got {other:?}"),
    }
}

/// The renderer never self-declares the gate: all-pass ⇒ PENDING HUMAN ACCEPTANCE; a failure ⇒ GATE
/// CANNOT PASS, and every check appears in the matrix. The provenance label follows `attester_supplied`.
#[test]
fn record_render_reflects_verdict() {
    let mk = |id: &str, pass: bool| Check {
        id: id.to_string(),
        area: "mint".to_string(),
        what: "x".to_string(),
        pass,
        detail: "d".to_string(),
    };
    let mut r = SanityReport {
        rpc_url: "http://127.0.0.1:57291".to_string(),
        node_version: "miden-node 0.16.0-alpha.2".to_string(),
        deployed_fresh: true,
        local_node: true,
        faucet_id: "0xfaucet".to_string(),
        owner_id: "0xowner".to_string(),
        recipient_id: "0xrecipient".to_string(),
        holder_id: "0xholder".to_string(),
        attester_commitment_hex: "0xcommit".to_string(),
        attester_supplied: false,
        checks: vec![mk("MINT-ROUND", true), mk("BURN-AMOUNT", true)],
    };
    let doc = super::render_sanity_record(&r);
    assert!(doc.contains("PENDING HUMAN ACCEPTANCE"));
    assert!(doc.contains("MINT-ROUND") && doc.contains("BURN-AMOUNT"));
    assert!(doc.contains(&MINT_NONROUND_UNITS.to_string()));
    assert!(r.all_passed());

    // Provenance label: only the LOCAL (harness-generated) branch may assert the key is not a Circle
    // key. The SUPPLIED branch makes NO origin claim (this run cannot establish who owns the key).
    assert!(doc.contains("Local test attester"), "fresh-deploy label");
    assert!(!doc.contains("Operator-supplied allowlisted attester"));
    assert!(
        doc.contains("NEVER a Circle key"),
        "the local throwaway key may assert non-Circle origin"
    );
    let supplied = SanityReport {
        deployed_fresh: false,
        attester_supplied: true,
        ..r.clone()
    };
    let sdoc = super::render_sanity_record(&supplied);
    assert!(
        sdoc.contains("Operator-supplied allowlisted attester"),
        "existing-faucet supplied-attester label"
    );
    assert!(!sdoc.contains("Local test attester"));
    // The supplied branch must NOT assert an unverifiable non-Circle origin; it defers provenance.
    assert!(
        !sdoc.contains("Circle key"),
        "the supplied key must make NO Circle-origin claim (verifiable or not)"
    );
    assert!(
        sdoc.contains("does NOT assert its origin"),
        "the supplied key defers provenance to the operator"
    );

    r.checks.push(mk("NEG-REPLAY", false));
    let doc = super::render_sanity_record(&r);
    assert!(doc.contains("GATE CANNOT PASS"));
    assert!(!r.all_passed());
    assert_eq!(r.failures().len(), 1);
}

/// A fresh path → a 0600 file with the exact bytes (the create mode is honored on a new inode).
#[cfg(unix)]
#[test]
fn write_secret_file_creates_a_fresh_0600_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("temp dir");
    let fresh = dir.path().join("fresh.hex");
    crate::actors::write_secret_file(&fresh, b"deadbeef").expect("write fresh");
    let mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "a fresh secret file must be 0600, got {mode:o}"
    );
    assert_eq!(std::fs::read(&fresh).unwrap(), b"deadbeef");
}

/// The writer FAILS CLOSED on a pre-existing regular file: it REFUSES to overwrite it (so a stale
/// path / attacker-planted file / operator typo can neither clobber the data nor let the secret
/// inherit foreign permissions). The existing file is left byte-for-byte untouched.
#[cfg(unix)]
#[test]
fn write_secret_file_refuses_an_existing_regular_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("temp dir");
    let existing = dir.path().join("existing.hex");
    std::fs::write(&existing, b"stale-public").unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o664)).unwrap();

    let err = crate::actors::write_secret_file(&existing, b"newsecret")
        .expect_err("writing over an existing file must be REFUSED");
    assert!(
        err.to_string().contains("already exists"),
        "the error must explain the refusal, got: {err}"
    );
    // Untouched: original content preserved, never replaced with the secret.
    assert_eq!(std::fs::read(&existing).unwrap(), b"stale-public");
}

/// The writer FAILS CLOSED on a pre-planted symlink (`O_CREAT|O_EXCL|O_NOFOLLOW`): it neither follows
/// the link nor removes it — the secret is never written, and the link + its target are untouched.
#[cfg(unix)]
#[test]
fn write_secret_file_refuses_a_symlink_and_never_writes_through_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let target = dir.path().join("attacker-target.hex");
    std::fs::write(&target, b"attacker-owned").unwrap();
    let link = dir.path().join("link.hex");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let err = crate::actors::write_secret_file(&link, b"newsecret")
        .expect_err("writing to a symlink path must be REFUSED");
    assert!(
        err.to_string().contains("already exists"),
        "the error must explain the refusal, got: {err}"
    );
    // The symlink itself remains, and its target keeps its original content (never written through).
    assert!(std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read(&target).unwrap(), b"attacker-owned");
}

/// The pure ownership-restore planner covers every ground-truth state, including the accept-path
/// failures the round-7 boolean missed: an unexpectedly-moved owner (committed-but-unobserved accept)
/// and a dangling step-1 nomination.
#[test]
fn plan_ownership_restore_covers_every_ground_truth_state() {
    let orig = dummy_id(1);
    let ephemeral = dummy_id(2);
    let stranger = dummy_id(3);

    // Owner intact, no nomination → nothing to do.
    assert_eq!(
        plan_ownership_restore(orig, None, orig, ephemeral),
        OwnershipRestore::None
    );
    // Owner intact, nominated to a harmless party (the orig itself) → still nothing to do.
    assert_eq!(
        plan_ownership_restore(orig, Some(orig), orig, ephemeral),
        OwnershipRestore::None
    );
    // Owner intact but the EPHEMERAL wallet is NOMINATED (step-1 committed, accept never ran) → cancel.
    assert_eq!(
        plan_ownership_restore(orig, Some(ephemeral), orig, ephemeral),
        OwnershipRestore::CancelNomination
    );
    // The EPHEMERAL wallet OWNS the faucet (accept committed, maybe unobserved by the client) → back.
    assert_eq!(
        plan_ownership_restore(ephemeral, None, orig, ephemeral),
        OwnershipRestore::TransferBack
    );
    assert_eq!(
        plan_ownership_restore(ephemeral, Some(stranger), orig, ephemeral),
        OwnershipRestore::TransferBack
    );
    // Owned by neither → cannot restore (surfaced, not silently ignored).
    assert_eq!(
        plan_ownership_restore(stranger, None, orig, ephemeral),
        OwnershipRestore::UnexpectedOwner(stranger)
    );
}

// ----------------------------------------------------------------------------------------------
// Record ENVIRONMENT / RUN-MODE labeling. The run is labeled by its ACTUAL mode — local-deploy (full
// gate, admin included) / local-existing / devnet — and an already-deployed faucet is NEVER a
// destructive-admin run: the record must not advertise a remote admin path against a deployed faucet.
// ----------------------------------------------------------------------------------------------

/// A minimal all-pass report for the renderer environment/run-mode tests. `local_node` picks a
/// loopback vs devnet RPC; `deployed_fresh` picks the fresh-deploy full gate vs an existing-faucet
/// non-destructive re-check.
fn env_report(deployed_fresh: bool, local_node: bool) -> SanityReport {
    let ok = |id: &str| Check {
        id: id.to_string(),
        area: "mint".to_string(),
        what: "x".to_string(),
        pass: true,
        detail: "d".to_string(),
    };
    SanityReport {
        rpc_url: if local_node {
            "http://127.0.0.1:57291"
        } else {
            "https://rpc.devnet.miden.io"
        }
        .to_string(),
        node_version: "miden-node 0.16.0-alpha.2".to_string(),
        deployed_fresh,
        local_node,
        faucet_id: "0x22c015510392b09170dc544bce3549".to_string(),
        owner_id: "0xowner".to_string(),
        recipient_id: "0xrecipient".to_string(),
        holder_id: "0xholder".to_string(),
        attester_commitment_hex: "0xcommit".to_string(),
        attester_supplied: !deployed_fresh,
        checks: vec![ok("MINT-ROUND"), ok("BURN-AMOUNT")],
    }
}

/// A DEVNET existing-faucet run renders as a DEVNET NON-DESTRUCTIVE re-check — it must NOT advertise
/// or require a remote admin / full-suite / `--credentials` path, and its reproduction is the
/// `--faucet-id` command (secret from env), never a fresh deploy.
#[test]
fn record_labels_devnet_existing_faucet_as_non_destructive_recheck() {
    let r = env_report(false, false);
    let doc = super::render_sanity_record(&r);

    assert!(
        doc.contains("DEVNET existing-faucet non-destructive re-check"),
        "a devnet existing-faucet run is a non-destructive re-check"
    );
    // NO remote destructive-admin / full-suite / credentials path may be advertised or required.
    assert!(
        !doc.contains("--credentials"),
        "no remote --credentials path"
    );
    assert!(
        !doc.contains("FULL re-run") && !doc.contains("FULL suite"),
        "a deployed faucet is never a full-admin re-run"
    );
    assert!(
        doc.contains("NOT run against a deployed faucet"),
        "the record must state admin is never run against a deployed faucet"
    );
    assert!(
        doc.contains("**This record** was produced by the DEVNET existing-faucet non-destructive")
    );
    assert!(
        doc.contains(
            "--rpc-url https://rpc.devnet.miden.io --faucet-id 0x22c015510392b09170dc544bce3549"
        ),
        "the reproduction is the --faucet-id command actually used"
    );
    // A devnet non-destructive re-check that passes is a COMPLETE gate (PENDING), not a PARTIAL/skip.
    assert!(doc.contains("PENDING HUMAN ACCEPTANCE"));
    assert!(!doc.contains("PARTIAL") && !doc.contains("SKIP"));
}

/// The SAME existing-faucet re-check on a LOOPBACK node is labeled LOCAL (not DEVNET) — the
/// environment word is driven by the node — and is still non-destructive.
#[test]
fn record_labels_localhost_existing_faucet_as_local_not_devnet() {
    let r = env_report(false, true);
    let doc = super::render_sanity_record(&r);
    assert!(doc.contains("LOCAL existing-faucet non-destructive re-check"));
    assert!(
        !doc.contains("DEVNET existing-faucet"),
        "a localhost run must not be mislabeled DEVNET"
    );
    assert!(
        doc.contains("**This record** was produced by the LOCAL existing-faucet non-destructive")
    );
    assert!(doc
        .contains("--rpc-url http://127.0.0.1:57291 --faucet-id 0x22c015510392b09170dc544bce3549"));
    assert!(!doc.contains("--credentials"));
}

/// The fresh-deploy LOCAL gate is the ONLY mode that reports the admin surface, and reproduces with
/// the fresh-deploy command.
#[test]
fn record_fresh_deploy_is_the_only_admin_mode() {
    let fresh = super::render_sanity_record(&env_report(true, true));
    assert!(fresh.contains("a FRESH production faucet deployed on the running LOCAL node"));
    assert!(fresh.contains("**This record** was produced by the FRESH-deploy LOCAL full gate"));
    assert!(fresh.contains("--bin sanity_e2e -- --rpc-url http://127.0.0.1:57291"));
    // The fresh-deploy record describes the admin surface; the existing-faucet record does NOT.
    assert!(fresh.contains("Admin (FRESH local faucet ONLY)"));
    let existing = super::render_sanity_record(&env_report(false, true));
    assert!(!existing.contains("Admin (FRESH local faucet ONLY)"));
}

// ----------------------------------------------------------------------------------------------
// Ownership reconcile loop (finding: cleanup raced a committed-but-unobserved accept). Driven with a
// scripted fake so the POST-SNAPSHOT ownership transition — which a single snapshot could not see — is
// exercised without a node.
// ----------------------------------------------------------------------------------------------

/// A scripted fake [`super::admin_restore::OwnershipOps`]: it holds the simulated on-chain
/// `(owner, nominated)` ground truth and lets a test inject the accept race + action failures.
struct RacingFake {
    orig: AccountId,
    ephemeral: AccountId,
    owner: AccountId,
    nominated: Option<AccountId>,
    /// The pending accept commits (ephemeral becomes owner) right AFTER the first observe — exactly
    /// the race window a single snapshot misses.
    accept_after_first_observe: bool,
    accept_committed: bool,
    /// `transfer_back` always errors (owner never moves) — the persistent-failure injection.
    transfer_always_fails: bool,
    /// `observe` always errors — the unreadable-ground-truth injection.
    observe_always_fails: bool,
    observes: usize,
    cancels: usize,
    transfers: usize,
}

impl RacingFake {
    fn new(
        orig: AccountId,
        ephemeral: AccountId,
        owner: AccountId,
        nominated: Option<AccountId>,
    ) -> Self {
        Self {
            orig,
            ephemeral,
            owner,
            nominated,
            accept_after_first_observe: false,
            accept_committed: false,
            transfer_always_fails: false,
            observe_always_fails: false,
            observes: 0,
            cancels: 0,
            transfers: 0,
        }
    }
}

impl super::admin_restore::OwnershipOps for RacingFake {
    async fn observe(&mut self) -> anyhow::Result<(AccountId, Option<AccountId>)> {
        self.observes += 1;
        if self.observe_always_fails {
            anyhow::bail!("simulated: the on-chain owner is unreadable");
        }
        let snapshot = (self.owner, self.nominated);
        // The pending accept commits in the window right after the FIRST observation.
        if self.accept_after_first_observe && !self.accept_committed && self.observes == 1 {
            self.accept_committed = true;
            self.owner = self.ephemeral;
            self.nominated = None;
        }
        Ok(snapshot)
    }
    async fn transfer_back(&mut self) -> anyhow::Result<()> {
        self.transfers += 1;
        if self.transfer_always_fails {
            anyhow::bail!("simulated: transfer-back keeps failing");
        }
        if self.owner != self.ephemeral {
            anyhow::bail!("transfer-back unauthorized: sender does not own the faucet");
        }
        self.owner = self.orig;
        self.nominated = None;
        Ok(())
    }
    async fn cancel_nomination(&mut self) -> anyhow::Result<()> {
        self.cancels += 1;
        if self.owner != self.orig {
            anyhow::bail!("cancel unauthorized: sender is no longer the owner");
        }
        self.nominated = None;
        Ok(())
    }
}

/// THE regression for the round-8 gap: the FIRST snapshot sees the original owner with the ephemeral
/// wallet nominated (plan = CancelNomination), but the accept commits before the cancel — so the
/// cancel is UNAUTHORIZED and fails. A single-snapshot cleanup would record that failure and STOP,
/// leaving the ephemeral wallet as owner. The bounded loop instead RE-OBSERVES the moved owner and
/// transfers it back, reaching Restored.
#[tokio::test]
async fn reconcile_recovers_from_post_snapshot_accept_race() {
    let orig = dummy_id(1);
    let ephemeral = dummy_id(2);
    let mut fake = RacingFake::new(orig, ephemeral, orig, Some(ephemeral));
    fake.accept_after_first_observe = true;

    let mut trace = Vec::new();
    let outcome = reconcile_ownership(&mut fake, orig, ephemeral, &mut trace).await;

    assert_eq!(
        outcome,
        OwnershipOutcome::Restored,
        "the loop must recover to Restored, not stop at the failed cancel"
    );
    assert_eq!(
        fake.cancels, 1,
        "it attempted the (doomed) cancel from the first snapshot"
    );
    assert_eq!(
        fake.transfers, 1,
        "then re-observed the moved owner and transferred back"
    );
    assert_eq!(
        fake.owner, orig,
        "ownership ends back with the original owner"
    );
    assert_eq!(fake.nominated, None, "no dangling nomination remains");
    assert!(
        trace
            .iter()
            .any(|t| t.contains("cancel") && t.contains("attempt failed")),
        "the trace records the doomed cancel"
    );
    assert!(
        trace
            .iter()
            .any(|t| t.contains("transfer-back") && t.contains("committed")),
        "the trace records the recovery transfer-back"
    );
}

/// A committed-but-unobserved accept (the ephemeral wallet already OWNS on the first observe) is
/// transferred back in one action.
#[tokio::test]
async fn reconcile_transfers_back_a_committed_accept() {
    let orig = dummy_id(1);
    let ephemeral = dummy_id(2);
    let mut fake = RacingFake::new(orig, ephemeral, ephemeral, None);

    let mut trace = Vec::new();
    let outcome = reconcile_ownership(&mut fake, orig, ephemeral, &mut trace).await;

    assert_eq!(outcome, OwnershipOutcome::Restored);
    assert_eq!(fake.transfers, 1);
    assert_eq!(fake.cancels, 0);
    assert_eq!(fake.owner, orig);
}

/// A persistently-failing action is surfaced as Unresolved after EXACTLY the bounded number of
/// attempts — never a silent pass and never an infinite loop.
#[tokio::test]
async fn reconcile_reports_unresolved_when_the_action_never_succeeds() {
    let orig = dummy_id(1);
    let ephemeral = dummy_id(2);
    let mut fake = RacingFake::new(orig, ephemeral, ephemeral, None);
    fake.transfer_always_fails = true;

    let mut trace = Vec::new();
    let outcome = reconcile_ownership(&mut fake, orig, ephemeral, &mut trace).await;

    assert_eq!(
        outcome,
        OwnershipOutcome::Unresolved(OwnershipRestore::TransferBack),
        "a persistently-failing action is surfaced, not silently passed"
    );
    assert_eq!(
        fake.transfers, MAX_OWNERSHIP_RECONCILE_ATTEMPTS,
        "it tried exactly the bounded number of times, then stopped (no infinite loop)"
    );
}

/// An unreadable owner is surfaced as ObserveFailed — the run never claims a restore it could not
/// verify.
#[tokio::test]
async fn reconcile_reports_observe_failure_when_ground_truth_is_unreadable() {
    let orig = dummy_id(1);
    let ephemeral = dummy_id(2);
    let mut fake = RacingFake::new(orig, ephemeral, orig, None);
    fake.observe_always_fails = true;

    let mut trace = Vec::new();
    let outcome = reconcile_ownership(&mut fake, orig, ephemeral, &mut trace).await;

    assert!(
        matches!(outcome, OwnershipOutcome::ObserveFailed(_)),
        "an unreadable owner is surfaced as unverified, never a silent pass"
    );
}

// ----------------------------------------------------------------------------------------------
// Runner-level LOCALITY INVARIANT (containment). The destructive admin suite runs ONLY for a fresh
// LOCAL faucet; a remote fresh-deploy must be refused BY THE RUNNER (not only the CLI), so a direct
// run_sanity caller — e.g. the live integration test — can never fresh-deploy + mutate a remote node.
// ----------------------------------------------------------------------------------------------

/// [`super::decide_run_mode`] is the single authority every caller of `run_sanity` passes through, so
/// this node-free test IS the runner's control-flow invariant: a fresh deploy (no faucet id) is
/// allowed ONLY on a loopback node and REFUSED on any remote/devnet (or spoofed-loopback) RPC; an
/// existing-faucet re-check is allowed anywhere and NEVER runs admin.
#[test]
fn decide_run_mode_enforces_local_only_fresh_deploy() {
    use super::{decide_run_mode, RunMode};

    // Local fresh deploy → OK, runs the full admin suite.
    assert_eq!(
        decide_run_mode(None, "http://127.0.0.1:57291").unwrap(),
        RunMode {
            deployed_fresh: true,
            local_node: true,
            run_admin: true,
        }
    );

    // REMOTE fresh deploy → REFUSED (the containment): no faucet id + a non-loopback RPC would
    // otherwise deploy + run the destructive admin suite against a remote/devnet faucet.
    let err = decide_run_mode(None, "https://rpc.devnet.miden.io").unwrap_err();
    assert!(
        err.to_string().contains("LOCAL-only"),
        "a remote fresh deploy must be refused: {err}"
    );
    // A spoofed-loopback host is REMOTE → also refused (never trust a substring).
    assert!(decide_run_mode(None, "http://127.0.0.1.evil.com").is_err());

    // Existing faucet on DEVNET → OK, non-destructive (run_admin false).
    assert_eq!(
        decide_run_mode(Some(dummy_id(1)), "https://rpc.devnet.miden.io").unwrap(),
        RunMode {
            deployed_fresh: false,
            local_node: false,
            run_admin: false,
        }
    );
    // Existing faucet on a LOCAL node → OK, still non-destructive.
    assert_eq!(
        decide_run_mode(Some(dummy_id(1)), "http://127.0.0.1:57291").unwrap(),
        RunMode {
            deployed_fresh: false,
            local_node: true,
            run_admin: false,
        }
    );
}

/// Pins the PUBLIC runner boundary itself (not just the helper): `run_sanity` must route a remote
/// fresh-deploy through the locality check and FAIL FAST — BEFORE any filesystem / RPC / deployment
/// work. Node-free: the refusal happens before the client ever connects, so no node is needed.
///
/// This is the regression the helper test cannot catch — if the `decide_run_mode` call were DELETED
/// from `run_sanity`, or MOVED below `create_dir_all` / `build_client_at`, `create_dir_all` would run
/// first and CREATE the run root, so the `!run_root.exists()` assertion below would FAIL. Asserting
/// the run root was never created therefore pins both the presence AND the fail-before-work ordering
/// of the containment check.
#[tokio::test]
async fn run_sanity_refuses_remote_fresh_deploy_before_any_work() {
    // A run-root path that does NOT exist yet, inside an auto-cleaned temp dir. `run_sanity`'s FIRST
    // side effect is `create_dir_all(run_root)`; if it refuses BEFORE that, this path stays absent.
    let tmp = tempfile::tempdir().expect("temp dir");
    let run_root = tmp.path().join("run-root-must-not-be-created");
    assert!(
        !run_root.exists(),
        "precondition: the run root must not exist yet"
    );

    let cfg = super::SanityConfig {
        // REMOTE (non-loopback) RPC + no faucet id ⇒ a fresh-deploy/admin configuration — the exact
        // combination the runner must refuse. No node is contacted because the refusal comes first.
        rpc_url: "https://rpc.devnet.miden.io".to_string(),
        faucet_id: None,
        run_root: run_root.clone(),
        attester_secret: None,
        node_log_dir: None,
    };

    let err = super::run_sanity(&cfg, "test-node")
        .await
        .expect_err("run_sanity must REFUSE a remote fresh-deploy");
    assert!(
        err.to_string().contains("LOCAL-only"),
        "the refusal must be the locality invariant, got: {err}"
    );
    // The refusal happened BEFORE `create_dir_all` (the first FS op, which precedes any RPC/deploy),
    // so the run root was never created — proving the containment check runs before ANY work.
    assert!(
        !run_root.exists(),
        "run_sanity must refuse a remote fresh-deploy BEFORE creating the run root (no FS/RPC/deploy)"
    );
}
