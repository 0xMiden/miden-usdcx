//! The cycle: T-C1 … T-C13, and the startup gates T-G1 … T-G4.

mod support;

use assert_matches::assert_matches;
use rstest::rstest;

use support::{
    attestation, attestation_for, error_response, intent_with, nonce, other_faucet_id, page,
    test_config, unbound_attestation, undecodable_attestation, Answer, Fixture, MockCircle,
    ScriptedSubmit, ATTESTER_PUBKEY_HEX,
};
use xreserve_deposit_relayer_lite::cycle::{run_cycle, CycleOutcome};
use xreserve_deposit_relayer_lite::mint::Identities;
use xreserve_deposit_relayer_lite::submit::production_submit_port;

/// Runs one cycle against `fixture`, submitting through `submit`.
async fn cycle(fixture: &mut Fixture, submit: &ScriptedSubmit) -> anyhow::Result<CycleOutcome> {
    let mut relayer = fixture.relayer(submit);
    run_cycle(&mut relayer).await
}

// THE CYCLE
// ================================================================================================

/// T-C1 — three valid attestations are all submitted, all recorded, and the cursor advances.
#[tokio::test]
async fn every_valid_attestation_on_a_page_is_submitted() {
    let mock = MockCircle::new(vec![page(
        &[attestation(1), attestation(2), attestation(3)],
        Some("page-2"),
    )]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::always(Answer::Accept);

    let outcome = cycle(&mut fixture, &submit).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages);
    assert_eq!(submit.calls(), 3);
    for seed in 1..=3 {
        assert!(fixture.store.is_submitted(&nonce(seed)).unwrap());
    }
    assert_eq!(fixture.store.cursor().unwrap().as_deref(), Some("page-2"));
}

/// **T-C2 — the regression test for the wedge bug in issue #160.**
///
/// The sibling crate collects the page through `collect::<Result<_>>()?`, so ONE malformed
/// attestation fails the whole fetch, the cursor never advances, and the service is stuck on that
/// page forever. Here the bad element is skipped, its neighbours are still submitted, and the
/// cursor MOVES — which is what makes the relayer unwedgeable.
#[tokio::test]
async fn a_malformed_attestation_does_not_wedge_the_page() {
    let mock = MockCircle::new(vec![page(
        &[attestation(1), undecodable_attestation(), attestation(3)],
        Some("page-2"),
    )]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::always(Answer::Accept);

    let outcome = cycle(&mut fixture, &submit).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages, "the cycle must not fail");
    assert_eq!(submit.calls(), 2, "the two good deposits still mint");
    assert!(fixture.store.is_submitted(&nonce(1)).unwrap());
    assert!(fixture.store.is_submitted(&nonce(3)).unwrap());
    assert_eq!(
        fixture.store.cursor().unwrap().as_deref(),
        Some("page-2"),
        "THE bug: the cursor must advance past a page carrying a bad element"
    );
}

/// T-C3 — an envelope whose `messageHash` does not bind its payload is skipped, not fatal.
#[tokio::test]
async fn an_unbound_envelope_is_skipped() {
    let mock = MockCircle::new(vec![page(
        &[unbound_attestation(1), attestation(2)],
        Some("page-2"),
    )]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::always(Answer::Accept);

    let outcome = cycle(&mut fixture, &submit).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages);
    assert_eq!(submit.calls(), 1);
    assert!(!fixture.store.is_submitted(&nonce(1)).unwrap());
    assert!(fixture.store.is_submitted(&nonce(2)).unwrap());
}

/// T-C4 — the same deposit twice on one page is submitted exactly once.
#[tokio::test]
async fn a_duplicate_within_a_page_is_submitted_once() {
    let mock = MockCircle::new(vec![page(
        &[attestation(1), attestation(1)],
        Some("page-2"),
    )]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::always(Answer::Accept);

    cycle(&mut fixture, &submit).await.unwrap();

    assert_eq!(submit.calls(), 1);
}

/// T-C5 — a deposit re-served on a later cycle is not submitted again.
#[tokio::test]
async fn a_duplicate_across_cycles_is_not_resubmitted() {
    let mock = MockCircle::new(vec![
        page(&[attestation(1)], Some("page-2")),
        page(&[attestation(1)], Some("page-3")),
    ]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::always(Answer::Accept);

    cycle(&mut fixture, &submit).await.unwrap();
    cycle(&mut fixture, &submit).await.unwrap();

    assert_eq!(submit.calls(), 1, "the second cycle must submit nothing");
    assert_eq!(fixture.store.cursor().unwrap().as_deref(), Some("page-3"));
}

/// T-C6 — a transient submit failure HOLDS the page: the cursor does not move, and the deposits
/// already submitted on that page stay recorded.
#[tokio::test]
async fn a_transient_failure_holds_the_cursor() {
    let mock = MockCircle::new(vec![page(
        &[attestation(1), attestation(2), attestation(3)],
        Some("page-2"),
    )]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::script(vec![Answer::Accept, Answer::Transient]);

    let outcome = cycle(&mut fixture, &submit).await.unwrap();

    assert_eq!(outcome, CycleOutcome::Retry);
    assert!(
        fixture.store.is_submitted(&nonce(1)).unwrap(),
        "what already went through stays recorded"
    );
    assert!(!fixture.store.is_submitted(&nonce(2)).unwrap());
    assert_eq!(
        fixture.store.cursor().unwrap(),
        None,
        "the cursor must NOT advance past a page that is still owed"
    );
}

/// T-C7 — the next cycle re-fetches the held page, skips what already minted, and finishes it.
#[tokio::test]
async fn the_held_page_is_finished_next_cycle() {
    let mock = MockCircle::new(vec![
        page(
            &[attestation(1), attestation(2), attestation(3)],
            Some("page-2"),
        ),
        page(
            &[attestation(1), attestation(2), attestation(3)],
            Some("page-2"),
        ),
    ]);
    let mut fixture = Fixture::new(mock);

    let failing = ScriptedSubmit::script(vec![Answer::Accept, Answer::Transient]);
    assert_eq!(
        cycle(&mut fixture, &failing).await.unwrap(),
        CycleOutcome::Retry
    );

    let recovering = ScriptedSubmit::always(Answer::Accept);
    let outcome = cycle(&mut fixture, &recovering).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages);
    assert_eq!(
        recovering.calls(),
        2,
        "deposit 1 already minted, so only 2 and 3 are submitted"
    );
    assert_eq!(fixture.store.cursor().unwrap().as_deref(), Some("page-2"));
}

/// T-C8 — a FATAL submit is skipped, the page completes, and the cursor advances: a permanent
/// refusal must not be re-driven forever.
#[tokio::test]
async fn a_fatal_submit_is_skipped_and_the_page_completes() {
    let mock = MockCircle::new(vec![page(
        &[attestation(1), attestation(2), attestation(3)],
        Some("page-2"),
    )]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::script(vec![Answer::Accept, Answer::Fatal, Answer::Accept]);

    let outcome = cycle(&mut fixture, &submit).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages);
    assert!(fixture.store.is_submitted(&nonce(1)).unwrap());
    assert!(
        !fixture.store.is_submitted(&nonce(2)).unwrap(),
        "a refused deposit was never submitted, so it is not recorded as such"
    );
    assert!(fixture.store.is_submitted(&nonce(3)).unwrap());
    assert_eq!(fixture.store.cursor().unwrap().as_deref(), Some("page-2"));
}

/// T-C9 — a deposit the note builder refuses (addressed to another faucet) is skipped.
#[tokio::test]
async fn a_note_that_will_not_build_is_skipped() {
    let elsewhere = attestation_for(&intent_with(nonce(1), other_faucet_id()));
    let mock = MockCircle::new(vec![page(&[elsewhere, attestation(2)], Some("page-2"))]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::always(Answer::Accept);

    let outcome = cycle(&mut fixture, &submit).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages);
    assert_eq!(
        submit.calls(),
        1,
        "only the well-addressed deposit is built"
    );
    assert!(fixture.store.is_submitted(&nonce(2)).unwrap());
}

/// T-C10 — an absent `Link` header leaves the cursor alone and reports the feed as caught up.
#[tokio::test]
async fn the_final_page_leaves_the_cursor_alone() {
    let mock = MockCircle::new(vec![page(&[attestation(1)], None)]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::always(Answer::Accept);

    let outcome = cycle(&mut fixture, &submit).await.unwrap();

    assert_eq!(outcome, CycleOutcome::Idle);
    assert!(fixture.store.is_submitted(&nonce(1)).unwrap());
    assert_eq!(fixture.store.cursor().unwrap(), None);
}

/// T-C11 — a multi-page scan walks the cursor forward and resumes from it.
#[tokio::test]
async fn a_multi_page_scan_walks_the_cursor_forward() {
    let mock = MockCircle::new(vec![
        page(&[attestation(1)], Some("page-2")),
        page(&[attestation(2)], None),
    ]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::always(Answer::Accept);

    assert_eq!(
        cycle(&mut fixture, &submit).await.unwrap(),
        CycleOutcome::MorePages
    );
    assert_eq!(
        cycle(&mut fixture, &submit).await.unwrap(),
        CycleOutcome::Idle
    );

    assert_eq!(submit.calls(), 2);
    // the SECOND request resumed from the cursor the first page handed back
    let requests = fixture.mock.requests();
    assert!(!requests[0].url.contains("pageAfter"));
    assert!(requests[1].url.contains("pageAfter=page-2"));
}

/// T-C12 — an empty page submits nothing and still advances.
#[tokio::test]
async fn an_empty_page_advances() {
    let mock = MockCircle::new(vec![page(&[], Some("page-2"))]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::always(Answer::Accept);

    let outcome = cycle(&mut fixture, &submit).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages);
    assert_eq!(submit.calls(), 0);
    assert_eq!(fixture.store.cursor().unwrap().as_deref(), Some("page-2"));
}

/// T-C13 — a Circle 5xx fails the cycle and leaves the cursor untouched, so the next cycle retries
/// the same page.
#[tokio::test]
async fn a_circle_failure_fails_the_cycle_without_moving_the_cursor() {
    let mock = MockCircle::new(vec![error_response(500)]);
    let mut fixture = Fixture::new(mock);
    let submit = ScriptedSubmit::always(Answer::Accept);

    let error = cycle(&mut fixture, &submit).await.unwrap_err();

    assert!(error.to_string().contains("500"), "{error}");
    assert_eq!(fixture.store.cursor().unwrap(), None);
}

// STARTUP GATES
// ================================================================================================

/// T-G1 / T-G2 — a malformed identity is refused at STARTUP, and the message names the FIELD.
#[rstest]
#[case::faucet("faucet_account_id", "not-an-account-id", "faucet_account_id")]
#[case::relayer("relayer_account_id", "0xzzzz", "relayer_account_id")]
#[case::pubkey_not_hex("attester_pubkey_hex", "nothex", "attester_pubkey_hex")]
#[case::pubkey_wrong_length("attester_pubkey_hex", "0xdeadbeef", "attester_pubkey_hex")]
#[case::pubkey_not_a_curve_point(
    "attester_pubkey_hex",
    "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "attester_pubkey_hex"
)]
fn a_malformed_identity_is_refused_at_startup(
    #[case] field: &str,
    #[case] value: &str,
    #[case] expected: &str,
) {
    let mut config = test_config("unused.db".into());
    match field {
        "faucet_account_id" => config.faucet_account_id = value.to_string(),
        "relayer_account_id" => config.relayer_account_id = value.to_string(),
        "attester_pubkey_hex" => config.attester_pubkey_hex = value.to_string(),
        other => panic!("unknown field `{other}`"),
    }

    let error = format!("{:#}", Identities::from_config(&config).unwrap_err());

    assert!(
        error.contains(expected),
        "the refusal must name the field `{expected}`, got: {error}"
    );
}

/// The valid fixture config is genuinely valid — otherwise the negatives above prove nothing.
#[test]
fn the_fixture_identities_are_accepted() {
    let config = test_config("unused.db".into());
    assert_eq!(config.attester_pubkey_hex, ATTESTER_PUBKEY_HEX);
    assert!(Identities::from_config(&config).is_ok());
}

/// T-G3 — a missing config file is a clear error rather than a default-configured relayer.
#[test]
fn a_missing_config_file_is_refused() {
    use xreserve_deposit_relayer_lite::config::Config;

    let error = format!(
        "{:#}",
        Config::load(std::path::Path::new("/nonexistent/relayer.toml")).unwrap_err()
    );

    assert!(error.contains("relayer.toml"), "unexpected error: {error}");
}

/// The shipped example config parses and validates — otherwise `just run-relayer-lite` would fail
/// on the config rather than at the submit port, and the example would be a broken demo.
#[test]
fn the_shipped_example_config_is_valid() {
    use xreserve_deposit_relayer_lite::config::Config;
    use xreserve_deposit_relayer_lite::mint::Identities;

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("relayer.toml");
    let config = Config::load(&path).expect("the shipped relayer.toml parses and validates");

    // and its identities are real values, not prose placeholders
    Identities::from_config(&config).expect("the shipped relayer.toml carries usable identities");
}

/// A malformed config file is a parse error naming the file, not a silent default.
#[test]
fn a_malformed_config_file_is_refused() {
    use xreserve_deposit_relayer_lite::config::Config;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relayer.toml");
    std::fs::write(&path, "this is not = valid toml [[[").unwrap();

    let error = format!("{:#}", Config::load(&path).unwrap_err());

    assert!(error.contains("parsing"), "unexpected error: {error}");
}

/// An unknown key is REFUSED rather than ignored: a mistyped key that silently kept its default is
/// how an operator ends up debugging a value they thought they set.
#[test]
fn an_unknown_config_key_is_refused() {
    use xreserve_deposit_relayer_lite::config::Config;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relayer.toml");
    let mut text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("relayer.toml"),
    )
    .unwrap();
    text.push_str("\npoll_intervall_ms = 1234\n");
    std::fs::write(&path, text).unwrap();

    let error = format!("{:#}", Config::load(&path).unwrap_err());

    assert!(
        error.contains("poll_intervall_ms"),
        "the refusal must name the unknown key, got: {error}"
    );
}

/// T-G4 — there is no production submit adapter, and the refusal says why.
///
/// A relayer that started with a no-op submit would poll, decode, dedup and build — and mint
/// nothing, looking healthy in every log and metric except the chain's.
#[test]
fn there_is_no_production_submit_adapter() {
    let error = production_submit_port().unwrap_err().to_string();

    assert!(error.contains("miden-client"), "unexpected error: {error}");
    assert_matches!(production_submit_port(), Err(_));
}

/// A range-checked config value is refused at startup.
#[rstest]
#[case::page_size_zero(0, 1)]
#[case::page_size_over_circles_ceiling(1001, 1)]
fn an_out_of_range_config_value_is_refused(#[case] page_size: u16, #[case] _unused: u8) {
    let mut config = test_config("unused.db".into());
    config.poll_page_size = page_size;

    assert!(config.validate().is_err());
}
