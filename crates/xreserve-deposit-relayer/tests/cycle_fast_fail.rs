//! `domain_token_mismatch_fast_fail` · GATING (liveness; values RCC) — the two
//! sub-cases of the optional domain/token fast-fail, plus the config gate that decides whether the
//! check runs at all.
//!
//! # This is a LIVENESS optimization, not a safety gate
//!
//! `remoteDomain == the configured Miden domain` and `remoteToken == the configured xUSDC
//! identifier` are compared ON-CHAIN in the faucet's deposit-intent parse, and only the chain's
//! verdict is authoritative. The check here saves a block by refusing an attestation the faucet
//! would refuse anyway. Deleting it would cost throughput; it could not cost safety.
//!
//! # Both expected values are Circle-owned and OPEN
//!
//! * The remote-domain id — Circle has assigned Miden none. `REQUIRES CIRCLE CONFIRMATION`.
//! * The xUSDC AccountId↔bytes32 identifier and its encoding are unsettled. `REQUIRES
//!   CIRCLE CONFIRMATION` · `NO EVIDENCE OF CIRCLE APPROVAL`.
//!
//! So every value here is a package-default PLACEHOLDER: these tests gate the DEFAULT this package
//! takes and the MECHANISM that consumes it, never Circle acceptance of either value. The
//! live-Circle leg stays `REQUIRES CIRCLE CONFIRMATION`, and that is also why the check ships OFF
//! by default — a fast-fail whose expected value is a placeholder would reject every honest
//! deposit.

mod cycle_support;
mod fixtures;
mod mint_support;
mod mock_circle;

use assert_matches::assert_matches;

use xreserve_deposit_relayer::config::RelayerConfig;
use xreserve_deposit_relayer::cycle::{run_relayer_cycle, Disposition, RelayerCtx};
use xreserve_deposit_relayer::error::RelayerError;
use xreserve_deposit_relayer::validate::check_domain_token_against_info;
use xusdc_encoding::xreserve::encoding::DepositIntent;

use cycle_support::{cycle_client, cycle_identities, cycle_store, ScriptedSubmit};
use fixtures::{canonical_payload, TEST_VECTOR_PAYLOAD_ID};
use mint_support::{faucet_id, note_rng};
use mock_circle::{
    attestation_page, info_body, MockCircle, RecordingSink, Reply, Script, MOCK_BASE_URL,
};

// THE UNIT — `check_domain_token_against_info`
// ================================================================================================

/// The positive control. The check is only evidence if it PASSES for the honest shape — otherwise
/// the two rejections below would pass for a relayer that rejects everything.
#[tokio::test]
async fn the_matching_domain_and_token_pass() {
    let intent = canonical_intent();
    let config = config_matching(&intent, true);
    let info = advertised_info(&intent).await;

    check_domain_token_against_info(&intent, &info, &config)
        .expect("the configured values match the intent's");
}

/// **`reject_remoteDomain_mismatch`** — a `messageHash`-matching, structurally valid DepositIntent
/// whose `remoteDomain` is not the configured Miden domain. The live value is still Circle's to
/// assign — `REQUIRES CIRCLE CONFIRMATION`.
#[tokio::test]
async fn reject_remote_domain_mismatch() {
    let intent = canonical_intent();
    let mut config = config_matching(&intent, true);
    config = with_remote_domain(config, intent.header().remote_domain().wrapping_add(1));
    let info = advertised_info(&intent).await;

    let error = check_domain_token_against_info(&intent, &info, &config)
        .expect_err("a domain the relayer is not configured for is refused");

    assert_matches!(
        error,
        RelayerError::DomainMismatch { expected, actual }
            if expected == intent.header().remote_domain().wrapping_add(1) && actual == intent.header().remote_domain()
    );
    assert!(
        !error.is_retryable(),
        "a domain mismatch does not clear on a retry"
    );
}

/// **`reject_remoteToken_mismatch`** — `remoteToken` is not the configured xUSDC identifier. The
/// live value is still unsettled — `REQUIRES CIRCLE CONFIRMATION` · `NO EVIDENCE OF CIRCLE
/// APPROVAL`.
#[tokio::test]
async fn reject_remote_token_mismatch() {
    let intent = canonical_intent();
    let mut foreign = *intent.header().remote_token();
    foreign[31] ^= 0xFF;
    let config = with_xusdc_identifier(config_matching(&intent, true), foreign);
    let info = advertised_info(&intent).await;

    let error = check_domain_token_against_info(&intent, &info, &config)
        .expect_err("a token the relayer is not configured for is refused");

    assert_matches!(
        error,
        RelayerError::TokenMismatch { expected, actual }
            if expected == foreign && actual == *intent.header().remote_token()
    );
    assert!(!error.is_retryable());
}

/// The domain is checked BEFORE the token, so an intent that fails both reports the domain — the
/// coarser fact, and the one an operator acts on first (a wrong domain means the poll itself is
/// pointed at the wrong place).
#[tokio::test]
async fn a_domain_mismatch_is_reported_before_a_token_mismatch() {
    let intent = canonical_intent();
    let mut foreign = *intent.header().remote_token();
    foreign[0] ^= 0xFF;
    let config = with_xusdc_identifier(
        with_remote_domain(
            config_matching(&intent, true),
            intent.header().remote_domain() + 7,
        ),
        foreign,
    );

    assert_matches!(
        check_domain_token_against_info(&intent, &advertised_info(&intent).await, &config),
        Err(RelayerError::DomainMismatch { .. })
    );
}

/// `/v1/info` is not decoration: if Circle does not ADVERTISE the domain the relayer is configured
/// for, the fast-fail's expected value is not Circle's, and every honest attestation would be
/// refused by it. The relayer says so instead — a misconfiguration surfaced as a misconfiguration.
///
/// Ordered AFTER the two attestation checks, so a mismatching intent still reports the field that
/// mismatched.
#[tokio::test]
async fn a_configured_domain_circle_does_not_advertise_is_refused() {
    let intent = canonical_intent();
    let config = config_matching(&intent, true);
    // the intent and the config agree, so neither attestation check can fire; discovery is the one
    // that disagrees, advertising a domain nobody here is configured for. (Both values stay
    // placeholders — the real Miden domain id awaits Circle.)
    let unadvertised = intent.header().remote_domain() + 7;
    let info = fetched_info(mock_circle::info_body_for(
        unadvertised,
        mock_circle::FIXTURE_XUSDC_IDENTIFIER,
    ))
    .await;

    let error = check_domain_token_against_info(&intent, &info, &config)
        .expect_err("Circle does not advertise the configured domain");
    assert_matches!(
        error,
        RelayerError::InfoDomainNotAdvertised { domain } if domain == intent.header().remote_domain()
    );
}

// THE CONFIG GATE — the check is OPTIONAL, and its being optional is observable
// ================================================================================================

/// With the fast-fail OFF (the package default), the cycle issues **no `/v1/info` request at all**.
///
/// That is the structural half of "optional": a check that is off does not merely skip its
/// comparison, it does not spend a request or a rate-limit token on the discovery it would have
/// needed. The mock's request log is the oracle — an assertion the relayer's own report could not
/// make.
#[tokio::test]
async fn with_the_fast_fail_off_no_info_request_is_issued() {
    let vector = fixtures::test_vector();
    let mock = MockCircle::start(
        Script::new()
            .batch(vec![Reply::ok(attestation_page(&[&vector]))])
            .info(vec![Reply::ok(info_body())]),
    );

    let config = cycle_support::cycle_config();
    assert!(
        !config.domain_token_fast_fail(),
        "the package default leaves the RCC-valued fast-fail off"
    );
    let report = run_cycle(&mock, &config).await;

    assert_eq!(report.fetched(), 1);
    assert_eq!(
        mock.requests_to(mock_circle::Endpoint::Info).len(),
        0,
        "the disabled fast-fail still fetched /v1/info"
    );
}

/// With the fast-fail ON, the cycle fetches `/v1/info` ONCE per cycle — not once per attestation.
/// The discovery answer is the same for every attestation on the page, and Circle's ceiling is 5
/// QPS per IP.
#[tokio::test]
async fn with_the_fast_fail_on_info_is_fetched_once_per_cycle() {
    let first = fixtures::test_vector();
    let second = fixtures::PartnerAttester::new().attest(&canonical_payload(
        fixtures::TEST_VECTOR_PAYLOAD_ID_EMPTY_HOOKDATA,
    ));
    let mock = MockCircle::start(
        Script::new()
            .batch(vec![Reply::ok(attestation_page(&[&first, &second]))])
            .info(vec![Reply::ok(advertised_info_body(&canonical_intent()))]),
    );

    let intent = canonical_intent();
    let config = config_matching(&intent, true);
    let report = run_cycle(&mock, &config).await;

    assert_eq!(report.fetched(), 2);
    assert_eq!(
        mock.requests_to(mock_circle::Endpoint::Info).len(),
        1,
        "/v1/info is discovery, not a per-attestation call"
    );
}

/// **The cycle-level**: with the fast-fail ON and a mismatching configured domain, the
/// attestation is refused PRE-SUBMISSION — the submit port is never reached — and it is reported
/// with its reason rather than dropped.
#[tokio::test]
async fn the_cycle_refuses_a_domain_mismatch_before_the_submit_port() {
    let vector = fixtures::test_vector();
    let mock = MockCircle::start(
        Script::new()
            .batch(vec![Reply::ok(attestation_page(&[&vector]))])
            .info(vec![Reply::ok(info_body())]),
    );

    let intent = canonical_intent();
    let config = with_remote_domain(
        config_matching(&intent, true),
        intent.header().remote_domain() + 1,
    );

    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::always_accepting();
    let identities = cycle_identities();
    let mut rng = note_rng(7);
    let mut ctx = RelayerCtx::new(
        &config,
        &client,
        &store,
        submit.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );
    let report = run_relayer_cycle(&mut ctx).await.expect("the cycle runs");

    assert_eq!(report.fetched(), 1);
    assert_eq!(
        submit.call_count(),
        0,
        "the fast-fail let a mismatching attestation reach the submit port"
    );
    assert_matches!(
        report.entries()[0].disposition(),
        Disposition::Rejected(RelayerError::DomainMismatch { .. })
    );
    assert!(!report.entries()[0].reason().is_empty());
}

/// The `/v1/info` fetch is on the cycle's critical path when the check is on: a 400 there fails the
/// cycle rather than silently disabling the check. A fast-fail that quietly stops checking when
/// discovery breaks is worse than one that is off, because the operator believes it is on.
#[tokio::test]
async fn a_broken_info_fetch_fails_the_cycle_rather_than_disabling_the_check() {
    let vector = fixtures::test_vector();
    let mock = MockCircle::start(
        Script::new()
            .batch(vec![Reply::ok(attestation_page(&[&vector]))])
            .info(vec![Reply::Status(400)]),
    );

    let intent = canonical_intent();
    let config = config_matching(&intent, true);
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::always_accepting();
    let identities = cycle_identities();
    let mut rng = note_rng(7);
    let mut ctx = RelayerCtx::new(
        &config,
        &client,
        &store,
        submit.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );

    let error = run_relayer_cycle(&mut ctx)
        .await
        .expect_err("a broken discovery fails the cycle");
    assert_matches!(error, RelayerError::Http { status: 400 });
    assert_eq!(submit.call_count(), 0);
}

// HELPERS
// ================================================================================================

/// The canonical mint-payload DepositIntent, decoded through the relayer's own validator — so
/// the expected `remoteDomain`/`remoteToken` are read from the golden artifact, never restated
/// here.
fn canonical_intent() -> DepositIntent {
    xreserve_deposit_relayer::validate::decode_and_validate_deposit_intent(&canonical_payload(
        TEST_VECTOR_PAYLOAD_ID,
    ))
    .expect("the canonical vector is a valid DepositIntent")
}

/// A config whose Circle-owned expectations MATCH `intent` — the values the still-OPEN domain and
/// identifier placeholders will one day carry, set here to what the golden vector actually holds so
/// the mechanism can be exercised without pretending either decision is settled.
fn config_matching(intent: &DepositIntent, fast_fail: bool) -> RelayerConfig {
    serde_json::from_value(serde_json::json!({
        "circle_base_url": MOCK_BASE_URL,
        "remote_domain": intent.header().remote_domain(),
        "xusdc_identifier": intent.header().remote_token().to_vec(),
        "faucet_account_id": faucet_id().to_hex(),
        "rate_qps_per_ip": 5,
        "rate_qps_global": 35,
        "max_retry_attempts": 3,
        "backoff_base_ms": 0,
        "poll_page_size": 10,
        "domain_token_fast_fail": fast_fail,
    }))
    .expect("the fast-fail config deserializes")
}

fn with_remote_domain(config: RelayerConfig, domain: u32) -> RelayerConfig {
    let mut value = serde_json::to_value(config).expect("the config serializes");
    value["remote_domain"] = serde_json::json!(domain);
    serde_json::from_value(value).expect("the config round-trips")
}

fn with_xusdc_identifier(config: RelayerConfig, identifier: [u8; 32]) -> RelayerConfig {
    let mut value = serde_json::to_value(config).expect("the config serializes");
    value["xusdc_identifier"] = serde_json::json!(identifier.to_vec());
    serde_json::from_value(value).expect("the config round-trips")
}

/// The `/v1/info` body that ADVERTISES `intent`'s own domain and token identifier — i.e. a Circle
/// whose discovery agrees with the deposit. Both values stay placeholders (the domain id and the
/// identifier are still OPEN).
fn advertised_info_body(intent: &DepositIntent) -> serde_json::Value {
    mock_circle::info_body_for(
        intent.header().remote_domain(),
        &format!("0x{}", hex::encode(intent.header().remote_token())),
    )
}

/// [`fetched_info`] over a discovery that advertises `intent`'s domain + token.
async fn advertised_info(
    intent: &DepositIntent,
) -> xreserve_deposit_relayer::circle::schema::InfoResponse {
    fetched_info(advertised_info_body(intent)).await
}

/// `/v1/info` as the relayer itself fetches it — through the real client against the mock, never a
/// hand-built `InfoResponse`.
async fn fetched_info(
    body: serde_json::Value,
) -> xreserve_deposit_relayer::circle::schema::InfoResponse {
    let mock = MockCircle::start(Script::new().info(vec![Reply::ok(body)]));
    let config = cycle_support::cycle_config();
    let client = cycle_client(&mock, &config, RecordingSink::new());
    xreserve_deposit_relayer::circle::fetch_info(&client)
        .await
        .expect("the mock serves the documented /v1/info shape")
}

/// One cycle against `mock` under `config`, with an always-accepting port.
async fn run_cycle(
    mock: &MockCircle,
    config: &RelayerConfig,
) -> xreserve_deposit_relayer::cycle::CycleReport {
    let sink = RecordingSink::new();
    let client = cycle_client(mock, config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::always_accepting();
    let identities = cycle_identities();
    let mut rng = note_rng(7);
    let mut ctx = RelayerCtx::new(
        config,
        &client,
        &store,
        submit.as_ref(),
        sink.as_ref(),
        &identities,
        &mut rng,
    );
    run_relayer_cycle(&mut ctx).await.expect("the cycle runs")
}
