//! **`T-RLY-09`** (`duplicate_attestation_no_double_submit`, INV-MINT-SECURITY) and the
//! cycle-level integration run — the 8-step `run_relayer_cycle` pipeline, driven end to end.
//!
//! # What is real here, and what is not (§11 mock disclosure)
//!
//! REAL: the `CircleClient` (a real `reqwest::Request` against the schema-exact mock Circle router),
//! the raw-keccak envelope binding, unit-04's DepositIntent codec, unit-04's
//! `XReserveMintNote::create`, and the SQLite idempotency store on a real file.
//!
//! MOCKED: the Circle endpoints (`CMP-D1`/`CMP-D3`/`CMP-D4`) — sanctioned: Circle API may be mocked,
//! and every live Circle leg is `REQUIRES CIRCLE CONFIRMATION` (`Q-API-AUTH`, `Q-DOM-1`,
//! `Q-INFO-PARAM` are OPEN).
//!
//! ADAPTED, and **NON-GATING**: the Miden submit leg, through the [`MintSubmit`] PORT. Miden
//! behaviour is not faked here — the adapter executes no transaction and claims no commit. The
//! GATING leg (a real `XReserveMintNote` committing in block N against a real local node,
//! T-RLY-14/T-RLY-15) is R6's and is blocked on a `miden-client` release for v0.16. This whole suite
//! is therefore NON-GATING for the Miden half and GATING for the orchestration around it.
//!
//! The dedup this file proves is a **LIVENESS** backstop. The authoritative duplicate defence is the
//! on-chain `usedNonces` assert-then-set at D5c (INV-MINT-SECURITY): a relayer bug here can only
//! withhold a mint, never authorize one.

mod cycle_support;
mod fixtures;
mod mint_support;
mod mock_circle;

use assert_matches::assert_matches;

use xreserve_deposit_relayer::cycle::{run_relayer_cycle, Disposition, RelayerCtx};
use xreserve_deposit_relayer::error::RelayerError;
use xreserve_deposit_relayer::idempotency::SubmissionStatus;
use xreserve_deposit_relayer::observability::RelayerEvent;

use cycle_support::{
    cycle_client, cycle_config, cycle_identities, cycle_store, tx_id, ScriptedSubmit, SubmitReply,
    CYCLE_DOMAIN,
};
use fixtures::{canonical_payload, AttestationVector, PartnerAttester, TEST_VECTOR_PAYLOAD_ID};
use mint_support::note_rng;
use mock_circle::{
    attestation_page, batch_href, link_header, MockCircle, RecordingSink, Reply, Script,
};

// THE HAPPY PATH — one page, one attestation, minted once
// ================================================================================================

/// **The cycle-level integration run.** One fetched attestation goes all eight steps: poll → envelope
/// + hash bind → DepositIntent validate → idempotency claim → build note → submit → record → advance
/// cursor.
#[tokio::test]
async fn one_cycle_fetches_validates_builds_submits_records_and_advances() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok_linked(
        attestation_page(&[&vector]),
        link_header(&[(
            "next",
            &batch_href(CYCLE_DOMAIN, 10, Some(("pageAfter", "cursor-page-2"))),
        )]),
    )]));

    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::new(vec![SubmitReply::Accepted(tx_id(0x11))]);
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

    // step 1 — one attestation was fetched, and the poll went to the configured remote domain
    assert_eq!(report.fetched(), 1);
    assert_eq!(report.remote_domain(), CYCLE_DOMAIN);

    // steps 2–6 — it crossed the seam and was submitted exactly once
    assert_eq!(submit.call_count(), 1, "the port was reached exactly once");
    assert_matches!(
        report.entries()[0].disposition(),
        Disposition::Submitted { tx_id } if *tx_id == cycle_support::tx_id(0x11)
    );

    // the note the port received is the note the relayer built for OUR faucet + sender
    let submission = &submit.calls()[0];
    assert_eq!(submission.sender, mint_support::relayer_sender_id());

    // step 7 — the outcome is durable: the nonce's log row carries the transaction id
    let nonce = nonce_of(&vector);
    let record = store
        .record(&nonce)
        .expect("the store reads")
        .expect("the nonce was claimed");
    assert_eq!(record.status(), SubmissionStatus::Submitted);
    assert_eq!(record.submitted_tx_id(), Some(&tx_id(0x11)));
    assert_eq!(record.attestation_message_hash(), &vector.message_hash());

    // step 8 — the `Link` header's `next` cursor was persisted, so a restart resumes from it
    assert_eq!(report.next_cursor(), Some("cursor-page-2"));
    assert!(!report.scan_complete());
    let cursor = store
        .read_cursor(CYCLE_DOMAIN)
        .expect("the store reads")
        .expect("the cursor advanced");
    assert_eq!(cursor.page_after(), "cursor-page-2");
}

/// A page whose `Link` header advertises no `next` ENDS the scan (§8.2 pagination boundary) — and
/// the cursor is NOT advanced past it, because there is nothing to resume from.
#[tokio::test]
async fn a_page_without_a_next_cursor_ends_the_scan() {
    let vector = test_vector();
    let mock = MockCircle::start(
        Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]), // no Link header
    );

    let (report, _submit, store, _sink, _dir) =
        run_one(&mock, ScriptedSubmit::always_accepting()).await;

    assert_eq!(report.fetched(), 1);
    assert!(report.scan_complete(), "an absent `next` ends the scan");
    assert_eq!(report.next_cursor(), None);
    assert_eq!(
        store.read_cursor(CYCLE_DOMAIN).expect("the store reads"),
        None,
        "no resume point is invented for a scan that reached its end"
    );
}

/// The cursor is READ back into the next poll: a second cycle asks Circle for the page AFTER the one
/// the first cycle finished. This is what a restart does, and it is why the whole window is not
/// re-scanned.
#[tokio::test]
async fn the_next_cycle_polls_from_the_persisted_cursor() {
    let first = test_vector();
    // a DIFFERENT deposit, not merely a different payload: the golden artifact's two DI vectors share
    // a nonce (they describe one deposit at two hookData lengths), and the idempotency gate keys on
    // the nonce — so reusing one here would dedup the second mint, and the cursor assertion below
    // would be measuring the wrong thing.
    let second = PartnerAttester::new().attest(&with_distinct_nonce(1));

    let mock = MockCircle::start(Script::new().batch(vec![
        Reply::ok_linked(
            attestation_page(&[&first]),
            link_header(&[(
                "next",
                &batch_href(CYCLE_DOMAIN, 10, Some(("pageAfter", "cursor-page-2"))),
            )]),
        ),
        Reply::ok(attestation_page(&[&second])),
    ]));

    let config = cycle_config();
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

    run_relayer_cycle(&mut ctx).await.expect("cycle 1 runs");
    run_relayer_cycle(&mut ctx).await.expect("cycle 2 runs");

    let requests = mock.requests_to(mock_circle::Endpoint::Batch);
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].query("pageAfter"),
        None,
        "the first poll of a fresh store has no resume point"
    );
    assert_eq!(
        requests[1].query("pageAfter"),
        Some("cursor-page-2"),
        "the second poll resumes from the cursor the first persisted"
    );
    assert_eq!(submit.call_count(), 2, "two distinct nonces, two mints");
}

// T-RLY-09 — THE DEDUP: a replayed attestation produces NO second mint
// ================================================================================================

/// A structurally invalid DepositIntent is REJECTED pre-submission (§8.1 check 4) — and reported
/// with the field that failed, never dropped. The on-chain D5a parse stays authoritative; this is
/// its liveness mirror.
#[tokio::test]
async fn a_structural_deposit_intent_reject_never_reaches_submit() {
    // a payload Circle signed (the envelope binds) whose magic is wrong — the shape that proves the
    // envelope layer validates the BINDING, never the DepositIntent structure
    let mut payload = canonical_payload(TEST_VECTOR_PAYLOAD_ID);
    payload[0] ^= 0xFF;
    let vector = PartnerAttester::new().attest(&payload);

    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let (report, submit, _store, sink, _dir) =
        run_one(&mock, ScriptedSubmit::always_accepting()).await;

    assert_eq!(report.fetched(), 1);
    assert_eq!(
        submit.call_count(),
        0,
        "a rejected intent must not be minted"
    );
    assert_matches!(
        report.entries()[0].disposition(),
        Disposition::Rejected(RelayerError::BadMagic(_))
    );
    assert!(!report.entries()[0].reason().is_empty());

    // §8.4: a structural error ALERTS — an operator must see it
    assert_eq!(sink.alerts().len(), 1, "a structural reject alerts");
}

/// A transient submit failure RETRIES within the cycle and the eventual success commits — the
/// attestation stays valid across the retry, because a deposit intent has no expiry (§8.2).
#[tokio::test]
async fn a_transient_submit_failure_retries_and_then_succeeds() {
    let vector = test_vector();
    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let (report, submit, store, _sink, _dir) = run_one(
        &mock,
        ScriptedSubmit::new(vec![
            SubmitReply::Transient,
            SubmitReply::Transient,
            SubmitReply::Accepted(tx_id(0x44)),
        ]),
    )
    .await;

    assert_eq!(
        submit.call_count(),
        3,
        "two transient failures, then the success"
    );
    assert_matches!(
        report.entries()[0].disposition(),
        Disposition::Submitted { tx_id } if *tx_id == cycle_support::tx_id(0x44)
    );
    assert_eq!(
        store
            .record(&nonce_of(&vector))
            .expect("reads")
            .expect("claimed")
            .status(),
        SubmissionStatus::Submitted
    );
}

/// A transient submit failure that OUTLASTS the attempt budget is DEFERRED, not dropped and not
/// failed-forever: the nonce goes back into the retryable pool (`Failed`), so the next cycle
/// re-claims it. The attestation has no expiry — giving up on this cycle is not giving up.
#[tokio::test]
async fn a_transient_submit_failure_that_exhausts_the_budget_defers() {
    let vector = test_vector();
    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let (report, submit, store, _sink, _dir) =
        run_one(&mock, ScriptedSubmit::new(vec![SubmitReply::Transient])).await;

    assert_eq!(
        submit.call_count(),
        cycle_config().max_retry_attempts() as usize,
        "the transient retry is bounded by the configured attempt budget"
    );
    assert_matches!(
        report.entries()[0].disposition(),
        Disposition::Deferred(error) if error.is_retryable()
    );
    assert_eq!(report.entries()[0].outcome(), "deferred");
    assert!(!report.entries()[0].reason().is_empty());
    assert_eq!(
        store
            .record(&nonce_of(&vector))
            .expect("reads")
            .expect("claimed")
            .status(),
        SubmissionStatus::Failed,
        "a deferred nonce is back in the retryable pool, not stranded mid-flight"
    );
}

/// A FATAL submit failure records a TERMINAL `Rejected`, alerts, and does NOT loop (§8.4 "Miden fatal
/// submit error" row).
///
/// Terminal, not `Failed`: a permanently-refused transaction that were left re-claimable would be
/// re-fetched and re-submitted by the retry driver on every subsequent cycle (proven across cycles in
/// `cycle_recovery.rs`). The fatal/transient split is only real if it survives to the durable record.
#[tokio::test]
async fn a_fatal_submit_failure_records_rejected_and_does_not_retry() {
    let vector = test_vector();
    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let (report, submit, store, sink, _dir) =
        run_one(&mock, ScriptedSubmit::new(vec![SubmitReply::Fatal])).await;

    assert_eq!(
        submit.call_count(),
        1,
        "a fatal submit error is not retried"
    );
    assert_matches!(
        report.entries()[0].disposition(),
        Disposition::Rejected(RelayerError::FatalSubmit(_))
    );
    assert_eq!(
        store
            .record(&nonce_of(&vector))
            .expect("reads")
            .expect("claimed")
            .status(),
        SubmissionStatus::Rejected,
        "a fatal submit must be recorded terminally, not as a re-claimable Failed"
    );
    assert_eq!(sink.alerts().len(), 1, "a fatal submit error alerts");
}

/// The on-chain nonce trap fired first — another relayer minted this deposit (§8.2 "Attestation
/// arrives after a competing relayer already minted"). The relayer records `AlreadyMinted`, does not
/// retry, and the cursor still advances. This is the SAFETY backstop doing its job, observed from
/// the liveness side; it is not a defect.
#[tokio::test]
async fn a_nonce_already_minted_on_chain_is_recorded_not_retried() {
    let vector = test_vector();
    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let (report, submit, store, _sink, _dir) =
        run_one(&mock, ScriptedSubmit::new(vec![SubmitReply::AlreadyMinted])).await;

    assert_eq!(submit.call_count(), 1);
    assert_matches!(
        report.entries()[0].disposition(),
        Disposition::AlreadyMinted
    );
    assert_eq!(report.entries()[0].outcome(), "already-minted");
    assert_eq!(
        store
            .record(&nonce_of(&vector))
            .expect("reads")
            .expect("claimed")
            .status(),
        SubmissionStatus::AlreadyMinted,
        "terminal: another attempt could only fail the same assert"
    );
}

/// TWO attestations claiming the SAME nonce with DIFFERENT `messageHash`es. At most one of them is
/// the deposit that happened, and the relayer cannot know which — so it refuses the newcomer and
/// leaves it for an operator (`reconciliation-required`), rather than guessing. Neither is dropped.
#[tokio::test]
async fn a_second_attestation_for_a_claimed_nonce_is_left_for_reconciliation() {
    let honest = test_vector();
    // the same DepositIntent nonce, a different payload → a different messageHash
    let mut impostor_payload = canonical_payload(TEST_VECTOR_PAYLOAD_ID);
    let hook_start = 240;
    impostor_payload[hook_start] ^= 0x01; // mutate hookData: the nonce field is untouched
    let impostor = PartnerAttester::new().attest(&impostor_payload);
    assert_eq!(
        nonce_of(&honest),
        nonce_of(&impostor),
        "the fixtures must share a nonce for this test to be about a nonce conflict"
    );
    assert_ne!(honest.message_hash(), impostor.message_hash());

    let mock = MockCircle::start(
        Script::new().batch(vec![Reply::ok(attestation_page(&[&honest, &impostor]))]),
    );
    let (report, submit, _store, sink, _dir) =
        run_one(&mock, ScriptedSubmit::always_accepting()).await;

    assert_eq!(report.fetched(), 2, "both were fetched, both are reported");
    assert_eq!(submit.call_count(), 1, "only the claimed one was minted");
    assert_matches!(
        report.entries()[0].disposition(),
        Disposition::Submitted { .. }
    );
    assert_matches!(
        report.entries()[1].disposition(),
        Disposition::ReconciliationRequired(RelayerError::NonceMessageHashMismatch { .. })
    );
    assert_eq!(report.entries()[1].outcome(), "reconciliation-required");
    assert!(sink.alerts().iter().any(|event| matches!(
        event,
        RelayerEvent::Alert { reason, .. } if reason.contains("nonce")
    )));
}

/// A permanent Circle status (400) on the PAGE fetch fails the cycle — and drops nothing, because
/// nothing was fetched. The distinction matters: "no attestation was dropped" is a claim about
/// attestations that existed.
#[tokio::test]
async fn a_400_on_the_page_fetch_fails_the_cycle_without_dropping_anything() {
    let mock = MockCircle::start(Script::new().batch(vec![Reply::Status(400)]));
    let config = cycle_config();
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
        .expect_err("a 400 fails the cycle");
    assert_matches!(error, RelayerError::Http { status: 400 });
    assert!(!error.is_retryable(), "400 is permanent");
    assert_eq!(
        mock.requests_to(mock_circle::Endpoint::Batch).len(),
        1,
        "a 400 is not retried"
    );
    assert_eq!(submit.call_count(), 0);
    assert_eq!(
        sink.rejections().len(),
        1,
        "the 400 is recorded, not swallowed"
    );
}

// METRICS
// ================================================================================================

/// The counters follow what actually happened — they are read from the cycle's own outcomes, so a
/// silent drop would show up as a fetched attestation with no disposition counted.
#[tokio::test]
async fn the_metrics_count_every_fetched_attestation_exactly_once() {
    let good = test_vector();
    let mut bad_payload = canonical_payload(TEST_VECTOR_PAYLOAD_ID);
    bad_payload[0] ^= 0xFF;
    let bad = PartnerAttester::new().attest(&bad_payload);

    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&good, &bad]))]));
    let config = cycle_config();
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

    run_relayer_cycle(&mut ctx).await.expect("the cycle runs");

    let metrics = ctx.metrics();
    assert_eq!(metrics.attestations_fetched(), 2);
    assert_eq!(metrics.mint_notes_built(), 1);
    assert_eq!(metrics.mint_notes_submitted(), 1);
    assert_eq!(metrics.attestations_rejected(), 1);
    assert_eq!(
        metrics.attestations_fetched(),
        metrics.mint_notes_submitted()
            + metrics.attestations_rejected()
            + metrics.attestations_duplicate()
            + metrics.attestations_already_minted()
            + metrics.attestations_deferred()
            + metrics.reconciliation_required(),
        "every fetched attestation is accounted for by exactly one terminal counter"
    );
}

/// The cycle-duration histogram observes one sample per cycle, with the sum tracking the samples —
/// a diagnostic surface, never load-bearing.
#[tokio::test]
async fn the_cycle_duration_histogram_records_one_sample_per_cycle() {
    let vector = test_vector();
    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let (_report, _submit, _store, _sink, _dir) =
        run_one(&mock, ScriptedSubmit::always_accepting()).await;

    let mut histogram = xreserve_deposit_relayer::observability::Histogram::cycle_duration_ms();
    assert_eq!(histogram.count(), 0);
    histogram.observe(3);
    histogram.observe(4_000);
    assert_eq!(histogram.count(), 2);
    assert_eq!(histogram.sum(), 4_003);
    assert_eq!(
        histogram.bucket(5),
        1,
        "the 3ms sample lands in the le=5 bucket"
    );
    assert_eq!(
        histogram.bucket(u64::MAX),
        2,
        "the cumulative +Inf bucket holds every sample"
    );
}

// HELPERS
// ================================================================================================

/// The standard vector: the partner key over the canonical `di-pos-hookdata` DepositIntent payload.
fn test_vector() -> AttestationVector {
    fixtures::test_vector()
}

/// The canonical payload with its `nonce` perturbed — a DIFFERENT deposit, still structurally valid.
/// The nonce's offset is located by SEARCHING the payload for the nonce the decoder reports, so the
/// test never restates a DC-1 offset unit-04 owns.
fn with_distinct_nonce(tweak: u8) -> Vec<u8> {
    let payload = canonical_payload(TEST_VECTOR_PAYLOAD_ID);
    let nonce = nonce_of(&PartnerAttester::new().attest(&payload));
    let offset = payload
        .windows(nonce.len())
        .position(|window| window == nonce)
        .expect("the nonce appears in its own payload");

    let mut tweaked = payload;
    tweaked[offset] ^= tweak;
    tweaked
}

/// The `DepositIntent.nonce` a vector's payload carries — read through the relayer's OWN decoder, so
/// the test never restates a DC-1 offset unit-04 owns.
fn nonce_of(vector: &AttestationVector) -> [u8; 32] {
    *xreserve_deposit_relayer::validate::decode_and_validate_deposit_intent(vector.payload())
        .expect("the fixture payload is a valid DepositIntent")
        .nonce()
}

/// Runs ONE cycle against `mock` with `submit`, returning everything a test asserts on. The temp
/// directory is returned so the store's file outlives the call.
async fn run_one(
    mock: &MockCircle,
    submit: std::sync::Arc<ScriptedSubmit>,
) -> (
    xreserve_deposit_relayer::cycle::CycleReport,
    std::sync::Arc<ScriptedSubmit>,
    xreserve_deposit_relayer::idempotency::IdempotencyStore,
    std::sync::Arc<RecordingSink>,
    tempfile::TempDir,
) {
    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let identities = cycle_identities();
    let mut rng = note_rng(7);

    let report = {
        let mut ctx = RelayerCtx::new(
            &config,
            &client,
            &store,
            submit.as_ref(),
            sink.as_ref(),
            &identities,
            &mut rng,
        );
        run_relayer_cycle(&mut ctx).await.expect("the cycle runs")
    };

    (report, submit, store, sink, dir)
}
