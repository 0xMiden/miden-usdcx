//! **Cross-cycle submit recovery** — the two halves of the terminal-vs-retryable split, driven
//! across more than one cycle, plus the loop-level failure emission.
//!
//! A driver that recorded BOTH a fatal submit and a budget-exhausted transient submit as
//! `SubmissionStatus::Failed` (which the store makes re-claimable) — and advanced
//! the page cursor without ever consuming `IdempotencyStore::retryable` — would host two opposite
//! bugs at once:
//!
//! * a **transient** failure on a page WITH a next cursor would be stranded: the cursor moves past
//!   its page and forward-only polling never re-observes its attestation, while the retry work list
//!   that was built for exactly this (`retryable()`) goes unused;
//! * a **fatal** failure on a re-polled or final page would be re-claimed and re-submitted, because
//!   `Failed` is retryable — the fatal/transient split would mean nothing across cycles.
//!
//! This suite drives real multi-cycle sequences and asserts neither happens: transient failures are
//! retried by re-fetching their attestation by `messageHash` regardless of the cursor, and fatal
//! failures are TERMINAL — never re-submitted, whether the page is re-polled or not.
//!
//! Every leg here is real except the Miden submit PORT (NON-GATING — it executes no transaction;
//! the mock boundary mock disclosure). The dedup and retry are LIVENESS backstops; the
//! authoritative duplicate defence is the on-chain `usedNonces` assert.

mod cycle_support;
mod fixtures;
mod mint_support;
mod mock_circle;

use assert_matches::assert_matches;

use xreserve_deposit_relayer::cycle::{
    run_relayer_cycle, run_relayer_loop, Disposition, RelayerCtx,
};
use xreserve_deposit_relayer::idempotency::SubmissionStatus;
use xreserve_deposit_relayer::observability::RelayerEvent;

use cycle_support::{
    cycle_client, cycle_config, cycle_identities, cycle_store, tx_id, ScriptedSubmit, SubmitReply,
    CYCLE_DOMAIN,
};
use fixtures::{canonical_payload, AttestationVector, PartnerAttester, TEST_VECTOR_PAYLOAD_ID};
use mint_support::note_rng;
use mock_circle::{
    attestation_page, batch_href, by_hash_wrapper, link_header, Endpoint, MockCircle,
    RecordingSink, Reply, Script,
};
use xusdc_encoding::xreserve::encoding::DepositIntent;

// THE TRANSIENT STRAND — a page-1 transient failure is retried across the cursor advance
// ================================================================================================

/// **A transient submit failure is NOT stranded behind the cursor.**
///
/// Cycle 1 polls page 1 (which advertises a `next` cursor), the lone attestation exhausts its
/// submit budget with transient failures, and the cursor advances to page 2. Forward polling will
/// never re-observe that attestation. Cycle 2 must therefore RE-FETCH it by `messageHash` from the
/// retry work list and re-submit it — and this time it lands.
#[tokio::test]
async fn a_transient_failure_is_retried_across_cycles_not_stranded_behind_the_cursor() {
    let stranded = test_vector();
    let page_two = PartnerAttester::new().attest(&with_distinct_nonce(2));

    let mock = MockCircle::start(
        Script::new()
            .batch(vec![
                // page 1, with a next cursor — cycle 1 will advance past it
                Reply::ok_linked(
                    attestation_page(&[&stranded]),
                    link_header(&[(
                        "next",
                        &batch_href(CYCLE_DOMAIN, 10, Some(("pageAfter", "cursor-page-2"))),
                    )]),
                ),
                // page 2, terminal — cycle 2's forward poll, which does NOT carry the stranded one
                Reply::ok(attestation_page(&[&page_two])),
            ])
            // the retry re-fetches the stranded attestation by its messageHash
            .by_hash(vec![Reply::ok(by_hash_wrapper(&stranded))]),
    );

    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    // cycle 1: submit budget is 3, all transient → Deferred. cycle 2 retry: the 4th call lands.
    let submit = ScriptedSubmit::new(vec![
        SubmitReply::Transient,
        SubmitReply::Transient,
        SubmitReply::Transient,
        SubmitReply::Accepted(tx_id(0x77)),
    ]);
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

    // cycle 1 — the stranded attestation defers, the cursor advances
    let first = run_relayer_cycle(&mut ctx).await.expect("cycle 1 runs");
    assert_matches!(first.entries()[0].disposition(), Disposition::Deferred(_));
    assert_eq!(
        store
            .read_cursor(CYCLE_DOMAIN)
            .expect("read")
            .expect("advanced")
            .page_after(),
        "cursor-page-2",
        "cycle 1 must have advanced past page 1"
    );
    assert_eq!(
        store
            .record(&nonce_of(&stranded))
            .expect("read")
            .expect("claimed")
            .status(),
        SubmissionStatus::Failed,
        "a deferred transient failure is retryable, not terminal"
    );

    // cycle 2 — the retry driver re-fetches the stranded attestation by hash and re-submits it
    let second = run_relayer_cycle(&mut ctx).await.expect("cycle 2 runs");

    assert!(
        !mock.requests_to(Endpoint::ByHash).is_empty(),
        "cycle 2 never re-fetched the stranded attestation by messageHash — the retry queue was not \
         consumed, so the deposit is stranded behind the cursor"
    );
    // the re-fetched attestation landed, and page 2's own attestation was also handled
    assert_eq!(
        store
            .record(&nonce_of(&stranded))
            .expect("read")
            .expect("claimed")
            .status(),
        SubmissionStatus::Submitted,
        "the stranded transient failure was never retried to success"
    );
    assert_eq!(
        store
            .record(&nonce_of(&stranded))
            .expect("read")
            .expect("claimed")
            .submitted_tx_id(),
        Some(&tx_id(0x77))
    );
    // the retried attestation is reported in cycle 2 (never silently retried)
    assert!(
        second
            .entries()
            .iter()
            .any(|e| e.message_hash() == &stranded.message_hash()
                && matches!(e.disposition(), Disposition::Submitted { .. })),
        "the retried attestation was not reported as submitted in cycle 2"
    );
}

/// A transient failure whose RE-FETCH also fails stays retryable — it is reported (deferred), not
/// dropped, and the record stays `Failed` so a later cycle tries again. The attestation has no
/// expiry, so a re-fetch that transiently fails is not the end of the deposit.
#[tokio::test]
async fn a_retry_whose_refetch_fails_stays_retryable_and_is_reported() {
    let stranded = test_vector();

    let mock = MockCircle::start(
        Script::new()
            .batch(vec![
                Reply::ok_linked(
                    attestation_page(&[&stranded]),
                    link_header(&[(
                        "next",
                        &batch_href(CYCLE_DOMAIN, 10, Some(("pageAfter", "cursor-page-2"))),
                    )]),
                ),
                // page 2 is empty — the only work in cycle 2 is the retry
                Reply::ok(attestation_page(&[])),
            ])
            // the re-fetch keeps 500-ing: transient, so the retry policy exhausts and the deposit
            // stays owed
            .by_hash(vec![Reply::Status(500)]),
    );

    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::new(vec![SubmitReply::Transient]);
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
    let second = run_relayer_cycle(&mut ctx).await.expect("cycle 2 runs");

    // the retry was attempted and REPORTED — not dropped
    assert!(
        second
            .entries()
            .iter()
            .any(|e| e.message_hash() == &stranded.message_hash()),
        "the retry attempt for the stranded attestation was not reported"
    );
    // …and the deposit is still owed: retryable, so a later cycle tries again
    assert_eq!(
        store
            .record(&nonce_of(&stranded))
            .expect("read")
            .expect("claimed")
            .status(),
        SubmissionStatus::Failed,
        "a failed re-fetch must leave the deposit retryable, not stranded or terminal"
    );
}

// THE FATAL TERMINAL — a fatal failure is not re-submitted, even on a re-poll
// ================================================================================================

/// **A fatal submit failure is TERMINAL and is not re-submitted on a final-page re-poll.**
///
/// Cycle 1 polls a final page (no `next` cursor, so the cursor does not advance) and the
/// attestation fatally fails. Cycle 2 re-polls the SAME final page. The fatal attestation must be
/// recorded terminally and recognized as already-decided on the re-poll — never built and submitted
/// a second time.
#[tokio::test]
async fn a_fatal_failure_is_terminal_and_not_resubmitted_on_a_final_page_repoll() {
    let doomed = test_vector();

    // a FINAL page (no Link header), served on every poll — cycle 2 re-polls the same page
    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&doomed]))]));

    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    // a single fatal answer; if the cycle ever re-submitted, the repeating last reply is still Fatal,
    // so the call COUNT is the real oracle
    let submit = ScriptedSubmit::new(vec![SubmitReply::Fatal]);
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

    // cycle 1 — fatal → terminal Rejected, cursor NOT advanced (final page)
    let first = run_relayer_cycle(&mut ctx).await.expect("cycle 1 runs");
    assert_matches!(
        first.entries()[0].disposition(),
        Disposition::Rejected(xreserve_deposit_relayer::error::RelayerError::FatalSubmit(
            _
        ))
    );
    assert_eq!(
        store
            .record(&nonce_of(&doomed))
            .expect("read")
            .expect("claimed")
            .status(),
        SubmissionStatus::Rejected,
        "a fatal submit must be recorded terminally, not as a re-claimable Failed"
    );
    assert!(store.read_cursor(CYCLE_DOMAIN).expect("read").is_none());

    // cycle 2 — the SAME page is re-polled; the doomed attestation is already decided
    let second = run_relayer_cycle(&mut ctx).await.expect("cycle 2 runs");
    assert_matches!(
        second.entries()[0].disposition(),
        Disposition::Duplicate {
            status: SubmissionStatus::Rejected
        }
    );

    assert_eq!(
        submit.call_count(),
        1,
        "a fatal (terminal) attestation was submitted a second time on the re-poll — the \
         fatal/transient split did not survive the cycle"
    );
    // …and it is NOT in the retry queue, so no retry driver will resurrect it either
    assert!(
        store
            .retryable(100)
            .expect("read the retry queue")
            .is_empty(),
        "a terminally-rejected attestation leaked into the retry queue"
    );
}

// THE LOOP EMITS ITS FAILURES
// ================================================================================================

/// `run_relayer_loop` emits a cycle-level failure event when a cycle errors — it does not swallow a
/// broken poll/discovery/store into an `Err(_)` arm that logs nothing. A cycle that failed silently
/// is a relayer that stopped making progress with no operator signal.
#[tokio::test]
async fn the_loop_emits_a_cycle_failure_event() {
    // the page fetch 400s every cycle → run_relayer_cycle returns Err each iteration
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

    // run exactly one iteration: stop on the second shutdown check
    let mut checks = 0u32;
    run_relayer_loop(&mut ctx, || {
        let stop = checks >= 1;
        checks += 1;
        stop
    })
    .await;

    let cycle_failures = sink
        .events()
        .into_iter()
        .filter(|e| matches!(e, RelayerEvent::Cycle { outcome, .. } if *outcome == "failed"))
        .count();
    assert!(
        cycle_failures >= 1,
        "the loop ran a failing cycle and emitted no cycle-failure event — the failure was swallowed"
    );
}

// HELPERS
// ================================================================================================

fn test_vector() -> AttestationVector {
    fixtures::test_vector()
}

/// A DIFFERENT deposit (distinct nonce), still structurally valid — the canonical payload with its
/// nonce perturbed. Located by searching the payload for the nonce the decoder reports, so no
/// layout offset the shared encoding crate owns is restated here.
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

/// The `DepositIntent.nonce` a vector's payload carries — read through the relayer's own decoder.
fn nonce_of(vector: &AttestationVector) -> [u8; 32] {
    *DepositIntent::try_from(vector.payload())
        .expect("the fixture payload is a valid DepositIntent")
        .header()
        .nonce()
        .as_bytes()
}
