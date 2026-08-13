//! **The assembled loop's observability, tested behaviourally.**
//!
//! A wiring test that only grepped `main.rs` for substrings would pass even if two DIFFERENT real
//! sinks were supplied, and would never check that metrics are surfaced — nor that the cumulative
//! counters/retries/histogram are, nor that a cycle's duration is recorded on more than the
//! success path.
//!
//! This suite assembles the relayer the way the binary does — ONE real `WriteEventSink` (over a
//! buffer, so the test reads exactly what an operator would) installed into BOTH the Circle client
//! and the `RelayerCtx` — runs the real loop, and asserts on the bytes: per-attestation events, the
//! cycle event, and a cumulative METRICS snapshot all land in the one buffer, and a Circle-level
//! retry event lands there too (proving the client and the context share the sink). Duration is
//! asserted on the failure path directly.

mod cycle_support;
mod fixtures;
mod mint_support;
mod mock_circle;

use std::sync::{Arc, Mutex};

use xreserve_deposit_relayer::cycle::{run_relayer_cycle, run_relayer_loop, RelayerCtx};
use xreserve_deposit_relayer::observability::WriteEventSink;

use cycle_support::{
    cycle_client, cycle_client_with, cycle_config, cycle_config_with, cycle_identities,
    cycle_store, tx_id, ScriptedSubmit, SubmitReply, CYCLE_DOMAIN,
};
use fixtures::{canonical_payload, PartnerAttester};
use mint_support::note_rng;
use mock_circle::{
    attestation_page, batch_href, link_header, MockCircle, RecordingSink, Reply, Script,
};

/// A shared `io::Write` a test reads back.
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8")
    }
}

impl std::io::Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// **The one-sink, real-loop test.** One `WriteEventSink` into both the client and the context; run
/// the loop for one cycle over a page that first 404s (a client retry event) then serves one
/// attestation that submits. The buffer must carry all of: the client's `pending` retry event, the
/// per-attestation terminal event, the cycle-completed event, and a cumulative metrics snapshot.
#[tokio::test]
async fn the_assembled_loop_surfaces_events_and_metrics_into_one_shared_sink() {
    let vector = fixtures::test_vector();
    let mock = MockCircle::start(Script::new().batch(vec![
        // a transient 404 first — the client logs a `pending` retry event…
        Reply::Status(404),
        // …then the page (final, no next cursor, so the loop stops after this one scan)
        Reply::ok(attestation_page(&[&vector])),
    ]));

    let config = cycle_config();
    let buffer = SharedBuffer::default();
    let sink: Arc<WriteEventSink<SharedBuffer>> = Arc::new(WriteEventSink::new(buffer.clone()));

    // the SAME sink into both — exactly the binary's wiring
    let client = cycle_client_with(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::new(vec![SubmitReply::Accepted(tx_id(0x91))]);
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

    // run exactly one iteration
    let mut checks = 0u32;
    run_relayer_loop(&mut ctx, || {
        let stop = checks >= 1;
        checks += 1;
        stop
    })
    .await;

    let text = buffer.text();
    // the CLIENT's retry event — proves the client shares this sink (not a separate NoopSink)
    assert!(
        text.contains("event=pending"),
        "the client's retry event is missing — the client is not wired to this sink.\n{text}"
    );
    // the CONTEXT's per-attestation terminal event — proves the ctx shares this sink
    assert!(
        text.contains("event=attestation") && text.contains("outcome=submitted"),
        "the per-attestation terminal event is missing from the shared sink.\n{text}"
    );
    // the loop's cycle event
    assert!(
        text.contains("event=cycle") && text.contains("outcome=completed"),
        "the cycle-completed event is missing.\n{text}"
    );
    // the CUMULATIVE metrics snapshot — the surfaced counters, not just a per-cycle disposition line
    assert!(
        text.contains("event=metrics"),
        "no metrics snapshot was surfaced by the loop.\n{text}"
    );
    assert!(
        text.contains("fetched=1") && text.contains("submitted=1"),
        "the metrics snapshot does not carry the cumulative counters.\n{text}"
    );
    // the DURATION HISTOGRAM buckets, not just the count/sum: the +Inf equals the one cycle run, and
    // the per-bound series is present so a dashboard can read the latency distribution
    assert!(
        text.contains("cycle_ms_le_inf=1"),
        "the metrics line does not surface the histogram +Inf bucket for the one cycle.\n{text}"
    );
    assert!(
        text.contains("cycle_ms_le_30000="),
        "the metrics line does not surface the per-bound histogram series.\n{text}"
    );
}

/// The metrics snapshot is CUMULATIVE across cycles, and carries the submit-retry count and the
/// cycle-duration sample count — not just a per-cycle disposition summary.
#[tokio::test]
async fn the_metrics_snapshot_accumulates_across_cycles() {
    let first = fixtures::test_vector();
    // a DIFFERENT deposit (distinct nonce) — the two canonical DI vectors share a nonce, so reusing
    // one would dedup the second mint and the cumulative count would be wrong
    let second = PartnerAttester::new().attest(&with_distinct_nonce(1));

    let mock = MockCircle::start(Script::new().batch(vec![
        Reply::ok_linked(
            attestation_page(&[&first]),
            link_header(&[(
                "next",
                &batch_href(CYCLE_DOMAIN, 10, Some(("pageAfter", "p2"))),
            )]),
        ),
        Reply::ok(attestation_page(&[&second])),
    ]));

    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    // one transient submit on the first attestation, so submit_retries is non-zero
    let submit = ScriptedSubmit::new(vec![
        SubmitReply::Transient,
        SubmitReply::Accepted(tx_id(0x01)),
        SubmitReply::Accepted(tx_id(0x02)),
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

    run_relayer_cycle(&mut ctx).await.expect("cycle 1");
    run_relayer_cycle(&mut ctx).await.expect("cycle 2");

    let snap = ctx.metrics().snapshot();
    assert_eq!(snap.attestations_fetched, 2, "both attestations counted");
    assert_eq!(snap.mint_notes_submitted, 2);
    assert!(
        snap.submit_retries >= 1,
        "the transient retry was not counted"
    );
    assert_eq!(
        snap.cycle_duration_samples, 2,
        "each cycle must record one duration sample"
    );
}

/// A FAILED cycle still records its duration — a loop that returned early on error, before the
/// duration was observed, would leave a relayer that only ever failed showing an empty latency
/// histogram.
#[tokio::test]
async fn a_failed_cycle_still_records_its_duration() {
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

    run_relayer_cycle(&mut ctx)
        .await
        .expect_err("a 400 fails the cycle");

    assert_eq!(
        ctx.metrics().snapshot().cycle_duration_samples,
        1,
        "a failed cycle recorded no duration — the latency histogram would be blind to failures"
    );
}

/// The loop emits a metrics snapshot even when the cycle FAILS — an operator watching throughput
/// must still see the counters (and the failure) when nothing is being minted.
#[tokio::test]
async fn the_loop_surfaces_metrics_on_a_failed_cycle_too() {
    let mock = MockCircle::start(Script::new().batch(vec![Reply::Status(500)]));
    let config = cycle_config_with(|c| c["max_retry_attempts"] = serde_json::json!(1));
    let buffer = SharedBuffer::default();
    let sink: Arc<WriteEventSink<SharedBuffer>> = Arc::new(WriteEventSink::new(buffer.clone()));
    let client = cycle_client_with(&mock, &config, sink.clone());
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

    let mut checks = 0u32;
    run_relayer_loop(&mut ctx, || {
        let stop = checks >= 1;
        checks += 1;
        stop
    })
    .await;

    let text = buffer.text();
    assert!(
        text.contains("event=cycle") && text.contains("outcome=failed"),
        "a failed cycle emitted no cycle-failed event.\n{text}"
    );
    assert!(
        text.contains("event=metrics"),
        "no metrics snapshot surfaced on the failed cycle.\n{text}"
    );
    // the duration histogram is surfaced even when the cycle FAILED — the +Inf counts the failed cycle
    assert!(
        text.contains("cycle_ms_le_inf=1"),
        "the failed cycle's duration is not in the surfaced histogram.\n{text}"
    );
}

/// The canonical payload with its nonce perturbed — a distinct, still-valid deposit.
fn with_distinct_nonce(tweak: u8) -> Vec<u8> {
    let payload = canonical_payload(fixtures::TEST_VECTOR_PAYLOAD_ID);
    let nonce = *xreserve_deposit_relayer::validate::decode_and_validate_deposit_intent(&payload)
        .expect("valid DI")
        .header()
        .nonce()
        .as_bytes();
    let offset = payload
        .windows(nonce.len())
        .position(|window| window == nonce)
        .expect("the nonce appears in its own payload");
    let mut tweaked = payload;
    tweaked[offset] ^= tweak;
    tweaked
}
