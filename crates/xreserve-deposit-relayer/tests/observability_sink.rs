//! The **real** event sink — the one the binary installs — and the proof it emits rather than drops.
//!
//! Round 1 shipped the observability SEAM (the `EventSink` trait) and a `RecordingSink` for tests,
//! but the binary installed `NoopSink`, so the service that is supposed to never silently drop an
//! attestation emitted nothing at all. `RecordingSink` proves only that an injected sink is called;
//! it says nothing about the production sink actually rendering an event to an operator.
//!
//! `WriteEventSink<W>` is that production sink, parameterized over its `io::Write` so a test can
//! point it at a buffer and read exactly what an operator would see on stderr. Every one of these
//! tests writes real bytes and asserts on them — none injects a recorder and trusts it.

use std::sync::{Arc, Mutex};

use xreserve_deposit_relayer::observability::{EventSink, RelayerEvent, WriteEventSink};

/// A shared `io::Write` a test can read back — an `Arc<Mutex<Vec<u8>>>` the sink writes into.
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).expect("the sink writes utf-8")
    }

    fn lines(&self) -> Vec<String> {
        self.contents()
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>()
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

/// Every variant of `RelayerEvent` the service emits — one of each, so the test covers the whole
/// vocabulary rather than the one shape a happy path produces.
fn one_of_each_event() -> Vec<RelayerEvent> {
    vec![
        RelayerEvent::Pending {
            endpoint: "GET /v1/remote-domains/1/attestations".to_string(),
            status: Some(404),
            attempt: 2,
            reason: "not published yet".to_string(),
        },
        RelayerEvent::Alert {
            endpoint: "mint 0xabc".to_string(),
            reason: "structural reject".to_string(),
        },
        RelayerEvent::Rejected {
            endpoint: "GET /v1/attestations".to_string(),
            reason: "http 400".to_string(),
        },
        RelayerEvent::Attestation {
            message_hash: "0xdeadbeef".to_string(),
            outcome: "submitted",
            reason: "submitted to the miden node in tx 0x11".to_string(),
        },
        RelayerEvent::Cycle {
            outcome: "failed",
            detail: "the config file could not be read".to_string(),
        },
        RelayerEvent::Metrics {
            detail: "fetched=3 submitted=2 rejected=1".to_string(),
        },
    ]
}

/// The sink renders EVERY event kind to a non-empty line — and one line per event, so nothing is
/// coalesced or dropped. A sink that silently ignored a variant it did not recognize would be the
/// §8.4 silent drop, moved from the cycle into the logger.
#[test]
fn the_write_sink_renders_every_event_kind_to_its_own_nonempty_line() {
    let buffer = SharedBuffer::default();
    let sink = WriteEventSink::new(buffer.clone());

    let events = one_of_each_event();
    for event in &events {
        sink.emit(event.clone());
    }

    let lines = buffer.lines();
    assert_eq!(
        lines.len(),
        events.len(),
        "the sink emitted {} lines for {} events — a variant was dropped or coalesced",
        lines.len(),
        events.len()
    );
    for (event, line) in events.iter().zip(&lines) {
        assert!(
            !line.trim().is_empty(),
            "{event:?} rendered an empty line — an event nobody can read is an event dropped"
        );
    }
}

/// The rendering carries the fields an operator acts on: the outcome/status and the reason. A line
/// that logged "something happened" without WHICH attestation or WHY would satisfy a line-count
/// check while still being useless — so this asserts the content, not just the cardinality.
#[test]
fn the_rendered_lines_carry_the_identifying_fields() {
    let buffer = SharedBuffer::default();
    let sink = WriteEventSink::new(buffer.clone());

    for event in one_of_each_event() {
        sink.emit(event);
    }
    let text = buffer.contents();

    // the per-attestation terminal event: its messageHash and its outcome slug
    assert!(
        text.contains("0xdeadbeef"),
        "the attestation's messageHash is not in the log"
    );
    assert!(
        text.contains("submitted"),
        "the attestation's outcome is not in the log"
    );
    // the transient retry: the endpoint, the status, the attempt
    assert!(text.contains("404"), "a retryable status is not in the log");
    assert!(
        text.contains("attempt"),
        "the attempt counter is not in the log"
    );
    // the cycle-level failure the loop emits
    assert!(
        text.contains("failed"),
        "the cycle outcome is not in the log"
    );
    assert!(
        text.contains("config file could not be read"),
        "the cycle failure reason is not in the log"
    );
}

/// The sink does not drop under volume: N events in, N lines out. This is the sink-level restatement
/// of the no-silent-drops obligation — the cycle produces one event per attestation, and the sink
/// must not be where they disappear.
#[test]
fn the_write_sink_drops_nothing_under_volume() {
    let buffer = SharedBuffer::default();
    let sink = WriteEventSink::new(buffer.clone());

    for i in 0..500u32 {
        sink.emit(RelayerEvent::Attestation {
            message_hash: format!("0x{i:064x}"),
            outcome: "rejected",
            reason: "structural".to_string(),
        });
    }

    assert_eq!(
        buffer.lines().len(),
        500,
        "the sink lost events under volume"
    );
}

/// `WriteEventSink` is a real `EventSink` — it can be installed where the binary installs it (behind
/// `Arc<dyn EventSink>`), which is the whole point: the production wiring and the tested type are the
/// same type.
#[test]
fn the_write_sink_is_installable_as_a_dyn_event_sink() {
    let buffer = SharedBuffer::default();
    let sink: Arc<dyn EventSink> = Arc::new(WriteEventSink::new(buffer.clone()));
    sink.emit(RelayerEvent::Rejected {
        endpoint: "e".to_string(),
        reason: "r".to_string(),
    });
    assert_eq!(buffer.lines().len(), 1);
}
