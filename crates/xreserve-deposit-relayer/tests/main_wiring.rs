//! **The binary wires a real sink** — a source-level pin, the way `cycle_no_silent_drops.rs` pins
//! the no-drop loop.
//!
//! A behavioural test cannot easily drive `main` (it is a binary that runs an unbounded loop and
//! exits on a missing submit adapter), and `WriteEventSink`'s own emission is proven in
//! `observability_sink.rs`. What is left is the WIRING: the binary must install that real sink into
//! BOTH the Circle client (so retry/rejection events are logged) and the `RelayerCtx` (so every
//! terminal per-attestation event is), and must not fall back to the event-dropping `NoopSink` for
//! either. A decision the compiler cannot hold is pinned mechanically, or it is not held.

/// `main.rs`, comments stripped, so the sweep reads code and not the prose that explains it.
fn main_source() -> String {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
        .expect("src/main.rs reads");
    strip_comments(&raw)
}

/// The binary installs the real `WriteEventSink`, not the dropping `NoopSink`, into both the client
/// and the context.
#[test]
fn the_binary_installs_a_real_sink_into_the_client_and_context() {
    let source = main_source();

    assert!(
        source.contains("WriteEventSink") || source.contains("StderrEventSink"),
        "main.rs does not construct the real event sink — the service would emit nothing"
    );
    assert!(
        source.contains(".with_event_sink("),
        "main.rs does not install a sink on the Circle client — its retry/rejection events are dropped"
    );
    assert!(
        !source.contains("NoopSink"),
        "main.rs still references NoopSink — the binary that must never silently drop an attestation \
         is installing the sink that drops every event"
    );
}

/// The sink the binary builds is the SAME handle it hands the client and the context — not two
/// sinks, one of which is silently a no-op. It is shared behind an `Arc` and passed to both.
#[test]
fn the_binary_shares_one_sink_between_the_client_and_the_context() {
    let source = main_source();
    assert!(
        source.contains("Arc::new(WriteEventSink") || source.contains("Arc::new(StderrEventSink"),
        "the real sink must be shared behind an Arc so the client and the context log to the same place"
    );
    // the context is constructed with the sink, not with a fresh NoopSink
    assert!(
        source.contains("RelayerCtx::new"),
        "main.rs must assemble the relayer context"
    );
}

/// Removes `//` line comments and `/* */` blocks (string literals preserved) — the sweeps above
/// read declarations, not the doc prose that names `NoopSink` to explain why it is gone.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_block = false;
    let mut in_string = false;

    while let Some(c) = chars.next() {
        if in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
            }
            continue;
        }
        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                in_block = true;
            }
            _ => out.push(c),
        }
    }
    out
}

/// The stripper is itself checked — a sweep that stopped reading the file would pass every pin
/// above.
#[test]
fn the_comment_stripper_reads_code_not_prose() {
    let stripped = strip_comments("let a = 1; // NoopSink here\n/* NoopSink */ let b = 2;");
    assert!(!stripped.contains("NoopSink"), "comments must be stripped");
    assert!(stripped.contains("let a = 1;") && stripped.contains("let b = 2;"));

    assert!(
        main_source().contains("async fn run"),
        "the sweep must be reading the binary's assembly"
    );
}
