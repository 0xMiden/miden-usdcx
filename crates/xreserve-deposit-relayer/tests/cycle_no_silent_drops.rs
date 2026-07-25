//! **No fetched attestation is ever silently dropped** (§8.4) — the obligation this slice exists to
//! keep, tested as an ABSENCE.
//!
//! A silent drop is not an error the relayer returns; it is an attestation that leaves no trace. So
//! testing it needs a different shape from the rest of the suite: not "did the right thing happen"
//! but "can the wrong thing be expressed at all".
//!
//! Three layers, weakest to strongest:
//!
//! 1. **Behavioural** — drive a page holding one attestation of EVERY disposition the failure catalog
//!    (§8.4) names, and assert the report accounts for every one of them, each with a reason and each
//!    with an emitted event. A drop would show as `fetched > entries`.
//! 2. **Structural (types)** — the per-attestation step returns a `CycleEntry`, not a
//!    `Result<CycleEntry, _>`. There is no `?` that can skip a recording, because there is no error
//!    to propagate: every failure is a DISPOSITION. And the reason is derived from a typed error, so
//!    an empty one is not constructible.
//! 3. **Structural (source)** — the loop consumes the page BY VALUE and pushes one entry per element.
//!    A `filter`/`continue`/`flat_map` on that path would be the edit that reintroduces a drop, so it
//!    is pinned mechanically, the way `listener_structural_absence.rs` (W9) pins the raw signer.
//!
//! The third layer is here because the first two are properties of code that a later edit can quietly
//! change. A decision the compiler cannot hold is pinned in a test, or it is not held.

mod cycle_support;
mod fixtures;
mod mint_support;
mod mock_circle;

use std::collections::BTreeSet;

use xreserve_deposit_relayer::cycle::{run_relayer_cycle, Disposition, RelayerCtx};
use xreserve_deposit_relayer::observability::RelayerEvent;

use cycle_support::{
    cycle_client, cycle_config, cycle_identities, cycle_store, tx_id, ScriptedSubmit, SubmitReply,
};
use fixtures::{canonical_payload, AttestationVector, PartnerAttester, TEST_VECTOR_PAYLOAD_ID};
use mint_support::note_rng;
use mock_circle::{attestation_page, MockCircle, RecordingSink, Reply, Script};

// LAYER 1 — BEHAVIOURAL: a page of every disposition, and not one of them lost
// ================================================================================================

/// A page carrying one attestation for EVERY §8.4 row the cycle can reach, mixed together — the
/// shape a real window produces and the shape a hand-written `continue` gets wrong.
///
/// Every one is fetched; every one is reported, with a reason; every one raises exactly one
/// observability event. Nothing is inferred from the happy path.
#[tokio::test]
async fn every_fetched_attestation_is_reported_with_a_reason() {
    let cases = mixed_page();
    let vectors: Vec<&AttestationVector> = cases.iter().map(|(_, v)| v).collect();

    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&vectors))]));
    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    // one reply per attestation, in page order: the ones that reach the port get their scripted
    // answer; the ones that do not, never consume theirs
    let submit = ScriptedSubmit::new(vec![
        SubmitReply::Accepted(tx_id(0x51)), // the honest one
        SubmitReply::AlreadyMinted,         // the one the chain minted first
        SubmitReply::Fatal,                 // the one the node permanently refused
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

    let report = run_relayer_cycle(&mut ctx).await.expect("the cycle runs");

    // THE assertion: as many entries as attestations. A drop is exactly the gap between these.
    assert_eq!(
        report.entries().len(),
        cases.len(),
        "{} attestations were fetched and {} were accounted for — the difference is the silent drop \
         this slice exists to prevent",
        cases.len(),
        report.entries().len()
    );
    assert_eq!(report.fetched(), cases.len());

    for (index, ((label, vector), entry)) in cases.iter().zip(report.entries()).enumerate() {
        assert_eq!(
            entry.message_hash(),
            &vector.message_hash(),
            "entry {index} ({label}) reports another attestation's messageHash — the report is not \
             in page order, so an operator cannot tell which deposit was dropped"
        );
        assert!(
            !entry.reason().trim().is_empty(),
            "entry {index} ({label}) carries no reason — a disposition without one IS the silent \
             drop, wearing a report's clothes"
        );
        assert!(
            !entry.outcome().is_empty(),
            "entry {index} ({label}) carries no outcome slug to alert on"
        );
    }

    // every attestation raised exactly one terminal event, and each names its own messageHash
    let emitted: Vec<(String, String)> = sink
        .events()
        .into_iter()
        .filter_map(|event| match event {
            RelayerEvent::Attestation {
                message_hash,
                outcome,
                ..
            } => Some((message_hash, outcome.to_string())),
            _ => None,
        })
        .collect();
    assert_eq!(
        emitted.len(),
        cases.len(),
        "one terminal event per fetched attestation, no more and no fewer"
    );
    let named: BTreeSet<&str> = emitted.iter().map(|(hash, _)| hash.as_str()).collect();
    assert_eq!(
        named.len(),
        cases.len(),
        "two events named the same attestation — one deposit's fate is unreported"
    );
    for (_, vector) in &cases {
        let hex = format!("0x{}", hex::encode(vector.message_hash()));
        assert!(
            named.contains(hex.as_str()),
            "no event named {hex} — that attestation's fate is unlogged"
        );
    }
}

/// The dispositions really are DIFFERENT — the test above would pass vacuously if every attestation
/// were reported the same way (e.g. all rejected). This pins that the mixed page produced the mixed
/// outcomes its construction claims.
#[tokio::test]
async fn the_mixed_page_actually_produces_distinct_dispositions() {
    let cases = mixed_page();
    let vectors: Vec<&AttestationVector> = cases.iter().map(|(_, v)| v).collect();
    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&vectors))]));
    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::new(vec![
        SubmitReply::Accepted(tx_id(0x52)),
        SubmitReply::AlreadyMinted,
        SubmitReply::Fatal,
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
    let report = run_relayer_cycle(&mut ctx).await.expect("the cycle runs");

    let outcomes: Vec<&str> = report.entries().iter().map(|e| e.outcome()).collect();
    assert_eq!(
        outcomes,
        vec!["submitted", "already-minted", "rejected", "rejected"],
        "the mixed page did not produce the mix it was built to produce, so the no-drop assertion \
         above is not exercising the failure paths it claims to"
    );
}

/// The report is a TOTAL account: the terminal counters partition the fetched attestations. A drop
/// would break the equality — and so would a double-count.
#[tokio::test]
async fn the_dispositions_partition_the_fetched_attestations() {
    let cases = mixed_page();
    let vectors: Vec<&AttestationVector> = cases.iter().map(|(_, v)| v).collect();
    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&vectors))]));
    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::new(vec![
        SubmitReply::Accepted(tx_id(0x53)),
        SubmitReply::AlreadyMinted,
        SubmitReply::Fatal,
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
    let report = run_relayer_cycle(&mut ctx).await.expect("the cycle runs");

    let counted = report.submitted()
        + report.rejected()
        + report.duplicates()
        + report.already_minted()
        + report.deferred()
        + report.reconciliation_required();
    assert_eq!(
        counted,
        report.fetched(),
        "the terminal counters do not partition the fetched attestations"
    );
}

// LAYER 2 — STRUCTURAL (types): a reason cannot be empty, and a disposition cannot be absent
// ================================================================================================

/// Every [`Disposition`] renders a non-empty reason. The reason is DERIVED — from the typed error for
/// the refusing arms, from the outcome for the settling ones — so there is no constructor that can
/// produce an entry with nothing to say.
#[test]
fn no_disposition_can_render_an_empty_reason() {
    let dispositions = [
        Disposition::Submitted { tx_id: tx_id(0x01) },
        Disposition::AlreadyMinted,
        Disposition::Duplicate {
            status: xreserve_deposit_relayer::idempotency::SubmissionStatus::Submitted,
        },
        Disposition::Rejected(
            xreserve_deposit_relayer::error::RelayerError::BadAttestationLength { actual: 3 },
        ),
        Disposition::Deferred(
            xreserve_deposit_relayer::error::RelayerError::RequestTimeout { after_ms: 1 },
        ),
        Disposition::ReconciliationRequired(
            xreserve_deposit_relayer::error::RelayerError::NonceMessageHashMismatch {
                nonce_key: [1; 32],
                stored: [2; 32],
                observed: [3; 32],
            },
        ),
    ];

    for disposition in dispositions {
        assert!(
            !disposition.reason().trim().is_empty(),
            "{disposition:?} renders no reason"
        );
        assert!(
            !disposition.outcome().is_empty(),
            "{disposition:?} renders no outcome slug"
        );
    }
}

/// The outcome slugs are STABLE and distinct — an operator's alert matches on them, so a duplicate
/// slug would silently merge two different fates.
#[test]
fn the_outcome_slugs_are_distinct() {
    let slugs = [
        Disposition::Submitted { tx_id: tx_id(0x01) }.outcome(),
        Disposition::AlreadyMinted.outcome(),
        Disposition::Duplicate {
            status: xreserve_deposit_relayer::idempotency::SubmissionStatus::Submitted,
        }
        .outcome(),
        Disposition::Rejected(
            xreserve_deposit_relayer::error::RelayerError::BadAttestationLength { actual: 3 },
        )
        .outcome(),
        Disposition::Deferred(
            xreserve_deposit_relayer::error::RelayerError::RequestTimeout { after_ms: 1 },
        )
        .outcome(),
        Disposition::ReconciliationRequired(
            xreserve_deposit_relayer::error::RelayerError::NonceMessageHashMismatch {
                nonce_key: [1; 32],
                stored: [2; 32],
                observed: [3; 32],
            },
        )
        .outcome(),
    ];
    let distinct: BTreeSet<&str> = slugs.iter().copied().collect();
    assert_eq!(distinct.len(), slugs.len(), "two dispositions share a slug");
}

// LAYER 3 — STRUCTURAL (source): the shapes that would reintroduce a drop
// ================================================================================================

/// **The page is consumed by value, one entry pushed per element.**
///
/// `Vec<ValidatedAttestation> → Vec<CycleEntry>` through a `for … in page` that pushes unconditionally
/// is a TOTAL map: it has no arity to lose an element through. A `filter`, a `filter_map`, a
/// `flat_map` or a bare `continue` on that path is precisely the edit that reintroduces a silent
/// drop, and each is a visible one — so it is pinned here rather than trusted.
#[test]
fn the_cycle_cannot_filter_the_page() {
    let source = cycle_source();

    for dropper in ["filter(", "filter_map(", "flat_map(", "retain(", "continue"] {
        assert!(
            !source.contains(dropper),
            "the orchestration uses `{dropper}` — every element of a fetched page must produce \
             exactly one reported entry, and each of these can lose one"
        );
    }

    // the positive control: the total loop this sweep is protecting IS there, so the sweep is not
    // passing because the orchestration stopped iterating the page at all
    assert!(
        source.contains("entries.push("),
        "the orchestration must push one entry per fetched attestation"
    );
}

/// **The per-attestation step cannot return an error.** `classify_one` returns a `CycleEntry`, full
/// stop — so there is no `?` in the loop, so there is no path that leaves a fetched attestation
/// without a disposition. This is the type-level half of layer 3.
#[test]
fn the_per_attestation_step_returns_a_disposition_not_a_result() {
    let source = cycle_source();
    assert!(
        source.contains("-> CycleEntry"),
        "the per-attestation step must return a `CycleEntry` — a `Result` there would let a `?` in \
         the loop skip an attestation's recording"
    );
    assert!(
        !source.contains("-> Result<CycleEntry"),
        "the per-attestation step returns a Result: a `?` on it drops the attestation"
    );
}

/// **The retry driver rotates via the ATOMIC CONDITIONAL touch, never a bare re-stamp.** A re-fetch
/// failure re-stamps its row through `touch_failed_timestamp`, which updates the timestamp ONLY while
/// the row is still `Failed`. A single-threaded test cannot behaviourally distinguish that from an
/// unconditional `record_failure` (both re-stamp a `Failed` row identically) — the difference is only
/// visible under the concurrent race `idempotency_touch.rs` proves at the store level — so the drive's
/// USE of the conditional primitive is pinned here mechanically, the way `listener_structural_absence`
/// pins the gated signer. Removing it (reverting to `record_failure`) would let this driver clobber a
/// concurrent driver's live claim.
#[test]
fn the_retry_driver_uses_the_atomic_conditional_touch() {
    let source = cycle_source();
    assert!(
        source.contains("touch_failed_timestamp("),
        "the retry driver must re-stamp a re-attempted row through the atomic conditional \
         `touch_failed_timestamp` — an unconditional re-stamp can overwrite a concurrent driver's live \
         claim (`idempotency_touch.rs`)"
    );
}

/// **The relayer never fakes a Miden submit.** The submit leg is a PORT with no production adapter —
/// R6 implements it once a `miden-client` for v0.16 exists — and the crate must not grow a stand-in
/// in the meantime: a simulated commit is a mint the operator believes happened.
#[test]
fn the_crate_has_no_miden_client_and_no_simulated_submit() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("the manifest reads");
    let declarations: Vec<&str> = manifest
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter(|line| line.starts_with("miden-client"))
        .collect();
    assert!(
        declarations.is_empty(),
        "`miden-client` is declared ({declarations:?}) — the submit port is R6's, and it is blocked \
         on a v0.16 release that does not exist"
    );

    let source = cycle_source();
    for fake in ["todo!(", "unimplemented!(", "simulate", "fake_submit"] {
        assert!(
            !source.contains(fake),
            "the orchestration contains `{fake}` — the submit seam is left open for R6, never \
             stubbed as real"
        );
    }
}

/// The production submit port is UNAVAILABLE, and says so — it does not silently succeed.
///
/// This is the seam, stated as a value a caller must handle. `main` fails at startup on it rather
/// than starting a relayer that would never mint, and no test may substitute for R6's real-node leg.
#[test]
fn the_production_submit_port_refuses_rather_than_pretending() {
    let error = xreserve_deposit_relayer::cycle::production_submit_port()
        .expect_err("there is no production submit adapter until R6");
    assert_matches::assert_matches!(
        error,
        xreserve_deposit_relayer::error::RelayerError::MintSubmitPortUnavailable
    );
    assert!(
        !error.is_retryable(),
        "an absent adapter does not appear on a retry"
    );
}

// HELPERS
// ================================================================================================

/// The orchestration's source, comments stripped — so a sweep reads DECLARATIONS, not prose about
/// them (this file's own doc comments name `filter`, and must not trip the sweep).
fn cycle_source() -> String {
    let mut source = String::new();
    for name in ["mod.rs", "submit.rs"] {
        source.push_str(&strip_comments(
            &std::fs::read_to_string(format!("{}/src/cycle/{name}", env!("CARGO_MANIFEST_DIR")))
                .unwrap_or_else(|error| panic!("src/cycle/{name} reads: {error}")),
        ));
        source.push('\n');
    }
    source
}

/// Removes `//`-comments and `/* */` blocks — the sweeps above assert on code, not on the prose that
/// explains it.
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

/// The comment stripper is itself tested — a sweep that silently stopped reading the file would pass
/// every absence assertion above.
#[test]
fn the_source_sweep_reads_code_and_not_prose() {
    let stripped = strip_comments("let a = 1; // filter( here\n/* filter( */ let b = \"filter(\";");
    assert!(!stripped.contains("// filter("));
    assert!(stripped.contains("let a = 1;"));
    assert!(
        stripped.contains("\"filter(\""),
        "a string literal is code, not a comment"
    );

    let source = cycle_source();
    assert!(
        source.contains("pub async fn run_relayer_cycle"),
        "the sweep must be reading the orchestration"
    );
}

/// A page holding one attestation for every disposition the cycle can reach without a second cycle:
/// the honest one, the one the chain minted first, the one the node fatally refused, and the one
/// unit-04's codec refuses. Each is a REAL, envelope-valid attestation — Circle signed all four —
/// because the drop this file is about happens AFTER the envelope, not before it.
fn mixed_page() -> Vec<(&'static str, AttestationVector)> {
    let attester = PartnerAttester::new();

    // three structurally VALID but distinct DepositIntents — distinct nonces, so none dedups the
    // others. The nonce sits at DC-1 offset 208 (read via the decoder below, never restated).
    let honest = attester.attest(&canonical_payload(TEST_VECTOR_PAYLOAD_ID));
    let already_minted = attester.attest(&with_nonce_tweak(1));
    let fatal = attester.attest(&with_nonce_tweak(2));

    // …and one Circle signed that unit-04's codec refuses: a wrong `version`.
    let mut bad_version = canonical_payload(TEST_VECTOR_PAYLOAD_ID);
    bad_version[4] ^= 0xFF;
    let structural = attester.attest(&bad_version);

    vec![
        ("honest → submitted", honest),
        ("nonce trap → already-minted", already_minted),
        ("fatal submit → rejected", fatal),
        ("bad version → rejected", structural),
    ]
}

/// The canonical payload with its `nonce` perturbed — a distinct deposit, still structurally valid.
/// The nonce's offset comes from the decoder's own view of the canonical payload, not from a literal
/// this crate restates (DC-1 is unit-04's).
fn with_nonce_tweak(tweak: u8) -> Vec<u8> {
    let payload = canonical_payload(TEST_VECTOR_PAYLOAD_ID);
    let nonce = *xreserve_deposit_relayer::validate::decode_and_validate_deposit_intent(&payload)
        .expect("the canonical payload decodes")
        .nonce();
    let offset = find_subslice(&payload, &nonce).expect("the nonce appears in its own payload");

    let mut tweaked = payload;
    tweaked[offset] ^= tweak;
    tweaked
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
