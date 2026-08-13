//! **The dedup: a replayed attestation produces no second mint** — the liveness side of the
//! no-double-mint guarantee, across a re-poll and across a restart. Split out of
//! `cycle_pipeline.rs` to keep each suite within its file-size ceiling; the two share the
//! `cycle_support` harness. The authoritative duplicate defence is the on-chain `usedNonces`
//! assert-then-set (the on-chain replay guard); this is the liveness backstop in front of it. Real
//! everywhere except the Miden submit PORT (NON-GATING; the mock boundary).

mod cycle_support;
mod fixtures;
mod mint_support;
mod mock_circle;

use assert_matches::assert_matches;

use xreserve_deposit_relayer::cycle::{run_relayer_cycle, Disposition, RelayerCtx};
use xreserve_deposit_relayer::idempotency::SubmissionStatus;

use cycle_support::{
    cycle_client, cycle_config, cycle_identities, cycle_store, tx_id, ScriptedSubmit, SubmitReply,
    CYCLE_DOMAIN,
};
use fixtures::AttestationVector;
use mint_support::note_rng;
use mock_circle::{
    attestation_page, batch_href, link_header, MockCircle, RecordingSink, Reply, Script,
};
use xusdc_encoding::xreserve::encoding::DepositIntent;

// ================================================================================================

/// this suite · GATING (orchestration) · the no-double-mint guarantee, liveness side.
///
/// The SAME attestation is served twice — the shape a re-poll of an overlapping window, a restarted
/// relayer, or a Circle page boundary actually produces. It is minted ONCE.
///
/// The oracle is the PORT's call count, not the report: "no second mint" means the submit leg was
/// never reached a second time, and a test that only read the disposition could not tell a note
/// that was never built from one that was built and submitted twice.
#[tokio::test]
async fn duplicate_attestation_no_double_submit() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().batch(vec![
        // the same attestation, on two consecutive pages
        Reply::ok_linked(
            attestation_page(&[&vector]),
            link_header(&[(
                "next",
                &batch_href(CYCLE_DOMAIN, 10, Some(("pageAfter", "cursor-page-2"))),
            )]),
        ),
        Reply::ok(attestation_page(&[&vector])),
    ]));

    let config = cycle_config();
    let sink = RecordingSink::new();
    let client = cycle_client(&mock, &config, sink.clone());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = cycle_store(&dir);
    let submit = ScriptedSubmit::new(vec![SubmitReply::Accepted(tx_id(0x22))]);
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

    let first = run_relayer_cycle(&mut ctx).await.expect("cycle 1 runs");
    let second = run_relayer_cycle(&mut ctx).await.expect("cycle 2 runs");

    assert_matches!(
        first.entries()[0].disposition(),
        Disposition::Submitted { .. }
    );

    // THE assertion: the replay was NOT minted again.
    assert_eq!(
        submit.call_count(),
        1,
        "the replayed attestation reached the submit port a second time — the idempotency gate did \
         not hold"
    );

    // …and it was not dropped either: it is reported, with a reason, as the duplicate it is.
    assert_eq!(second.fetched(), 1);
    assert_matches!(
        second.entries()[0].disposition(),
        Disposition::Duplicate { status } if *status == SubmissionStatus::Submitted
    );
    assert!(!second.entries()[0].reason().is_empty());
    assert_eq!(second.entries()[0].outcome(), "duplicate");

    // the store still holds exactly the first mint's transaction id — the replay overwrote nothing
    let record = store
        .record(&nonce_of(&vector))
        .expect("the store reads")
        .expect("the nonce is claimed");
    assert_eq!(record.submitted_tx_id(), Some(&tx_id(0x22)));
}

/// The dedup survives a RESTART: a second cycle over a second, independently-opened store on the
/// same file still refuses the second mint. This is the property a process-lifetime cache could not
/// have, and the reason the seam is on disk.
#[tokio::test]
async fn the_dedup_survives_a_restart() {
    let vector = test_vector();
    let dir = tempfile::tempdir().expect("tempdir");
    let config = cycle_config();
    let submit = ScriptedSubmit::new(vec![SubmitReply::Accepted(tx_id(0x33))]);

    for _pass in 0..2 {
        let mock =
            MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
        let sink = RecordingSink::new();
        let client = cycle_client(&mock, &config, sink.clone());
        // a NEW store handle on the SAME file — the restart
        let store = cycle_store(&dir);
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
    }

    assert_eq!(
        submit.call_count(),
        1,
        "a restarted relayer re-minted an attestation its store had already recorded"
    );
}

// THE FAILURE CATALOG, WIRED THROUGH THE CYCLE

// HELPERS
// ================================================================================================

/// The standard vector: the partner key over the canonical `mi-pos-hookdata` DepositIntent payload.
fn test_vector() -> AttestationVector {
    fixtures::test_vector()
}

/// The `DepositIntent.nonce` a vector's payload carries — read through the relayer's OWN decoder.
fn nonce_of(vector: &AttestationVector) -> [u8; 32] {
    *DepositIntent::try_from(vector.payload())
        .expect("the fixture payload is a valid DepositIntent")
        .header()
        .nonce()
        .as_bytes()
}
