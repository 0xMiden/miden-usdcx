//! The `miden-client`-backed discovery leg: the exact-tag `SyncNotes` scan and the `GetNotesById`
//! retrieval, mapped into the [`DiscoveredNote`] B3 validates.
//!
//! # What is under test, and why it is testable without a node
//!
//! The adapter is two RPCs and the translations between them. The RPCs need a node; the
//! translations do not, and they are where a fund-safety mistake would live — a prefix match
//! instead of an exact one, a private note read as public, the wrong felts pulled out of the note's
//! attachments, a script root or vault that does not come off the note the node actually returned,
//! or a scanned burn that the retrieval never answers for and nobody notices. So the scan filter,
//! the note mapping and the retrieval accounting are PURE functions over the client's own reply
//! types, and this file drives them directly with reply values built from the protocol's public
//! constructors.
//!
//! # Nothing the scan saw may vanish
//!
//! The reconciliation cases are the fund-safety half of this file. `SyncNotes` naming a note and
//! `GetNotesById` answering for it are two different events, and the gap between them is where a
//! real burn can be seen and then lost — silently, behind a range that looks complete. Those cases
//! drive omissions, duplicate answers, and the trap in between: a reply with the RIGHT NUMBER of
//! rows, one of which nobody asked for.
//!
//! # The oracle is the real burn note
//!
//! The happy-path case does not hand-assemble a plausible reply. It builds a REAL
//! [`XReserveBurnNote`] with the shared encoding crate's own factory — the same call the on-chain
//! note is created by — hands it to the mapping as the node would, and then runs the mapped record
//! through the REAL `validate_discovery`. That closes the write-side/read-side loop: if the note
//! factory and the adapter ever disagree about where the withdrawal payload lives, which script the
//! note is consumed by, or what it carries, this case fails.
//!
//! NON-GATING: no node runs here. The gating real-node leg is the validation harness's.

use assert_matches::assert_matches;

use miden_client::rpc::domain::note::{CommittedNote, FetchedNote};

use miden_protocol::note::{Note, NoteTag, NoteType, PartialNoteMetadata};

use withdrawal_listener_attester::config::ListenerConfig;
use withdrawal_listener_attester::error::DiscoveryReject;
use withdrawal_listener_attester::miden::discovery::{
    discovered_note, exact_tag_matches, reconcile_retrieval, DiscoveryReadError,
};
use withdrawal_listener_attester::validate::validate_discovery;
use xusdc_encoding::note::xreserve_burn::{XReserveBurnNote, FIXED_XUSDC_BURN_TAG};

// FIXTURES
// ================================================================================================

// the scan rows and retrieval replies every case here is built from — shared with
// `miden_discovery_wiring.rs`.
#[path = "miden_discovery_support/mod.rs"]
mod miden_discovery_support;

use miden_discovery_support::*;

// THE SCAN — EXACT TAG EQUALITY, NEVER A PREFIX
// ================================================================================================

/// The scan keeps only the notes whose tag is the configured one, on FULL 32-bit equality.
#[test]
fn the_scan_keeps_only_the_exact_tag() {
    let wanted = note_id(1);
    let notes = [
        committed(wanted, FIXED_XUSDC_BURN_TAG, NoteType::Public),
        committed(note_id(2), 0x0000_0001, NoteType::Public),
    ];

    assert_eq!(
        exact_tag_matches(notes.iter(), FIXED_XUSDC_BURN_TAG),
        vec![wanted]
    );
}

/// **The prefix trap.** `SyncNotes` matches tags exactly; the 16-bit prefix belongs to
/// `SyncNullifiers`. A note sharing the burn tag's high 16 bits is a DIFFERENT note, and an
/// implementation that compared `>> 16` would select it — so the case is driven with a tag whose
/// prefix matches and whose low bits do not.
#[test]
fn the_scan_refuses_a_prefix_only_match() {
    let prefix_only = FIXED_XUSDC_BURN_TAG & 0xFFFF_0000;
    assert_ne!(
        prefix_only, FIXED_XUSDC_BURN_TAG,
        "the fixture must actually differ in the low bits"
    );
    let notes = [committed(note_id(3), prefix_only, NoteType::Public)];

    assert!(
        exact_tag_matches(notes.iter(), FIXED_XUSDC_BURN_TAG).is_empty(),
        "a 16-bit prefix match is not a tag match"
    );
}

/// A scan that matched nothing yields nothing — no retrieval is attempted for a note the scan did
/// not select.
#[test]
fn an_empty_scan_yields_no_ids() {
    let notes: Vec<CommittedNote> = Vec::new();
    assert!(exact_tag_matches(notes.iter(), FIXED_XUSDC_BURN_TAG).is_empty());
}

/// The scan reports every exact match, in the order the node listed them — a second burn in the
/// same block is not silently dropped.
#[test]
fn the_scan_reports_every_exact_match() {
    let notes = [
        committed(note_id(4), FIXED_XUSDC_BURN_TAG, NoteType::Public),
        committed(note_id(5), 0xDEAD_BEEF, NoteType::Public),
        committed(note_id(6), FIXED_XUSDC_BURN_TAG, NoteType::Public),
    ];

    assert_eq!(
        exact_tag_matches(notes.iter(), FIXED_XUSDC_BURN_TAG),
        vec![note_id(4), note_id(6)]
    );
}

// THE RETRIEVAL — A NODE REPLY BECOMES A DISCOVERY REPORT
// ================================================================================================

/// **The write-side/read-side loop.** A real burn note, mapped as the node would return it, passes
/// the REAL discovery checklist — including the two fund-safety checks — and yields the payload it
/// was built with.
#[test]
fn a_real_burn_note_maps_into_a_record_that_passes_discovery() {
    let note = real_burn_note(BURN_AMOUNT);
    let fetched = FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK));

    let discovered = discovered_note(&fetched);
    assert_eq!(discovered.note_id(), note.id(), "the id is the note's own");
    assert_eq!(discovered.record().tag(), FIXED_XUSDC_BURN_TAG);

    let burn = validate_discovery(discovered.record(), &cfg())
        .expect("a real burn note passes the discovery checklist");
    assert_eq!(burn.payload(), &items(BURN_AMOUNT));
    assert_eq!(burn.depositor(), burner());
}

/// The mapped record carries the note's OWN script root and its OWN vault — the two facts the
/// fund-safety checks judge. Read off the note rather than assumed, which is what makes the checks
/// mean anything once a node is on the other end.
#[test]
fn the_mapped_details_carry_the_notes_script_root_and_vault() {
    let note = real_burn_note(BURN_AMOUNT);
    let fetched = FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK));

    let discovered = discovered_note(&fetched);
    let details = discovered
        .record()
        .details()
        .expect("a public note has details");

    assert_eq!(details.script_root(), note.script().root());
    assert_eq!(details.script_root(), XReserveBurnNote::script_root());
    assert_eq!(details.assets(), note.assets().as_slice());
}

/// A PRIVATE note comes back without its columns, so the report carries `details = None` — exactly
/// the shape the existing model already expects, and the one discovery refuses as unobservable.
#[test]
fn a_private_note_maps_to_no_details_and_is_refused() {
    let id = note_id(7);
    let fetched = private_reply(id);

    let discovered = discovered_note(&fetched);
    assert_eq!(discovered.note_id(), id);
    assert!(
        discovered.record().details().is_none(),
        "a private note is unobservable, so it reports no details"
    );
    assert_matches!(
        validate_discovery(discovered.record(), &cfg()),
        Err(DiscoveryReject::PrivateNoteUnobservable)
    );
}

/// A public note whose tag is not the burn tag is mapped FAITHFULLY — the report says what the node
/// said, and `validate_discovery` is what refuses it. The adapter does not pre-filter, because a
/// report that quietly dropped the wrong-tag note would make the checklist's first rung untestable
/// against a real node.
#[test]
fn a_wrong_tag_note_is_reported_as_it_is_and_refused_by_the_checklist() {
    let note = real_burn_note(BURN_AMOUNT);
    let fetched = FetchedNote::Public(note, inclusion_proof(CREATE_BLOCK));
    let discovered = discovered_note(&fetched);

    let cfg = ListenerConfig::builder()
        .burn_tag(0xAABB_CCDD)
        .build()
        .expect("a valid config");
    assert_matches!(
        validate_discovery(discovered.record(), &cfg),
        Err(DiscoveryReject::TagMismatch { .. })
    );
}

/// A public note carrying NO withdrawal-payload attachment yields no payload felts, so the decode
/// refuses it. The adapter does not invent a payload for a note that has none.
#[test]
fn a_public_note_without_the_withdrawal_attachment_decodes_to_nothing() {
    // A note with the burn note's own script and vault but no attachments at all — the shape a
    // note that merely borrowed the tag would have.
    let note = real_burn_note(BURN_AMOUNT);
    let stripped = Note::new(
        note.assets().clone(),
        PartialNoteMetadata::new(burner(), NoteType::Public)
            .with_tag(NoteTag::new(FIXED_XUSDC_BURN_TAG)),
        note.recipient().clone(),
    );
    let fetched = FetchedNote::Public(stripped, inclusion_proof(CREATE_BLOCK));

    let discovered = discovered_note(&fetched);
    let details = discovered
        .record()
        .details()
        .expect("a public note has details");
    assert!(
        details.items().is_empty(),
        "no withdrawal attachment means no payload felts"
    );
    assert_matches!(
        validate_discovery(discovered.record(), &cfg()),
        Err(DiscoveryReject::Decode(_))
    );
}

// THE RECONCILIATION — A SCANNED ID NEVER VANISHES
// ================================================================================================

/// The happy path, and the ordering: every scanned id is answered exactly once, and the records
/// come back in SCAN order rather than in whatever order the node happened to list them. The reply
/// here is deliberately REVERSED, so an implementation that simply mapped the reply would fail.
#[test]
fn every_scanned_id_is_answered_and_the_records_follow_the_scan_order() {
    let first = seeded_burn_note(1, BURN_AMOUNT);
    let second = seeded_burn_note(2, BURN_AMOUNT);
    assert_ne!(first.id(), second.id(), "the fixture must be two notes");

    let scanned = vec![first.id(), second.id()];
    let fetched = vec![public_reply(&second), public_reply(&first)];

    let discovered = reconcile_retrieval(&scanned, &fetched).expect("every scanned id is answered");

    assert_eq!(
        discovered
            .iter()
            .map(|note| note.note_id())
            .collect::<Vec<_>>(),
        scanned,
        "the records follow the scan, not the node's row order"
    );
}

/// **The fund-safety case.** A scanned, tag-matching id that `GetNotesById` does not answer for is
/// SURFACED — never silently dropped. A dropped id is a real burn that was seen and then never
/// processed, with a cursor free to advance past it; here the read fails instead, and it names the
/// id an operator has to reconcile.
#[test]
fn a_scanned_id_the_retrieval_omits_is_surfaced_rather_than_dropped() {
    let answered = seeded_burn_note(1, BURN_AMOUNT);
    let omitted = seeded_burn_note(2, BURN_AMOUNT);

    let scanned = vec![answered.id(), omitted.id()];
    let fetched = vec![public_reply(&answered)];

    let gap = reconcile_retrieval(&scanned, &fetched)
        .expect_err("an unanswered scanned id cannot be reported as a complete range");

    assert_eq!(gap.omitted(), [omitted.id()]);
    assert!(gap.duplicated().is_empty());
}

/// **The count trap.** The node answers with as many rows as the scan asked about — but one of them
/// is a note nobody asked for, and one scanned id is still unanswered. An implementation that
/// compared LENGTHS, or that trusted the reply's own count, would call this reconciled and lose the
/// burn.
#[test]
fn an_unrequested_row_cannot_stand_in_for_an_omitted_one() {
    let answered = seeded_burn_note(1, BURN_AMOUNT);
    let omitted = seeded_burn_note(2, BURN_AMOUNT);
    let stranger = seeded_burn_note(3, BURN_AMOUNT);

    let scanned = vec![answered.id(), omitted.id()];
    let fetched = vec![public_reply(&answered), public_reply(&stranger)];
    assert_eq!(
        scanned.len(),
        fetched.len(),
        "the counts must actually match"
    );

    let gap = reconcile_retrieval(&scanned, &fetched)
        .expect_err("a row nobody asked about does not answer for the one that is missing");

    assert_eq!(gap.omitted(), [omitted.id()]);
}

/// Every omitted id is named, in scan order — not just the first one found. An operator
/// reconciling a gap needs the whole list, and a report that stopped at the first would hide the
/// rest behind one repair.
#[test]
fn every_omitted_id_is_named_not_only_the_first() {
    let first = seeded_burn_note(1, BURN_AMOUNT);
    let answered = seeded_burn_note(2, BURN_AMOUNT);
    let third = seeded_burn_note(3, BURN_AMOUNT);

    let scanned = vec![first.id(), answered.id(), third.id()];
    let fetched = vec![public_reply(&answered)];

    let gap = reconcile_retrieval(&scanned, &fetched).expect_err("two ids are unanswered");

    assert_eq!(gap.omitted(), [first.id(), third.id()]);
}

/// One id answered TWICE is the node answering something other than the question it was asked. The
/// two rows are not necessarily the same note-state, nothing here can choose between them, and
/// emitting both would send one burn down the withdrawal path twice — so it fails the read.
#[test]
fn an_id_the_retrieval_answers_twice_is_surfaced() {
    let note = seeded_burn_note(1, BURN_AMOUNT);

    let scanned = vec![note.id()];
    let fetched = vec![public_reply(&note), public_reply(&note)];

    let gap = reconcile_retrieval(&scanned, &fetched)
        .expect_err("one scanned id answered twice is not one answer");

    assert_eq!(gap.duplicated(), [note.id()]);
    assert!(gap.omitted().is_empty());
}

/// A scan that matched nothing reconciles to nothing: there is no id to account for, so an empty
/// retrieval is a complete answer rather than a gap.
#[test]
fn an_empty_scan_reconciles_to_an_empty_answer() {
    let discovered =
        reconcile_retrieval(&[], &[]).expect("an empty scan has nothing left unaccounted for");
    assert!(discovered.is_empty());
}

/// Reconciliation accounts for IDS; it does not re-decide what a note is. The records it returns are
/// the real mapping — a public note keeps the details the checklist judges, a private one reports
/// none — so nothing is quietly turned into a placeholder on the way through.
#[test]
fn a_reconciled_record_is_the_real_mapping_not_a_placeholder() {
    let public = seeded_burn_note(1, BURN_AMOUNT);
    let private_id = note_id(11);

    let scanned = vec![public.id(), private_id];
    let fetched = vec![public_reply(&public), private_reply(private_id)];

    let discovered = reconcile_retrieval(&scanned, &fetched).expect("both ids are answered");

    let details = discovered[0]
        .record()
        .details()
        .expect("the public note keeps its details");
    assert_eq!(details.script_root(), public.script().root());
    assert_eq!(details.assets(), public.assets().as_slice());
    assert_eq!(discovered[0].record().tag(), FIXED_XUSDC_BURN_TAG);

    assert!(
        discovered[1].record().details().is_none(),
        "the private note is still unobservable"
    );

    // and the whole point of carrying it faithfully: the checklist is what judges it.
    let burn = validate_discovery(discovered[0].record(), &cfg())
        .expect("the reconciled public record passes the discovery checklist");
    assert_eq!(burn.payload(), &items(BURN_AMOUNT));
}

/// The gap an operator reads: it names the unaccounted-for ids in hex, so the record of a burn that
/// went missing between the scan and the retrieval is actionable rather than a bare count.
#[test]
fn the_gap_names_the_ids_it_could_not_account_for() {
    let omitted = seeded_burn_note(2, BURN_AMOUNT);
    let scanned = vec![omitted.id()];

    let gap = reconcile_retrieval(&scanned, &[]).expect_err("the only scanned id is unanswered");

    let rendered = gap.to_string();
    assert!(
        rendered.contains(&omitted.id().to_hex()),
        "the gap must name the id: {rendered}"
    );

    // and it is an error a caller can chain a cause onto, not just a message.
    fn assert_is_error<E: core::error::Error>(_: &E) {}
    assert_is_error(&gap);
}

/// A gap is what the RETRIEVAL failed at, and it reaches the caller saying so: the adapter turns it
/// into a `GetNotesById` read failure that keeps the gap — and therefore the ids — as its cause.
/// This is the step between the reconciliation above and what `discover` returns, so an omission
/// arrives at an operator as a named, actionable read failure rather than as a shorter list.
#[test]
fn a_gap_becomes_a_named_get_notes_by_id_read_failure() {
    let omitted = seeded_burn_note(2, BURN_AMOUNT);
    let gap = reconcile_retrieval(&[omitted.id()], &[]).expect_err("the scanned id is unanswered");

    let error = DiscoveryReadError::from(gap.clone());

    assert_eq!(error.rpc(), "GetNotesById");
    let source = core::error::Error::source(&error).expect("the gap is preserved as the cause");
    assert_eq!(source.to_string(), gap.to_string());
    assert!(
        error.to_string().contains(&omitted.id().to_hex()),
        "the read failure still names the lost id: {error}"
    );
}

/// One note the SCAN listed twice is one note, not two burns: it is reconciled once, against the
/// single row that answers for it. Accounting for it twice would send the same withdrawal down the
/// path twice, which is the mirror image of dropping it.
#[test]
fn a_note_the_scan_listed_twice_is_reconciled_once() {
    let note = seeded_burn_note(1, BURN_AMOUNT);

    let scanned = vec![note.id(), note.id()];
    let fetched = vec![public_reply(&note)];

    let discovered =
        reconcile_retrieval(&scanned, &fetched).expect("the repeated scan entry is one note");

    assert_eq!(
        discovered
            .iter()
            .map(|note| note.note_id())
            .collect::<Vec<_>>(),
        vec![note.id()],
        "one note, reported once"
    );
}
