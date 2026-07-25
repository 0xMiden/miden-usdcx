//! The mint-note builder (`miden::mint_note::build_mint_note`) — the DELEGATION contract.
//!
//! The builder's entire job is to hand unit-04's owned factory
//! ([`XReserveMintNote::create`]) the inputs the relayer has validated, and return the note it
//! produces. Every byte of the note's wire form — the u32-LE-packed DepositIntent storage (DC-1),
//! the scheme-1 attestation attachment, the scheme-2 `NetworkAccountTarget` routing bind (F5), the
//! forced `NoteType::Public`, the account-target tag, the pinned script root — belongs to unit-04
//! (single-owner rule). The relayer restates NONE of it, and this suite is what pins that:
//!
//! * [`t_delegation_is_byte_for_byte_unit04_create`] is the load-bearing one — the note the relayer
//!   builds must be EQUAL (`Note: PartialEq` — header, details, storage, attachments, metadata) to
//!   the note unit-04's factory builds from the same inputs and the same seeded RNG. A hand-rolled
//!   layout that "looks right" cannot survive it; neither can a rebuilt attachment, a re-derived
//!   tag, or a locally-drawn serial number.
//! * The remaining tests read the note back through the PROTOCOL's / the STANDARD's own accessors
//!   (`note.attachments().find(scheme)`, `NetworkAccountTarget::try_from`, `note.storage().items()`,
//!   `XReserveMintNote::script_root()`) and through unit-04's own codecs
//!   (`deposit_intent_to_packed_felts`, `signature_felts`, `affine_pubkey_felts`) — never against a
//!   layout re-derived here. An assertion that restated the layout would be a SECOND definition of
//!   an owned format, i.e. exactly the drift seam the ownership map exists to close.
//!
//! **There is no advice map in any of this.** The attestation travels INSIDE the note, as a note
//! attachment; the consuming transaction (the network's ntx-builder — the faucet is a keyless
//! network account) rebuilds the advice map from those attachments. The relayer cannot reach that
//! transaction's advice provider at all, so it does not try (see `RIV-ADVICE-KEY.md` for the
//! advice-key finding this supersedes, and `relayer_has_no_advice_surface.rs` for the executable
//! gate).
//!
//! **What this suite does NOT prove:** that the faucet ACCEPTS the note. Only a real-node mint does
//! (`REQUIRES IMPLEMENTATION VALIDATION`; the submit leg is parked until a v0.16 `miden-client`
//! exists). What it proves is that the note the relayer emits IS the note unit-04's factory emits —
//! and unit-04 proves THAT note mints, on a mock chain, in its own executing suite
//! (`crates/xusdc-encoding/tests/xreserve_mint_note.rs`).

mod fixtures;
mod mint_support;

use assert_matches::assert_matches;
use miden_protocol::note::{NoteTag, NoteType};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};

use xreserve_deposit_relayer::miden::build_mint_note;
use xusdc_encoding::note::xreserve_mint::{
    MintAttestation, XReserveMintNote, XRESERVE_MINT_ATTACHMENT_NUM_WORDS,
    XRESERVE_MINT_ATTACHMENT_SCHEME,
};
use xusdc_encoding::xreserve::encoding::{
    affine_pubkey_felts, deposit_intent_to_packed_felts, signature_felts,
};

use mint_support::*;

// THE DELEGATION ITSELF
// ================================================================================================

/// The load-bearing proof: `build_mint_note` produces EXACTLY the note
/// `XReserveMintNote::create` produces from the same validated inputs and the same RNG seed.
///
/// `Note`'s `PartialEq` covers the header (id, metadata: sender / tag / type / execution hint), the
/// details (serial number, script root, storage items, assets) and the attachments. So this single
/// assertion refutes every form of "the relayer built the note itself": a re-derived storage
/// packing, a rebuilt attestation attachment, a locally-invented tag, an extra or missing
/// attachment, a differently-drawn serial number.
#[test]
fn t_delegation_is_byte_for_byte_unit04_create() {
    let attestation = validated_test_vector();
    let attester = attester_pubkey();

    let built = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &attestation,
        &attester,
        &mut note_rng(0xC1_2C_1E),
    )
    .expect("the canonical vector builds a mint note");

    // unit-04's factory, called directly — the same inputs, the same seed.
    let unit04 = XReserveMintNote::create(
        relayer_sender_id(),
        faucet_id(),
        attestation.payload(),
        &MintAttestation::new(attestation.attestation(), *attester.as_bytes()),
        &mut note_rng(0xC1_2C_1E),
    )
    .expect("unit-04's factory builds the same note");

    assert_eq!(
        built, unit04,
        "build_mint_note must BE XReserveMintNote::create — not a second implementation of it"
    );
}

/// The note script is unit-04's — and it is the PINNED root (`masm-rust-constant-parity`), so a
/// relayer that ever compiled its own note script (or pinned its own root) fails here.
#[test]
fn t_script_root_is_unit04s_pinned_root() {
    let note = build_note();

    assert_eq!(
        note.script().root(),
        XReserveMintNote::script_root(),
        "the note must carry unit-04's compiled mint-note script"
    );
    assert_eq!(
        note.script().root(),
        XReserveMintNote::pinned_script_root(),
        "…which is the PINNED root the faucet's shim is built against"
    );
}

// THE TWO ATTACHMENTS (F5)
// ================================================================================================

/// Exactly TWO attachments — the scheme-1 attestation and the scheme-2 routing target — asserted
/// through the note's own attachment API (`num_attachments` / `find`), never by indexing a layout
/// this crate re-derived. The entry shim's `eq.2` is what makes the count load-bearing: a third
/// attachment, or a missing one, fails the mint on-chain.
#[test]
fn t_note_carries_exactly_the_two_attachments() {
    let note = build_note();
    let attachments = note.attachments();

    assert_eq!(
        attachments.num_attachments(),
        2,
        "the mint note carries exactly the scheme-1 attestation + the scheme-2 routing target"
    );

    let attestation_attachment = attachments
        .find(
            miden_protocol::note::NoteAttachmentScheme::new(XRESERVE_MINT_ATTACHMENT_SCHEME)
                .expect("unit-04's scheme id is a valid scheme"),
        )
        .expect("the scheme-1 attestation attachment is present");

    // the WIDTH is unit-04's constant, consumed by reference — not a number restated here
    assert_eq!(
        usize::from(attestation_attachment.content().num_words()),
        XRESERVE_MINT_ATTACHMENT_NUM_WORDS,
        "the attestation attachment is unit-04's width"
    );

    assert!(
        attachments
            .find(NetworkAccountTarget::ATTACHMENT_SCHEME)
            .is_some(),
        "the scheme-2 NetworkAccountTarget routing attachment is present"
    );
}

/// The routing attachment binds the FAUCET — read back through the standard's own parser, which is
/// the same parser the network's note router uses. A note routed at the wrong account is a mint
/// that never happens.
#[test]
fn t_routing_attachment_binds_the_faucet_network_account() {
    let note = build_note();

    let target = NetworkAccountTarget::try_from(
        note.attachments()
            .find(NetworkAccountTarget::ATTACHMENT_SCHEME)
            .expect("the routing attachment is present"),
    )
    .expect("the routing attachment parses as a NetworkAccountTarget");

    assert_eq!(target.target_id(), faucet_id(), "routed at the faucet");
    assert_eq!(
        target.execution_hint(),
        NoteExecutionHint::Always,
        "the network transaction is always eligible to consume it"
    );
}

/// The faucet argument is genuinely the routing/tag source: a DIFFERENT faucet id yields a
/// different routing bind and a different tag. (Guards against a builder that hardcoded either.)
#[test]
fn t_the_faucet_argument_drives_the_route_and_the_tag() {
    let attestation = validated_test_vector();
    let attester = attester_pubkey();

    let note = build_mint_note(
        relayer_sender_id(),
        other_faucet_id(),
        &attestation,
        &attester,
        &mut note_rng(9),
    )
    .expect("a second public faucet is routable");

    let target = NetworkAccountTarget::try_from(
        note.attachments()
            .find(NetworkAccountTarget::ATTACHMENT_SCHEME)
            .expect("the routing attachment is present"),
    )
    .expect("the routing attachment parses");

    assert_eq!(target.target_id(), other_faucet_id());
    assert_ne!(target.target_id(), faucet_id());
    assert_eq!(
        note.metadata().tag(),
        NoteTag::with_account_target(other_faucet_id()),
        "the tag follows the faucet, too"
    );
}

// THE STORAGE — THE VALIDATED DEPOSITINTENT PREIMAGE (DC-1)
// ================================================================================================

/// The note's storage IS the validated DepositIntent, packed by unit-04's OWNED codec
/// (`deposit_intent_to_packed_felts`, consumed here BY REFERENCE — the test does not restate the
/// 60-felt header / ⌈hookDataLen/4⌉ packing, it calls the owner).
#[test]
fn t_storage_is_the_validated_deposit_intent_preimage() {
    let attestation = validated_test_vector();
    let note = build_note();

    let expected =
        deposit_intent_to_packed_felts(attestation.payload()).expect("the canonical payload packs");

    assert_eq!(
        note.storage().items(),
        expected.as_slice(),
        "the note's storage is the packed preimage of the payload the relayer validated"
    );
}

/// …and the payload really comes from the ValidatedAttestation that was handed in: a validated
/// attestation over a DIFFERENT canonical payload produces DIFFERENT storage.
#[test]
fn t_storage_follows_the_validated_payload() {
    let attester = attester_pubkey();

    let with_hookdata = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &validated_over_vector_id("di-pos-hookdata"),
        &attester,
        &mut note_rng(1),
    )
    .expect("builds");

    let empty_hookdata = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &validated_over_vector_id("di-pos-empty-hookdata"),
        &attester,
        &mut note_rng(1),
    )
    .expect("builds");

    assert_ne!(
        with_hookdata.storage().items(),
        empty_hookdata.storage().items(),
        "the storage tracks the validated payload, not a fixed blob"
    );
    assert_eq!(
        empty_hookdata.storage().items(),
        deposit_intent_to_packed_felts(&fixtures::canonical_payload("di-pos-empty-hookdata"))
            .expect("packs")
            .as_slice()
    );
}

// THE ATTESTATION ATTACHMENT — THE VALIDATED SIGNATURE + THE CONFIGURED PUBKEY
// ================================================================================================

/// The scheme-1 attachment carries the 65-byte signature the relayer VALIDATED (from
/// `ValidatedAttestation`, never from a raw-bytes side door) and the 33-byte attester pubkey the
/// OPERATOR configured — both in unit-04's felt encoding, checked by looking for the owner's own
/// packing (`signature_felts` / `affine_pubkey_felts`) inside the attachment's elements. The test
/// asserts PRESENCE of the owner-packed runs, not their offsets: the offsets are unit-04's to
/// choose, and restating them here would fork the layout.
#[test]
fn t_attestation_attachment_carries_the_validated_signature_and_configured_pubkey() {
    let attestation = validated_test_vector();
    let attester = attester_pubkey();
    let note = build_note();

    let elements = note
        .attachments()
        .find(
            miden_protocol::note::NoteAttachmentScheme::new(XRESERVE_MINT_ATTACHMENT_SCHEME)
                .expect("valid scheme"),
        )
        .expect("the attestation attachment is present")
        .content()
        .to_elements();

    let signature = signature_felts(&attestation.attestation());
    let pubkey = affine_pubkey_felts(attester.as_bytes()).expect("the partner key is on the curve");

    assert!(
        elements.windows(signature.len()).any(|w| w == signature),
        "the attachment carries the VALIDATED 65-byte signature, in unit-04's packing"
    );
    assert!(
        elements.windows(pubkey.len()).any(|w| w == pubkey),
        "the attachment carries the CONFIGURED attester pubkey, in unit-04's packing"
    );
}

/// A different configured attester key produces a different attachment — so the pubkey argument is
/// really the source of those felts (a builder that hardcoded a key would pass the containment test
/// above only by accident, and fails here).
#[test]
fn t_the_configured_pubkey_is_the_one_that_travels() {
    let attestation = validated_test_vector();

    let partner = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &attestation,
        &attester_pubkey(),
        &mut note_rng(2),
    )
    .expect("builds");
    let foreign = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &attestation,
        &foreign_attester_pubkey(),
        &mut note_rng(2),
    )
    .expect("builds");

    assert_ne!(
        partner.attachments().to_commitment(),
        foreign.attachments().to_commitment(),
        "the attester pubkey the operator configured is the one the note carries"
    );
    // same deposit, same serial: ONLY the attestation attachment moved
    assert_eq!(partner.storage().items(), foreign.storage().items());
    assert_eq!(partner.serial_num(), foreign.serial_num());
}

/// A different validated attestation over the SAME payload (a re-signed envelope) changes the
/// attachment too — the signature that travels is the one that was validated, not a stale one.
#[test]
fn t_the_validated_signature_is_the_one_that_travels() {
    let payload = fixtures::canonical_payload("di-pos-hookdata");
    let partner_signed = validated_over(&payload);
    let foreign_signed = validated(
        &fixtures::PartnerAttester::with_seed(fixtures::FOREIGN_KEY_SEED).attest(&payload),
    );

    assert_ne!(
        partner_signed.attestation(),
        foreign_signed.attestation(),
        "the two envelopes really carry different signatures"
    );

    let a = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &partner_signed,
        &attester_pubkey(),
        &mut note_rng(3),
    )
    .expect("builds");
    let b = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &foreign_signed,
        &attester_pubkey(),
        &mut note_rng(3),
    )
    .expect("builds");

    assert_eq!(
        a.storage().items(),
        b.storage().items(),
        "same deposit intent"
    );
    assert_ne!(
        a.attachments().to_commitment(),
        b.attachments().to_commitment(),
        "different validated signature → different attestation attachment"
    );
}

// THE NOTE'S SHAPE (unit-04's contract, observed — not restated)
// ================================================================================================

/// Public (the network-tx observability mandate), asset-less, sent by the relayer, tagged at the
/// faucet.
#[test]
fn t_note_is_public_assetless_and_addressed_to_the_faucet() {
    let note = build_note();

    assert_eq!(note.metadata().note_type(), NoteType::Public);
    assert_eq!(note.metadata().sender(), relayer_sender_id());
    assert_eq!(
        note.metadata().tag(),
        NoteTag::with_account_target(faucet_id())
    );
    assert!(
        note.assets().is_empty(),
        "the mint note carries no assets — the faucet MINTS the amount, it is not transported"
    );
}

/// Two mints of the SAME deposit intent must be two DISTINCT notes (distinct serial numbers →
/// distinct note ids), or a legitimate retry would be indistinguishable from the first attempt at
/// the note level. (The duplicate-mint defence is elsewhere and is absolute: the on-chain
/// `usedNonces` assert-then-set, backstopped off-chain by the idempotency store.)
#[test]
fn t_each_build_draws_a_fresh_serial_number() {
    let attestation = validated_test_vector();
    let attester = attester_pubkey();

    let first = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &attestation,
        &attester,
        &mut note_rng(10),
    )
    .expect("builds");
    let second = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &attestation,
        &attester,
        &mut note_rng(11),
    )
    .expect("builds");

    assert_ne!(first.serial_num(), second.serial_num());
    assert_ne!(first.id(), second.id());
    assert_eq!(
        first.storage().items(),
        second.storage().items(),
        "…over the same deposit intent"
    );
}

/// Draws from ONE rng across two builds: the second note differs from the first, i.e. the builder
/// advances the caller's RNG rather than seeding a fresh one per call (a builder that ignored the
/// passed RNG could still pass the test above by accident).
#[test]
fn t_the_callers_rng_is_the_one_that_is_drawn_from() {
    let attestation = validated_test_vector();
    let attester = attester_pubkey();
    let mut rng = note_rng(12);

    let first = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &attestation,
        &attester,
        &mut rng,
    )
    .expect("builds");
    let second = build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &attestation,
        &attester,
        &mut rng,
    )
    .expect("builds");

    assert_ne!(first.serial_num(), second.serial_num());
    assert_matches!(
        build_mint_note(
            relayer_sender_id(),
            faucet_id(),
            &attestation,
            &attester,
            &mut note_rng(12),
        ),
        Ok(note) if note.serial_num() == first.serial_num(),
        "a freshly seeded rng reproduces the FIRST draw — proving the builder drew from the caller's"
    );
}

// helpers
// ================================================================================================

/// The standard note: the canonical vector, the partner attester key, the public faucet.
fn build_note() -> miden_protocol::note::Note {
    build_mint_note(
        relayer_sender_id(),
        faucet_id(),
        &validated_test_vector(),
        &attester_pubkey(),
        &mut note_rng(0x5EED),
    )
    .expect("the canonical vector builds a mint note")
}
