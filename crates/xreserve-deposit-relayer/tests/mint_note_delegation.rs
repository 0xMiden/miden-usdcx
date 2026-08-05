//! The mint-note builder (`miden::mint_note::build_mint_note`) — the DELEGATION contract.
//!
//! The builder's entire job is to hand the shared encoding crate's owned factory
//! ([`XUsdcMintNote::create`]) the inputs the relayer has validated, and return the note it
//! produces. That note is a STOCK miden-standards `MintNote`: its storage is the stock
//! `MintNoteStorage::FungiblePublic` embedding the ATTESTED output (the P2ID recipe to the intent's
//! `remoteRecipient` under the canonical nonce-key serial, the scale-0-reduced amount as a
//! `FungibleAsset` of the faucet, the recipient's account-target tag), and the Circle-signed
//! transport rides as TWO attachments — the merged scheme-4 transport (the attestation followed
//! by the DepositIntent preimage) and the scheme-2
//! `NetworkAccountTarget` routing bind. Every byte of that wire form
//! belongs to the shared encoding crate (single-owner rule); the note script is the STOCK standards
//! MINT script, and the faucet's attestation mint policy — not a custom note script — is what
//! verifies the attachments and assert-matches the storage. The relayer restates NONE of it, and
//! this suite is what pins that:
//!
//! * [`t_delegation_is_byte_for_byte_unit04_create`] is the load-bearing one — the note the relayer
//!   builds must be EQUAL (`Note: PartialEq` — header, details, storage, attachments, metadata) to
//!   the note the shared encoding crate's factory builds from the same inputs and the same seeded
//!   RNG. A hand-rolled layout that "looks right" cannot survive it; neither can a rebuilt
//!   attachment, a re-derived tag, or a locally-drawn serial number.
//! * The remaining tests read the note back through the PROTOCOL's / the STANDARD's own accessors
//!   (`note.attachments().find(scheme)`, `NetworkAccountTarget::try_from`,
//!   `note.storage().items()`, `MintNote::script_root()`, `P2idNote::script_root()`) and through
//!   the shared encoding crate's own codecs (`parse_deposit_intent_header`,
//!   `deposit_intent_to_packed_felts`, `bytes32_to_account_id`, `bytes32_to_storage_map_key`,
//!   `uint256_to_asset_amount`, `signature_felts`, `affine_pubkey_felts`) — never against a layout
//!   re-derived here. An assertion that restated the layout would be a SECOND definition of an
//!   owned format, i.e. exactly the drift seam the ownership map exists to close.
//!
//! **There is no advice map in any of this.** The attestation travels INSIDE the note, as a note
//! attachment; the consuming transaction (the network's ntx-builder — the faucet is a keyless
//! network account) rebuilds the advice map from those attachments. The relayer cannot reach that
//! transaction's advice provider at all, so it does not try (see `RIV-ADVICE-KEY.md` for the
//! preserved advice-key finding, and `relayer_has_no_advice_surface.rs` for the executable
//! gate).
//!
//! **What this suite does NOT prove:** that the faucet ACCEPTS the note. Only a real-node mint does
//! (`REQUIRES IMPLEMENTATION VALIDATION`; the submit leg is parked until a v0.16 `miden-client`
//! exists). What it proves is that the note the relayer emits IS the note the shared encoding
//! crate's factory emits — and the shared encoding crate proves THAT note mints, on a mock chain,
//! in its own executing suites (`crates/xusdc-encoding/tests/mint_policy_e2e.rs` and friends).

mod fixtures;
mod mint_support;

use assert_matches::assert_matches;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::{NoteAttachmentScheme, NoteTag, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::note::{MintNote, NetworkAccountTarget, NoteExecutionHint, P2idNote};

use xreserve_deposit_relayer::miden::build_mint_note;
use xusdc_encoding::note::xreserve_mint::{
    MintAttestation, XUsdcMintNote, XUSDC_DEPOSIT_SCALE_EXP,
    XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME, XUSDC_MINT_TRANSPORT_INTENT_WORD_OFF,
};
use xusdc_encoding::xreserve::encoding::{
    affine_pubkey_felts, bytes32_to_account_id, bytes32_to_packed_felts,
    bytes32_to_storage_map_key, deposit_intent_to_packed_felts, parse_deposit_intent_header,
    signature_felts, uint256_to_asset_amount,
};

use mint_support::*;

// THE DELEGATION ITSELF
// ================================================================================================

/// The load-bearing proof: `build_mint_note` produces EXACTLY the note
/// `XUsdcMintNote::create` produces from the same validated inputs and the same RNG seed.
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

    // the shared encoding crate's factory, called directly — the same inputs, the same seed.
    let unit04 = XUsdcMintNote::create(
        relayer_sender_id(),
        faucet_id(),
        attestation.payload(),
        &MintAttestation::new(attestation.attestation(), *attester.as_bytes()),
        &mut note_rng(0xC1_2C_1E),
    )
    .expect("unit-04's factory builds the same note");

    assert_eq!(
        built, unit04,
        "build_mint_note must BE XUsdcMintNote::create — not a second implementation of it"
    );
}

/// The note script is the STOCK standards MINT script — there is NO custom pinned-root constant.
/// The script identity is held by the faucet's note-script allowlist: its row 1 pins
/// `MintNote::script_root()`, so a relayer (or a factory) that ever compiled its own note script
/// would emit a note the faucet refuses — and fails here first.
#[test]
fn t_script_root_is_the_stock_mint_root() {
    let note = build_note();

    assert_eq!(
        note.script().root(),
        XUsdcMintNote::script_root(),
        "the note must carry the script unit-04's factory rides the transport on"
    );
    assert_eq!(
        note.script().root(),
        MintNote::script_root(),
        "…which IS the stock standards MINT root — the identity the note-script allowlist row 1 \
         pins on-chain"
    );
}

// THE TWO ATTACHMENTS
// ================================================================================================

/// Exactly TWO attachments — the merged scheme-4 transport and the scheme-2 routing target —
/// asserted through the note's own attachment API (`num_attachments` / `find`), never by indexing
/// a layout this crate re-derived. The faucet's attestation mint policy asserts exactly these two,
/// so the count is load-bearing: a third attachment, or a missing one, fails the mint on-chain.
#[test]
fn t_note_carries_exactly_the_two_attachments() {
    let attestation = validated_test_vector();
    let note = build_note();
    let attachments = note.attachments();

    assert_eq!(
        attachments.num_attachments(),
        2,
        "the mint note carries exactly the merged scheme-4 transport + the scheme-2 routing target"
    );

    let transport = attachments
        .find(
            NoteAttachmentScheme::new(XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME)
                .expect("unit-04's transport scheme id is a valid scheme"),
        )
        .expect("the scheme-4 merged transport attachment is present");

    // the transport is word-granular: the attestation, and ⌈packed payload felts / 4⌉ words of
    // intent — every width computed by the shared encoding crate's OWNED codec and constants, not
    // a number restated here
    let packed_felts =
        deposit_intent_to_packed_felts(attestation.payload()).expect("the canonical payload packs");
    assert_eq!(
        usize::from(transport.content().num_words()),
        XUSDC_MINT_TRANSPORT_INTENT_WORD_OFF + packed_felts.len().div_ceil(4),
        "the transport is the attestation + the packed payload, zero-padded to the word boundary"
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

// THE STORAGE — THE STOCK LAYOUT EMBEDDING THE ATTESTED OUTPUT
// ================================================================================================

/// The note's storage is the STOCK `MintNoteStorage::FungiblePublic` layout — `SCRIPT_ROOT(4) +
/// SERIAL(4) + ASSET_ID(4) + ASSET_VALUE(4) + tag(1) + pad(3) + P2ID storage(2)` — and every
/// attested value embedded in it is derived from the VALIDATED payload by the shared encoding
/// crate's own codecs, consumed by reference: the P2ID recipe targets the intent's
/// `remoteRecipient` (`bytes32_to_account_id`) under the canonical nonce-key serial
/// (`bytes32_to_storage_map_key`), the asset is the scale-0-reduced attested amount
/// (`uint256_to_asset_amount` at `XUSDC_DEPOSIT_SCALE_EXP`) bound to the faucet, and the
/// output-note tag targets the attested recipient. This is the storage the faucet's attestation
/// mint policy re-derives on-chain and `assert_eqw`s — a value invented by the relayer instead of
/// taken from the payload would fail the ASSERT-MATCH binding there, and fails here first.
#[test]
fn t_storage_embeds_the_attested_output() {
    let attestation = validated_test_vector();
    let note = build_note();

    // the attested ingredients, re-derived through the shared encoding crate's OWNED codecs (by
    // reference)
    let header =
        parse_deposit_intent_header(attestation.payload()).expect("the canonical payload parses");
    let recipient_id = bytes32_to_account_id(&header.remote_recipient)
        .expect("the canonical payload's remoteRecipient is a valid account id");
    let limbs: [u32; 8] = bytes32_to_packed_felts(&header.amount)
        .map(|limb| u32::try_from(limb.as_canonical_u64()).expect("a packed u32 limb"));
    let amount = uint256_to_asset_amount(limbs, XUSDC_DEPOSIT_SCALE_EXP)
        .expect("the attested amount reduces at unit-04's scale");
    let asset = FungibleAsset::new(faucet_id(), u64::from(amount))
        .expect("the reduced amount is a fungible asset of the faucet");

    let items = note.storage().items();
    assert_eq!(
        items.len(),
        MintNote::MIN_NUM_STORAGE_ITEMS_PUBLIC + P2idNote::NUM_STORAGE_ITEMS,
        "the stock fungible-public MINT layout with a P2ID output recipe: 22 items"
    );

    // SCRIPT_ROOT(4): the output-note recipe is a P2ID note — the stock standards root
    assert_eq!(
        &items[0..4],
        P2idNote::script_root().as_elements(),
        "the output recipe rides the stock P2ID script"
    );

    // SERIAL(4): the canonical nonce key — the shared encoding crate's owned bytes32→Word keying
    // primitive over the
    // payload's nonce, the SAME derivation the on-chain policy recomputes
    assert_eq!(
        &items[4..8],
        Word::from(bytes32_to_storage_map_key(&header.nonce)).as_elements(),
        "the output recipe's serial is the canonical nonce key"
    );

    // ASSET_ID(4) + ASSET_VALUE(4): the scale-0-reduced attested amount, bound to the faucet
    assert_eq!(
        &items[8..12],
        asset.to_id_word().as_elements(),
        "ASSET_ID binds the note to the faucet the asset is minted from"
    );
    assert_eq!(
        &items[12..16],
        asset.to_value_word().as_elements(),
        "ASSET_VALUE carries the reduced attested amount"
    );
    // …and ASSET_VALUE[0] really is the PAYLOAD's amount (the scale-0 reduction identity): the u64 at
    // the tail of the 32-byte big-endian wire amount
    let wire_amount = u64::from_be_bytes(
        header.amount[24..32]
            .try_into()
            .expect("the 8-byte tail of the 32-byte amount field"),
    );
    assert_eq!(
        items[12],
        Felt::try_from(wire_amount).expect("the canonical amount fits the field"),
        "the embedded amount is the payload's attested amount, unreduced (scale 0)"
    );

    // tag(1) + pad(3): the output-note tag targets the ATTESTED recipient
    assert_eq!(
        items[16],
        Felt::from(NoteTag::with_account_target(recipient_id)),
        "the output-note tag targets the payload's remoteRecipient"
    );
    assert_eq!(&items[17..20], &[Felt::ZERO; 3], "word-alignment padding");

    // P2ID storage(2): [suffix, prefix] — the attested recipient is the only account that can
    // consume the minted output note
    assert_eq!(
        &items[20..22],
        &[recipient_id.suffix(), recipient_id.prefix().as_felt()],
        "the P2ID output recipe targets the payload's remoteRecipient account"
    );
}

/// The validated DepositIntent payload travels VERBATIM in the transport's intent sub-region — at
/// the FIXED word offset that makes the Circle-signed byte extent 1:1 identifiable inside the
/// merged attachment. Its elements are the shared encoding crate's OWNED packing
/// (`deposit_intent_to_packed_felts`, consumed here BY REFERENCE — the test does not restate the
/// 60-felt header / ⌈hookDataLen/4⌉ packing, it calls the owner), zero-padded to the word boundary.
/// And the sub-region really tracks the VALIDATED payload that was handed in: attestations over
/// two DIFFERENT canonical payloads produce different transports.
#[test]
fn t_the_transport_intent_sub_region_is_the_validated_payload() {
    let attester = attester_pubkey();
    let scheme = NoteAttachmentScheme::new(XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME)
        .expect("unit-04's transport scheme id is a valid scheme");
    let intent_felt_off = XUSDC_MINT_TRANSPORT_INTENT_WORD_OFF * 4;

    let intent_elements = |vector_id: &str, seed: u64| {
        let note = build_mint_note(
            relayer_sender_id(),
            faucet_id(),
            &validated_over_vector_id(vector_id),
            &attester,
            &mut note_rng(seed),
        )
        .expect("the canonical vector builds");
        note.attachments()
            .find(scheme)
            .expect("the scheme-4 merged transport attachment is present")
            .content()
            .to_elements()[intent_felt_off..]
            .to_vec()
    };

    for vector_id in ["di-pos-hookdata", "di-pos-empty-hookdata"] {
        let mut expected = deposit_intent_to_packed_felts(&fixtures::canonical_payload(vector_id))
            .expect("the canonical payload packs");
        while !expected.len().is_multiple_of(4) {
            expected.push(Felt::ZERO);
        }

        assert_eq!(
            intent_elements(vector_id, 1),
            expected,
            "vector {vector_id}: the intent sub-region is the packed preimage of the payload the \
             relayer validated, zero-padded to the word boundary"
        );
    }

    assert_ne!(
        intent_elements("di-pos-hookdata", 1),
        intent_elements("di-pos-empty-hookdata", 1),
        "the sub-region tracks the validated payload, not a fixed blob"
    );
}

// THE ATTESTATION ATTACHMENT — THE VALIDATED SIGNATURE + THE CONFIGURED PUBKEY
// ================================================================================================

/// The transport's attestation section carries the 65-byte signature the relayer VALIDATED (from
/// `ValidatedAttestation`, never from a raw-bytes side door) and the 33-byte attester pubkey the
/// OPERATOR configured — both in the shared encoding crate's felt encoding, checked by looking for
/// the owner's own packing (`signature_felts` / `affine_pubkey_felts`) inside the attachment's
/// elements. The test asserts PRESENCE of the owner-packed runs, not their offsets: the offsets are
/// the shared encoding crate's to choose, and restating them here would fork the layout.
#[test]
fn t_transport_carries_the_validated_signature_and_configured_pubkey() {
    let attestation = validated_test_vector();
    let attester = attester_pubkey();
    let note = build_note();

    let elements = note
        .attachments()
        .find(
            NoteAttachmentScheme::new(XUSDC_MINT_TRANSPORT_ATTACHMENT_SCHEME)
                .expect("valid scheme"),
        )
        .expect("the merged transport attachment is present")
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

// THE NOTE'S SHAPE (the shared encoding crate's contract, observed — not restated)
// ================================================================================================

/// Public (the network-tx observability mandate — the stock `MintNote` conversion FORCES it),
/// carrying no ATTACHED asset (the attested amount rides in the note's storage), sent by the
/// relayer, tagged at the faucet.
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
        "the mint note carries no assets — the faucet MINTS the amount (embedded in the storage's \
         FungibleAsset), it is not transported"
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
