//! `note_decode` — the PURE parts of the burn-note decode path: the burn-payload decode and the
//! sender read.
//!
//! **NON-GATING.** The GATING versions of these are the real-local-node runs
//! (`tests/local_node/tag_scan_retrieval.rs`, `tests/local_node/sender_exposure.rs`): a real public
//! `XReserveBurnNote`, discovered by an exact-tag `SyncNotes` scan and retrieved by `GetNotesById`.
//! Those need `miden-client`, which has no v0.16 release — they are PARKED
//! (`PHASE4-VERIFICATION-HARNESS.md:28`,`:65`-`68`: a non-node leg is NON-GATING and must be paired
//! with a real-node run). What is testable purely, and is tested here, is the decode itself: given
//! the felts and the sender a node WILL hand over, the module must produce the exact `BurnPayload`
//! and the exact burner — or refuse.
//!
//! The inputs are the ONE canonical golden-vector artifact
//! (`crates/xusdc-encoding/tests/vectors/xreserve-encoding-vectors.json`, families `bn` and `aid`),
//! never a table re-typed here: the burn-note payload is the shared encoding crate's format, and a
//! second copy of its vectors would be a second source of truth for how much USDC a burn releases.

use assert_matches::assert_matches;
use miden_protocol::account::AccountId;
use miden_protocol::note::{NoteAttachments, NoteMetadata, NoteType, PartialNoteMetadata};
use miden_protocol::Felt;
use rstest::rstest;
use withdrawal_listener_attester::error::DecodeError;
use withdrawal_listener_attester::note_decode::{
    decode_burn_payload, read_sender, BurnNoteMetadata,
};
use xusdc_encoding::vectors::{load, parse_hex32, BnVector};
use xusdc_encoding::xreserve::encoding::{
    account_id_to_bytes32, account_id_to_felts, bytes32_to_account_id, decode_burn_note_items,
    encode_burn_note_items, EncodingError, BURN_NOTE_ITEMS_FELTS,
};

// HELPERS
// ================================================================================================

/// The `bn` accept vectors — the golden `NoteStorage.items` layouts (min / typical / max).
fn accept_vectors() -> Vec<&'static BnVector> {
    let v: Vec<_> = load()
        .families
        .bn
        .iter()
        .filter(|x| x.kind == "accept")
        .collect();
    assert!(
        !v.is_empty(),
        "the bn accept vectors must be present — an empty table would pass every loop below \
         vacuously"
    );
    v
}

/// Real, canonical `AccountId`s, reconstructed from the `aid` round-trip vectors through the shared
/// encoding crate's `AccountId↔bytes32` codec — the same ids whose `bytes32` form becomes
/// `remoteDepositor`.
fn golden_senders() -> Vec<(AccountId, [u8; 32])> {
    let v: Vec<_> = load()
        .families
        .aid
        .iter()
        .filter(|a| a.id.starts_with("aid-rt"))
        .map(|a| {
            let bytes = parse_hex32(&a.bytes32);
            let id = bytes32_to_account_id(&bytes).expect("aid round-trip vector is a valid id");
            (id, bytes)
        })
        .collect();
    assert!(!v.is_empty(), "the aid round-trip vectors must be present");
    v
}

/// An in-field `Felt` — `Felt::new` is fallible at the v16 base (values ≥ p are rejected), and
/// every value these tests build is a literal well inside the field.
fn felt(value: u64) -> Felt {
    Felt::new(value).expect("test value is in the field")
}

fn public_metadata(sender: AccountId) -> NoteMetadata {
    NoteMetadata::new(
        PartialNoteMetadata::new(sender, NoteType::Public),
        &NoteAttachments::default(),
    )
}

// (PURE) — BURN-PAYLOAD DECODE VIA THE UNIT-04 BURN-NOTE CODEC
// ================================================================================================

/// Every accept vector's golden felts decode to exactly the four fields the burn wrote — asserted
/// FIELD BY FIELD, so a permuted layout (`destRecipient` read where `salt` lives, say) fails here
/// rather than silently sending someone else's money to the wrong address.
#[test]
fn t_la_01_decode_golden_items_field_by_field() {
    for vector in accept_vectors() {
        let expected = vector.expected_struct();
        let decoded = decode_burn_payload(&vector.items_values())
            .unwrap_or_else(|e| panic!("{}: golden items must decode, got {e}", vector.id));

        assert_eq!(decoded.amount, expected.amount, "{}: amount", vector.id);
        assert_eq!(
            decoded.dest_domain, expected.dest_domain,
            "{}: destDomain",
            vector.id
        );
        assert_eq!(
            decoded.dest_recipient, expected.dest_recipient,
            "{}: destRecipient",
            vector.id
        );
        assert_eq!(decoded.salt, expected.salt, "{}: salt", vector.id);
        assert_eq!(decoded, expected, "{}: whole payload", vector.id);
    }
}

/// The decode is the shared encoding crate's decode — not a second one that happens to agree on
/// these vectors. The mapping into `BurnPayload` is 1:1 with `XReserveBurnItems`, asserted against
/// the codec's own output on the same felts (single-owner codec).
#[test]
fn t_la_01_decode_is_the_unit_04_codec_by_reference() {
    for vector in accept_vectors() {
        let items = vector.items_values();
        let via_module = decode_burn_payload(&items).expect("module decode");
        let via_codec = decode_burn_note_items(&items).expect("unit-04 decode");
        assert_eq!(
            via_module, via_codec,
            "{}: the module's payload IS the codec's",
            vector.id
        );
    }
}

/// Felt-exact round trip: re-encoding what was decoded reproduces the golden `NoteStorage.items`
/// felts bit for bit. A decoder that dropped, reordered, or truncated a field cannot survive this.
#[test]
fn t_la_01_decode_round_trips_to_the_golden_felts() {
    for vector in accept_vectors() {
        let golden = vector.items_values();
        let decoded = decode_burn_payload(&golden).expect("golden items decode");
        assert_eq!(
            encode_burn_note_items(&decoded),
            golden,
            "{}: re-encode reproduces the golden felts exactly",
            vector.id
        );
    }
}

/// The boundary vector: `amount` at the `AssetAmount` maximum and `destDomain` at `u32::MAX` decode
/// exactly, with no wraparound and no saturation.
#[test]
fn t_la_01_decodes_the_boundary_payload() {
    let vector = load()
        .families
        .bn
        .iter()
        .find(|x| x.id == "bn-pos-max")
        .expect("bn-pos-max vector present");
    let decoded = decode_burn_payload(&vector.items_values()).expect("max payload decodes");
    let expected = vector.expected_struct();
    assert_eq!(decoded.amount, expected.amount, "max amount is exact");
    assert_eq!(
        decoded.dest_domain,
        u32::MAX,
        "destDomain at the u32 boundary is exact"
    );
    assert_eq!(decoded, expected);
}

/// The typical vector carries a `destRecipient` and a `salt` that differ, so a decoder that swapped
/// the two 8-felt regions is caught rather than hidden behind the all-zero minimum vector.
#[test]
fn t_la_01_recipient_and_salt_are_not_interchangeable() {
    let vector = load()
        .families
        .bn
        .iter()
        .find(|x| x.id == "bn-pos-typical")
        .expect("bn-pos-typical vector present");
    let expected = vector.expected_struct();
    assert_ne!(
        expected.dest_recipient, expected.salt,
        "the vector itself must distinguish the two regions, or this test proves nothing"
    );
    let decoded = decode_burn_payload(&vector.items_values()).expect("typical payload decodes");
    assert_eq!(decoded.dest_recipient, expected.dest_recipient);
    assert_eq!(decoded.salt, expected.salt);
}

/// Every malformed-items vector — wrong felt count (short and long), an out-of-range `amount`, a
/// `destDomain` above `u32::MAX`, a non-`u32` limb in either bytes32 region — is REFUSED with the
/// exact crate variant, and nothing partial is surfaced.
#[rstest]
#[case("bn-rej-len-short")]
#[case("bn-rej-len-long")]
#[case("bn-rej-amount-over-cap")]
#[case("bn-rej-domain-over-u32")]
#[case("bn-rej-recipient-limb-not-u32")]
#[case("bn-rej-salt-limb-not-u32")]
fn t_la_01_malformed_items_are_refused_exactly(#[case] id: &str) {
    let vector = load()
        .families
        .bn
        .iter()
        .find(|x| x.id == id)
        .unwrap_or_else(|| panic!("vector {id} present"));

    assert_matches!(
        decode_burn_payload(&vector.items_values()),
        Err(DecodeError::BurnItemsMalformed {
            source: EncodingError::BurnItemsMalformed
        }),
        "{id}: malformed items must be refused with the exact variant",
    );
}

/// The shared encoding crate's verdict is PRESERVED as the error's source, not flattened into a
/// message: a caller can recover the concrete [`EncodingError`] the codec returned
/// (`preserve-error-source`).
#[test]
fn t_la_01_unit_04_error_is_preserved_as_the_source() {
    use core::error::Error;

    let short = &load()
        .families
        .bn
        .iter()
        .find(|x| x.id == "bn-rej-len-short")
        .expect("bn-rej-len-short present")
        .items_values();

    let err = decode_burn_payload(short).expect_err("short items are refused");
    let source = err.source().expect("the codec's error is preserved");
    assert_eq!(
        source.downcast_ref::<EncodingError>(),
        Some(&EncodingError::BurnItemsMalformed),
        "the source is the unit-04 error itself, still typed"
    );
}

/// Felt-count boundaries taken from a VALID payload: one felt short, one felt long, and empty. A
/// decoder that read the first fields and ignored the rest (or that padded a short vector) would
/// accept the truncation — it must not.
#[test]
fn t_la_01_felt_count_boundaries_are_refused() {
    let golden = load()
        .families
        .bn
        .iter()
        .find(|x| x.id == "bn-pos-typical")
        .expect("bn-pos-typical present")
        .items_values();
    assert_eq!(golden.len(), BURN_NOTE_ITEMS_FELTS);

    let mut long = golden.clone();
    long.push(felt(1));

    for (label, items) in [
        (
            "one felt short",
            golden[..BURN_NOTE_ITEMS_FELTS - 1].to_vec(),
        ),
        ("one felt long", long),
        ("empty", Vec::new()),
    ] {
        assert_matches!(
            decode_burn_payload(&items),
            Err(DecodeError::BurnItemsMalformed {
                source: EncodingError::BurnItemsMalformed
            }),
            "{label}: a felt count other than {BURN_NOTE_ITEMS_FELTS} is refused",
        );
    }
}

// (PURE) — SENDER READ (`metadata.sender` → the burner →
// `remoteDepositor`)
// ================================================================================================

/// `metadata.sender` is read and surfaced as the depositor, exactly (the burner IS exposed by
/// protocol — the spec must not claim otherwise, and the read must not lose it).
#[test]
fn t_la_04_sender_is_read_from_metadata() {
    for (sender, _) in golden_senders() {
        let meta = BurnNoteMetadata::from_metadata(&public_metadata(sender));
        let read = read_sender(&meta).expect("a public note's sender reads back");
        assert_eq!(read, sender, "the sender read is the burning account id");
        assert_eq!(
            account_id_to_felts(read),
            account_id_to_felts(sender),
            "both id felts survive — a prefix/suffix swap is not a round trip"
        );
    }
}

/// The value the read surfaces is the one that later becomes `remoteDepositor`: its bytes32 form
/// (the shared encoding crate's codec, consumed by reference) equals the golden vector's bytes32.
/// `sourceDepositor` is Circle's to fill server-side (and stays OPEN); this is the partner-built
/// side of that pair.
#[test]
fn t_la_04_sender_feeds_remote_depositor() {
    for (sender, bytes32) in golden_senders() {
        let read = read_sender(&BurnNoteMetadata::from_metadata(&public_metadata(sender)))
            .expect("sender reads back");
        assert_eq!(
            account_id_to_bytes32(read),
            bytes32,
            "the burner's bytes32 (= remoteDepositor) is the DC-6 encoding of the sender read"
        );
    }
}

/// A note that came back with no metadata at all — a PRIVATE or erased note (`details = None`,
/// unobservable to Circle) — yields NO depositor. Not a default, not a zero: an `Err`.
#[test]
fn t_la_04_absent_sender_is_refused() {
    assert_matches!(
        read_sender(&BurnNoteMetadata::absent()),
        Err(DecodeError::SenderAbsent)
    );
}

/// A zero sender is refused with its OWN variant, never promoted into a zero `remoteDepositor` —
/// which would attribute a real burn, and the USDC it releases, to an account that does not exist.
#[test]
fn t_la_04_zero_sender_is_refused() {
    assert_matches!(
        read_sender(&BurnNoteMetadata::from_raw_sender(felt(0), felt(0))),
        Err(DecodeError::SenderZero)
    );
}

/// A sender whose felts are not a canonical `AccountId` is refused, with the protocol's own
/// `AccountIdError` preserved as the source. The cases: an unknown id version in the prefix (zero,
/// and 2), and a suffix violating the id's low-bit constraint — each a felt pair a buggy or hostile
/// node could report.
#[rstest]
#[case::zero_prefix_unknown_version(0, 0x1234_5678_0000_0000)]
#[case::version_two_prefix(2, 0)]
fn t_la_04_non_canonical_sender_is_refused(#[case] prefix: u64, #[case] suffix: u64) {
    use core::error::Error;

    let err = read_sender(&BurnNoteMetadata::from_raw_sender(
        felt(prefix),
        felt(suffix),
    ))
    .expect_err("a non-canonical sender is refused");

    assert_matches!(err, DecodeError::SenderMalformed { .. });
    let source = err.source().expect("the AccountIdError is preserved");
    assert!(
        source
            .downcast_ref::<miden_protocol::errors::AccountIdError>()
            .is_some(),
        "the preserved source is the protocol's AccountIdError, still typed (got: {source})"
    );
}

/// A suffix that violates the account-id constraint (its low 8 bits must be zero) — built by
/// perturbing a VALID golden sender, so only the constraint changes.
#[test]
fn t_la_04_sender_with_invalid_suffix_is_refused() {
    let (sender, _) = golden_senders()[0];
    let [prefix, suffix] = account_id_to_felts(sender);
    let perturbed = felt(suffix.as_canonical_u64() + 1);
    assert_ne!(perturbed, suffix);

    assert_matches!(
        read_sender(&BurnNoteMetadata::from_raw_sender(prefix, perturbed)),
        Err(DecodeError::SenderMalformed { .. }),
        "a suffix violating the id constraint is refused, not silently reshaped"
    );
}

/// A raw sender that IS canonical reads back as that id — the raw path is not a rubber stamp that
/// rejects everything, and it agrees with the metadata path on the same account.
#[test]
fn t_la_04_canonical_raw_sender_reads_back() {
    for (sender, _) in golden_senders() {
        let [prefix, suffix] = account_id_to_felts(sender);
        let via_raw = read_sender(&BurnNoteMetadata::from_raw_sender(prefix, suffix))
            .expect("a canonical raw sender reads back");
        let via_metadata =
            read_sender(&BurnNoteMetadata::from_metadata(&public_metadata(sender))).expect("meta");
        assert_eq!(via_raw, sender);
        assert_eq!(via_raw, via_metadata, "both paths agree on the burner");
    }
}
