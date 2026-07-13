//! The mint note's WIRE FORM: the note the relayer builds must be the exact post-F5
//! `XReserveMintNote` the faucet's `receive_and_mint` shim consumes.
//!
//! Every expectation here is pinned against an artifact this crate does not own — the unit-04
//! factory and codecs, and the pinned script-root constant. Nothing is re-derived: a test that
//! restated the layout could pass while the faucet rejected the note, which is the one outcome the
//! wire form exists to prevent.
//!
//! The script-root guard (`check_script_root`) is exercised here too, in both directions. The
//! happy-path suites cannot reach its failure branch — that would take linking a DIFFERENT xreserve
//! library than the one the crate ships, which is precisely the drift the guard exists to catch and
//! precisely what a test cannot fabricate — so the comparison is driven directly.

mod fixtures;
mod mint_support;

use assert_matches::assert_matches;
use miden_protocol::note::{NoteScriptRoot, NoteTag, NoteType};
use miden_protocol::{Felt, Word};
use miden_standards::note::NetworkAccountTarget;
use rstest::rstest;

use std::error::Error;

use xreserve_deposit_relayer::error::RelayerError;
use xreserve_deposit_relayer::miden::mint_note_builder::{
    build_mint_note_with_entropy, check_script_root, OsEntropy, SerialNumberEntropy,
};
use xusdc_encoding::note::xreserve_mint::{
    MintAttestation, XReserveMintNote, XRESERVE_MINT_ATTACHMENT_NUM_WORDS,
    XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX,
};
use xusdc_encoding::xreserve::encoding::{
    compressed_pubkey_felts, deposit_intent_to_packed_felts, signature_felts,
};

use mint_support::{
    attestation_scheme, di_by_id, failing_entropy, faucet_id, producer_id, Fixture, BASE_VECTOR,
    ENTROPY_FAILURE_MESSAGE, FELTS_PER_WORD,
};

// 1 — THE PINNED SCRIPT ROOT (compared, never recomputed)
// ================================================================================================

#[test]
fn mint_note_script_root_is_the_pinned_constant() {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(1);

    // The pinned constant, parsed independently of the factory: the builder must not "recompute" a
    // root and must not substitute a locally-assembled one.
    let pinned = NoteScriptRoot::from_raw(
        Word::parse(XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX).expect("the pinned root parses"),
    );

    assert_eq!(
        built.script_root(),
        pinned,
        "the built note's script root == the PINNED XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX"
    );
    assert_eq!(
        built.note().recipient().script().root(),
        XReserveMintNote::pinned_script_root(),
        "the NOTE ITSELF commits to the pinned root (the recipient is what the chain sees)"
    );
}

#[test]
fn the_pinned_script_root_is_accepted() {
    check_script_root(XReserveMintNote::pinned_script_root())
        .expect("the shipped library's root IS the pinned root (unit-04's parity test pins it)");
}

#[test]
fn a_drifted_script_root_is_refused_and_names_both_roots() {
    // The faucet is a v0.15 network account: its `AuthNetworkAccount` note-script allowlist is fixed
    // at account creation, and the ntx-builder runs ONLY notes whose root is on it. A note built
    // against a drifted library would be executed by nobody — it would sit in the pool while the
    // relayer reported success. Failing the BUILD is the only honest outcome.
    let drifted = NoteScriptRoot::from_raw(Word::from([Felt::from(7u32); 4]));

    let err = check_script_root(drifted)
        .expect_err("a root the faucet's allowlist does not carry must fail the BUILD");

    match err {
        RelayerError::ScriptRootMismatch { expected, actual } => {
            // Both roots are named: the operator has to diff the deployed faucet's allowlisted root
            // against the one this binary now produces, and a bare "mismatch" would not let them.
            assert_eq!(expected, XReserveMintNote::pinned_script_root().to_string());
            assert_eq!(actual, drifted.to_string());
        }
        other => panic!("expected ScriptRootMismatch, got {other}"),
    }
}

// 2 — PUBLIC, ASSET-LESS, ACCOUNT-TARGETED AT THE FAUCET
// ================================================================================================

#[test]
fn mint_note_is_public_asset_less_and_targets_the_faucet() {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(2);
    let note = built.note();

    assert_eq!(
        note.metadata().note_type(),
        NoteType::Public,
        "NoteType::Public is FORCED (the network-tx observability mandate)"
    );
    assert_eq!(
        note.metadata().tag(),
        NoteTag::with_account_target(faucet_id()),
        "the mint note carries the faucet account-target tag"
    );
    assert_eq!(
        note.metadata().sender(),
        producer_id(),
        "the sender is the relayer's producer account"
    );
    assert_eq!(
        note.assets().num_assets(),
        0,
        "the mint note carries NO assets (the faucet mints; it is not funded)"
    );
}

// 3 — NoteStorage.items == the unit-04 packing, felt-exact
// ================================================================================================

#[rstest]
#[case::empty_hookdata("di-pos-empty-hookdata")]
#[case::with_hookdata("di-pos-hookdata")]
fn mint_note_storage_is_the_unit04_packed_preimage(#[case] vector_id: &str) {
    let fx = Fixture::new(vector_id);
    let built = fx.built(3);

    let expected =
        deposit_intent_to_packed_felts(fx.payload()).expect("the canonical payload packs");
    assert_eq!(
        built.note().recipient().storage().items(),
        expected.as_slice(),
        "NoteStorage.items == deposit_intent_to_packed_felts(payload), felt-exact — the codec is \
         consumed BY REFERENCE, never re-implemented"
    );
    assert_eq!(
        built.preimage_felt_len(),
        expected.len(),
        "the reported felt length is the packed length"
    );
}

// 4 — EXACTLY THE TWO F5 ATTACHMENTS
// ================================================================================================

#[test]
fn mint_note_carries_exactly_the_two_f5_attachments() {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(4);
    let attachments = built.note().attachments();

    // The shim asserts `eq.2` on the attachment count and fails closed on anything else
    // (ERR_XRESERVE_MINT_NOTE_ATTACHMENT_COUNT).
    assert_eq!(
        attachments.num_attachments(),
        2,
        "exactly two attachments: the scheme-1 attestation + the scheme-2 routing target (F5)"
    );

    let schemes: Vec<_> = attachments.iter().map(|a| a.attachment_scheme()).collect();
    assert!(
        schemes.contains(&attestation_scheme()),
        "the scheme-1 attestation attachment is present"
    );
    assert!(
        schemes.contains(&NetworkAccountTarget::ATTACHMENT_SCHEME),
        "the scheme-2 NetworkAccountTarget routing attachment is present (routing-only)"
    );

    // The routing attachment binds THIS faucet — the ntx-builder routes on it.
    let target = NetworkAccountTarget::try_from(attachments)
        .expect("the routing attachment decodes as a NetworkAccountTarget");
    assert_eq!(
        target.target_id(),
        faucet_id(),
        "the routing target is the faucet the note is minted against"
    );
}

// 5 — THE ATTESTATION ATTACHMENT IS UNIT-04'S, NOT A LOCAL RECONSTRUCTION
// ================================================================================================

#[test]
fn mint_note_attestation_attachment_is_the_unit04_codec_output() {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(5);
    let attestation = built.attestation_attachment();

    // The ORACLE is unit-04's own exported attachment codec — the single owner of the
    // [feeAmount(8), pubkey(9), signature(17), pad(2)] layout (G1). This suite deliberately does NOT
    // restate that layout: a second definition of an owned format is exactly the drift seam the
    // ownership map forbids, and it would let the relayer and the faucet disagree in lockstep.
    let owned =
        XReserveMintNote::attestation_attachment(&MintAttestation::new(fx.signature(), fx.pubkey))
            .expect("unit-04 builds the attestation attachment for a well-formed attestation");

    assert_eq!(
        attestation.as_elements(),
        owned.as_elements(),
        "the note's attestation attachment IS unit-04's codec output, felt-exact"
    );
    assert_eq!(
        attestation.content().as_words().len(),
        XRESERVE_MINT_ATTACHMENT_NUM_WORDS,
        "9 words — the shim asserts exactly this (ERR_XRESERVE_MINT_NOTE_ATTACHMENT_NUM_WORDS)"
    );

    // …and the attested material really is in there, in unit-04's own felt encodings. Located by
    // SEARCH, not by a restated offset — the point is that the pubkey and signature are reachable,
    // not where this crate thinks unit-04 put them.
    let pubkey_felts = compressed_pubkey_felts(&fx.pubkey);
    let sig_felts = signature_felts(&fx.signature());
    let elements = attestation.as_elements();
    assert!(
        elements
            .windows(pubkey_felts.len())
            .any(|w| w == pubkey_felts),
        "the 9-felt candidate pubkey is carried in the attachment"
    );
    assert!(
        elements.windows(sig_felts.len()).any(|w| w == sig_felts),
        "the 17-felt signature is carried in the attachment"
    );
    assert_eq!(
        elements.len() % FELTS_PER_WORD,
        0,
        "the attachment is word-aligned"
    );
}

// 6 — THE PRODUCTION ENTRY POINT: `build_mint_note(&req)`, one argument
// ================================================================================================
//
// The service calls the one-argument form; it draws its own serial number rather than making every
// call site invent an entropy policy. The injectable variant (`build_mint_note_with_entropy`) exists
// so a test can assert on a note's identity, and so the entropy-FAILURE branch is reachable at all —
// it is the seam, not the contract.

#[test]
fn the_production_entry_point_builds_the_same_wire_form() {
    let fx = Fixture::new(BASE_VECTOR);

    let built = fx
        .build_production()
        .expect("the one-argument production entry point builds the canonical note");

    // Everything the faucet checks is identical to the seeded path — the RNG only picks the serial
    // number, and must not be able to reach any other part of the note.
    assert_eq!(
        built.script_root(),
        XReserveMintNote::pinned_script_root(),
        "the pinned script root"
    );
    assert_eq!(
        built.note().attachments().num_attachments(),
        2,
        "both F5 attachments"
    );
    assert_eq!(
        built.note().recipient().storage().items(),
        deposit_intent_to_packed_felts(fx.payload())
            .expect("the payload packs")
            .as_slice(),
        "the unit-04-packed preimage"
    );
    assert_eq!(
        built.note().metadata().tag(),
        NoteTag::with_account_target(faucet_id()),
        "the faucet account-target tag"
    );
    assert_eq!(
        built.attestation_attachment().as_elements(),
        XReserveMintNote::attestation_attachment(&MintAttestation::new(fx.signature(), fx.pubkey))
            .expect("unit-04 builds the attachment")
            .as_elements(),
        "the 04-owned attestation attachment"
    );
}

#[test]
fn the_production_entry_point_draws_a_fresh_serial_number_every_call() {
    let fx = Fixture::new(BASE_VECTOR);

    // Same request, twice. A serial number seeded from a constant would make these the SAME note —
    // and two identical notes cannot both be emitted (the second is a duplicate note id), so a
    // retry after a crash would be unable to re-submit at all. The entropy must be real.
    let first = fx.build_production().expect("first build");
    let second = fx.build_production().expect("second build");

    assert_ne!(
        first.id(),
        second.id(),
        "each call draws a FRESH serial number — a constant seed would mint one note id forever"
    );
    assert_ne!(
        first.note().recipient().serial_num(),
        second.note().recipient().serial_num(),
        "and the difference is in the serial number, which is the only thing the RNG may touch"
    );
}

#[test]
fn the_production_entry_point_enforces_the_same_guards() {
    // The one-argument form is not a back door around the bounds: it runs the same codec, the same
    // pinned-root check, and the same attachment check.
    let vector = di_by_id("di-rej-hookdata-overflow");
    let err = Fixture::with_payload(vector.bytes())
        .build_production()
        .expect_err("the production entry point rejects an over-bound preimage too");

    assert_matches!(&err, RelayerError::PreimageTooLarge(_));
    assert!(!err.is_retryable(), "and it is permanent");
}

// 7 — AN ENTROPY FAILURE IS A TYPED ERROR, NEVER A PANIC
// ================================================================================================
//
// `build_mint_note` advertises a `Result`. `Rng::fill` — the ergonomic wrapper — ABORTS the process
// when the OS source refuses, and a host whose `getrandom` was unavailable would then take the whole
// relayer down. This is a LIVENESS service: the one thing it must not do is stop relaying mints that
// are otherwise perfectly valid. The failure has to come back as an error the retry policy can act
// on, which means the production adapter must reach for the FALLIBLE `try_fill`.
//
// These cases run through `CsprngEntropy` — the REAL adapter — with a broken CSPRNG beneath it,
// because that is the only arrangement in which the choice between `try_fill` and `fill` is
// observable. A fake that implemented `SerialNumberEntropy` directly would never execute the adapter
// at all, and the panicking regression would walk straight back in under a green suite.

#[test]
fn the_production_adapter_uses_the_fallible_fill() {
    // Straight at the adapter: given an RNG that cannot produce bytes, `seed()` must RETURN the
    // failure. If it reached for `Rng::fill`, this would panic (that is exactly what `OsRng` does
    // when the OS refuses, and `FailingRng` models it faithfully) and the test would die instead of
    // asserting.
    let err = failing_entropy()
        .seed()
        .expect_err("the production adapter must RETURN an entropy failure, not panic on it");

    assert!(
        err.to_string().contains(ENTROPY_FAILURE_MESSAGE),
        "the adapter propagates the RNG's own error, got `{err}`"
    );
}

#[test]
fn the_production_adapter_seeds_from_the_real_os_source() {
    // The other half: against the REAL OS CSPRNG the adapter produces a usable, non-degenerate seed.
    // (The failure branch cannot be forced here — a test cannot take the OS's randomness away, which
    // is exactly why the adapter is generic over the RNG beneath it.)
    let first = OsEntropy::default().seed().expect("the OS CSPRNG seeds");
    let second = OsEntropy::default()
        .seed()
        .expect("the OS CSPRNG seeds again");

    assert_ne!(
        first, second,
        "the OS source yields a fresh seed each draw — a constant would make every note identical"
    );
    assert_ne!(first, [0u32; 4], "and it is not a degenerate all-zero seed");
}

#[test]
fn an_entropy_failure_is_a_typed_error_not_a_panic() {
    let fx = Fixture::new(BASE_VECTOR);

    let err = build_mint_note_with_entropy(&fx.request(), &mut failing_entropy())
        .expect_err("an entropy source that cannot produce randomness must ERROR, not panic");

    assert_matches!(&err, RelayerError::Entropy(_));

    // The original cause survives the trip BY TYPE, not merely by rendered text. Flattening the
    // `rand::Error` into a fresh error carrying the same message would keep every string assertion
    // green while destroying the structured chain an operator (or a `downcast_ref`) needs — so the
    // chain is pinned all the way down: RelayerError::Entropy -> rand::Error -> io::Error.
    let source = err
        .source()
        .expect("the entropy error preserves its source");
    let rand_error = source.downcast_ref::<rand::Error>().unwrap_or_else(|| {
        panic!("the immediate source is the CSPRNG's own rand::Error, not a re-stringified copy")
    });
    let os_error = rand_error
        .inner()
        .downcast_ref::<std::io::Error>()
        .expect("and the OS error underneath the rand::Error survives too");

    assert_eq!(os_error.kind(), std::io::ErrorKind::Other);
    assert!(
        os_error.to_string().contains(ENTROPY_FAILURE_MESSAGE),
        "the preserved OS error names the underlying failure, got `{os_error}`"
    );

    // And it is RETRYABLE: an exhausted or not-yet-seeded entropy pool is a host condition that
    // clears. Treating it as permanent would DROP a valid mint over a transient fault; the attempt
    // budget and its alert are what surface a host that never recovers.
    assert!(
        err.is_retryable(),
        "an entropy failure is transient — the mint must not be abandoned over it"
    );
}

#[test]
fn a_malformed_payload_is_rejected_even_when_entropy_fails() {
    // Ordering matters. The payload is checked BEFORE the serial number is drawn, so a permanently
    // malformed attestation reports as itself — `PreimageTooLarge`, permanent, do not retry — and is
    // not disguised as a transient entropy fault that the relayer would then retry forever.
    let err = Fixture::with_payload(di_by_id("di-rej-hookdata-overflow").bytes())
        .build_with_entropy(&mut failing_entropy())
        .expect_err("an over-bound preimage rejects regardless of the entropy source");

    assert_matches!(&err, RelayerError::PreimageTooLarge(_));
    assert!(
        !err.is_retryable(),
        "and it stays PERMANENT — a broken payload is not a transient host fault"
    );
}

// 8 — DETERMINISM: the serial number is the only source of note-id variation
// ================================================================================================

#[test]
fn mint_note_is_deterministic_in_its_serial_number() {
    let fx = Fixture::new(BASE_VECTOR);

    assert_eq!(
        fx.built(9).id(),
        fx.built(9).id(),
        "the same payload + attestation + serial number is the same note"
    );
    assert_ne!(
        fx.built(9).id(),
        fx.built(10).id(),
        "a fresh serial number is a fresh note — a resubmit is a NEW note, and safety against a \
         replay comes from the faucet's on-chain usedNonces assert-then-set, never from the note id"
    );
}
