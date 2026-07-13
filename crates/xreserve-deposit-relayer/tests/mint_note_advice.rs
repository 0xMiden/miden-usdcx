//! RIV-ADVICE-KEY — the advice-map witness, and the key the faucet actually reads.
//!
//! The spec paraphrase (`COMPONENT-SPEC.md:215`, itself labelled `REQUIRES IMPLEMENTATION
//! VALIDATION`) says the sig + pubkey go into the advice map "keyed by the note commitment". The
//! on-chain reader says otherwise: `xreserve_mint_note_entry.masm` loads the scheme-1 attachment's
//! COMMITMENT out of the note-committed attachment-commitments list — by its found index — and
//! calls `adv.push_mapval` on that word. The key is therefore a hash of the attested bytes
//! themselves, never the note id, and never anything the relayer picks.
//!
//! That contradiction was reported (G5's STOP rule) and ADJUDICATED by the human operator on
//! 2026-07-13: the on-chain reader governs. `RIV-ADVICE-KEY.md` is the record. These tests pin the
//! decision so it cannot be quietly reverted — including the negative
//! (`advice_key_is_not_the_note_id_the_pre_f5_spec_paraphrased`), which fails if anyone "fixes" the
//! code back towards the stale paraphrase.
//!
//! The production sink is the REAL `miden-client` `TransactionRequestBuilder`
//! (`populate_advice_feeds_the_real_transaction_request_builder`) — the fake is the NON-GATING
//! T-RLY-16 speed check only, and is labelled as such.

mod fixtures;
mod mint_support;

use miden_client::transaction::TransactionRequestBuilder;
use miden_protocol::note::NoteId;
use miden_protocol::Word;
use rstest::rstest;

use xreserve_deposit_relayer::miden::advice::{mint_note_advice_entries, populate_advice};
use xusdc_encoding::xreserve::encoding::{compressed_pubkey_felts, signature_felts};

use fixtures::{PartnerAttester, FOREIGN_KEY_SEED};
use mint_support::{
    assert_attestation_mismatch, attestation_scheme, validated, FakeAdviceSink, Fixture,
    BASE_VECTOR, FELTS_PER_WORD,
};

// 1 — THE PRODUCTION SURFACE: the real miden-client TransactionRequestBuilder
// ================================================================================================

#[test]
fn populate_advice_feeds_the_real_transaction_request_builder() {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(1);

    // The real builder, the real `extend_advice_map` (which CONSUMES self — hence the consuming
    // sink), the real `TransactionRequest`. No fake anywhere on this path.
    let request = populate_advice(
        TransactionRequestBuilder::new(),
        &built,
        &fx.signature(),
        &fx.pubkey,
    )
    .expect("advice populates")
    .build()
    .expect("the transaction request builds");

    let attestation = built.attestation_attachment();
    let key = attestation.content().to_commitment();

    let value = request.advice_map().get(&key).expect(
        "the REAL request's advice map carries the attestation under its CONTENT COMMITMENT",
    );
    assert_eq!(
        &value[..],
        attestation.as_elements(),
        "the value is the attachment's own elements — the exact preimage the shim's \
         `write_attachment_to_memory` hash-check binds to that commitment"
    );

    // Both attachments are resolvable: the PRODUCER tx resolves each by commitment when it emits the
    // note (`output_note::add_attachment`), so publishing only the attestation would leave the note
    // unemittable and it would never reach the faucet at all.
    for attachment in built.note().attachments().iter() {
        let entry = request
            .advice_map()
            .get(&attachment.content().to_commitment())
            .unwrap_or_else(|| {
                panic!(
                    "attachment scheme {} is published under its commitment",
                    attachment.attachment_scheme()
                )
            });
        assert_eq!(&entry[..], attachment.as_elements());
    }
}

// 2 — THE RECONCILED KEY: the attestation attachment's CONTENT COMMITMENT
// ================================================================================================

#[test]
fn advice_key_is_the_attestation_attachment_commitment() {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(2);

    let sink = populate_advice(
        FakeAdviceSink::default(),
        &built,
        &fx.signature(),
        &fx.pubkey,
    )
    .expect("advice populates");

    let attestation = built.attestation_attachment();
    let value = sink
        .get(attestation.content().to_commitment())
        .expect("the advice map carries the attestation under its content commitment");

    assert_eq!(value, attestation.as_elements());
    assert_eq!(
        value.len() % FELTS_PER_WORD,
        0,
        "the advice value is word-aligned"
    );

    // The attested material is reachable in advice at submission time — the relayer-side contract
    // the spec actually asks for. Located by SEARCH, not by a restated offset: unit-04 owns where
    // in the attachment they sit.
    let pubkey_felts = compressed_pubkey_felts(&fx.pubkey);
    let sig_felts = signature_felts(&fx.signature());
    assert!(
        value.windows(pubkey_felts.len()).any(|w| w == pubkey_felts),
        "the 9-felt candidate pubkey is reachable in advice"
    );
    assert!(
        value.windows(sig_felts.len()).any(|w| w == sig_felts),
        "the 17-felt signature is reachable in advice"
    );
}

// 3 — THE NEGATIVE HALF OF THE ADJUDICATION: it is NOT the note id
// ================================================================================================

#[test]
fn advice_key_is_not_the_note_id_the_pre_f5_spec_paraphrased() {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(3);

    let entries =
        mint_note_advice_entries(&built, &fx.signature(), &fx.pubkey).expect("entries compute");

    // A note-id-keyed entry would leave `adv.push_mapval` with nothing under the word it actually
    // pushes: the mint would fail closed on-chain, every time, for every deposit.
    assert!(
        entries
            .iter()
            .all(|(key, _)| NoteId::from_raw(*key) != built.id()),
        "no advice entry is keyed by the note id (the pre-F5 paraphrase)"
    );

    // The keys are EXACTLY the attachment content commitments — nothing else is published.
    let expected: Vec<Word> = built
        .note()
        .attachments()
        .iter()
        .map(|a| a.content().to_commitment())
        .collect();
    let actual: Vec<Word> = entries.iter().map(|(key, _)| *key).collect();
    assert_eq!(
        actual, expected,
        "the advice keys are exactly the note's attachment content commitments"
    );
    assert!(!entries.is_empty(), "and there is something to key");
}

// 4 — REPRODUCE THE SHIM'S OWN INDEX MATH
// ================================================================================================

#[test]
fn advice_key_matches_the_masm_indexed_commitment_load() {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(4);

    let sink = populate_advice(
        FakeAdviceSink::default(),
        &built,
        &fx.signature(),
        &fx.pubkey,
    )
    .expect("advice populates");

    // `xreserve_mint_note_entry.masm`: `find_attachment(scheme 1)` yields sc1_idx;
    // `write_attachment_commitments_to_memory` writes the note-committed commitments list; the shim
    // loads the word at `commitments_base + sc1_idx * WORD_NUM_ELEMENTS` and `adv.push_mapval`s it.
    // Reproduce that selection: the commitment of the attachment AT THE FOUND INDEX.
    let sc1_idx = built
        .note()
        .attachments()
        .iter()
        .position(|a| a.attachment_scheme() == attestation_scheme())
        .expect("the scheme-1 attestation is found by scheme, as `find_attachment` does");
    let commitment_at_index = built
        .note()
        .attachments()
        .iter()
        .nth(sc1_idx)
        .expect("the attachment at the found index")
        .content()
        .to_commitment();

    let value = sink.get(commitment_at_index).expect(
        "the word the shim pushes to `adv.push_mapval` resolves to an entry the relayer published",
    );
    assert_eq!(
        value,
        built.attestation_attachment().as_elements(),
        "and it resolves to the attestation the faucet then hash-verifies"
    );
}

// 5 — FAIL-CLOSED: an attestation the note does not carry is refused, and NOTHING is written
// ================================================================================================

#[rstest]
#[case::foreign_signature(true, false)]
#[case::foreign_pubkey(false, true)]
#[case::both_foreign(true, true)]
fn populate_advice_refuses_an_attestation_the_note_does_not_carry(
    #[case] swap_sig: bool,
    #[case] swap_pubkey: bool,
) {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(5);

    // A DIFFERENT attester's material, handed to `populate_advice` alongside a note built from the
    // partner's. Publishing a witness that disagrees with the note's committed attachment would
    // produce a note the faucet rejects on-chain (the shim's hash check) — so the crossed wire must
    // surface HERE, off-chain, where it costs nothing.
    let foreign = PartnerAttester::with_seed(FOREIGN_KEY_SEED);
    let foreign_attestation = validated(&foreign.attest(fx.payload()));

    let sig = if swap_sig {
        foreign_attestation.attestation()
    } else {
        fx.signature()
    };
    let pubkey = if swap_pubkey {
        foreign.pubkey()
    } else {
        fx.pubkey
    };

    let err = populate_advice(FakeAdviceSink::default(), &built, &sig, &pubkey)
        .expect_err("an attestation the note does not commit to must be refused");
    assert_attestation_mismatch(&err);

    // Fail-closed all the way to the REAL builder: nothing reaches the request either.
    let err = populate_advice(TransactionRequestBuilder::new(), &built, &sig, &pubkey)
        .expect_err("the real builder is refused the same way");
    assert_attestation_mismatch(&err);

    // The direct helper refuses it too, with the SAME specific variant — `Err(_)` would still pass
    // if this ever regressed into some unrelated failure (G4: negative tests assert the exact error).
    let err = mint_note_advice_entries(&built, &sig, &pubkey)
        .expect_err("no entries are produced at all");
    assert_attestation_mismatch(&err);
}

// 6 — T-RLY-16 (NON-GATING): the adapter fake, labelled
// ================================================================================================

#[test]
fn t_rly_16_non_gating_miden_adapter_fake_speed_check() {
    let fx = Fixture::new(BASE_VECTOR);
    let built = fx.built(6);

    let sink = populate_advice(
        FakeAdviceSink::default(),
        &built,
        &fx.signature(),
        &fx.pubkey,
    )
    .expect("advice populates");

    assert_eq!(sink.entries.len(), 2, "both attachments are published");

    // NON-GATING, and it is not load-bearing: the production surface is proven against the real
    // `TransactionRequestBuilder` above, and the gating end-to-end proof that the faucet ACCEPTS the
    // note is T-RLY-14 against a real local node (R6). Miden behaviour is never faked for
    // acceptance (TEST-AND-VERIFICATION-HARNESS.md:277).
}

// 7 — THE ADJUDICATED RECONCILIATION IS ON THE RECORD
// ================================================================================================

#[test]
fn riv_advice_key_reconciliation_is_documented() {
    let doc = include_str!("../RIV-ADVICE-KEY.md");

    assert!(
        doc.contains("attachment") && doc.contains("commitment"),
        "the note records the reconciled key: the attestation attachment's content commitment"
    );
    assert!(
        doc.contains("xreserve_mint_note_entry.masm"),
        "the note cites the on-chain reader it was reconciled against"
    );
    assert!(
        doc.contains("COMPONENT-SPEC.md:215"),
        "the note cites the spec line it contradicts (the note-commitment paraphrase)"
    );
    assert!(
        doc.contains("ADJUDICATED"),
        "the note records the human adjudication of the G5 STOP — the loop did not decide this on \
         its own authority"
    );
    assert!(
        doc.contains("REQUIRES IMPLEMENTATION VALIDATION"),
        "and the RIV label is PRESERVED — the on-chain proof is T-RLY-14 (R6), not this slice"
    );
}
