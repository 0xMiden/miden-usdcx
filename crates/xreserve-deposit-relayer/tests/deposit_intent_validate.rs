//! `tests/deposit_intent_validate.rs` — structural-validation harness for the off-chain
//! DepositIntent decoder (the component spec's module `deposit_intent_validate`; harness the
//! documented policy). No Circle call, no Miden: deterministic unit tests on
//! `decode_and_validate_deposit_intent`, the fast-fail mirror of the on-chain parse.
//!
//! **Oracle discipline.** Every accept/reject case is driven by the ONE canonical golden-vector
//! artifact (`xusdc_encoding::vectors::load()`, the DepositIntent `di` family) — the SAME artifact
//! that drives the shared encoding crate's own MASM + Rust tests. Field expectations come from the
//! vectors' independently generated `fields` / `len_felts` / `expected_variant`, NEVER from the
//! decoder's own offset accessor, so a drift between the relayer and the canonical DepositIntent
//! layout is detectable. Every rejection asserts the EXACT `RelayerError` variant (never
//! `is_err()`) AND that the EXACT originating `EncodingError` is preserved as its source (both via
//! the typed `encoding_source()` accessor and the std `Error::source()` chain) — a corruption of
//! the mapped source is caught.
//!
//! What this file covers — the harness and the per-field rejects live together here:
//! * `decode_well_formed_deposit_intent` — every field at its canonical offset.
//! * `deposit_intent_amount_not_reduced_offchain` — amount/maxFee carried RAW (no reduce).
//! * `deposit_intent_structural_reject` — per-field rejects, EXACT variant + source.
//! * `deposit_intent_felt_count_guard` — header is 60 felts (four bytes per felt, so 60 and never
//!   30), the full preimage `60 + ceil(hookDataLen/4)`, hookData AT its ceiling accepted and one
//!   byte past it rejected, and the >1024-felt overflow → PreimageTooLarge.

use std::error::Error;

use assert_matches::assert_matches;
use miden_protocol::utils::serde::Serializable;
use rstest::rstest;

use xreserve_deposit_relayer::error::RelayerError;
use xusdc_encoding::vectors::{load, DiVector};
use xusdc_encoding::xreserve::encoding::{
    DepositIntent, DepositIntentField, EncodingError, HookData,
};

/// The fixed DepositIntent header length (bytes), taken from the shared encoding crate (the single
/// owner of the 240-byte header) — the canonical `len_felts` independently confirms it as 60 felts.
const HEADER_LEN: usize = DepositIntent::HEADER_SIZE;

/// Fetches a canonical `di`-family vector by id (the artifact is the single source of test data).
fn di_by_id(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical DI vector `{id}` present in the artifact"))
}

/// Asserts a relayer rejection preserves the EXACT originating `EncodingError` from the shared
/// encoding crate. Pins the specific variant — not merely "some EncodingError" — through BOTH the
/// typed `encoding_source()` accessor and the std
/// `Error::source()` chain, so corrupting the mapped source (e.g. `variant(err)` →
/// `variant(EncodingError::BadMagic)`) fails a test.
fn assert_exact_source(err: &RelayerError, expected: &EncodingError) {
    // `encoding_source()` is an Option since the envelope-family variants are leaf errors with no
    // cause from the shared encoding crate; a DepositIntent-path variant must still carry its
    // exact originating error.
    assert_eq!(
        err.encoding_source(),
        Some(expected),
        "typed encoding_source() must be the originating EncodingError"
    );
    let std_source = err.source().and_then(|s| s.downcast_ref::<EncodingError>());
    assert_eq!(
        std_source,
        Some(expected),
        "std Error::source() chain must be the originating EncodingError"
    );
}

// ================================================================================================
// decode_well_formed_deposit_intent (every field at its exact
// canonical offset).
// The oracle is the vector's independently generated `fields`, NOT the decoder's offset accessor.
// ================================================================================================

#[rstest]
#[case::with_hookdata("di-pos-hookdata")]
#[case::empty_hookdata("di-pos-empty-hookdata")]
fn t_rly_12_decode_well_formed_all_offsets(#[case] id: &str) {
    let vector = di_by_id(id);
    let bytes = vector.bytes();
    let f = vector
        .fields
        .as_ref()
        .expect("accept vector carries per-field expectations");

    let di = DepositIntent::try_from(bytes.as_slice())
        .map_err(RelayerError::from_deposit_intent)
        .expect("a canonical accept vector must decode");

    // Every field is checked against the canonical (independent) expectation, through the bytes the
    // decode's inverse writes back: the wire form is what both sides of the seam agree on, and
    // checking it at the frozen offsets pins placement and value together. `magic` and `version`
    // are not fields at all — the decode already refused any payload that carries anything else,
    // which the reject rows below pin.
    let header = di.header();
    let written = di.to_bytes();
    for (name, field, label) in [
        ("amount", DepositIntentField::Amount, "amount@8"),
        (
            "remote_token",
            DepositIntentField::RemoteToken,
            "remoteToken@44",
        ),
        (
            "remote_recipient",
            DepositIntentField::RemoteRecipient,
            "remoteRecipient@76",
        ),
        (
            "local_token",
            DepositIntentField::LocalToken,
            "localToken@108",
        ),
        (
            "local_depositor",
            DepositIntentField::LocalDepositor,
            "localDepositor@140",
        ),
        ("max_fee", DepositIntentField::MaxFee, "maxFee@172"),
        ("nonce", DepositIntentField::Nonce, "nonce@204"),
    ] {
        let offset = field.offset();
        assert_eq!(&written[offset..offset + 32], &f.bytes32(name), "{label}");
    }
    assert_eq!(header.remote_domain(), f.remote_domain, "remoteDomain@40");
    assert_eq!(u64::from(header.amount()), f.amount, "amount, reduced");
    assert_eq!(u64::from(header.max_fee()), f.max_fee, "maxFee, reduced");
    assert_eq!(di.hook_data().len_u32(), f.hook_data_len, "hookDataLen@236");

    // hookData@240 and the re-encoded preimage relate to the exact payload bytes.
    assert_eq!(
        di.hook_data().as_bytes().len(),
        f.hook_data_len as usize,
        "hookData length"
    );
    assert_eq!(di.to_bytes(), bytes, "re-encoded preimage == payload");
    assert_eq!(
        di.to_bytes().len(),
        HEADER_LEN + f.hook_data_len as usize,
        "preimage length == 240 + hookDataLen"
    );
}

/// Validity by construction: the decoded type derives its own hookData length rather than trusting
/// the wire field, so the declared and actual lengths cannot disagree, and `preimage_felt_len`
/// follows from the bytes it will actually emit.
#[rstest]
#[case("di-pos-hookdata")]
#[case("di-pos-empty-hookdata")]
fn decoded_type_is_internally_consistent(#[case] id: &str) {
    let di = DepositIntent::try_from(di_by_id(id).bytes().as_slice())
        .map_err(RelayerError::from_deposit_intent)
        .expect("decodes");
    let hook_data_len = di.hook_data().as_bytes().len();
    assert_eq!(di.hook_data().len_u32() as usize, hook_data_len);
    assert_eq!(di.to_bytes().len(), HEADER_LEN + hook_data_len);
    assert_eq!(di.preimage_felt_len(), 60 + hook_data_len.div_ceil(4));
}

// ================================================================================================
// amount/maxFee survive the decode with every unit intact.
// The canonical amount 0x0f4240 (1_000_000) has non-zero low bytes: a decode that divided them away
// (any scale above zero) would both change the value AND change the bytes written back — and the
// bytes written back are what the faucet's signature is verified over, so the loss would be fatal
// rather than cosmetic. Both halves are asserted.
// ================================================================================================

#[rstest]
#[case::with_hookdata("di-pos-hookdata")]
#[case::empty_hookdata("di-pos-empty-hookdata")]
fn t_rly_13_amount_and_maxfee_survive_the_decode(#[case] id: &str) {
    let vector = di_by_id(id);
    let f = vector.fields.as_ref().expect("accept vector fields");
    let di = DepositIntent::try_from(vector.bytes().as_slice())
        .map_err(RelayerError::from_deposit_intent)
        .expect("decodes");

    assert_eq!(
        u64::from(di.header().amount()),
        f.amount,
        "amount keeps every unit the wire stated"
    );
    assert_eq!(
        u64::from(di.header().max_fee()),
        f.max_fee,
        "maxFee keeps every unit the wire stated"
    );

    // and writing it back reproduces the canonical 32-byte big-endian fields exactly
    let written = di.to_bytes();
    for (name, field) in [
        ("amount", DepositIntentField::Amount),
        ("max_fee", DepositIntentField::MaxFee),
    ] {
        let offset = field.offset();
        assert_eq!(
            &written[offset..offset + 32],
            &f.bytes32(name),
            "{name} is written back byte-for-byte"
        );
    }
}

// ================================================================================================
// deposit_intent_structural_reject (one rstest case per field, EXACT
// variant + source).
// Driven by the canonical DI rejection vectors; the expected relayer variant AND the exact
// originating EncodingError source are both pinned per case.
// ================================================================================================

#[derive(Clone, Copy, Debug)]
enum Expect {
    BadMagic,
    BadVersion,
    LengthMismatch,
    ZeroAmount,
    ZeroLocalToken,
    ZeroLocalDepositor,
    ShortHeader,
}

#[rstest]
#[case::bad_magic("di-rej-bad-magic", Expect::BadMagic, EncodingError::BadMagic)]
#[case::bad_version("di-rej-bad-version", Expect::BadVersion, EncodingError::BadVersion)]
#[case::length_mismatch(
    "di-rej-length-mismatch",
    Expect::LengthMismatch,
    EncodingError::LengthMismatch
)]
#[case::zero_amount("di-rej-zero-amount", Expect::ZeroAmount, EncodingError::ZeroField { field: DepositIntentField::Amount })]
#[case::zero_local_token("di-rej-zero-local-token", Expect::ZeroLocalToken, EncodingError::ZeroField { field: DepositIntentField::LocalToken })]
#[case::zero_local_depositor("di-rej-zero-local-depositor", Expect::ZeroLocalDepositor, EncodingError::ZeroField { field: DepositIntentField::LocalDepositor })]
#[case::truncated_header(
    "di-rej-truncated",
    Expect::ShortHeader,
    EncodingError::TruncatedHeader
)]
fn t_rly_08_structural_reject(
    #[case] id: &str,
    #[case] expect: Expect,
    #[case] expected_source: EncodingError,
) {
    let err = DepositIntent::try_from(di_by_id(id).bytes().as_slice())
        .map_err(RelayerError::from_deposit_intent)
        .expect_err("a canonical reject vector must be rejected");

    // (1) the exact field-specific outer variant...
    match expect {
        Expect::BadMagic => assert_matches!(&err, RelayerError::BadMagic(_)),
        Expect::BadVersion => assert_matches!(&err, RelayerError::BadVersion(_)),
        Expect::LengthMismatch => assert_matches!(&err, RelayerError::LengthMismatch(_)),
        Expect::ZeroAmount => assert_matches!(&err, RelayerError::ZeroAmount(_)),
        Expect::ZeroLocalToken => assert_matches!(&err, RelayerError::ZeroLocalToken(_)),
        Expect::ZeroLocalDepositor => assert_matches!(&err, RelayerError::ZeroLocalDepositor(_)),
        Expect::ShortHeader => assert_matches!(&err, RelayerError::ShortHeader(_)),
    }
    // (2)... and the EXACT originating EncodingError preserved as its source.
    assert_exact_source(&err, &expected_source);
}

/// An empty payload is a short header (below the 240-byte fixed header) — a relayer-specific
/// boundary the canonical corpus does not carry (it needs no artifact to construct).
#[test]
fn t_rly_08_empty_payload_is_short_header() {
    let err = DepositIntent::try_from([].as_slice())
        .map_err(RelayerError::from_deposit_intent)
        .expect_err("empty payload rejects");
    assert_matches!(&err, RelayerError::ShortHeader(_));
    assert_exact_source(&err, &EncodingError::TruncatedHeader);
}

// ================================================================================================
// deposit_intent_felt_count_guard (the same trap + both ceilings a payload has to pass: hookData's
// own, and the 1024-felt NoteStorage bound).
// The oracle is the vector's independent `len_felts` (60 / 63 / 1025); cross-checked against
// the shared encoding crate's authoritative packing.
// ================================================================================================

#[rstest]
#[case::empty_hookdata("di-pos-empty-hookdata", 60)]
#[case::with_hookdata("di-pos-hookdata", 63)]
fn t_rly_11_preimage_felt_count(#[case] id: &str, #[case] expected_felts: usize) {
    let vector = di_by_id(id);

    // The canonical artifact independently states the felt count (60 for the header, 63 with 10
    // bytes of hookData) — 60, never 240/8 = 30.
    assert_eq!(
        vector.len_felts as usize, expected_felts,
        "canonical len_felts"
    );
    assert_ne!(vector.len_felts, 30, "anti-ASG-16: never 240/8 = 30");

    let di = DepositIntent::try_from(vector.bytes().as_slice())
        .map_err(RelayerError::from_deposit_intent)
        .expect("decodes");
    // the decoder's own count matches the canonical artifact...
    assert_eq!(di.preimage_felt_len(), expected_felts);
    //... and matches the shared encoding crate's authoritative packing of the same payload.
    let packed =
        xusdc_encoding::xreserve::encoding::DepositIntent::try_from(vector.bytes().as_slice())
            .expect("packs")
            .to_preimage_felts();
    assert_eq!(di.preimage_felt_len(), packed.len());
}

#[test]
fn t_rly_11_maximal_hook_data_accepted() {
    // The INCLUSIVE upper bound, so an accidental `>=` reject cannot pass. What binds a payload is
    // hookData's own ceiling — how much the mint transport that delivers the deposit can still
    // carry past its fixed prefix — and it is TIGHTER than the 1024-felt NoteStorage bound the
    // overflow case below trips, so the largest accepted preimage is short of 1024 felts. The
    // canonical corpus has no vector at the ceiling, so this is a relayer-specific boundary
    // fixture: take a canonical accept vector (240-byte header, hookDataLen = 0) and extend it to
    // exactly that many hookData bytes. The length is taken from the shared encoding crate rather
    // than restated, so a change to the transport's fixed prefix moves this case with it. Only the
    // hookDataLen field is edited, at the crate's authoritative offset, so the field-decode oracle
    // stays canonical-vector-driven and this case pins the bound alone.
    let hook_len = u32::try_from(HookData::MAX_LEN).expect("the hookData ceiling fits its field");
    let expected_felts = HEADER_LEN / 4 + HookData::MAX_LEN.div_ceil(4);

    let mut payload = di_by_id("di-pos-empty-hookdata").bytes();
    assert_eq!(payload.len(), HEADER_LEN, "base vector is a bare header");

    let off = DepositIntentField::HookDataLen.offset();
    payload[off..off + 4].copy_from_slice(&hook_len.to_be_bytes());
    payload.resize(HEADER_LEN + HookData::MAX_LEN, 0u8);

    let di = DepositIntent::try_from(payload.as_slice())
        .map_err(RelayerError::from_deposit_intent)
        .expect("hookData AT the ceiling is accepted (inclusive bound)");
    assert_eq!(di.preimage_felt_len(), expected_felts);
    assert_eq!(
        xusdc_encoding::xreserve::encoding::DepositIntent::try_from(payload.as_slice())
            .expect("packs")
            .to_preimage_felts()
            .len(),
        expected_felts,
        "unit-04 packs the same payload to the same felt count"
    );
}

#[test]
fn t_rly_11_hook_data_one_byte_past_the_ceiling_rejected() {
    // The exclusive side of the same bound: one byte more than the case above must reject. Pairing
    // the two is what makes the ceiling INCLUSIVE rather than merely "somewhere around here" — the
    // canonical overflow vector below sits far past it and cannot tell the two apart.
    let hook_len =
        u32::try_from(HookData::MAX_LEN + 1).expect("one past the hookData ceiling fits its field");

    let mut payload = di_by_id("di-pos-empty-hookdata").bytes();
    let off = DepositIntentField::HookDataLen.offset();
    payload[off..off + 4].copy_from_slice(&hook_len.to_be_bytes());
    payload.resize(HEADER_LEN + HookData::MAX_LEN + 1, 0u8);

    let err = DepositIntent::try_from(payload.as_slice())
        .map_err(RelayerError::from_deposit_intent)
        .expect_err("hookData one byte past the ceiling must reject");
    assert_matches!(&err, RelayerError::PreimageTooLarge(_));
    assert_exact_source(&err, &EncodingError::HookDataTooLarge);
}

#[test]
fn t_rly_11_oversized_preimage_rejected() {
    // The canonical overflow vector is 1025 felts (> the 1024-felt NoteStorage bound).
    let vector = di_by_id("di-rej-hookdata-overflow");
    assert_eq!(vector.len_felts, 1025, "canonical overflow felt count");

    let err = DepositIntent::try_from(vector.bytes().as_slice())
        .map_err(RelayerError::from_deposit_intent)
        .expect_err("an over-bound preimage must reject");
    assert_matches!(&err, RelayerError::PreimageTooLarge(_));
    assert_exact_source(&err, &EncodingError::HookDataTooLarge);
}
