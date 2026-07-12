//! `tests/deposit_intent_validate.rs` — structural-validation harness for the off-chain
//! DepositIntent decoder (COMPONENT-SPEC §4 module `deposit_intent_validate`; harness §4). No
//! Circle call, no Miden: deterministic unit tests on `decode_and_validate_deposit_intent`, the
//! fast-fail mirror of the on-chain D5a parse.
//!
//! **Oracle discipline.** Every accept/reject case is driven by the ONE canonical golden-vector
//! artifact (`xusdc_encoding::vectors::load()`, the DC-1 `di` family) — the SAME artifact that
//! drives unit-04's own MASM + Rust tests. Field expectations come from the vectors' independently
//! generated `fields` / `len_felts` / `expected_variant`, NEVER from the decoder's own offset
//! accessor, so a drift between the relayer and the canonical DC-1 layout is detectable. Every
//! rejection asserts the EXACT `RelayerError` variant (never `is_err()`) AND that the EXACT
//! originating `EncodingError` is preserved as its source (both via the typed `encoding_source()`
//! accessor and the std `Error::source()` chain) — a corruption of the mapped source is caught.
//!
//! Covered (harness §4 + §3.2 co-located per the harness note that T-RLY-08's per-field rejects may
//! live in this module):
//!   * T-RLY-12 `decode_well_formed_deposit_intent`         — every field at its DC-1 offset.
//!   * T-RLY-13 `deposit_intent_amount_not_reduced_offchain` — amount/maxFee carried RAW (no reduce).
//!   * T-RLY-08 `deposit_intent_structural_reject`          — per-field rejects, EXACT variant + source.
//!   * T-RLY-11 `deposit_intent_felt_count_guard`           — header is 60 felts (anti-ASG-16), the full
//!                                                            preimage `60 + ceil(hookDataLen/4)`, the
//!                                                            INCLUSIVE 1024-felt bound accepted, and
//!                                                            the >1024-felt overflow → PreimageTooLarge.

use std::error::Error;

use assert_matches::assert_matches;
use rstest::rstest;

use xreserve_deposit_relayer::error::RelayerError;
use xreserve_deposit_relayer::validate::deposit_intent::decode_and_validate_deposit_intent;
use xusdc_encoding::vectors::{load, DiVector};
use xusdc_encoding::xreserve::encoding::{
    deposit_intent_field_offset, deposit_intent_to_packed_felts, DepositIntentField, EncodingError,
    DEPOSIT_INTENT_HEADER_LEN,
};

/// The fixed DC-1 header length (bytes), taken from unit-04 (the single owner of the 240-byte
/// header) — the canonical `len_felts` independently confirms it as 60 felts.
const HEADER_LEN: usize = DEPOSIT_INTENT_HEADER_LEN;

/// Fetches a canonical `di`-family vector by id (the artifact is the single source of test data).
fn di_by_id(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical DI vector `{id}` present in the artifact"))
}

/// Asserts a relayer rejection preserves the EXACT originating unit-04 `EncodingError` (G-RUST
/// preserve-error-source). Pins the specific variant — not merely "some EncodingError" — through
/// BOTH the typed `encoding_source()` accessor and the std `Error::source()` chain, so corrupting
/// the mapped source (e.g. `variant(err)` → `variant(EncodingError::BadMagic)`) fails a test.
fn assert_exact_source(err: &RelayerError, expected: &EncodingError) {
    assert_eq!(
        err.encoding_source(),
        expected,
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
// T-RLY-12 — decode_well_formed_deposit_intent (every field at its exact DC-1 offset).
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

    let di =
        decode_and_validate_deposit_intent(&bytes).expect("a canonical accept vector must decode");

    // Every field is checked against the canonical (independent) expectation.
    assert_eq!(di.magic(), f.magic, "magic@0");
    assert_eq!(di.version(), f.version, "version@4");
    assert_eq!(di.amount(), &f.bytes32("amount"), "amount@8");
    assert_eq!(di.remote_domain(), f.remote_domain, "remoteDomain@40");
    assert_eq!(
        di.remote_token(),
        &f.bytes32("remote_token"),
        "remoteToken@44"
    );
    assert_eq!(
        di.remote_recipient(),
        &f.bytes32("remote_recipient"),
        "remoteRecipient@76"
    );
    assert_eq!(
        di.local_token(),
        &f.bytes32("local_token"),
        "localToken@108"
    );
    assert_eq!(
        di.local_depositor(),
        &f.bytes32("local_depositor"),
        "localDepositor@140"
    );
    assert_eq!(di.max_fee(), &f.bytes32("max_fee"), "maxFee@172");
    assert_eq!(di.nonce(), &f.bytes32("nonce"), "nonce@204");
    assert_eq!(di.hook_data_len(), f.hook_data_len, "hookDataLen@236");

    // hookData@240 and the raw preimage relate to the exact payload bytes.
    assert_eq!(
        di.hook_data().len(),
        f.hook_data_len as usize,
        "hookData length"
    );
    assert_eq!(
        di.raw_preimage(),
        bytes.as_slice(),
        "raw preimage == payload"
    );
    assert_eq!(
        di.raw_preimage().len(),
        HEADER_LEN + f.hook_data_len as usize,
        "raw preimage length == 240 + hookDataLen"
    );
}

/// Validity by construction: the decoder is the ONLY way to obtain a `DepositIntent`, so its
/// private fields cannot disagree — `hook_data`, `hook_data_len`, and `raw_preimage` are always
/// mutually consistent, and `preimage_felt_len` is derived from the actual bytes, not a trusted
/// length field.
#[rstest]
#[case("di-pos-hookdata")]
#[case("di-pos-empty-hookdata")]
fn decoded_type_is_internally_consistent(#[case] id: &str) {
    let di = decode_and_validate_deposit_intent(&di_by_id(id).bytes()).expect("decodes");
    assert_eq!(di.hook_data().len(), di.hook_data_len() as usize);
    assert_eq!(
        di.raw_preimage().len(),
        HEADER_LEN + di.hook_data_len() as usize
    );
    assert_eq!(
        di.preimage_felt_len(),
        60 + (di.hook_data_len() as usize).div_ceil(4)
    );
}

// ================================================================================================
// T-RLY-13 — amount/maxFee NOT reduced off-chain (carried raw).
// The canonical amount 0x0f4240 (1_000_000) has non-zero low bytes: any uint256 → AssetAmount
// reduction (÷ 10^scale) would change these bytes (e.g. to 0x01), so raw preservation catches it.
// ================================================================================================

#[rstest]
#[case::with_hookdata("di-pos-hookdata")]
#[case::empty_hookdata("di-pos-empty-hookdata")]
fn t_rly_13_amount_and_maxfee_carried_raw(#[case] id: &str) {
    let vector = di_by_id(id);
    let f = vector.fields.as_ref().expect("accept vector fields");
    let di = decode_and_validate_deposit_intent(&vector.bytes()).expect("decodes");

    // byte-for-byte the canonical 32-byte big-endian value — NO reduction / scaling.
    assert_eq!(
        di.amount(),
        &f.bytes32("amount"),
        "amount carried raw (reduction is on-chain at D5b)"
    );
    assert_eq!(di.max_fee(), &f.bytes32("max_fee"), "maxFee carried raw");
}

// ================================================================================================
// T-RLY-08 — deposit_intent_structural_reject (one rstest case per field, EXACT variant + source).
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
    let err = decode_and_validate_deposit_intent(&di_by_id(id).bytes())
        .expect_err("a canonical reject vector must be rejected");

    // (1) the exact field-specific outer variant ...
    match expect {
        Expect::BadMagic => assert_matches!(&err, RelayerError::BadMagic(_)),
        Expect::BadVersion => assert_matches!(&err, RelayerError::BadVersion(_)),
        Expect::LengthMismatch => assert_matches!(&err, RelayerError::LengthMismatch(_)),
        Expect::ZeroAmount => assert_matches!(&err, RelayerError::ZeroAmount(_)),
        Expect::ZeroLocalToken => assert_matches!(&err, RelayerError::ZeroLocalToken(_)),
        Expect::ZeroLocalDepositor => assert_matches!(&err, RelayerError::ZeroLocalDepositor(_)),
        Expect::ShortHeader => assert_matches!(&err, RelayerError::ShortHeader(_)),
    }
    // (2) ... and the EXACT originating EncodingError preserved as its source.
    assert_exact_source(&err, &expected_source);
}

/// An empty payload is a short header (below the 240-byte fixed header) — a relayer-specific
/// boundary the canonical corpus does not carry (it needs no artifact to construct).
#[test]
fn t_rly_08_empty_payload_is_short_header() {
    let err = decode_and_validate_deposit_intent(&[]).expect_err("empty payload rejects");
    assert_matches!(&err, RelayerError::ShortHeader(_));
    assert_exact_source(&err, &EncodingError::TruncatedHeader);
}

// ================================================================================================
// T-RLY-11 — deposit_intent_felt_count_guard (anti-ASG-16 + the 1024-felt NoteStorage bound).
// The oracle is the vector's independent `len_felts` (60 / 63 / 1025); cross-checked against
// unit-04's authoritative packing.
// ================================================================================================

#[rstest]
#[case::empty_hookdata("di-pos-empty-hookdata", 60)]
#[case::with_hookdata("di-pos-hookdata", 63)]
fn t_rly_11_preimage_felt_count(#[case] id: &str, #[case] expected_felts: usize) {
    let vector = di_by_id(id);

    // The canonical artifact independently states the felt count (60 for the header, 63 with 10
    // bytes of hookData) — anti-ASG-16: 60, never 240/8 = 30.
    assert_eq!(
        vector.len_felts as usize, expected_felts,
        "canonical len_felts"
    );
    assert_ne!(vector.len_felts, 30, "anti-ASG-16: never 240/8 = 30");

    let di = decode_and_validate_deposit_intent(&vector.bytes()).expect("decodes");
    // the decoder's own count matches the canonical artifact ...
    assert_eq!(di.preimage_felt_len(), expected_felts);
    // ... and matches unit-04's authoritative packing of the same payload.
    let packed = deposit_intent_to_packed_felts(&vector.bytes()).expect("packs");
    assert_eq!(di.preimage_felt_len(), packed.len());
}

#[test]
fn t_rly_11_preimage_exactly_1024_felts_accepted() {
    // The INCLUSIVE upper bound: a preimage of EXACTLY 1024 felts must be accepted (so an accidental
    // `>= 1024` reject cannot pass). The canonical corpus has 60 / 63 / 1025 but not 1024, so this
    // is a relayer-specific boundary fixture: take a canonical accept vector (240-byte header,
    // hookDataLen = 0) and extend it to 240 + 3856 = 4096 bytes = exactly 1024 u32-LE felts
    // (60 header felts + ceil(3856/4) = 60 + 964). Only the hookDataLen field is edited, at
    // unit-04's authoritative offset — the field-decode oracle stays the canonical-vector-driven
    // T-RLY-12; this case pins the felt-count bound alone.
    const HOOK_LEN: u32 = 3856;
    let mut payload = di_by_id("di-pos-empty-hookdata").bytes();
    assert_eq!(payload.len(), HEADER_LEN, "base vector is a bare header");

    let off = deposit_intent_field_offset(DepositIntentField::HookDataLen);
    payload[off..off + 4].copy_from_slice(&HOOK_LEN.to_be_bytes());
    payload.resize(HEADER_LEN + HOOK_LEN as usize, 0u8);

    let di = decode_and_validate_deposit_intent(&payload)
        .expect("a preimage of exactly 1024 felts is accepted (inclusive bound)");
    assert_eq!(di.preimage_felt_len(), 1024);
    assert_eq!(
        deposit_intent_to_packed_felts(&payload)
            .expect("packs")
            .len(),
        1024,
        "unit-04 packs the same payload to exactly 1024 felts"
    );
}

#[test]
fn t_rly_11_oversized_preimage_rejected() {
    // The canonical overflow vector is 1025 felts (> the 1024-felt NoteStorage bound).
    let vector = di_by_id("di-rej-hookdata-overflow");
    assert_eq!(vector.len_felts, 1025, "canonical overflow felt count");

    let err = decode_and_validate_deposit_intent(&vector.bytes())
        .expect_err("an over-bound preimage must reject");
    assert_matches!(&err, RelayerError::PreimageTooLarge(_));
    assert_exact_source(&err, &EncodingError::HookDataTooLarge);
}
