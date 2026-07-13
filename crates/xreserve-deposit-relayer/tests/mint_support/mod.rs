//! Shared fixtures for the mint-note suites (`mint_note_wire_form`, `mint_note_bounds`,
//! `mint_note_advice`).
//!
//! One thing here is load-bearing rather than convenient: [`Fixture`] can only hand a build request
//! a [`ValidatedAttestation`], and the only way to get one of those is through
//! `ValidatedAttestation::validate` — the `messageHash == keccak256(payload)` binding. So no test in
//! these suites can build a mint note out of bytes that were never bound to their digest, which is
//! exactly the invariant the production path relies on.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

use assert_matches::assert_matches;
use miden_protocol::account::AccountId;
use miden_protocol::note::NoteAttachmentScheme;
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::{Felt, Word};
use rand::RngCore;

use xreserve_deposit_relayer::circle::schema::{AttestationObject, ValidatedAttestation};
use xreserve_deposit_relayer::error::RelayerError;
use xreserve_deposit_relayer::miden::advice::AdviceMapSink;
use xreserve_deposit_relayer::miden::mint_note_builder::{
    build_mint_note, build_mint_note_with_entropy, BuiltMintNote, CsprngEntropy,
    MintNoteBuildRequest, SerialNumberEntropy,
};
use xusdc_encoding::note::xreserve_mint::XRESERVE_MINT_ATTACHMENT_SCHEME;
use xusdc_encoding::vectors::{load, DiVector};

use crate::fixtures::{canonical_payload, AttestationVector, PartnerAttester};

/// The canonical accept vector the suites build notes from (240-byte header, empty hookData).
pub const BASE_VECTOR: &str = "di-pos-empty-hookdata";

/// A felt is 4 bytes of the u32-LE preimage; a Word is 4 felts. Used only to state word-alignment
/// in assertions — the attachment LAYOUT itself is unit-04's, and is never restated here.
pub const FELTS_PER_WORD: usize = 4;

/// The faucet the mint note targets: a PUBLIC account (the F5 routing attachment binds a network
/// account, and `NetworkAccountTarget::new` rejects a non-public target).
pub fn faucet_id() -> AccountId {
    AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).expect("a valid public faucet id")
}

/// The relayer's own producer account — the note's sender. It carries no on-chain authority: the
/// mint is authorized by the attestation, not by who relayed it.
pub fn producer_id() -> AccountId {
    AccountId::try_from(ACCOUNT_ID_SENDER).expect("a valid sender id")
}

/// A FIXED serial-number seed: the note built from it is the same note every run, so a suite can
/// assert on a note's identity. Production draws this from the OS CSPRNG.
#[derive(Debug, Clone, Copy)]
pub struct FixedEntropy(pub u64);

impl SerialNumberEntropy for FixedEntropy {
    fn seed(&mut self) -> Result<[u32; 4], rand::Error> {
        Ok([self.0 as u32, (self.0 >> 32) as u32, 1, 2])
    }
}

/// The message the broken RNG reports, asserted verbatim downstream to prove the ORIGINAL cause
/// survives the trip into `RelayerError`.
pub const ENTROPY_FAILURE_MESSAGE: &str = "getrandom: entropy source unavailable";

/// A CSPRNG on a host whose `getrandom` has failed — modelled on `OsRng` EXACTLY:
///
/// - `try_fill_bytes` (the fallible call) returns the error;
/// - `fill_bytes` (the infallible one) **panics**, which is precisely what `OsRng` does when the OS
///   refuses (`rand_core::os`), and precisely why the production adapter must never reach for it.
///
/// Injecting this *beneath* the real [`CsprngEntropy`] adapter is what makes the entropy-failure
/// branch reachable. A fake that implemented `SerialNumberEntropy` directly would skip the adapter
/// entirely — and a regression that swapped the adapter's `try_fill` back to the panicking `fill`
/// would sail past a suite built on one.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailingRng;

impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        panic!("{ENTROPY_FAILURE_MESSAGE}")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("{ENTROPY_FAILURE_MESSAGE}")
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!("{ENTROPY_FAILURE_MESSAGE}")
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand::Error> {
        Err(rand::Error::new(std::io::Error::other(
            ENTROPY_FAILURE_MESSAGE,
        )))
    }
}

/// The PRODUCTION entropy adapter, with a broken CSPRNG under it — the same code path
/// `build_mint_note` runs, minus a working OS.
pub fn failing_entropy() -> CsprngEntropy<FailingRng> {
    CsprngEntropy::new(FailingRng)
}

/// Fetches a canonical `di`-family vector by id (the golden artifact is the single source of data).
pub fn di_by_id(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical DI vector `{id}` present in the artifact"))
}

/// The scheme-1 (attestation) attachment scheme as the protocol type.
pub fn attestation_scheme() -> NoteAttachmentScheme {
    NoteAttachmentScheme::new(XRESERVE_MINT_ATTACHMENT_SCHEME)
        .expect("the mint attestation scheme is a valid attachment scheme")
}

/// Asserts `err`'s SOURCE is exactly the expected unit-04 encoding error (the typed cause is
/// preserved, not flattened into a string).
pub fn assert_exact_source(
    err: &RelayerError,
    expected: &xusdc_encoding::xreserve::encoding::EncodingError,
) {
    use std::error::Error;

    let source = err
        .source()
        .unwrap_or_else(|| panic!("`{err}` preserves its unit-04 source"));
    let actual = source
        .downcast_ref::<xusdc_encoding::xreserve::encoding::EncodingError>()
        .unwrap_or_else(|| panic!("`{err}`'s source is an EncodingError"));
    assert_eq!(actual, expected, "the exact unit-04 cause is preserved");
}

/// Wraps a signed vector in the Circle wire shape and runs it through the REAL validation path —
/// there is no back door that mints a [`ValidatedAttestation`] without the keccak binding.
pub fn validated(vector: &AttestationVector) -> ValidatedAttestation {
    let object: AttestationObject = serde_json::from_value(serde_json::json!({
        "payload": vector.payload_hex(),
        "messageHash": vector.message_hash_hex(),
        "attestation": vector.attestation_hex(),
    }))
    .expect("the fixture decodes as the Circle wire object");

    ValidatedAttestation::validate(object).expect("the fixture attestation binds to its digest")
}

/// A validated attestation over a chosen payload, plus the attester's candidate pubkey — everything
/// `build_mint_note` needs.
pub struct Fixture {
    pub attestation: ValidatedAttestation,
    pub pubkey: [u8; 33],
}

impl Fixture {
    /// The partner attester's signature over a canonical golden payload.
    pub fn new(vector_id: &str) -> Self {
        Self::with_payload(canonical_payload(vector_id))
    }

    /// The partner attester's signature over a caller-chosen payload (the bound and reject cases
    /// craft their own). The DepositIntent may be malformed — the envelope binding is orthogonal to
    /// the DepositIntent structure, and `build_mint_note` is what must reject the latter.
    pub fn with_payload(payload: Vec<u8>) -> Self {
        let attester = PartnerAttester::new();
        Self {
            attestation: validated(&attester.attest(&payload)),
            pubkey: attester.pubkey(),
        }
    }

    /// The raw payload bytes the attestation is bound to.
    pub fn payload(&self) -> &[u8] {
        self.attestation.payload()
    }

    /// The 65-byte `r‖s‖v` signature.
    pub fn signature(&self) -> [u8; 65] {
        self.attestation.attestation()
    }

    pub fn request(&self) -> MintNoteBuildRequest<'_> {
        MintNoteBuildRequest::new(producer_id(), faucet_id(), &self.attestation, self.pubkey)
    }

    /// Builds through the seeded entropy source, so a suite that asserts on a note's identity gets
    /// the SAME note every run.
    pub fn build(&self, seed: u64) -> Result<BuiltMintNote, RelayerError> {
        build_mint_note_with_entropy(&self.request(), &mut FixedEntropy(seed))
    }

    pub fn built(&self, seed: u64) -> BuiltMintNote {
        self.build(seed).expect("the canonical mint note builds")
    }

    /// Builds through the PRODUCTION entry point — the one-argument `build_mint_note` the service
    /// actually calls, which draws its own serial number from the OS.
    pub fn build_production(&self) -> Result<BuiltMintNote, RelayerError> {
        build_mint_note(&self.request())
    }

    /// Builds against a caller-chosen entropy source (the failing one, in the negative cases).
    pub fn build_with_entropy<E: SerialNumberEntropy>(
        &self,
        entropy: &mut E,
    ) -> Result<BuiltMintNote, RelayerError> {
        build_mint_note_with_entropy(&self.request(), entropy)
    }
}

/// Asserts a permanent (non-retryable) rejection — a malformed payload or a crossed wire is not a
/// condition that clears, and re-submitting it would burn the rate budget the transient failures
/// need.
pub fn assert_permanent(err: &RelayerError) {
    assert!(
        !err.is_retryable(),
        "`{err}` is permanent: retrying re-submits identical bytes that must fail identically"
    );
}

/// Asserts the error is the crossed-wire refusal.
pub fn assert_attestation_mismatch(err: &RelayerError) {
    assert_matches!(err, RelayerError::AttestationMismatch);
    assert_permanent(err);
}

// THE T-RLY-16 ADVICE SINK FAKE (NON-GATING)
// ================================================================================================

/// A recording [`AdviceMapSink`] used ONLY for the fast note-construction feedback loop (T-RLY-16,
/// explicitly NON-GATING). It proves nothing about Miden: the production sink is the real
/// `miden-client` `TransactionRequestBuilder` (exercised for real in `mint_note_advice`), and the
/// gating end-to-end proof is T-RLY-14 against a real local node.
#[derive(Debug, Default)]
pub struct FakeAdviceSink {
    pub entries: Vec<(Word, Vec<Felt>)>,
}

impl AdviceMapSink for FakeAdviceSink {
    fn with_advice_entries(mut self, entries: Vec<(Word, Vec<Felt>)>) -> Self {
        self.entries.extend(entries);
        self
    }
}

impl FakeAdviceSink {
    pub fn get(&self, key: Word) -> Option<&[Felt]> {
        self.entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_slice())
    }
}
