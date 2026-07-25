//! `tests/mint_support/mod.rs` — the shared scaffolding for the mint-note-builder suite.
//!
//! Everything here either (a) drives the relayer's OWN validated boundary
//! ([`ValidatedAttestation`], built from the wire JSON exactly as the Circle client builds it), or
//! (b) reaches for a value the PROTOCOL owns (an `AccountId`, an RNG). Nothing here restates a
//! layout unit-04 owns — the note's storage packing, its attachment content, its script root and
//! its tag are all read back through unit-04's / the protocol's own API in the tests themselves.
//!
//! The attestation vectors come from [`crate::fixtures`] — the one partner-attester fixture every
//! relayer slice shares (a real secp256k1 key over a real keccak digest of a canonical DC-1
//! payload), so the mint-note suite cannot drift onto a second, divergent key.

#![allow(dead_code)] // a shared fixture: each integration test uses the subset it needs.

use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::{Felt, Word};

use xreserve_deposit_relayer::circle::schema::{AttestationObject, ValidatedAttestation};
use xreserve_deposit_relayer::miden::AttesterPubkey;

use crate::fixtures::{canonical_payload, AttestationVector, PartnerAttester};

/// A DETERMINISTIC note RNG. The serial number a mint note carries is drawn from it, so seeding it
/// is what lets a test build the SAME note twice — once through the relayer, once through unit-04's
/// factory directly — and compare them for equality. Production draws from OS entropy; determinism
/// here is a property of the test, not of the builder (which is generic over the `FeltRng`).
pub fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(1u32),
        Felt::from(2u32),
    ]))
}

/// The relayer's own account — the note's sender/producer. Private is the realistic shape for an
/// operator-held key; nothing about the sender has to be public.
pub fn relayer_sender_id() -> AccountId {
    AccountId::dummy(
        [0x11; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

/// The xUSDC faucet — a PUBLIC (network) account. The mint note's scheme-2 routing attachment binds
/// the faucet's network account, and only a public id can be bound; the private id below is the
/// negative.
pub fn faucet_id() -> AccountId {
    AccountId::dummy(
        [0x22; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// A second, different PUBLIC faucet — proves the tag/routing bind actually follows the argument.
pub fn other_faucet_id() -> AccountId {
    AccountId::dummy(
        [0x33; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// A PRIVATE account id in the faucet position — the faucet of a network mint cannot be private
/// (the note could not be routed to it), and the builder must refuse it rather than emit a note
/// nothing will ever consume.
pub fn private_faucet_id() -> AccountId {
    AccountId::dummy(
        [0x44; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

/// The operator-configured attester key: the partner fixture's 33-byte compressed SEC1 pubkey.
///
/// It is CONFIGURATION, not a Circle response field — Circle's attestation object carries only
/// `payload` / `messageHash` / `attestation`, so the key the faucet's allowlist commitment (DC-3)
/// is derived from reaches the relayer through its config, and the builder takes it as an argument.
pub fn attester_pubkey() -> AttesterPubkey {
    AttesterPubkey::new(PartnerAttester::new().pubkey()).expect("the partner key is a curve point")
}

/// A genuinely DIFFERENT attester key (the fixture's foreign signer) — used to prove the attachment
/// really carries the pubkey it was handed, rather than a hardcoded one.
pub fn foreign_attester_pubkey() -> AttesterPubkey {
    AttesterPubkey::new(PartnerAttester::with_seed(crate::fixtures::FOREIGN_KEY_SEED).pubkey())
        .expect("the foreign key is a curve point")
}

/// Puts a fixture vector through the relayer's REAL validated boundary: the three wire fields are
/// serialized exactly as Circle returns them (camelCase, `0x`-hex), deserialized into the wire
/// [`AttestationObject`], and run through [`ValidatedAttestation::validate`] — the same §8.1 checks
/// (raw-keccak binding + the 65-byte shape) the Circle client runs. A test never hands the builder
/// bytes by any other route: that IS the "no raw-bytes side door" requirement, expressed as the only
/// way the suite can construct an input.
pub fn validated(vector: &AttestationVector) -> ValidatedAttestation {
    let object: AttestationObject = serde_json::from_value(serde_json::json!({
        "payload": vector.payload_hex(),
        "messageHash": vector.message_hash_hex(),
        "attestation": vector.attestation_hex(),
    }))
    .expect("the wire object deserializes");

    ValidatedAttestation::validate(object).expect("the fixture vector passes the envelope checks")
}

/// The standard validated attestation: the partner key over the canonical `di-pos-hookdata` payload.
pub fn validated_test_vector() -> ValidatedAttestation {
    validated(&crate::fixtures::test_vector())
}

/// A validated attestation over an ARBITRARY payload — the envelope checks pass (the digest binds
/// the bytes, the signature is 65 bytes), but the payload is whatever was handed in.
///
/// This is the shape that matters for the builder's fail-closed path: the envelope layer validates
/// the BINDING, never the DepositIntent structure, so a payload Circle signed but unit-04's codec
/// refuses can and does reach the builder. It must surface as a typed error, not a panic and not a
/// malformed note.
pub fn validated_over(payload: &[u8]) -> ValidatedAttestation {
    validated(&PartnerAttester::new().attest(payload))
}

/// A validated attestation over a canonical golden-artifact vector, by id (the positive vectors and
/// the structural-reject vectors alike — the ONE artifact that drives unit-04's own MASM and Rust
/// tests, consumed by reference).
pub fn validated_over_vector_id(id: &str) -> ValidatedAttestation {
    validated_over(&canonical_payload(id))
}
