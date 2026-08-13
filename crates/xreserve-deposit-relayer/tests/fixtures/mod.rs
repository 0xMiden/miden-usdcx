//! `tests/fixtures/mod.rs` — the **partner-held attestation test vector** (the raw-keccak
//! attestation-envelope contract). The single, deterministic source of attestation test data
//! for the relayer's slices: the envelope suite here, and the mint-note-builder / idempotency /
//! local-node slices that follow (they reuse [`PartnerAttester`] and [`AttestationVector`] rather
//! than minting a second, divergent key).
//!
//! **What it is.** A deterministic secp256k1 keypair (seeded `StdRng`, so it is byte-identical on
//! every machine and every run) that SIGNS `keccak256(DepositIntent payload)` and yields the
//! 65-byte `r‖s‖v` attestation, the 33-byte compressed pubkey, and the Poseidon2 pubkey commitment
//! — the key the on-chain `xReserveAttesters` allowlist is keyed by, which the later local-node
//! rows seed via `set_attester`.
//!
//! **What it is NOT.** Not a Miden fake and not a mock: the signature is a real secp256k1 signature
//! over a real keccak digest of a real canonical DepositIntent payload, produced by `k256`/`sha3`
//! exactly as the shared encoding crate's own in-test attestation vectors and the `gen_vectors`
//! `att_*` helpers produce theirs (same `sign_prehash_recoverable` → `r‖s‖v`, `v` = recovery id,
//! carried and unused on-chain). It stands in only for CIRCLE — the party that holds the real
//! attester key.
//!
//! **Ownership.** The Poseidon2 commitment is NOT re-derived here: it is
//! [`PublicKey::to_commitment`], the
//! shared encoding crate's owned allowlist-keying primitive (single-owner rule), the same procedure
//! the faucet's on-chain attestation check recomputes on-chain. Likewise the payload is the
//! canonical DepositIntent vector from the ONE golden artifact, never a hand-rolled byte blob.
//!
//! **Signing only.** `k256` appears in this crate's dev-dependencies to SIGN. The relayer never
//! verifies an ECDSA signature off-chain — that is on-chain and faucet-owned.

#![allow(dead_code)] // a shared fixture: each integration test uses the subset it needs.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::crypto::utils::{Deserializable, Serializable};
use miden_protocol::{Hasher, Word};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha3::{Digest, Keccak256};

use xusdc_encoding::vectors::{load, MiVector};
use xusdc_encoding::xreserve::encoding::{DepositIntent, MintIntent};

/// Seed of the partner-held attester key. Deliberately distinct from the seeds the canonical
/// `att-*` artifact vectors use, so this key is unmistakably the RELAYER-side test key and can
/// never be confused with (or silently substituted for) an artifact vector's key.
pub const PARTNER_KEY_SEED: u64 = 0x7852_5356_5f52_4459; // "xRSV_RDY"

/// Seed of a SECOND, genuinely different attester key — the "foreign" (non-allowlisted) signer. It
/// exists so a test about a foreign key really uses a foreign key: same construction, different
/// seed, therefore a different pubkey and a different allowlist commitment.
pub const FOREIGN_KEY_SEED: u64 = 0x464f_5245_4947_4e00; // "FOREIGN\0"

/// The partner key's 33-byte compressed SEC1 pubkey, PINNED. This is a determinism pin, not a
/// correctness oracle: it fails the moment the seed, the curve, or the key-derivation path changes,
/// so every later slice (and the local-node allowlist it seeds) is guaranteed the same attester.
/// Correctness of the commitment derived from it is anchored by the shared encoding crate's
/// `PublicKey::to_commitment` (pinned == miden-crypto `PublicKey::to_commitment` by TV-ATT-2).
pub const PARTNER_PUBKEY_HEX: &str =
    "03a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3f";

/// The Miden destination domain this suite's payloads are addressed to, and the domain the mock
/// Circle advertises. **Placeholder — the Miden domain id is OPEN (`REQUIRES CIRCLE
/// CONFIRMATION`).** The mint-note factory needs it because the faucet stamps its own configured
/// domain into the message it rebuilds, so a note built for the wrong one could only ever fail as a
/// bad signature.
pub const TEST_REMOTE_DOMAIN: u32 = 10001;

/// The xUSDC faucet every relayer slice mints at — a PUBLIC (network) account, because the mint
/// note's scheme-2 routing attachment can bind nothing else.
///
/// It lives here rather than beside the other test account ids because the fixture PAYLOADS are
/// addressed to it: `DC-14` binds `remoteToken` to the faucet, so the id and the payload have to
/// come from one place or the compress step refuses every vector.
pub fn faucet_id() -> AccountId {
    AccountId::dummy(
        [0x22; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// The canonical DepositIntent payload the standard [`test_vector`] is built over: the golden
/// artifact's `mi-pos-hookdata` vector (a full 240-byte header + hookData), re-addressed to this
/// suite's faucet and domain by [`canonical_payload`]. Taken from the ONE artifact that drives the
/// shared encoding crate's MASM and Rust tests — never a hand-rolled blob.
pub const TEST_VECTOR_PAYLOAD_ID: &str = "mi-pos-hookdata";

/// [`test_vector`]'s `messageHash` — `keccak256` of the canonical payload, PINNED.
pub const TEST_VECTOR_MESSAGE_HASH_HEX: &str =
    "8e24efc812c0bb48f307270843c0f0f6b09b25d0328687c4ce4d2173b9a8a198";

/// [`test_vector`]'s 65-byte `r‖s‖v`, PINNED. secp256k1 signing here is RFC 6979 DETERMINISTIC, so
/// this is a fixed value — an independent golden pin on the whole chain (key → raw-keccak digest →
/// signing convention). It moves only if one of those changes, which is exactly when every later
/// slice reusing this vector needs to know.
pub const TEST_VECTOR_ATTESTATION_HEX: &str = concat!(
    "1f3dfce199935983b468a86f0282db1fc683d6ebd0d4a3ec3a5de0611ac7f026", // r
    "23f373ffa40c3d03f9f74869169fda27cf0a3adaa099003065aa619ad53b67e3", // s
    "00",                                                               // v (recovery id)
);

/// The canonical DepositIntent payload with EMPTY hookData — the second shape (240 bytes exactly),
/// for slices that need a boundary-length payload.
pub const TEST_VECTOR_PAYLOAD_ID_EMPTY_HOOKDATA: &str = "mi-pos-empty-hookdata";

/// keccak256 (original Keccak, NOT NIST SHA3-256) — the digest family the attestation is taken
/// over. Mirrors the shared encoding crate's `att_keccak256`.
pub fn keccak256(msg: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(msg);
    h.finalize().into()
}

/// Fetches a canonical DepositIntent payload from the golden artifact by vector id.
///
/// A `mi-*` id is a `DC-14`-shaped payload and comes back re-addressed to [`faucet_id`] and
/// [`TEST_REMOTE_DOMAIN`] (see [`mint_payload_for`]). A `di-*` id is the older, unshaped form and
/// comes back verbatim — those vectors exist to exercise the structural parse, which runs before
/// the compress step ever looks at the addressing.
pub fn canonical_payload(id: &str) -> Vec<u8> {
    if let Some(vector) = mi_vector(id) {
        return mint_payload_for(vector, faucet_id(), TEST_REMOTE_DOMAIN);
    }
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical DI vector `{id}` present in the artifact"))
        .bytes()
}

/// The canonical `mi-*` accept vector by id, or `None` if the id names no such vector.
pub fn mi_vector(id: &str) -> Option<&'static MiVector> {
    load().families.mi.iter().find(|v| v.id == id)
}

/// A canonical `mi-*` accept payload re-addressed to `faucet` and `remote_domain`.
///
/// The artifact's synthetic faucet is a PRIVATE account and a network mint note can only be routed
/// at a public one, so no relayer slice can use those vectors verbatim. Re-addressing runs through
/// the owned codec in both directions — compress under the vector's own faucet and domain, expand
/// under the ones asked for — so what comes back is still the encoding crate's bytes rather than a
/// payload rewritten here.
pub fn mint_payload_for(vector: &MiVector, faucet: AccountId, remote_domain: u32) -> Vec<u8> {
    let payload = vector.payload();
    let intent = DepositIntent::try_from(payload.as_slice())
        .expect("the canonical mi vector is a structurally valid deposit intent");
    let amount = intent
        .header()
        .reduced_amount()
        .expect("the canonical mi vector's amount is mintable");

    MintIntent::from_deposit_intent(&intent, vector.faucet_id(), vector.remote_domain)
        .expect("the canonical mi accept vector compresses under its own faucet and domain")
        .to_deposit_intent(amount, remote_domain, faucet)
        .to_bytes()
}

/// [`canonical_payload`] for an `mi-*` id, addressed to a faucet other than [`faucet_id`] — for the
/// slices that prove the faucet argument really drives the note.
pub fn canonical_payload_addressed_to(id: &str, faucet: AccountId) -> Vec<u8> {
    let vector =
        mi_vector(id).unwrap_or_else(|| panic!("canonical MI vector `{id}` in the artifact"));
    mint_payload_for(vector, faucet, TEST_REMOTE_DOMAIN)
}

/// Lower-case hex, no `0x` prefix (the bare form; the wire form is produced by [`with_0x`]).
pub fn hex_of(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// The `0x`-prefixed wire form Circle's API returns.
pub fn with_0x(bare_hex: &str) -> String {
    format!("0x{bare_hex}")
}

// THE PARTNER ATTESTER (deterministic secp256k1 keypair)
// ================================================================================================

/// The partner-held attester key — stands in for Circle's attester in every relayer test.
///
/// Deterministic: [`PartnerAttester::new`] always produces the same key (seeded RNG), so the
/// pubkey, the commitment, and every signature it makes are reproducible across runs, machines,
/// and slices.
pub struct PartnerAttester {
    signing_key: SigningKey,
}

impl Default for PartnerAttester {
    fn default() -> Self {
        Self::new()
    }
}

impl PartnerAttester {
    /// The deterministic partner key (seeded `StdRng`, mirroring the shared encoding crate's
    /// `att_keypair`).
    pub fn new() -> Self {
        Self::with_seed(PARTNER_KEY_SEED)
    }

    /// A deterministic attester from an explicit seed — used to build a genuinely DIFFERENT signer
    /// (e.g. [`FOREIGN_KEY_SEED`], the non-allowlisted key), since [`Self::new`] always returns the
    /// one partner key.
    pub fn with_seed(seed: u64) -> Self {
        Self {
            signing_key: SigningKey::random(&mut StdRng::seed_from_u64(seed)),
        }
    }

    /// The 33-byte compressed SEC1 public key — the wire form the allowlist commitment is derived
    /// from (decompressed to 16 affine felts before hashing), and the form
    /// `set_attester` is called with.
    pub fn pubkey(&self) -> [u8; 33] {
        self.signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed secp256k1 pubkey is 33 bytes")
    }

    /// The attester-allowlist key: `Poseidon2(affine pubkey felts)` →
    /// one `Word` (the compressed wire key is decompressed inside the owned primitive).
    ///
    /// Delegated to the protocol's own [`PublicKey::to_commitment`] — the SINGLE owner of this
    /// keying primitive and the exact procedure the faucet's on-chain attestation check recomputes
    /// on-chain. This fixture never re-implements it, so the local-node allowlist it seeds cannot
    /// drift from the on-chain lookup.
    pub fn commitment(&self) -> Word {
        PublicKey::read_from_bytes(&self.pubkey())
            .expect("the deterministic partner key is a valid point")
            .to_commitment()
    }

    /// Signs `keccak256(payload)` — RAW secp256k1 over the raw keccak digest of the FULL payload.
    ///
    /// No EIP-712 `\x19\x01` domain separator, no typed-data struct hash, no personal-sign prefix,
    /// no Poseidon2. The 65 bytes are `r‖s‖v` with `v` = the recovery id (carried on the wire,
    /// unused on-chain) — byte-for-byte the layout the shared encoding crate's `att_sign65` and
    /// miden-crypto's `Signature` serialization use.
    pub fn attest(&self, payload: &[u8]) -> AttestationVector {
        let message_hash = keccak256(payload);
        let (sig, recid): (K256Signature, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(&message_hash)
            .expect("k256 prehash sign");

        let mut attestation = [0u8; 65];
        attestation[..64].copy_from_slice(sig.to_bytes().as_slice()); // 64-byte big-endian r‖s
        attestation[64] = recid.to_byte(); // v ∈ {0..3}

        AttestationVector {
            payload: payload.to_vec(),
            message_hash,
            attestation,
        }
    }
}

/// One signed attestation: the payload, the raw-keccak `messageHash` that binds it, and the 65-byte
/// `r‖s‖v` signature over that hash — i.e. exactly the three wire fields the relayer's envelope
/// validation consumes from Circle.
#[derive(Debug, Clone)]
pub struct AttestationVector {
    payload: Vec<u8>,
    message_hash: [u8; 32],
    attestation: [u8; 65],
}

impl AttestationVector {
    /// The DepositIntent payload bytes the attestation covers.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// `messageHash` = `keccak256(payload)` (raw keccak — the ONLY accepted binding).
    pub fn message_hash(&self) -> [u8; 32] {
        self.message_hash
    }

    /// The 65-byte `r‖s‖v` attestation.
    pub fn attestation(&self) -> [u8; 65] {
        self.attestation
    }

    /// `r` — signature bytes 0..32.
    pub fn r(&self) -> [u8; 32] {
        self.attestation[..32].try_into().expect("32 bytes")
    }

    /// `s` — signature bytes 32..64.
    pub fn s(&self) -> [u8; 32] {
        self.attestation[32..64].try_into().expect("32 bytes")
    }

    /// `v` — the recovery id, byte 64 (carried on the wire, unused on-chain).
    pub fn v(&self) -> u8 {
        self.attestation[64]
    }

    /// The wire (hex) forms Circle's API returns, `0x`-prefixed.
    pub fn payload_hex(&self) -> String {
        with_0x(&hex_of(&self.payload))
    }

    pub fn message_hash_hex(&self) -> String {
        with_0x(&hex_of(&self.message_hash))
    }

    pub fn attestation_hex(&self) -> String {
        with_0x(&hex_of(&self.attestation))
    }
}

/// THE test vector every later slice reuses: the partner key's attestation over the canonical
/// `mi-pos-hookdata` DepositIntent payload, addressed to this suite's faucet.
pub fn test_vector() -> AttestationVector {
    PartnerAttester::new().attest(&canonical_payload(TEST_VECTOR_PAYLOAD_ID))
}

/// The canonical payload with a hookData tail past the `NoteStorage` felt bound — `DC-14`-shaped
/// and correctly addressed in every other respect, so a build over it reaches the hookData bound
/// rather than tripping an addressing check first.
///
/// The tail is grown on the canonical payload rather than composed from scratch: `MintIntent`
/// refuses to hold an over-long hookData at all, so the owned writer cannot produce this shape and
/// only the declared length plus the appended bytes are touched here.
pub fn oversized_hook_data_payload() -> Vec<u8> {
    // 60 header felts + ⌈len/4⌉ hookData felts must exceed the 1024-felt NoteStorage bound
    let hook_data_len = (1024 - 60) * 4 + 4;
    let mut payload = canonical_payload(TEST_VECTOR_PAYLOAD_ID_EMPTY_HOOKDATA);
    let hook_data_len_off = payload.len() - 4;
    payload[hook_data_len_off..].copy_from_slice(&(hook_data_len as u32).to_be_bytes());
    payload.extend(std::iter::repeat_n(0xab, hook_data_len));
    payload
}

// THE SIGNATURE ORACLE — test-only ECDSA verification
// ================================================================================================
// This is the ONLY place an ECDSA signature is verified off-chain, and it is TEST-ONLY (`k256` is a
// dev-dependency; the relayer library does not link it). It exists to prove a property of the
// FIXTURE, not to gate a mint: that the 65 bytes the partner key produces actually cover the RAW
// KECCAK digest they claim to. Without it, a fixture could report the right `message_hash` while
// having signed something else, and the "partner vector signs raw keccak" invariant would be
// unfalsifiable. Production code must never do this (the chain verifies in the faucet's attestation
// check).

/// Verifies a 65-byte `r‖s‖v` attestation over `digest` under the 33-byte compressed `pubkey`
/// (`verify_prehash` — the digest is signed as-is, exactly as the on-chain `verify_prehash` in the
/// faucet's attestation check consumes the keccak precompile's output). Returns `false` on any
/// malformed input rather than panicking, so a negative test cannot pass merely because the oracle
/// blew up.
pub fn verify_attestation(pubkey: &[u8; 33], digest: &[u8; 32], attestation: &[u8; 65]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = K256Signature::from_slice(&attestation[..64]) else {
        return false;
    };
    verifying_key.verify_prehash(digest, &signature).is_ok()
}

/// Recovers the 33-byte compressed pubkey from `digest` + the 65-byte `r‖s‖v` (using `v` as the
/// recovery id). `Some(pubkey)` only if the signature really is over that digest — so this pins the
/// signer, the digest, AND that `v` is the true recovery id rather than a stray constant.
pub fn recover_pubkey(digest: &[u8; 32], attestation: &[u8; 65]) -> Option<[u8; 33]> {
    let signature = K256Signature::from_slice(&attestation[..64]).ok()?;
    let recovery_id = RecoveryId::from_byte(attestation[64])?;
    let recovered = VerifyingKey::recover_from_prehash(digest, &signature, recovery_id).ok()?;

    recovered.to_encoded_point(true).as_bytes().try_into().ok()
}

// NEGATIVE COMPARATORS — the three WRONG digests, each computed over the SAME payload
// ================================================================================================
// The raw-keccak binding is a claim about WHICH digest binds the envelope, so the
// invariant is only actually tested by digests that are plausible-but-wrong: each of these is what
// `messageHash` WOULD have been had Circle used the Ethereum convention (EIP-712 / personal-sign)
// or the Miden-native hash family (Poseidon2) instead of raw keccak. A binding check that accepted
// any of them would be silently verifying a DIFFERENT message than the one it mints.

/// The EIP-712 typed-data digest over the same payload: `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖
/// hashStruct)` — the convention the invariant explicitly forbids ("NOT EIP-712").
pub fn eip712_digest(payload: &[u8]) -> [u8; 32] {
    // domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, name, version, chainId, verifyingContract))
    let domain_typehash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let mut domain = Vec::new();
    domain.extend_from_slice(&domain_typehash);
    domain.extend_from_slice(&keccak256(b"XReserve"));
    domain.extend_from_slice(&keccak256(b"1"));
    domain.extend_from_slice(&u256_be(1)); // chainId
    domain.extend_from_slice(&u256_be(0xc1_2c_1e)); // verifyingContract (left-padded to 32B)
    let domain_separator = keccak256(&domain);

    // hashStruct = keccak256(abi.encode(DEPOSIT_TYPEHASH, keccak256(payload)))
    let deposit_typehash = keccak256(b"DepositAttestation(bytes payload)");
    let mut struct_bytes = Vec::new();
    struct_bytes.extend_from_slice(&deposit_typehash);
    struct_bytes.extend_from_slice(&keccak256(payload));
    let hash_struct = keccak256(&struct_bytes);

    let mut preimage = Vec::with_capacity(2 + 32 + 32);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(&domain_separator);
    preimage.extend_from_slice(&hash_struct);
    keccak256(&preimage)
}

/// The `personal_sign` (EIP-191) digest over the same payload:
/// `keccak256("\x19Ethereum Signed Message:\n" ‖ len ‖ payload)` — a keccak digest, but of a
/// PREFIXED preimage, so it does not bind the payload the faucet keccaks on-chain.
pub fn personal_sign_digest(payload: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    preimage.extend_from_slice(payload.len().to_string().as_bytes());
    preimage.extend_from_slice(payload);
    keccak256(&preimage)
}

/// The Miden-native Poseidon2 `Word` over the same payload, serialized to 32 bytes — the
/// wrong-hash-FAMILY comparator (Poseidon2 is what Miden hashes with everywhere else in this
/// system: the nonce key, the attester commitment; the attestation digest is the one place it is
/// keccak). The payload is packed into felts by the shared encoding crate's owned DepositIntent
/// packer, then hashed with the protocol `Hasher` (Poseidon2) — the same primitive
/// `PublicKey::to_commitment` uses.
pub fn poseidon2_word_digest(payload: &[u8]) -> [u8; 32] {
    let felts = DepositIntent::try_from(payload)
        .expect("the comparator is built over a canonical DC-1 payload")
        .to_preimage_felts();
    word_to_bytes32(Hasher::hash_elements(&felts))
}

/// A `Word`'s 32-byte serialization: 4 felts × their canonical u64, little-endian.
pub fn word_to_bytes32(w: Word) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, f) in w.as_elements().iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&f.as_canonical_u64().to_le_bytes());
    }
    out
}

/// A `u128` as a 32-byte big-endian uint256 (EIP-712 `abi.encode` word).
fn u256_be(x: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&x.to_be_bytes());
    out
}
