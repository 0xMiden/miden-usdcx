//! Deterministic WITHDRAWAL-LOCAL attester vectors for signing and
//! quorum.
//!
//! **What it is.** Deterministic secp256k1 keypairs (seeded `StdRng`, byte-identical on every
//! machine and run) that sign Circle's **opaque** `messageHashToSign`, plus the test-only oracles
//! that prove a produced signature actually covers the digest it claims (`verify` / `recover`).
//!
//! **Distinct from the relayer's fixture on purpose.** The deposit relayer's `PartnerAttester`
//! signs `keccak256(DepositIntent payload)` — a digest it re-derives locally. This withdrawal
//! fixture signs [`MESSAGE_HASH_TO_SIGN`], a fixed 32-byte value standing in for the digest Circle
//! RETURNS, hashed from nothing here (signing is off-chain and opaque-and-sign; the digest's
//! derivation stays OPEN with Circle). Seeds are withdrawal-local, so a vector here can never be
//! confused with a relayer mint vector.
//!
//! **No real key material.** Every key is seed-derived and test-only. The production attester keys
//! (KMS/HSM, ≥2, rotation) are human/ops-owned; nothing here is, or stands in for, a real
//! Circle-registered key.
//!
//! **`address()` derives the Ethereum-style signer address** (`keccak256(uncompressed
//! pubkey)[12..]`) only to feed the quorum's ascending-address ordering — the value Circle recovers
//! via `ECDSA.recover` (`CIRCLE-DATA-SCHEMAS.md:46`,`:193`). It lives in this dev fixture, not the
//! library: `attester::sign` links no keccak (it signs Circle's digest opaquely).

#![allow(dead_code)] // shared across two test targets; each uses a subset.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha3::{Digest, Keccak256};

use withdrawal_listener_attester::attester::{sign, Address, Signature65, EVM_V_OFFSET};

/// The opaque `messageHashToSign` the withdrawal path signs — a FIXED 32-byte digest standing in
/// for what Circle returns from `POST /v1/prepare-withdrawal`. It is deliberately NOT
/// `keccak256(payload)` or any locally re-derived hash: the burn path treats Circle's digest as
/// opaque.
pub const MESSAGE_HASH_TO_SIGN: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// A DIFFERENT opaque digest — the wrong-hash comparator: a signature over [`MESSAGE_HASH_TO_SIGN`]
/// must NOT verify against this one.
pub const OTHER_MESSAGE_HASH: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];

/// Withdrawal-local attester key seeds — distinct from the relayer's (`0x7852...`/`0x464f...`), so
/// these keys are unmistakably burn-attester test keys. Chosen to give three DISTINCT signer
/// addresses whose order differs from their seed order (exercised by the quorum ordering tests).
pub const ATTESTER_SEEDS: [u64; 3] = [
    0x7844_5257_4154_5f31, // "xDRWAT_1"
    0x7844_5257_4154_5f32, // "xDRWAT_2"
    0x7844_5257_4154_5f33, // "xDRWAT_3"
];

/// A deterministic withdrawal-side attester (test-only secp256k1 keypair).
pub struct TestAttester {
    secret: SecretKey,
}

impl TestAttester {
    /// The deterministic key for `seed` (seeded `StdRng` — reproducible across runs/machines).
    pub fn from_seed(seed: u64) -> Self {
        Self {
            secret: SecretKey::random(&mut StdRng::seed_from_u64(seed)),
        }
    }

    /// The secret key `attester::sign` consumes (`&SecretKey`).
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// The 33-byte compressed SEC1 public key — what the signing oracle verifies against.
    pub fn pubkey_compressed(&self) -> [u8; 33] {
        self.secret
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed secp256k1 pubkey is 33 bytes")
    }

    /// The 20-byte Ethereum-style signer address: `keccak256(uncompressed pubkey X‖Y)[12..]`. This
    /// is the value Circle recovers via `ECDSA.recover` and orders the quorum by, and it is
    /// byte-identical to what `attester::recover_address` recovers from this attester's signatures
    /// (same derivation).
    pub fn address(&self) -> Address {
        let point = self.secret.public_key().to_encoded_point(false);
        let uncompressed = point.as_bytes(); // 0x04 ‖ X(32) ‖ Y(32)
        assert_eq!(uncompressed[0], 0x04, "uncompressed SEC1 point");
        let hash = keccak256(&uncompressed[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        Address::new(addr)
    }

    /// A `(claimed signer address, signature)` pair over `digest` — exactly the input
    /// `attester::assemble_quorum` takes, produced through the production `attester::sign` so the
    /// signature really is this attester's over `digest` (and thus recovers to its address).
    pub fn signed_pair(&self, digest: &[u8; 32]) -> (Address, Signature65) {
        (
            self.address(),
            sign(digest, self.secret()).expect("sign a 32-byte digest"),
        )
    }
}

/// The three canonical withdrawal attesters, in seed order (NOT address order — the quorum tests
/// sort them explicitly).
pub fn attesters() -> Vec<TestAttester> {
    ATTESTER_SEEDS
        .iter()
        .map(|&s| TestAttester::from_seed(s))
        .collect()
}

/// keccak256 (original Keccak, matching Ethereum address derivation).
pub fn keccak256(msg: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(msg);
    h.finalize().into()
}

/// TEST-ONLY signature oracle: does the 65-byte `r‖s‖v` verify over `digest` under the 33-byte
/// compressed `pubkey`? `verify_prehash` — the digest is verified AS-IS, exactly the opaque digest
/// `sign` consumed. Returns `false` on any malformed input (never panics), so a negative test
/// cannot pass merely because the oracle blew up.
pub fn verify(pubkey: &[u8; 33], digest: &[u8; 32], sig: &Signature65) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = K256Signature::from_slice(&sig.as_bytes()[..64]) else {
        return false;
    };
    verifying_key.verify_prehash(digest, &signature).is_ok()
}

/// Recovers the 33-byte compressed pubkey from `digest` + the 65-byte `r‖s‖v`, reading the **EVM**
/// `v` (`27`/`28`) back to a k256 recovery id (`v - 27`). `Some` only if the signature really is
/// over `digest` — pinning the signer, the digest, AND that `v` is the true EVM recovery byte (so
/// it proves `sign` signed the digest OPAQUELY and emitted the Ethereum-shaped `v`). A `v` outside
/// the EVM range yields `None`, so a regression to raw `0`/`1` is caught.
pub fn recover(digest: &[u8; 32], sig: &Signature65) -> Option<[u8; 33]> {
    let signature = K256Signature::from_slice(&sig.as_bytes()[..64]).ok()?;
    let recovery_id = RecoveryId::from_byte(sig.v().checked_sub(EVM_V_OFFSET)?)?;
    let recovered = VerifyingKey::recover_from_prehash(digest, &signature, recovery_id).ok()?;
    recovered.to_encoded_point(true).as_bytes().try_into().ok()
}

/// Crafts a 65-byte signature carrying a **non-EVM `v`** (`29` for `recid_byte = 2`, `30` for `3` —
/// the x-reduced recovery ids) that a RANGE-UNCHECKED recovery WOULD accept, paired with the
/// address k256 recovers for it under that x-reduced id.
///
/// This is the discriminating vector for the v=29/30 fix: it uses a small `r` (so `r + n < p` and
/// the x-reduced point exists), then reads back the address the buggy `v - 27 →
/// RecoveryId::from_byte` path would have blessed. A CORRECT `recover_address` rejects it purely on
/// the `v` range — never reaching recovery — so the pair is refused; a range-unchecked one recovers
/// this very address and accepts it. Panics if no small `r` yields a recoverable x-reduced point
/// (it does, quickly).
pub fn x_reduced_pair(digest: &[u8; 32], recid_byte: u8) -> (Address, Signature65) {
    assert!(recid_byte == 2 || recid_byte == 3, "x-reduced ids are 2/3");
    let recovery_id = RecoveryId::from_byte(recid_byte).expect("2/3 is a valid recovery id");
    // s is fixed and small; iterate r upward until the x-reduced point exists and recovers.
    let s = {
        let mut b = [0u8; 32];
        b[31] = 0x10;
        b
    };
    for r_low in 1u16..=4096 {
        let mut sig64 = [0u8; 64];
        sig64[30] = (r_low >> 8) as u8; // keep r well under 2^128 so r + n < p
        sig64[31] = (r_low & 0xff) as u8;
        sig64[32..].copy_from_slice(&s);
        let Ok(signature) = K256Signature::from_slice(&sig64) else {
            continue;
        };
        let Ok(verifying_key) = VerifyingKey::recover_from_prehash(digest, &signature, recovery_id)
        else {
            continue;
        };
        let point = verifying_key.to_encoded_point(false);
        let hash = keccak256(&point.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);

        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig64);
        bytes[64] = EVM_V_OFFSET + recid_byte; // 29 or 30 — the non-EVM wire v
        return (
            Address::new(addr),
            Signature65::from_bytes(&bytes).expect("65 bytes"),
        );
    }
    panic!("no small-r x-reduced recoverable signature found for recid {recid_byte}");
}
