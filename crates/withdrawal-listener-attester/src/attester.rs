//! `attester` — the PURE off-chain burn-signing core: [`sign`] (a single `k256` ECDSA over Circle's
//! `messageHashToSign`) and [`assemble_quorum`] (the exactly-threshold, ascending-address,
//! no-duplicate, all-signatures-verify `burnSignatures` bundle Circle verifies on the source chain).
//!
//! # `INV-OFFCHAIN-BURN-SIGNING`
//!
//! The burn path does its cryptography OFF-CHAIN. Partner attesters `k256`-ECDSA-sign the
//! `messageHashToSign` Circle returns from `POST /v1/prepare-withdrawal`; there is **no on-chain
//! Miden typed-data hashing on the burn path**. This module IS that leg — the off-chain signature it
//! produces is the product (contrast the deposit relayer, where the attestation is Circle's and is
//! verified ON-CHAIN by the faucet, so the relayer links `k256` only as a dev dependency).
//!
//! # The source-chain verifier is EVM `ECDSA.recover` — so the wire is Ethereum-shaped
//!
//! Unlike the mint side (where the Miden faucet verifies and the recovery byte is carried unused),
//! the BURN side is verified by Circle on the **source chain** via OpenZeppelin-style
//! `ECDSA.recover(digest, signature)` → 20-byte address → `require(attesters[addr])`
//! (`CIRCLE-DATA-SCHEMAS.md:46`,`:183`,`:196`). That imposes two Ethereum conventions this module
//! MUST honour or Circle rejects the signature at the fund-release boundary:
//!
//! * **`v` is exactly `27`/`28`.** [`sign`] encodes `v = 27 + recovery_id` ([`EVM_V_OFFSET`]) and
//!   REFUSES to emit anything else — an x-reduced recovery id (`2`/`3` → `v = 29`/`30`) has no EVM
//!   representation and is turned into [`SignError::UnrepresentableRecoveryId`] rather than an invalid
//!   signature. On the way back in, [`recover_address`] accepts ONLY [`EVM_V_VALUES`] (`27`/`28`), so
//!   a `v = 0`/`1` or `29`/`30` — each of which k256 could otherwise recover — can never verify. This
//!   matters because a `29`/`30` signature recovers locally but the source-chain OpenZeppelin verifier
//!   rejects it. k256 signing is low-`s`-normalized, so the malleability check the same verifier
//!   applies also passes.
//! * **A signature is only worth anything paired with the signer it recovers to.**
//!   [`assemble_quorum`] therefore takes the digest and, for each `(claimed address, signature)`,
//!   recovers the signer and REQUIRES it to equal the claimed address — the exact
//!   `ECDSA.recover`-then-authorize step Circle performs — before any ordering/threshold check. This
//!   is a deliberate widening of the `COMPONENT-SPEC.md:343` interface (which listed no digest):
//!   `TEST-AND-VERIFICATION-HARNESS.md:157` requires a signature that does not verify against its
//!   claimed signer to be excluded with an exact error, and that is impossible without the digest.
//!
//! # `Q-CRY-2` — OPEN, and treated as opaque-and-sign
//!
//! `messageHashToSign` is *strongly evidenced* to be the final EIP-712 digest
//! (`keccak256(0x1901 ‖ domainSeparator ‖ structHash)`), but the exact equivalence **REQUIRES CIRCLE
//! CONFIRMATION** (`Q-CRY-2`, still OPEN — this module parameterizes it, it does not resolve it).
//! Circle computes the digest server-side; [`sign`] therefore consumes it as an **opaque 32-byte
//! value** and re-derives NOTHING locally — no EIP-712 struct hash, no personal-sign prefix, no
//! Poseidon2. The only thing [`sign`] can reject about the digest is that it is the wrong length. The
//! keccak this module DOES link is used only for address RECOVERY (pubkey → Ethereum address), never
//! to re-derive the signing digest.
//!
//! # Single-key signing is a non-gating LOCAL PRIMITIVE — NEVER submitted
//!
//! [`sign`] produces ONE signature. A single signature is a unit-test-only primitive and is **never
//! submitted to Circle**: any `/v1/withdraw` submission carries the exactly-threshold bundle
//! [`assemble_quorum`] assembles (`MIN_SIGNATURE_THRESHOLD`; §10.9, `CMP-C3`). Key custody (KMS/HSM,
//! ≥2 keys, rotation) is the operational concern owned by `TASK-P4-MONITORING-ADMIN-OPS` (`CMP-C3`
//! prod, W11); this module owns the signing INTERFACE only, and holds no real key material.

use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
pub use k256::SecretKey;
use sha3::{Digest, Keccak256};

use crate::error::{QuorumError, SignError, SignatureError};

/// The `messageHashToSign` digest length — Circle returns a 32-byte digest and [`sign`] consumes it
/// opaquely, so this is the ONE shape the signing input must have.
pub const DIGEST_LEN: usize = 32;

/// A burn signature on the Circle wire: secp256k1 ECDSA, 65 bytes `r‖s‖v` (`r` 32B, `s` 32B, `v` the
/// 1-byte EVM recovery id) — `CIRCLE-DATA-SCHEMAS.md:184`.
pub const SIGNATURE_LEN: usize = 65;

/// The Ethereum-style signer address length: `ECDSA.recover(digest, sig)` yields a 20-byte address
/// (`CIRCLE-DATA-SCHEMAS.md:46`,`:193`), which is the key the quorum is ordered by.
pub const ADDRESS_LEN: usize = 20;

/// The offset added to the k256 recovery id (`0`/`1`) to form the Ethereum `v` (`27`/`28`) that
/// OpenZeppelin-style `ECDSA.recover` on the source chain requires (OpenZeppelin ECDSA: "libraries
/// returning `0`/`1` must add 27"). A signature carrying a raw `0`/`1` would be rejected by Circle.
pub const EVM_V_OFFSET: u8 = 27;

/// The ONLY two `v` bytes OpenZeppelin `ECDSA.recover` on the source chain accepts. The x-reduced
/// recovery ids `2`/`3` (wire `v = 29`/`30`) are deliberately NOT here — they recover locally but the
/// source-chain verifier rejects them, so a bundle counting one would fail at the fund-release
/// boundary. [`recover_address`] gates on exactly these values.
pub const EVM_V_VALUES: [u8; 2] = [EVM_V_OFFSET, EVM_V_OFFSET + 1];

/// Encodes a k256 recovery id as the Ethereum `v` byte, or `None` when it has no EVM representation.
///
/// `Some(27 + b)` for a non-x-reduced recovery id `b ∈ {0, 1}`; `None` for an x-reduced id `{2, 3}`,
/// which OpenZeppelin `ECDSA.recover` cannot accept. This is the single source of truth for the `v`
/// range: [`sign`] uses it to REFUSE emitting a `v = 29`/`30` signature, and [`recover_address`]
/// enforces the same range on the way back in.
pub fn evm_v_from_recovery_id(recovery_id: RecoveryId) -> Option<u8> {
    match recovery_id.to_byte() {
        b @ (0 | 1) => Some(EVM_V_OFFSET + b),
        _ => None, // x-reduced (2/3): no 27/28 representation
    }
}

/// Circle's `MIN_SIGNATURE_THRESHOLD` (`CIRCLE-DATA-SCHEMAS.md:196`; `CIRCLE-API-SURFACE.md:184`
/// `minItems 2`). Circle's source-chain verifier is **exactly-threshold** — a `/v1/withdraw` batch
/// carries exactly this many `burnSignatures`, no fewer and no more (`Attestable.sol:75,333-381`);
/// [`assemble_quorum`] enforces that exact count. A single-key set is a non-gating local primitive
/// that is never submitted.
pub const MIN_SIGNATURE_THRESHOLD: usize = 2;

/// A 65-byte `r‖s‖v` burn signature — the exact wire form `burnSignatures[]` carries.
///
/// A newtype, not a bare `[u8; 65]`, so the shape is guaranteed by construction: [`from_bytes`] is
/// the only fallible entry point and it rejects anything that is not exactly 65 bytes (a DER blob, a
/// 64-byte `r‖s` with the recovery id dropped). Length is a wire-shape concern only — whether the
/// signature is VALID (verifies to its claimed signer) is established by [`assemble_quorum`], which
/// has the digest; a `Signature65` on its own asserts nothing about who signed what.
///
/// [`from_bytes`]: Signature65::from_bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature65([u8; SIGNATURE_LEN]);

impl Signature65 {
    /// Wraps an already-correctly-sized array (the [`sign`] output path, where the 65 bytes are
    /// assembled in-crate and cannot be the wrong length).
    pub fn from_array(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// Builds a signature from raw wire bytes, rejecting any length other than 65
    /// ([`SignatureError::Length`]). This is the boundary a signature coming OFF the wire (or out of
    /// a fixture) must pass through — a non-65-byte or DER-encoded blob never becomes a
    /// `Signature65`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let array: [u8; SIGNATURE_LEN] = bytes.try_into().map_err(|_| SignatureError::Length {
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// The 65 raw bytes `r‖s‖v`.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    /// `r` — bytes 0..32.
    pub fn r(&self) -> [u8; 32] {
        self.0[..32].try_into().expect("32 bytes")
    }

    /// `s` — bytes 32..64.
    pub fn s(&self) -> [u8; 32] {
        self.0[32..64].try_into().expect("32 bytes")
    }

    /// `v` — the EVM recovery id, byte 64 (`27`/`28`).
    pub fn v(&self) -> u8 {
        self.0[SIGNATURE_LEN - 1]
    }

    /// The `0x`-prefixed lower-case hex the `burnSignatures[]` wire carries (matches the OpenAPI
    /// `^0x[a-fA-F0-9]*$` pattern).
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

/// A 20-byte Ethereum-style signer address — the value `ECDSA.recover(digest, signature)` yields on
/// the source chain (`CIRCLE-DATA-SCHEMAS.md:46`,`:193`), and the key the quorum bundle is ordered
/// by.
///
/// `Ord` is the plain big-endian byte order — the same total order Circle's ascending-address check
/// uses. A caller pairs each signature with the address it EXPECTS signed it (the registered
/// attester); [`assemble_quorum`] then proves that expectation by recovering the real signer from the
/// signature and the digest, so a freely-constructed [`Address::new`] can never smuggle an
/// unauthorized signature into a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    /// Wraps 20 raw address bytes.
    pub fn new(bytes: [u8; ADDRESS_LEN]) -> Self {
        Self(bytes)
    }

    /// The 20 raw address bytes.
    pub fn as_bytes(&self) -> &[u8; ADDRESS_LEN] {
        &self.0
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// Signs Circle's opaque `messageHashToSign` with `key`, producing the 65-byte `r‖s‖v` burn
/// signature (`DC-11`; `INV-OFFCHAIN-BURN-SIGNING`).
///
/// `msg_hash_to_sign` is the digest Circle returned, treated as **opaque** (`Q-CRY-2`, OPEN): it is
/// signed AS-IS via `sign_prehash` — no local re-hashing, no EIP-712 re-derivation, no domain
/// separator. The 65 bytes are `r‖s‖v` with `v` the **EVM** recovery id `27`/`28`
/// ([`EVM_V_OFFSET`]), the form Circle's source-chain `ECDSA.recover` requires. k256 signing is
/// low-`s`-normalized, so the EVM malleability check passes too. secp256k1 ECDSA here is RFC 6979
/// deterministic, so a given `(digest, key)` always yields the same signature.
///
/// # Errors
///
/// * [`SignError::DigestLength`] — `msg_hash_to_sign` is not exactly 32 bytes. The digest is opaque;
///   `sign` will not hash or pad it into shape.
/// * [`SignError::Ecdsa`] — `k256` refused to sign (not reachable with a valid key and a 32-byte
///   prehash; surfaced as a typed error rather than a `panic`).
///
/// Single-key signing is a non-gating local primitive and is NEVER submitted to Circle on its own;
/// see [`assemble_quorum`].
pub fn sign(msg_hash_to_sign: &[u8], key: &SecretKey) -> Result<Signature65, SignError> {
    if msg_hash_to_sign.len() != DIGEST_LEN {
        return Err(SignError::DigestLength {
            actual: msg_hash_to_sign.len(),
        });
    }

    let signing_key = SigningKey::from(key.clone());
    let (signature, recovery_id): (K256Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(msg_hash_to_sign)
        .map_err(|e| SignError::Ecdsa {
            source: crate::error::Cause::new(e),
        })?;

    // Refuse to emit a signature whose recovery id has no EVM `v` — an x-reduced `2`/`3` would become
    // wire `v = 29`/`30`, which the source-chain `ECDSA.recover` rejects. (Unreachable for real
    // inputs: k256 low-`s`-normalizes and an x-reduced `r` has probability ≈ 2^-128.)
    let v = evm_v_from_recovery_id(recovery_id).ok_or(SignError::UnrepresentableRecoveryId {
        recovery_id: recovery_id.to_byte(),
    })?;

    let mut out = [0u8; SIGNATURE_LEN];
    out[..64].copy_from_slice(signature.to_bytes().as_slice()); // r‖s, 64 big-endian bytes
    out[SIGNATURE_LEN - 1] = v; // EVM v ∈ {27, 28}
    Ok(Signature65::from_array(out))
}

/// Recovers the 20-byte Ethereum signer address from `digest` + a 65-byte `r‖s‖v` signature — the
/// exact `ECDSA.recover(digest, signature)` Circle runs on the source chain: decode `r‖s`, read the
/// EVM `v` (`27`/`28`) back to a k256 recovery id, recover the secp256k1 pubkey over `digest`, then
/// take `keccak256(uncompressed pubkey X‖Y)[12..]`.
///
/// Returns `None` for anything that does not recover — a `v` outside `27`/`28` (a raw `0`/`1`, an
/// x-reduced `29`/`30`, or garbage), an `r`/`s` that is not a valid signature, or a digest the
/// signature does not cover. The `v` range is enforced STRUCTURALLY against [`EVM_V_VALUES`] before
/// any recovery is attempted, so a `v = 29`/`30` (recovery id `2`/`3`) can never verify here even
/// though k256 could recover it — it is exactly the value Circle's source-chain verifier rejects. A
/// `None` here is "this signature does not verify", which [`assemble_quorum`] turns into
/// [`QuorumError::SignatureDoesNotVerify`].
pub fn recover_address(digest: &[u8; DIGEST_LEN], sig: &Signature65) -> Option<Address> {
    // Only the EVM `v` bytes 27/28 are accepted — NOT the full k256 recovery-id range 0..=3. This is
    // the fix's core: `v - 27` on a 29/30 wire byte would otherwise be a valid x-reduced recovery id
    // (2/3) that recovers locally but is rejected on the source chain.
    let recovery_id_byte = match sig.v() {
        v if v == EVM_V_VALUES[0] => 0,
        v if v == EVM_V_VALUES[1] => 1,
        _ => return None,
    };
    let signature = K256Signature::from_slice(&sig.as_bytes()[..64]).ok()?;
    let recovery_id = RecoveryId::from_byte(recovery_id_byte)?;
    let verifying_key = VerifyingKey::recover_from_prehash(digest, &signature, recovery_id).ok()?;

    let point = verifying_key.to_encoded_point(false); // 0x04 ‖ X(32) ‖ Y(32)
    let hash: [u8; 32] = Keccak256::digest(&point.as_bytes()[1..]).into();
    let mut addr = [0u8; ADDRESS_LEN];
    addr.copy_from_slice(&hash[12..]);
    Some(Address::new(addr))
}

/// Assembles the `burnSignatures[]` bundle Circle verifies on the source chain: **exactly
/// [`MIN_SIGNATURE_THRESHOLD`] signatures, each verifying to its claimed signer, ascending
/// signer-address order, no duplicates** (`DC-11`; `CIRCLE-DATA-SCHEMAS.md:196`).
///
/// `msg_hash_to_sign` is the same opaque digest [`sign`] signed. Each input pair is a signature and
/// the 20-byte address the caller EXPECTS signed it (the registered attester). On success the
/// addresses are stripped and the signatures returned in the SAME order — which, having been
/// validated ascending, is the ascending-address order Circle expects.
///
/// Checks, in order:
///
/// 1. **Exactly-threshold** — `len == MIN_SIGNATURE_THRESHOLD`. Circle's verifier is exactly-threshold
///    (`Attestable.sol:75,333-381`); a single-key set is never submitted, and an over-threshold bundle
///    Circle would reject is caught here rather than at the fund-release boundary.
/// 2. **Each signature verifies to its claimed signer** — [`recover_address`] must yield the claimed
///    address. This is the `ECDSA.recover`-then-authorize step; a signature paired with the wrong
///    address (or one that does not recover at all) is refused.
/// 3. **No duplicate signer** — refused, never de-duplicated.
/// 4. **Strictly ascending by address**.
///
/// # Errors
///
/// * [`QuorumError::BelowThreshold`] / [`QuorumError::AboveThreshold`] — the count is not exactly
///   the threshold.
/// * [`QuorumError::SignatureDoesNotVerify`] — a signature does not recover to its claimed signer.
/// * [`QuorumError::DuplicateSigner`] — an address appears more than once.
/// * [`QuorumError::NotAscending`] — the addresses are not in strictly ascending order.
///
/// Ordering and uniqueness are over the signer ADDRESS, never the pubkey or signature bytes.
pub fn assemble_quorum(
    msg_hash_to_sign: &[u8; DIGEST_LEN],
    sigs: Vec<(Address, Signature65)>,
) -> Result<Vec<Signature65>, QuorumError> {
    if sigs.len() < MIN_SIGNATURE_THRESHOLD {
        return Err(QuorumError::BelowThreshold {
            have: sigs.len(),
            need: MIN_SIGNATURE_THRESHOLD,
        });
    }
    if sigs.len() > MIN_SIGNATURE_THRESHOLD {
        return Err(QuorumError::AboveThreshold {
            have: sigs.len(),
            need: MIN_SIGNATURE_THRESHOLD,
        });
    }

    // Each signature must recover to its CLAIMED signer over the digest — the `ECDSA.recover`-then-
    // authorize step. A pair the caller mis-attributed (or a signature that does not recover at all)
    // is refused before it can be counted toward the quorum.
    for (i, (claimed, sig)) in sigs.iter().enumerate() {
        match recover_address(msg_hash_to_sign, sig) {
            Some(recovered) if recovered == *claimed => {}
            _ => return Err(QuorumError::SignatureDoesNotVerify { at: i }),
        }
    }

    // Duplicate scan over the FULL set (not just adjacent pairs): a duplicate must be caught wherever
    // it sits, and reported as DuplicateSigner rather than masquerading as an ordering error.
    for i in 0..sigs.len() {
        for j in (i + 1)..sigs.len() {
            if sigs[i].0 == sigs[j].0 {
                return Err(QuorumError::DuplicateSigner { address: sigs[i].0 });
            }
        }
    }

    // Strictly ascending by address. Duplicates are already excluded, so any non-increase here is a
    // genuine ordering violation (descending or otherwise unsorted).
    for i in 1..sigs.len() {
        if sigs[i].0 <= sigs[i - 1].0 {
            return Err(QuorumError::NotAscending { at: i });
        }
    }

    Ok(sigs.into_iter().map(|(_, sig)| sig).collect())
}
