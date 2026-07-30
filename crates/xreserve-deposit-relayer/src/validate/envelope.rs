//! Attestation-envelope validation — binds Circle's envelope to the payload it claims to attest
//! (raw keccak over the full payload, not EIP-712).
//!
//! Circle publishes three wire fields: the DepositIntent `payload`, a `messageHash`, and a 65-byte
//! `attestation`. This module answers the two structural questions the relayer must answer BEFORE
//! it builds a mint note:
//!
//!   1. [`verify_message_hash`] — does `messageHash` actually equal `keccak256(payload)`? The
//!      digest is **RAW keccak256 over the FULL payload**: no EIP-712 `\x19\x01` domain separator
//!      or typed-data struct hash, no `personal_sign` prefix, no Poseidon2. This is not a stylistic
//!      choice — it is the digest the faucet recomputes on-chain in the faucet's attestation check
//!      with the keccak precompile and verifies the signature against. An envelope bound by any
//!      other digest attests a DIFFERENT message than the one that would be minted, so it is
//!      refused here.
//!   2. [`validate_attestation_envelope`] — is `attestation` exactly 65 bytes (`r‖s‖v`)?
//!
//! **What this module deliberately does NOT do: verify the signature.** The relayer is a LIVENESS
//! service. ECDSA verification and the attester-allowlist gate are ON-CHAIN and faucet-owned (in
//! the faucet's attestation check) — the sole authority on whether a mint is authorized. Verifying
//! off-chain here would add a rejection surface that could WITHHOLD a mint the chain would have
//! accepted, while adding no security (a relayer that skipped the check could not authorize
//! anything either). So the checks here are shape + binding only, and `k256` is not a dependency of
//! this crate's library. Both functions are fast-fail liveness filters: they stop the relayer from
//! wasting a Miden transaction on an envelope the chain would certainly reject.

use sha3::{Digest, Keccak256};

use crate::error::{HexField, RelayerError};

/// A keccak256 digest is exactly 32 bytes.
const MESSAGE_HASH_LEN: usize = 32;

/// A raw secp256k1 attestation is exactly 65 bytes: `r` (32) ‖ `s` (32) ‖ `v` (1). `v` is the
/// recovery id — carried on the wire, unused on-chain (the faucet verifies against a supplied
/// candidate pubkey, so no key recovery is performed).
const ATTESTATION_LEN: usize = 65;

/// Verifies that the envelope's `messageHash` binds the payload: `messageHash ==
/// keccak256(payload)` (RAW keccak over the FULL payload — NOT EIP-712, NOT `personal_sign`, NOT
/// Poseidon2).
///
/// Both arguments are the Circle wire hex strings, with or without a `0x` prefix. Returns the
/// decoded payload bytes, so a caller that goes on to the DepositIntent structural decode does not
/// re-decode the hex.
///
/// This does NOT verify the ECDSA signature — see the module docs (that is on-chain, faucet-owned)
/// — and it does not structurally validate the payload: it establishes only that this hash covers
/// these bytes. The DepositIntent parse is
/// [`decode_and_validate_deposit_intent`](super::deposit_intent::decode_and_validate_deposit_intent),
/// the next filter in the chain.
///
/// # Errors
/// * [`RelayerError::MalformedHex`] — `payload_hex` (checked first) or `message_hash_hex` is not
///   valid hex.
/// * [`RelayerError::BadMessageHashLength`] — `messageHash` is not 32 bytes.
/// * [`RelayerError::MessageHashMismatch`] — the hash does not equal `keccak256(payload)`; carries
///   both the expected raw-keccak digest and the digest that was presented.
pub fn verify_message_hash(
    payload_hex: &str,
    message_hash_hex: &str,
) -> Result<Vec<u8>, RelayerError> {
    verify_message_hash_bytes(payload_hex, message_hash_hex).map(|(payload, _digest)| payload)
}

/// [`verify_message_hash`], returning the verified 32-byte digest alongside the decoded payload.
///
/// Identical check, strictly more of its result kept: a caller that needs the digest (the Circle
/// fetch path, which carries it into the validated attestation) would otherwise have to re-decode
/// the hex or re-run keccak256 over the payload — a second, drift-prone copy of the binding. There
/// is exactly one binding computation, here.
///
/// # Errors
/// Identical to [`verify_message_hash`].
pub fn verify_message_hash_bytes(
    payload_hex: &str,
    message_hash_hex: &str,
) -> Result<(Vec<u8>, [u8; MESSAGE_HASH_LEN]), RelayerError> {
    // The payload is the thing being bound, so it is decoded first: with both fields malformed, the
    // operator hears about the payload (deterministic precedence, no ambiguity in the logs).
    let payload = decode_hex(HexField::Payload, payload_hex)?;
    let message_hash = decode_hex(HexField::MessageHash, message_hash_hex)?;

    // A shape failure is reported as a shape failure — never as a binding mismatch (which would
    // send an operator hunting a hash-family bug when Circle simply sent a short field).
    let actual: [u8; MESSAGE_HASH_LEN] =
        message_hash
            .as_slice()
            .try_into()
            .map_err(|_| RelayerError::BadMessageHashLength {
                actual: message_hash.len(),
            })?;

    // THE binding: raw keccak256 over the FULL payload — the exact digest the faucet recomputes
    // on-chain (the faucet's attestation check) and verifies the attestation against. Every byte of
    // the payload is covered
    // (never a subset of the fields), and the comparison is over all 32 digest bytes.
    let expected = keccak256(&payload);
    if actual != expected {
        return Err(RelayerError::MessageHashMismatch { expected, actual });
    }

    Ok((payload, actual))
}

/// Validates the attestation envelope's shape: exactly 65 bytes (`r‖s‖v`), hex-valid.
///
/// Returns the raw 65 bytes verbatim (`r` = `[..32]`, `s` = `[32..64]`, `v` = `[64]`), ready for
/// the mint-note builder to hand to the faucet, which packs them into 17 u32-LE felts (the shared
/// encoding crate's [`signature_felts`](xusdc_encoding::xreserve::encoding::signature_felts)) and
/// verifies them on-chain.
///
/// SHAPE ONLY — this never verifies the signature, and never inspects `r`/`s`/`v` for
/// well-formedness beyond the length (see the module docs: the relayer must not be able to withhold
/// a mint the chain would accept). A 65-byte attestation that is cryptographic nonsense passes here
/// and is rejected on-chain in the faucet's attestation check, which is the correct division of
/// authority.
///
/// # Errors
/// * [`RelayerError::MalformedHex`] — not valid hex.
/// * [`RelayerError::BadAttestationLength`] — not exactly 65 bytes (a 64-byte, `v`-less signature
///   is rejected, not zero-extended).
pub fn validate_attestation_envelope(
    attestation_hex: &str,
) -> Result<[u8; ATTESTATION_LEN], RelayerError> {
    let bytes = decode_hex(HexField::Attestation, attestation_hex)?;

    bytes
        .as_slice()
        .try_into()
        .map_err(|_| RelayerError::BadAttestationLength {
            actual: bytes.len(),
        })
}

/// keccak256 (the original Keccak padding, NOT NIST SHA3-256 — they differ, and only the former is
/// what the on-chain keccak precompile and every EVM-side attestation produce).
fn keccak256(bytes: &[u8]) -> [u8; MESSAGE_HASH_LEN] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Decodes a Circle wire-hex field, tolerating the optional `0x`/`0X` prefix the API emits. The
/// rejection names WHICH field was malformed and CARRIES the originating [`hex::FromHexError`] as
/// its source, so the exact character and index survive into the error chain rather than being
/// flattened to "bad hex" (G-RUST preserve-error-source).
fn decode_hex(field: HexField, s: &str) -> Result<Vec<u8>, RelayerError> {
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);

    hex::decode(digits).map_err(|source| RelayerError::MalformedHex { field, source })
}
