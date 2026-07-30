//! Attestation encoding: turning Circle's signature material into the form the faucet verifies
//! against.
//!
//! A deposit attestation is a raw secp256k1 ECDSA signature over `keccak256` of the full deposit
//! payload — 65 bytes of `r‖s‖v` — and deliberately not EIP-712. The signature is what makes a mint
//! legitimate, so how it is packed matters as much as the cryptography: the faucet recomputes the
//! digest on-chain and looks the signer up in its attester allowlist, and both sides have to agree
//! byte for byte or a valid attestation would be rejected (or, worse, the wrong key would be looked
//! up).
//!
//! This module owns the packing, in both directions of the wire:
//!
//! - The digest and the signature are packed into u32-little-endian field elements with the same
//!   primitive miden-crypto uses for byte streams, four bytes per element. These conversions cannot
//!   fail: every element is a `u32`, and the lengths come
//!   from fixed-size arrays rather than from input.
//! - The public key is different, and its packing IS fallible. Circle hands over the 33-byte
//!   compressed SEC1 form, while the chain works with the point's affine coordinates as sixteen
//!   field elements. Decompressing is where a malformed or off-curve key is caught — rejecting it
//!   here is honest, since such a key could never verify on-chain either. The element order matches
//!   miden-crypto's own affine-point conversion: the x coordinate's eight limbs followed by the y
//!   coordinate's, each limb read big-endian, the limbs themselves in little-endian order.
//! - `pubkey_commitment` hashes those sixteen elements into the single Word that keys the attester
//!   allowlist. It is the one routine here with an on-chain twin: the faucet's verify recomputes the
//!   same commitment from the key presented to it and looks up that Word, so a mismatch between the
//!   two implementations would silently un-allowlist every attester. The cross-language conformance
//!   test is what holds them together.
//!
//! Producing the digest and running the signature check are the faucet's job, not this module's.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Hasher, Word};

use super::error::EncodingError;

/// Number of u32 field elements an affine secp256k1 public key packs to
/// (`qx_le_u32[8] || qy_le_u32[8]`) — the element count the commitment hashes.
/// The MASM side declares a `PUBKEY_FELTS` constant with the same value, and a parity test fails
/// if the two ever diverge.
pub const PUBKEY_FELTS: usize = 16;

/// Packs a 32-byte keccak digest into 8 u32-LE field elements (4 bytes/felt).
pub fn keccak_digest_felts(digest: &[u8; 32]) -> [Felt; 8] {
    bytes_to_packed_u32_elements(digest)
        .try_into()
        .expect("32 bytes always pack to exactly 8 u32 felts")
}

/// Decompresses a 33-byte compressed SEC1 secp256k1 public key (the Circle-facing wire form)
/// and packs its affine coordinates into the 16 u32 field elements the on-chain
/// attestation surface consumes (`qx_le_u32[8] || qy_le_u32[8]`; byte-order
/// identical to miden-crypto 0.28 `affine_point_to_elements`: each 32-byte big-endian
/// coordinate is read as eight big-endian u32 limbs emitted least-significant-limb first).
///
/// # Errors
///
/// Returns [`EncodingError::InvalidPubkey`] if the bytes do not decode to a curve point.
pub fn affine_pubkey_felts(pk: &[u8; 33]) -> Result<[Felt; 16], EncodingError> {
    let point = k256::PublicKey::from_sec1_bytes(pk)
        .map_err(|_| EncodingError::InvalidPubkey)?
        .to_encoded_point(false);
    let qx: &[u8] = point
        .x()
        .expect("an uncompressed point carries x")
        .as_slice();
    let qy: &[u8] = point
        .y()
        .expect("an uncompressed point carries y")
        .as_slice();
    let limb = |coord: &[u8], idx: usize| {
        let start = 32 - 4 * (idx + 1);
        u32::from_be_bytes(coord[start..start + 4].try_into().expect("4-byte chunk"))
    };
    Ok(core::array::from_fn(|idx| {
        if idx < 8 {
            Felt::from(limb(qx, idx))
        } else {
            Felt::from(limb(qy, idx - 8))
        }
    }))
}

/// Packs a 65-byte `r‖s‖v` signature into 17 u32-LE field elements; `v` is carried in felt
/// 16 (byte 64, upper 3 bytes zero-filled) and is unused on-chain.
pub fn signature_felts(sig: &[u8; 65]) -> [Felt; 17] {
    bytes_to_packed_u32_elements(sig)
        .try_into()
        .expect("65 bytes always pack to exactly 17 u32 felts")
}

/// The attester-allowlist commitment key: Poseidon2 over the 16 affine pubkey felts,
/// identical to miden-crypto 0.28 `PublicKey::to_commitment`
/// (`Poseidon2::hash_elements(affine_point_to_elements())`) and to the MASM
/// `xreserve::attestation_verify::pubkey_commitment` the faucet recomputes. `Hasher` is the
/// protocol's Poseidon2 (same primitive as `bytes32_to_storage_map_key`); the 16-felt input
/// sets the sponge capacity domain tag to `16 % 8 = 0` — verified == `to_commitment` by
/// TV-ATT-2 and the cross-implementation vector check. Takes the 33-byte compressed wire form
/// and decompresses internally (single-owner rule: this encoding crate owns the SEC1→affine seam).
///
/// # Errors
///
/// Returns [`EncodingError::InvalidPubkey`] if the bytes do not decode to a curve point.
pub fn pubkey_commitment(pk: &[u8; 33]) -> Result<Word, EncodingError> {
    Ok(Hasher::hash_elements(&affine_pubkey_felts(pk)?))
}

// TESTS — TV-ATT-1..3
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::utils::bytes_to_packed_u32_elements;

    use super::*;
    use crate::vectors::load;

    /// TV-ATT-1 (felt shapes): the three packers yield exactly 8 / 16 / 17 felts and match
    /// the canonical packing of every vector's digest / pubkey / signature.
    #[test]
    fn tv_att_1_felt_shapes() {
        for v in &load().families.att {
            let pk = affine_pubkey_felts(&v.pubkey()).expect("vector pubkeys are valid points");
            assert_eq!(pk.len(), 16, "{}: pubkey felt width", v.id);
            assert_eq!(
                pk.as_slice(),
                v.packed_felts_values().as_slice(),
                "{}: pubkey felts",
                v.id
            );

            let d = keccak_digest_felts(&v.digest());
            assert_eq!(d.len(), 8, "{}: digest felt width", v.id);
            assert_eq!(
                d.as_slice(),
                v.digest_felts_values().as_slice(),
                "{}: digest felts",
                v.id
            );

            let s = signature_felts(&v.sig());
            assert_eq!(s.len(), 17, "{}: signature felt width", v.id);
            assert_eq!(
                s.as_slice(),
                v.sig_felts_values().as_slice(),
                "{}: signature felts",
                v.id
            );
        }
    }

    /// TV-ATT-2 (commitment): `pubkey_commitment(pk)` equals miden-crypto
    /// `PublicKey::to_commitment` (the value the generator baked into each vector — the
    /// attester-allowlist keying primitive the faucet's attestation verify looks up).
    #[test]
    fn tv_att_2_commitment() {
        for v in &load().families.att {
            assert_eq!(
                pubkey_commitment(&v.pubkey()).expect("vector pubkeys are valid points"),
                v.expected_commitment_word(),
                "{}: pubkey_commitment must equal miden-crypto PublicKey::to_commitment",
                v.id
            );
        }
    }

    /// TV-ATT-3 (raw keccak, not EIP-712): the digest helper packs the raw keccak digest
    /// VERBATIM — it prepends no EIP-712 `\x19\x01` domain / personal-sign prefix and hashes
    /// no `depositAttestation` struct; the digest is over a FULL DepositIntent payload; the
    /// input is the RAW 65-byte `r‖s‖v` signature (`v` carried in felt 16).
    #[test]
    fn tv_att_3_raw_keccak_not_eip712() {
        for v in &load().families.att {
            let digest = v.digest();
            // pure verbatim packer — no domain/struct framing felts added.
            assert_eq!(
                keccak_digest_felts(&digest).as_slice(),
                bytes_to_packed_u32_elements(&digest).as_slice(),
                "{}: digest helper must pack the raw keccak digest verbatim (no EIP-712 framing)",
                v.id
            );
            // raw keccak is taken over the ENTIRE DepositIntent payload (>= the 240-byte header).
            assert!(
                v.payload().len() >= 240,
                "{}: digest must be keccak over a full DepositIntent payload, got {} bytes",
                v.id,
                v.payload().len()
            );
            // the input is the raw 65-byte r||s||v signature, NOT an EIP-712 typed-data sig.
            assert_eq!(
                v.sig().len(),
                65,
                "{}: raw r||s||v signature is 65 bytes",
                v.id
            );
            assert_eq!(
                signature_felts(&v.sig())[16],
                Felt::from(u32::from(v.v_byte)),
                "{}: v byte carried in felt 16 (unused on-chain)",
                v.id
            );
        }
    }

    /// The SEC1 decompression seam fail-closes: bytes that are not a curve point reject with
    /// `InvalidPubkey` (an even-parity prefix with an x that has no square-root partner).
    #[test]
    fn invalid_pubkey_rejects() {
        let mut bogus = [0xFFu8; 33];
        bogus[0] = 0x02;
        assert_eq!(
            affine_pubkey_felts(&bogus).unwrap_err(),
            EncodingError::InvalidPubkey,
        );
        assert_eq!(
            pubkey_commitment(&bogus).unwrap_err(),
            EncodingError::InvalidPubkey,
        );
    }
}
