//! Attestation (ATT) surface — frozen signatures per the shared-encoding spec
//! (INV-DEPOSIT-ATTESTATION-RAW-KECCAK, DC-2 under its v16 supersession —
//! MIGRATION-V16-ALPHA2.md S16). This library owns the byte→felt packing of the digest /
//! pubkey / signature (relayer + harness, Rust-only), the DC-2 SEC1→affine pubkey
//! decompression (the Circle-facing wire form stays the 33-byte compressed SEC1 key; the
//! on-chain form is the 16 affine-coordinate felts since vm#3342), and the on-chain
//! commitment-keying primitive `pubkey_commitment` — the canonical attester-allowlist key the
//! faucet D5d verify (R-MINT-13) recomputes and looks up by reference
//! (`xreserve::encoding::pubkey_commitment`, the ONLY on-chain proc of this surface). The
//! `keccak256::hash_bytes` digest production and the `ecdsa_k256_keccak::verify_prehash`
//! call are faucet-owned (flow D5d); this library owns only the packing + commitment keying.
//!
//! The digest/signature packers are infallible u32-LE packers — the same
//! `bytes_to_packed_u32_elements` primitive miden-crypto uses for byte streams, so each
//! `Felt` is a `u32 < p` (`felt-construction`: `Felt::from(u32)`, never `Felt::new`, no
//! truncation; lengths are type-guaranteed, not input-dependent). The pubkey packer is
//! FALLIBLE: it decompresses the SEC1 point first (an off-curve key rejects here — it could
//! never verify on-chain either) and then packs the affine coordinates exactly as
//! miden-crypto 0.28's `affine_point_to_elements` does (per-limb big-endian u32 reads in
//! little-endian limb order: `qx_le_u32[8] || qy_le_u32[8]`).

use k256::elliptic_curve::sec1::ToEncodedPoint;
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Hasher, Word};

use super::error::EncodingError;

/// Number of u32 field elements an affine secp256k1 public key packs to
/// (`qx_le_u32[8] || qy_le_u32[8]`) — the element count the commitment hashes (vm#3342).
/// Parity-pinned against the MASM `PUBKEY_FELTS` constant by `tests/constant_parity.rs`
/// (`masm-rust-constant-parity`).
pub const PUBKEY_FELTS: usize = 16;

/// Packs a 32-byte keccak digest into 8 u32-LE field elements (4 bytes/felt).
pub fn keccak_digest_felts(digest: &[u8; 32]) -> [Felt; 8] {
    bytes_to_packed_u32_elements(digest)
        .try_into()
        .expect("32 bytes always pack to exactly 8 u32 felts")
}

/// Decompresses a 33-byte compressed SEC1 secp256k1 public key (the Circle-facing wire form)
/// and packs its affine coordinates into the 16 u32 field elements the v16 on-chain
/// attestation surface consumes (`qx_le_u32[8] || qy_le_u32[8]` — vm#3342; byte-order
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
/// `xreserve::encoding::pubkey_commitment` the faucet D5d verify recomputes. `Hasher` is the
/// protocol's Poseidon2 (same primitive as `bytes32_to_storage_map_key`); the 16-felt input
/// sets the sponge capacity domain tag to `16 % 8 = 0` — verified == `to_commitment` by
/// TV-ATT-2 / TV-DUAL-5. Takes the 33-byte compressed wire form and decompresses internally
/// (single-owner rule: unit-04 owns the SEC1→affine seam).
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
    /// attester-allowlist keying primitive D5d looks up).
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
