//! Attestation (ATT) surface — frozen signatures per the shared-encoding spec
//! (INV-DEPOSIT-ATTESTATION-RAW-KECCAK, DC-2). This library owns the byte→felt packing of
//! the digest / compressed pubkey / signature (relayer + harness, Rust-only) and the
//! on-chain commitment-keying primitive `pubkey_commitment` — the canonical attester-
//! allowlist key the faucet D5d verify (R-MINT-13) recomputes and looks up by reference
//! (`xreserve::encoding::pubkey_commitment`, the ONLY on-chain proc of this surface). The
//! `keccak256::hash_bytes` digest production and the `ecdsa_k256_keccak::verify_prehash`
//! call are faucet-owned (flow D5d); this library owns only the packing + commitment keying.
//!
//! All four are infallible u32-LE packers / the Poseidon2 commitment — the same
//! `bytes_to_packed_u32_elements` primitive miden-crypto uses for `to_elements`, so each
//! `Felt` is a `u32 < p` (`felt-construction`: `Felt::from(u32)`, never `Felt::new`, no
//! truncation; lengths are type-guaranteed, not input-dependent).

use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Hasher, Word};

/// Number of u32-LE field elements a 33-byte compressed secp256k1 public key packs to
/// (`33.div_ceil(4) = 9`) — the element count the commitment hashes. Parity-pinned against
/// the MASM `PUBKEY_FELTS` constant by `tests/constant_parity.rs` (`masm-rust-constant-parity`).
pub const PUBKEY_FELTS: usize = 9;

/// Packs a 32-byte keccak digest into 8 u32-LE field elements (4 bytes/felt).
pub fn keccak_digest_felts(digest: &[u8; 32]) -> [Felt; 8] {
    bytes_to_packed_u32_elements(digest)
        .try_into()
        .expect("32 bytes always pack to exactly 8 u32 felts")
}

/// Packs a 33-byte compressed secp256k1 public key into 9 u32-LE field elements (the final
/// felt holds byte 32 with the upper 3 bytes zero-filled).
pub fn compressed_pubkey_felts(pk: &[u8; 33]) -> [Felt; 9] {
    bytes_to_packed_u32_elements(pk)
        .try_into()
        .expect("33 bytes always pack to exactly 9 u32 felts")
}

/// Packs a 65-byte `r‖s‖v` signature into 17 u32-LE field elements; `v` is carried in felt
/// 16 (byte 64, upper 3 bytes zero-filled) and is unused on-chain.
pub fn signature_felts(sig: &[u8; 65]) -> [Felt; 17] {
    bytes_to_packed_u32_elements(sig)
        .try_into()
        .expect("65 bytes always pack to exactly 17 u32 felts")
}

/// The attester-allowlist commitment key: Poseidon2 over the 9 u32-LE pubkey felts, identical
/// to miden-crypto `PublicKey::to_commitment` (`Poseidon2::hash_elements(to_elements())`,
/// `to_elements = bytes_to_packed_u32_elements(to_bytes())`) and to the MASM
/// `xreserve::encoding::pubkey_commitment` the faucet D5d verify recomputes. `Hasher` is the
/// protocol's Poseidon2 (same primitive as `bytes32_to_storage_map_key`); the 9-felt input
/// engages the sponge capacity domain tag (`9 % 8 = 1`) — verified == `to_commitment` by
/// TV-ATT-2 / TV-DUAL-5.
// clippy 1.93 flags the `Word::from` as `useless_conversion`, but removing it would change
// executable behaviour, so the lint is suppressed in place instead.
#[allow(clippy::useless_conversion)]
pub fn pubkey_commitment(pk: &[u8; 33]) -> Word {
    Word::from(Hasher::hash_elements(&compressed_pubkey_felts(pk)))
}

// TESTS — TV-ATT-1..3
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::utils::bytes_to_packed_u32_elements;

    use super::*;
    use crate::vectors::load;

    /// TV-ATT-1 (felt shapes): the three packers yield exactly 8 / 9 / 17 felts and match
    /// the canonical packing of every vector's digest / pubkey / signature.
    #[test]
    fn tv_att_1_felt_shapes() {
        for v in &load().families.att {
            let pk = compressed_pubkey_felts(&v.pubkey());
            assert_eq!(pk.len(), 9, "{}: pubkey felt width", v.id);
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
                pubkey_commitment(&v.pubkey()),
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
}
