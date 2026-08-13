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
//! - The digest is packed into u32-little-endian field elements with the same primitive
//!   miden-crypto uses for byte streams, four bytes per element. The signature keeps its raw
//!   `r‖s‖v` byte interface but is staged in the verifier's native scalar order: eight
//!   least-significant-first u32 limbs for `r`, eight for `s`, then `v`. These conversions cannot
//!   fail: every element is a `u32`, and the lengths come from fixed-size arrays rather than input.
//! - The public key is different, and its packing IS fallible. Circle hands over the 33-byte
//!   compressed SEC1 form, while the chain works with the point's affine coordinates as sixteen
//!   field elements. Decompressing is where a malformed or off-curve key is caught — rejecting it
//!   here is honest, since such a key could never verify on-chain either. Both the affine packing
//!   and the commitment below are the protocol's own `ecdsa_k256_keccak::PublicKey` conversions
//!   rather than a local reimplementation of them, so the element order — the x coordinate's eight
//!   limbs followed by the y coordinate's, each limb read big-endian, the limbs themselves in
//!   little-endian order — cannot drift away from the order the chain expects.
//! - The commitment (`PublicKey::to_commitment`) hashes those sixteen elements into the single Word
//!   that keys the attester allowlist. It is the one routine here with an on-chain twin: the
//!   faucet's verify recomputes the
//!   same commitment from the key presented to it and looks up that Word, so a mismatch between the
//!   two implementations would silently un-allowlist every attester.
//!
//! Producing the digest and running the signature check are the faucet's job, not this module's.

use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey as StockPublicKey;
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::crypto::SequentialCommit;
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::Felt;

use super::error::EncodingError;

/// Re-export of the stock commitment type: the attester-allowlist commitment path produces a raw
/// commitment `Word`, and the protocol already owns a newtype over exactly that `Word`, so a typed
/// caller names the commitment as this stock type rather than re-deriving one. A caller that needs
/// the raw `Word` back converts with `Word::from(commitment)`.
pub use miden_protocol::account::auth::PublicKeyCommitment;

/// Number of u32 field elements an affine secp256k1 public key packs to
/// (`qx_le_u32[8] || qy_le_u32[8]`) — the element count the commitment hashes.
pub const PUBKEY_FELTS: usize = 16;

/// Packs a 32-byte keccak digest into 8 u32-LE field elements (4 bytes/felt).
pub fn keccak_digest_felts(digest: &[u8; 32]) -> [Felt; 8] {
    bytes_to_packed_u32_elements(digest)
        .try_into()
        .expect("32 bytes always pack to exactly 8 u32 felts")
}

/// A Circle deposit attestation's raw 65-byte `r‖s‖v` ECDSA signature.
///
/// Wrapping the fixed-width byte array turns the packing into a method — `Signature::new(bytes)
/// .to_felts()` — so a caller states what the bytes ARE at the call site instead of passing a bare
/// `[u8; 65]` around. The type owns the packing (the golden-vector-locked felt layout below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 65]);

impl Signature {
    /// Wraps a raw 65-byte `r‖s‖v` signature (`v` carried in the last byte, unused on-chain).
    pub const fn new(bytes: [u8; 65]) -> Self {
        Self(bytes)
    }

    /// The raw 65 signature bytes.
    pub const fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }

    /// Packs the signature into the 17 field elements the on-chain attestation surface reads:
    /// `R[8] ‖ S[8] ‖ v`, where each scalar is split into least-significant-first u32 limbs and
    /// `v` is carried in felt 16 but unused on-chain. This is the native RC4 verifier witness order.
    /// Infallible: every element is a `u32` and the length comes from the fixed-size array, not from
    /// input.
    pub fn to_felts(&self) -> [Felt; 17] {
        let mut felts = [Felt::from(0u32); 17];
        for scalar_idx in 0..2 {
            for limb_idx in 0..8 {
                let byte_offset = scalar_idx * 32 + (7 - limb_idx) * 4;
                let limb = u32::from_be_bytes([
                    self.0[byte_offset],
                    self.0[byte_offset + 1],
                    self.0[byte_offset + 2],
                    self.0[byte_offset + 3],
                ]);
                felts[scalar_idx * 8 + limb_idx] = Felt::from(limb);
            }
        }
        felts[16] = Felt::from(u32::from(self.0[64]));
        felts
    }
}

/// A Circle attester's public key in Circle's 33-byte compressed SEC1 wire form.
///
/// The newtype names the Circle-facing wire form and carries the two fallible conversions as
/// methods — the affine-coordinate packing ([`PublicKey::to_affine_felts`]) and the allowlist
/// commitment ([`PublicKey::to_commitment`]) — so a caller states what the bytes ARE at the call
/// site instead of passing a bare `[u8; 33]` around. Both conversions delegate to the protocol's
/// own secp256k1 key type; this crate owns the seam, not the curve arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 33]);

impl PublicKey {
    /// Wraps a 33-byte compressed SEC1 candidate public key.
    pub const fn new(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }

    /// The raw 33 compressed-SEC1 bytes.
    pub const fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    /// Decompresses the compressed SEC1 key and packs its affine coordinates into the 16 u32-LE
    /// field elements the on-chain attestation surface consumes (`qx_le_u32[8] || qy_le_u32[8]`:
    /// each 32-byte big-endian coordinate read as eight big-endian u32 limbs emitted
    /// least-significant-limb first).
    ///
    /// # Errors
    ///
    /// Returns [`EncodingError::InvalidPubkey`] if the bytes do not decode to a curve point.
    pub fn to_affine_felts(&self) -> Result<[Felt; 16], EncodingError> {
        Ok(self
            .decompress()?
            .to_elements()
            .try_into()
            .expect("an affine secp256k1 point packs to exactly 16 felts"))
    }

    /// The attester-allowlist commitment key: the stock key's own commitment, Poseidon2 over the
    /// same 16 affine felts [`PublicKey::to_affine_felts`] returns, which is what the MASM
    /// `xreserve::attestation_verify::pubkey_commitment` recomputes from the felts staged in the
    /// mint note; the 16-felt input sets the sponge capacity domain tag to `16 % 8 = 0`. The
    /// commitment is the stock [`PublicKeyCommitment`]; `Word::from(commitment)` recovers the raw
    /// `Word`.
    ///
    /// # Errors
    ///
    /// Returns [`EncodingError::InvalidPubkey`] if the bytes do not decode to a curve point.
    pub fn to_commitment(&self) -> Result<PublicKeyCommitment, EncodingError> {
        Ok(PublicKeyCommitment::from(
            self.decompress()?.to_commitment(),
        ))
    }

    /// The SEC1 decompression seam: the 33 compressed bytes read as the protocol's own secp256k1
    /// key, which is where a malformed or off-curve key is caught — rejecting it here is honest,
    /// since such a key could never verify on-chain either.
    fn decompress(&self) -> Result<StockPublicKey, EncodingError> {
        StockPublicKey::read_from_bytes(&self.0).map_err(|_| EncodingError::InvalidPubkey)
    }
}

// TESTS — TV-ATT-1..3
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::utils::bytes_to_packed_u32_elements;
    use miden_protocol::Word;

    use super::*;
    use crate::vectors::load;

    /// TV-ATT-1 (felt shapes): the three packers yield exactly 8 / 16 / 17 felts and match
    /// the canonical packing of every vector's digest / pubkey / signature. Signature scalars use
    /// the native RC4 verifier limb order while the digest remains packed bytes.
    #[test]
    fn tv_att_1_felt_shapes() {
        for v in &load().families.att {
            let pk = PublicKey::new(v.pubkey())
                .to_affine_felts()
                .expect("vector pubkeys are valid points");
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

            let s = Signature::new(v.sig()).to_felts();
            assert_eq!(s.len(), 17, "{}: signature felt width", v.id);
            assert_eq!(
                s.as_slice(),
                v.sig_felts_values().as_slice(),
                "{}: signature felts",
                v.id
            );
        }
    }

    /// TV-ATT-2 (commitment): `PublicKey::to_commitment` equals miden-crypto
    /// `PublicKey::to_commitment`, the attester-allowlist keying primitive the faucet's
    /// attestation verify looks up.
    #[test]
    fn tv_att_2_commitment() {
        for v in &load().families.att {
            let commitment = PublicKey::new(v.pubkey())
                .to_commitment()
                .expect("vector pubkeys are valid points");
            assert_eq!(
                Word::from(commitment),
                v.expected_commitment_word(),
                "{}: the commitment must equal miden-crypto PublicKey::to_commitment",
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
                Signature::new(v.sig()).to_felts()[16],
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
            PublicKey::new(bogus).to_affine_felts().unwrap_err(),
            EncodingError::InvalidPubkey,
        );
        assert_eq!(
            PublicKey::new(bogus).to_commitment().unwrap_err(),
            EncodingError::InvalidPubkey,
        );
    }
}
