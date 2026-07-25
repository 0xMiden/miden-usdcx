//! `build_mint_note` — the DepositIntent-attestation → mint-note translation, and the
//! operator-configured attester key it needs.
//!
//! The builder is thin ON PURPOSE. It performs exactly two acts: it bundles the attestation the
//! relayer VALIDATED (`ValidatedAttestation` — the type that has passed the §8.1 raw-keccak binding
//! and the 65-byte shape check) with the attester pubkey the OPERATOR configured, and it hands both,
//! plus the payload, to unit-04's [`XReserveMintNote::create`]. Everything a mint note IS — the
//! packed storage, the two attachments, the tag, the note type, the script — is decided there.
//!
//! **Why the pubkey is a parameter and the signature is not.** Circle's attestation object carries
//! three fields: `payload`, `messageHash`, `attestation` (the 65-byte `r‖s‖v`). It does NOT carry
//! the attester's public key. But the faucet's D5d verify needs the candidate pubkey in the note, so
//! the 33-byte compressed key comes from the relayer's own configuration — it is the key whose
//! DC-3 commitment (Poseidon2 over the 16 affine felts it decompresses to, v16 vm#3342) the
//! operator was told is enabled in the faucet's `xReserveAttesters` allowlist. The payload and the
//! signature, in contrast, are Circle's, and they come through the validated boundary and nowhere
//! else: there is no public entry point here that accepts them as raw bytes (a note built from bytes
//! whose `messageHash == keccak256(payload)` binding was never checked is a transaction spent on an
//! envelope the chain will reject).
//!
//! **What the builder can and cannot cause.** It is a liveness component: a bug here withholds a
//! mint (a note the faucet refuses, an error where a note should have been) — it cannot authorize
//! one. The nonce assert-then-set, the amount reduction, the attester-allowlist check and the ECDSA
//! verification are all on-chain and faucet-owned (§1.2). That is also why every failure path below
//! is a typed, NON-retryable error: a payload the codec refuses does not become valid on a retry,
//! and a relayer that looped on one would stop minting everything else.

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::Note;

use xusdc_encoding::note::xreserve_mint::{MintAttestation, XReserveMintNote};
use xusdc_encoding::xreserve::encoding::affine_pubkey_felts;

use crate::circle::schema::ValidatedAttestation;
use crate::error::{Cause, HexField, RelayerError};

/// The 33-byte compressed SEC1 length — the ONLY attester-key form the relayer handles (the
/// allowlist itself is keyed by the DC-3 Poseidon2 commitment over the affine coordinates this
/// key decompresses to — 16 felts since v16, vm#3342).
const COMPRESSED_PUBKEY_LEN: usize = 33;

/// The attester public key the relayer is configured with: 33 compressed SEC1 bytes that ARE a
/// secp256k1 curve point.
///
/// A newtype, and validated in its constructor, because it is neither a Circle wire field nor a
/// value any check downstream would catch in time: it arrives from the operator's config, it travels
/// inside every mint note, and the faucet checks it against `xReserveAttesters` on-chain. A typo
/// caught at startup costs a restart; the same typo caught by the chain costs every mint until
/// someone reads the logs. Point validity is judged by unit-04's own SEC1 decompression
/// ([`affine_pubkey_felts`], the same primitive that packs the affine felts the faucet verifies) —
/// this crate does not re-implement curve arithmetic.
///
/// It is NOT an authority: an allowlisted key is one the FAUCET has in its allowlist, and only the
/// chain knows that. This type only guarantees the bytes are a key at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttesterPubkey([u8; COMPRESSED_PUBKEY_LEN]);

impl AttesterPubkey {
    /// Validates 33 raw bytes as a compressed SEC1 secp256k1 point.
    ///
    /// # Errors
    /// * [`RelayerError::InvalidAttesterPubkey`] — the bytes are not a curve point (unit-04's
    ///   [`EncodingError::InvalidPubkey`](xusdc_encoding::xreserve::encoding::EncodingError) is
    ///   preserved as the source).
    pub fn new(bytes: [u8; COMPRESSED_PUBKEY_LEN]) -> Result<Self, RelayerError> {
        // the felts are discarded: this call is here as the OWNER's validity judgement on the key,
        // not to encode anything (the encoding happens inside unit-04's note factory).
        affine_pubkey_felts(&bytes)
            .map_err(|source| RelayerError::InvalidAttesterPubkey(Cause::new(source)))?;

        Ok(Self(bytes))
    }

    /// Parses the key as an operator writes it in configuration: hex, with or without the `0x`
    /// prefix.
    ///
    /// # Errors
    /// * [`RelayerError::MalformedHex`] — not hex ([`HexField::AttesterPubkey`]).
    /// * [`RelayerError::BadAttesterPubkeyLength`] — not 33 bytes (an uncompressed 65-byte key lands
    ///   here: it is a different encoding of the point, and not the form the allowlist commitment
    ///   (DC-3) is derived from).
    /// * [`RelayerError::InvalidAttesterPubkey`] — 33 bytes that are not a curve point.
    pub fn from_hex(hex: &str) -> Result<Self, RelayerError> {
        let bytes = hex::decode(hex.strip_prefix("0x").unwrap_or(hex)).map_err(|source| {
            RelayerError::MalformedHex {
                field: HexField::AttesterPubkey,
                source,
            }
        })?;

        let bytes: [u8; COMPRESSED_PUBKEY_LEN] =
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| RelayerError::BadAttesterPubkeyLength {
                    actual: bytes.len(),
                })?;

        Self::new(bytes)
    }

    /// The 33 compressed SEC1 bytes.
    pub fn as_bytes(&self) -> &[u8; COMPRESSED_PUBKEY_LEN] {
        &self.0
    }
}

/// Builds the mint note for a validated Circle deposit attestation — by DELEGATION to unit-04's
/// [`XReserveMintNote::create`], which owns every byte of the note's form.
///
/// `sender` is the relayer's own account (the note's producer), `faucet_id` the xUSDC faucet the
/// note is routed at (a PUBLIC network account — the scheme-2 routing attachment can bind nothing
/// else), `attestation` the validated envelope (its DepositIntent payload becomes the note's
/// storage; its 65-byte `r‖s‖v` travels in the scheme-1 attestation attachment), `attester` the
/// operator-configured candidate pubkey that travels beside the signature, and `rng` the caller's
/// randomness — the note's serial number is drawn from it, which is what makes a re-mint of the same
/// DepositIntent a distinct note rather than a collision.
///
/// The note is asset-less and public; the faucet MINTS the amount when it consumes the note (the
/// amount is not transported).
///
/// # Errors
/// [`RelayerError::MintNoteBuild`] — unit-04's factory refused the inputs: the payload is not a
/// structurally valid DepositIntent or exceeds the 1024-felt `NoteStorage` bound, or `faucet_id` is
/// not a public network account. Unit-04's `NoteError` (and the `EncodingError` beneath it) is
/// preserved as the error's source. The variant is NOT retryable — none of those conditions clears
/// on its own.
pub fn build_mint_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    attestation: &ValidatedAttestation,
    attester: &AttesterPubkey,
    rng: &mut R,
) -> Result<Note, RelayerError> {
    let mint_attestation = MintAttestation::new(attestation.attestation(), *attester.as_bytes());

    XReserveMintNote::create(
        sender,
        faucet_id,
        attestation.payload(),
        &mint_attestation,
        rng,
    )
    .map_err(|source| RelayerError::MintNoteBuild(Cause::new(source)))
}
