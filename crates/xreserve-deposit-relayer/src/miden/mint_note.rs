//! Builds mint notes from a validated attestation and the configured attester public key.
//! Circle's response carries the signature but not the key, so the operator supplies the key.
//! [`XUsdcMintNote`] owns the note layout; the faucet verifies authorization on-chain.

use miden_protocol::account::AccountId;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::note::Note;

use xusdc_encoding::note::xreserve_mint::{DepositAttestation, XUsdcMintNote};
use xusdc_encoding::xreserve::encoding::{DepositIntent, Signature};

use crate::error::{Cause, HexField, RelayerError};

/// The 33-byte compressed SEC1 length — the ONLY attester-key form the relayer handles (the
/// allowlist itself is keyed by the Poseidon2 commitment over the 16 affine felts this
/// key decompresses to).
const COMPRESSED_PUBKEY_LEN: usize = 33;

/// The attester public key the relayer is configured with: the key 33 compressed SEC1 bytes
/// decoded to.
///
/// A newtype, and decoded in its constructor, because the bytes are neither a Circle wire field nor
/// a value any check downstream would catch in time: they arrive from the operator's config, they
/// travel inside every mint note, and the faucet checks the key against `xReserveAttesters`
/// on-chain. A typo caught at startup costs a restart; the same typo caught by the chain costs
/// every mint until someone reads the logs. Point validity is judged by the protocol's own SEC1
/// decompression — this crate does not re-implement curve arithmetic — and holding the decoded key
/// rather than the bytes means the mint note never re-decodes what was already judged valid.
///
/// It is NOT an authority: an allowlisted key is one the FAUCET has in its allowlist, and only the
/// chain knows that. This type only guarantees the bytes are a key at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttesterPubkey(PublicKey);

impl AttesterPubkey {
    /// Decodes 33 raw bytes as a compressed SEC1 secp256k1 point.
    ///
    /// # Errors
    /// * [`RelayerError::InvalidAttesterPubkey`] — the bytes are not a curve point (the protocol's
    ///   `DeserializationError` is preserved as the source).
    pub fn new(bytes: [u8; COMPRESSED_PUBKEY_LEN]) -> Result<Self, RelayerError> {
        let key = PublicKey::read_from_bytes(&bytes)
            .map_err(|source| RelayerError::InvalidAttesterPubkey(Cause::new(source)))?;

        Ok(Self(key))
    }

    /// Parses the key as an operator writes it in configuration: hex, with or without the `0x`
    /// prefix.
    ///
    /// # Errors
    /// * [`RelayerError::MalformedHex`] — not hex ([`HexField::AttesterPubkey`]).
    /// * [`RelayerError::BadAttesterPubkeyLength`] — not 33 bytes (an uncompressed 65-byte key
    ///   lands here: it is a different encoding of the point, and not the form the allowlist
    ///   commitment is derived from).
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

    /// The decoded key, as it travels in every mint note.
    pub fn key(&self) -> &PublicKey {
        &self.0
    }
}

/// Builds the mint note for a validated Circle deposit attestation, by delegation to the shared
/// encoding crate's typed [`XUsdcMintNote`] builder.
///
/// The parameters:
///
/// * `sender` — the relayer's own account.
/// * `faucet_id` — the xUSDC faucet the note is routed at. It must be a PUBLIC network account:
///   the routing attachment can bind nothing else.
/// * `remote_domain` — the destination domain that faucet has configured. The faucet writes its own
///   into the message it rebuilds, so an intent naming a different one could never verify there.
/// * `deposit_intent` — the decoded Circle message, already through the shared codec.
/// * `attestation` — the validated 65-byte `r‖s‖v`. It and the intent travel together in the merged
///   scheme-4 transport attachment.
/// * `attester` — the operator-configured candidate pubkey, travelling beside the signature.
/// * `rng` — the caller's randomness. The serial number is drawn from it, which is what makes a
///   re-mint of the same DepositIntent a distinct note rather than a collision.
///
/// Nothing is ATTACHED to the note as an asset — `note.assets()` is empty — but the attested
/// amount travels all the same: it is embedded in the note's `MintNoteStorage` as the output
/// asset value, and the faucet mints exactly that amount when it consumes the note. The note is
/// public.
///
/// # Errors
/// [`RelayerError::MintNoteBuild`] — the shared encoding crate's factory refused the inputs: the
/// intent is addressed to a different faucet or a different domain, or a field it must carry is
/// unrepresentable (a `maxFee` beyond `AssetAmount::MAX`), or `faucet_id` is not a public network
/// account. That crate's `NoteError`
/// (and the `EncodingError` beneath it) is preserved as the error's source. The variant is NOT
/// retryable — none of those conditions clears on its own.
pub fn build_mint_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    remote_domain: u32,
    deposit_intent: DepositIntent,
    attestation: [u8; 65],
    attester: &AttesterPubkey,
    rng: &mut R,
) -> Result<Note, RelayerError> {
    XUsdcMintNote::builder()
        .sender(sender)
        .target(faucet_id)
        .remote_domain(remote_domain)
        .deposit_intent(deposit_intent)
        .attestation(DepositAttestation::new(
            Signature::new(attestation),
            attester.key().clone(),
        ))
        .generate_serial_number(rng)
        .build()
        .map(Note::from)
        .map_err(|source| RelayerError::MintNoteBuild(Cause::new(source)))
}
