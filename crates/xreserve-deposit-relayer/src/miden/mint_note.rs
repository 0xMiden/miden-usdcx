//! `build_mint_note` — the DepositIntent-attestation → mint-note translation, and the
//! operator-configured attester key it needs.
//!
//! The builder is thin ON PURPOSE. It bundles the attestation the relayer VALIDATED (a
//! `ValidatedAttestation` has passed the raw-keccak digest binding and the 65-byte shape check)
//! with the attester pubkey the OPERATOR configured, and hands both — plus the DepositIntent payload
//! (as the typed [`DepositIntent`](xusdc_encoding::xreserve::encoding::DepositIntent)) — to the shared encoding crate's typed [`XUsdcMintNote`] builder,
//! which decides every byte of the note's form: the storage, the two attachments, the note type, and
//! the script.
//!
//! **Why the pubkey is a parameter and the signature is not.** Circle's attestation object carries
//! `payload`, `messageHash`, and `attestation` (the 65-byte `r‖s‖v`) — but NOT the attester's
//! public key, which the faucet's on-chain check needs in the note. So the 33-byte compressed key
//! comes from the relayer's own configuration: it is the key whose commitment (Poseidon2 over the
//! 16 affine felts it decompresses to) the operator was told is enabled in the faucet's
//! `xReserveAttesters` allowlist. The payload and the signature are Circle's, and they reach this
//! module only through the validated boundary — there is no entry point that takes them as raw
//! bytes, because a note built from bytes whose `messageHash == keccak256(payload)` binding was
//! never checked is a transaction spent on an envelope the chain will reject.
//!
//! **What the builder can and cannot cause.** It is a liveness component: a bug here withholds a
//! mint (a note the faucet refuses, an error where a note should have been) — it cannot authorize
//! one. The nonce assert-then-set, the amount reduction, the attester-allowlist check and the ECDSA
//! verification are all on-chain and faucet-owned. That is also why every failure path below
//! is a typed, NON-retryable error: a payload the codec refuses does not become valid on a retry,
//! and a relayer that looped on one would stop minting everything else.

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
/// unrepresentable (a `maxFee` beyond `AssetAmount::MAX`, a `localToken` / `localDepositor` that is
/// not a 20-byte address), or `faucet_id` is not a public network account. That crate's `NoteError`
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
        .faucet_id(faucet_id)
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
