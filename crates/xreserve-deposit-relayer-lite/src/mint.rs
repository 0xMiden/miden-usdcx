//! Builds xUSDC mint notes from Circle attestations.
//!
//! The note encoding is delegated to `xusdc-encoding`. This module supplies the configured
//! attester key required by the note and skips individual attestations that cannot be decoded or
//! built, allowing the remaining attestations in the page to proceed.

use anyhow::{anyhow, ensure, Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::note::Note;
use tracing::warn;

use xusdc_encoding::note::xreserve_mint::{DepositAttestation, XUsdcMintNote};
use xusdc_encoding::xreserve::encoding::{DepositIntent, Signature};

use crate::circle::Attestation;
use crate::config::Config;

/// The only attester-key form handled: 33-byte compressed SEC1.
const COMPRESSED_PUBKEY_LEN: usize = 33;

/// A raw secp256k1 attestation is `r` (32) ‖ `s` (32) ‖ `v` (1).
const ATTESTATION_LEN: usize = 65;

/// The configured identities used to build mint notes.
///
/// These values are parsed before the relay loop starts, so invalid configuration terminates the
/// process before any deposits are handled.
#[derive(Debug, Clone)]
pub struct Identities {
    sender: AccountId,
    faucet: AccountId,
    attester: PublicKey,
}

impl Identities {
    /// Parses the identities from the operator configuration.
    pub fn from_config(config: &Config) -> Result<Self> {
        Ok(Self {
            sender: config.relayer_account_id,
            faucet: config.faucet_account_id,
            attester: attester_pubkey(&config.attester_public_key)?,
        })
    }

    /// The relayer's own account — the notes' producer.
    pub fn sender(&self) -> AccountId {
        self.sender
    }
}

/// Decodes a compressed SEC1 attester key from hex with an optional `0x` prefix.
fn attester_pubkey(value: &str) -> Result<PublicKey> {
    let bytes = decode_hex(value).context("the attester public key is not hex")?;

    ensure!(
        bytes.len() == COMPRESSED_PUBKEY_LEN,
        "the attester public key is {} bytes, not {COMPRESSED_PUBKEY_LEN}",
        bytes.len()
    );

    PublicKey::read_from_bytes(&bytes).context("the attester public key is not a curve point")
}

/// Builds the mint notes for one page.
///
/// An attestation that cannot be decoded or built is logged and skipped. Each successful note
/// receives a serial number from `rng`, so rebuilding the same deposit produces a distinct note.
pub fn build_notes<R: FeltRng>(
    identities: &Identities,
    remote_domain: u32,
    attestations: &[Attestation],
    rng: &mut R,
) -> Vec<Note> {
    attestations
        .iter()
        .filter_map(|attestation| {
            build_note(identities, remote_domain, attestation, rng)
                .map_err(|error| {
                    warn!(
                        message_hash = %attestation.message_hash,
                        error = format!("{error:#}"),
                        "skipping an attestation that will not build"
                    );
                })
                .ok()
        })
        .collect()
}

/// Builds one note from one attestation.
///
/// Failures depend only on the attestation and configured identities, so retrying the same input
/// cannot make it build successfully.
fn build_note<R: FeltRng>(
    identities: &Identities,
    remote_domain: u32,
    attestation: &Attestation,
    rng: &mut R,
) -> Result<Note> {
    let payload = decode_hex(&attestation.payload).context("the payload is not hex")?;
    let signature = decode_hex(&attestation.attestation).context("the attestation is not hex")?;
    let signature: [u8; ATTESTATION_LEN] = signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("the attestation is not {ATTESTATION_LEN} bytes"))?;

    let intent = DepositIntent::try_from(payload.as_slice())
        .context("the payload is not a deposit intent")?;

    XUsdcMintNote::builder()
        .sender(identities.sender)
        .target(identities.faucet)
        .remote_domain(remote_domain)
        .deposit_intent(intent)
        .attestation(DepositAttestation::new(
            Signature::new(signature),
            identities.attester.clone(),
        ))
        .generate_serial_number(rng)
        .build()
        .map(Note::from)
        .context("building the mint note")
}

/// Circle wire hex, tolerating the optional `0x` prefix the API emits.
fn decode_hex(value: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(value.strip_prefix("0x").unwrap_or(value))?)
}
