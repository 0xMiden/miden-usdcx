//! The Miden-facing translation: a validated attestation becomes an `XUsdcMintNote`.
//!
//! This module is thin on purpose. Every byte of the note's wire form — the storage, the
//! attachments, the note type, the script — belongs to `xusdc-encoding`'s builder and is not
//! restated here (single-owner rule). What this adds is the operator-configured attester key, which
//! Circle's attestation object does not carry but the faucet's on-chain check needs in the note.
//!
//! A failure here is PERMANENT: a payload addressed to another faucet does not become valid on a
//! retry, so the caller skips the deposit rather than looping on it.

use anyhow::{ensure, Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::note::Note;
use tracing::instrument;

use xusdc_encoding::note::xreserve_mint::{DepositAttestation, XUsdcMintNote};
use xusdc_encoding::xreserve::encoding::{DepositIntent, Signature};

use crate::config::Config;

/// The only attester-key form handled: 33-byte compressed SEC1.
const COMPRESSED_PUBKEY_LEN: usize = 33;

/// The three identities a mint note is built from, all parsed at STARTUP.
///
/// Bundled because they travel together and are meaningless apart: the note is built BY `sender`
/// FOR `faucet` carrying `attester`'s key. Two of them are same-typed `AccountId`s with opposite
/// meanings, so loose arguments would let a swap compile.
#[derive(Debug, Clone)]
pub struct Identities {
    sender: AccountId,
    faucet: AccountId,
    attester: PublicKey,
}

impl Identities {
    /// Parses all three out of the operator's config.
    ///
    /// # Errors
    /// Any of the three is malformed. Refused here, at startup: a typo caught now costs a restart,
    /// and the same typo caught by the chain costs every mint until someone reads the logs.
    #[instrument(name = "identities.from_config", skip_all)]
    pub fn from_config(config: &Config) -> Result<Self> {
        Ok(Self {
            sender: account_id("relayer_account_id", &config.relayer_account_id)?,
            faucet: account_id("faucet_account_id", &config.faucet_account_id)?,
            attester: attester_pubkey(&config.attester_pubkey_hex)?,
        })
    }

    /// The relayer's own account — the note's producer.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// The xUSDC faucet the note is routed at.
    pub fn faucet(&self) -> AccountId {
        self.faucet
    }

    /// The configured attester key. It is a KEY, not an authority: whether it is allowlisted is the
    /// faucet's `xReserveAttesters` to say, on-chain.
    pub fn attester(&self) -> &PublicKey {
        &self.attester
    }
}

/// Parses a configured account id, naming the FIELD — "some account id is bad" is not something an
/// operator can act on.
#[instrument(level = "trace", skip(value))]
fn account_id(field: &str, value: &str) -> Result<AccountId> {
    AccountId::from_hex(value)
        .with_context(|| format!("the configured {field} is not an account id"))
}

/// Decodes the attester key as an operator writes it: hex, with or without `0x`.
#[instrument(level = "trace", skip_all)]
fn attester_pubkey(value: &str) -> Result<PublicKey> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .context("the configured attester_pubkey_hex is not hex")?;

    ensure!(
        bytes.len() == COMPRESSED_PUBKEY_LEN,
        "the configured attester_pubkey_hex is {} bytes, not {COMPRESSED_PUBKEY_LEN} (an \
         uncompressed 65-byte key is a different encoding and not the form the allowlist \
         commitment is derived from)",
        bytes.len()
    );

    PublicKey::read_from_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("the configured attester_pubkey_hex is not a curve point")
}

/// Builds the mint note for one validated deposit.
///
/// Nothing is attached as an asset — the attested amount travels in the note's storage, and the
/// faucet mints exactly that when it consumes the note. The serial number is drawn from `rng`,
/// which is what makes a re-mint of the same deposit a distinct note rather than a collision.
///
/// # Errors
/// The builder refused the inputs: the intent is addressed to another faucet or another domain, a
/// field it must carry is unrepresentable, or the faucet is not a public network account. All
/// PERMANENT.
#[instrument(name = "build_mint_note", skip_all, fields(remote_domain))]
pub fn build_mint_note<R: FeltRng>(
    identities: &Identities,
    remote_domain: u32,
    deposit_intent: DepositIntent,
    signature: [u8; 65],
    rng: &mut R,
) -> Result<Note> {
    XUsdcMintNote::builder()
        .sender(identities.sender())
        .target(identities.faucet())
        .remote_domain(remote_domain)
        .deposit_intent(deposit_intent)
        .attestation(DepositAttestation::new(
            Signature::new(signature),
            identities.attester().clone(),
        ))
        .generate_serial_number(rng)
        .build()
        .map(Note::from)
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("building the mint note")
}
