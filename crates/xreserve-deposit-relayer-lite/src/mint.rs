//! Builds xUSDC mint notes from Circle attestations.
//!
//! The note encoding is delegated to `xusdc-encoding`. This module supplies the configured
//! attester key required by the note and skips individual attestations that cannot be decoded or
//! built, allowing the remaining attestations in the page to proceed.

use anyhow::{ensure, Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::crypto::rand::{random_word, RandomCoin};
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::note::Note;
use tracing::warn;

use xusdc_encoding::note::xreserve_mint::{DepositAttestation, XUsdcMintNote};
use xusdc_encoding::xreserve::encoding::{DepositIntent, Signature};

use crate::circle::Attestation;
use crate::config::Config;

/// The only attester-key form handled: 33-byte compressed SEC1.
const COMPRESSED_PUBKEY_LEN: usize = 33;

/// Builds mint notes for one faucet from the attestations of one remote domain.
///
/// The identities are parsed from the configuration before the relay loop starts, so an invalid
/// configuration terminates the process before any deposits are handled.
#[derive(Debug)]
pub struct Minter {
    sender: AccountId,
    faucet: AccountId,
    attester: PublicKey,
    remote_domain: u32,
    rng: RandomCoin,
}

impl Minter {
    /// Builds a minter from the operator configuration. Note serial numbers are drawn from a
    /// generator seeded by the operating system.
    ///
    /// # Errors
    ///
    /// - The attester public key is not a 33-byte compressed SEC1 curve point in hex.
    pub fn from_config(config: &Config) -> Result<Self> {
        Ok(Self {
            sender: config.relayer_account_id,
            faucet: config.faucet_account_id,
            attester: Self::attester_pubkey(&config.attester_public_key)?,
            remote_domain: config.remote_domain,
            rng: RandomCoin::new(random_word()),
        })
    }

    /// The relayer's own account — the notes' producer.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// Builds the mint notes for one page.
    ///
    /// An attestation that cannot be decoded or built is logged and skipped. Each successful note
    /// receives a fresh serial number, so rebuilding the same deposit produces a distinct note.
    pub fn build_notes(&mut self, attestations: &[Attestation]) -> Vec<Note> {
        attestations
            .iter()
            .filter_map(|attestation| {
                self.build_note(attestation)
                    .map_err(|error| {
                        warn!(
                            message_hash = format!("0x{}", hex::encode(attestation.message_hash)),
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
    /// Failures depend only on the attestation and the configured identities, so retrying the
    /// same input cannot make it build successfully.
    fn build_note(&mut self, attestation: &Attestation) -> Result<Note> {
        let intent = DepositIntent::try_from(attestation.payload.as_slice())
            .context("the payload is not a deposit intent")?;

        XUsdcMintNote::builder()
            .sender(self.sender)
            .target(self.faucet)
            .remote_domain(self.remote_domain)
            .deposit_intent(intent)
            .attestation(DepositAttestation::new(
                Signature::new(attestation.signature),
                self.attester.clone(),
            ))
            .generate_serial_number(&mut self.rng)
            .build()
            .map(Note::from)
            .context("building the mint note")
    }

    /// Decodes a compressed SEC1 attester key from hex with an optional `0x` prefix.
    fn attester_pubkey(value: &str) -> Result<PublicKey> {
        let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
            .context("the attester public key is not hex")?;

        ensure!(
            bytes.len() == COMPRESSED_PUBKEY_LEN,
            "the attester public key is {} bytes, not {COMPRESSED_PUBKEY_LEN}",
            bytes.len()
        );

        PublicKey::read_from_bytes(&bytes).context("the attester public key is not a curve point")
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::Minter;
    use crate::config::Config;
    use crate::testing::{
        attestation, attestation_for, deposit_intent, other_dummy_faucet_id,
        undecodable_attestation,
    };

    fn minter() -> Minter {
        Minter::from_config(&Config::test()).expect("the test config is valid")
    }

    /// Every valid attestation on a page becomes a note.
    #[test]
    fn valid_attestations_build_notes() {
        let notes = minter().build_notes(&[attestation(1), attestation(2)]);
        assert_eq!(notes.len(), 2);
    }

    /// A malformed attestation is skipped while the valid attestations in the page still build.
    #[test]
    fn a_malformed_attestation_is_skipped_not_fatal() {
        let notes =
            minter().build_notes(&[attestation(1), undecodable_attestation(), attestation(3)]);
        assert_eq!(notes.len(), 2, "the two good deposits still build");
    }

    /// A deposit addressed to another faucet is skipped while the rest of the page still builds.
    #[test]
    fn a_deposit_for_another_faucet_is_skipped() {
        let elsewhere = attestation_for(&deposit_intent([9; 32], other_dummy_faucet_id()));
        let notes = minter().build_notes(&[elsewhere, attestation(2)]);
        assert_eq!(notes.len(), 1);
    }

    /// Rebuilding the same deposit twice yields distinct notes because each receives a new serial
    /// number.
    #[test]
    fn a_rebuilt_deposit_is_a_distinct_note() {
        let mut minter = minter();
        let first = minter.build_notes(&[attestation(1)]);
        let second = minter.build_notes(&[attestation(1)]);
        assert_ne!(first[0].id(), second[0].id());
    }

    /// A malformed attester key is rejected during startup.
    #[rstest]
    #[case::not_hex("nothex")]
    #[case::wrong_length("0xdeadbeef")]
    #[case::not_a_point("03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
    fn a_malformed_attester_key_is_refused_at_startup(#[case] value: &str) {
        let mut config = Config::test();
        config.attester_public_key = value.to_string();

        let error = format!("{:#}", Minter::from_config(&config).unwrap_err());
        assert!(
            error.contains("attester public key"),
            "unexpected error: {error}"
        );
    }
}
