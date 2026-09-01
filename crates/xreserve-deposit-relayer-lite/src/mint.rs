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
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
    use miden_protocol::crypto::utils::Serializable;
    use rstest::rstest;

    use xusdc_encoding::vectors::load;
    use xusdc_encoding::xreserve::encoding::{DepositIntent, DepositIntentHeader, DepositNonce};

    use super::Minter;
    use crate::circle::{Attestation, PageSize};
    use crate::config::Config;

    /// The Miden destination domain these tests address payloads to — a placeholder value, since
    /// the real identifier is a Circle-owned decision that is still open.
    const REMOTE_DOMAIN: u32 = 10001;

    /// A valid 33-byte compressed SEC1 attester key (the pinned partner-fixture key). These tests
    /// never verify a signature, so it only has to be a real curve point.
    const ATTESTER_PUBKEY_HEX: &str =
        "03a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3f";

    /// A public account with this seed byte. All the identities here are public because the
    /// note's routing attachment can bind nothing else.
    fn dummy_account_id(seed: u8) -> AccountId {
        AccountId::dummy(
            [seed; 15],
            AccountIdVersion::Version1,
            AccountType::Public,
            AssetCallbackFlag::Disabled,
        )
    }

    /// The xUSDC faucet the notes are routed at.
    fn xusdc_dummy_faucet_id() -> AccountId {
        dummy_account_id(0x22)
    }

    /// A second faucet, for proving a note addressed elsewhere will not build.
    fn other_dummy_faucet_id() -> AccountId {
        dummy_account_id(0x33)
    }

    /// A valid config over the dummy identities.
    fn config() -> Config {
        Config {
            circle_url: "https://circle.test".parse().unwrap(),
            page_size: PageSize::try_from(100).unwrap(),
            request_timeout: std::time::Duration::from_secs(30),
            remote_domain: REMOTE_DOMAIN,
            faucet_account_id: xusdc_dummy_faucet_id(),
            relayer_account_id: dummy_account_id(0x11),
            attester_public_key: ATTESTER_PUBKEY_HEX.to_string(),
            state_file: "unused".into(),
        }
    }

    fn minter() -> Minter {
        Minter::from_config(&config()).expect("the test config is valid")
    }

    /// A DepositIntent carrying the canonical golden vector's amounts and hook data, with
    /// `faucet` as the remote token and `nonce` as the deposit nonce. It is assembled through the
    /// encoding crate's header builder, never by editing the vector's bytes.
    fn deposit_intent(nonce: [u8; 32], faucet: AccountId) -> DepositIntent {
        let vector = load()
            .families
            .mi
            .iter()
            .find(|vector| vector.id == "mi-pos-hookdata")
            .expect("the canonical accept vector is in the artifact");

        let base = DepositIntent::try_from(vector.payload().as_slice())
            .expect("the canonical vector is a structurally valid deposit intent");
        let header = base.header();

        let rebuilt = DepositIntentHeader::builder()
            .amount(header.amount())
            .remote_domain(REMOTE_DOMAIN)
            .remote_token(faucet)
            .remote_recipient(header.remote_recipient())
            .local_token(header.local_token())
            .local_depositor(header.local_depositor())
            .max_fee(header.max_fee())
            .nonce(DepositNonce::new(nonce))
            .build();

        DepositIntent::new(rebuilt, base.hook_data().clone())
    }

    /// The feed form of an arbitrary intent. The signature bytes are shape-only: nothing
    /// off-chain verifies them.
    fn attestation_for(intent: &DepositIntent) -> Attestation {
        Attestation {
            payload: intent.to_bytes(),
            message_hash: [0u8; 32],
            signature: [0xAB; 65],
        }
    }

    /// A buildable attestation for a deposit with this nonce seed, addressed to the dummy xUSDC
    /// faucet.
    fn attestation(seed: u8) -> Attestation {
        attestation_for(&deposit_intent([seed; 32], xusdc_dummy_faucet_id()))
    }

    /// An attestation whose payload is not a DepositIntent at all.
    fn undecodable_attestation() -> Attestation {
        Attestation {
            payload: vec![0xFF; 16],
            message_hash: [0u8; 32],
            signature: [0xAB; 65],
        }
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
        let mut config = config();
        config.attester_public_key = value.to_string();

        let error = format!("{:#}", Minter::from_config(&config).unwrap_err());
        assert!(
            error.contains("attester public key"),
            "unexpected error: {error}"
        );
    }
}
