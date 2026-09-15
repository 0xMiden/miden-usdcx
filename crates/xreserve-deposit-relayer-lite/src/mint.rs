//! Builds xUSDC mint notes from Circle attestations.
//!
//! The note encoding is delegated to `xusdc-encoding`. This module supplies the configured
//! attester key required by the note and skips individual attestations that cannot be decoded or
//! built, allowing the remaining attestations in the page to proceed.

use std::str::FromStr;

use anyhow::{ensure, Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::crypto::utils::Deserializable;
use miden_protocol::{Felt, Word};
use tracing::{error, instrument};

use xusdc_encoding::note::xreserve_mint::{DepositAttestation, XUsdcMintNote};
use xusdc_encoding::xreserve::encoding::DepositIntent;

use crate::circle::{Attestation, RemoteDomain};
use crate::config::Config;

/// The public key of the Circle attester whose signatures the mint notes carry. Parsed from the
/// 33-byte compressed SEC1 form, so a value that is not a curve point never becomes a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttesterPublicKey(PublicKey);

impl AttesterPublicKey {
    /// The only key form handled: 33-byte compressed SEC1.
    const COMPRESSED_LEN: usize = 33;
}

impl FromStr for AttesterPublicKey {
    type Err = anyhow::Error;

    /// Decodes a compressed SEC1 key from hex with an optional `0x` prefix.
    fn from_str(value: &str) -> Result<Self> {
        let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
            .context("the attester public key is not hex")?;

        // Reading the key takes the first 33 bytes and leaves the rest where they are, without
        // complaining that they went unread. A longer value would therefore be accepted as
        // whatever key its opening 33 bytes happen to spell, so the length is checked here.
        ensure!(
            bytes.len() == Self::COMPRESSED_LEN,
            "the attester public key is {} bytes, not {}",
            bytes.len(),
            Self::COMPRESSED_LEN
        );

        PublicKey::read_from_bytes(&bytes)
            .map(Self)
            .context("the attester public key is not a curve point")
    }
}

/// A 128-bit seed for the note serial numbers, from a cryptographic generator the operating system
/// seeds with its own entropy.
///
/// The serial number is what makes a re-mint of the same DepositIntent a DISTINCT note rather than
/// a collision, so it must NOT be reproducible across restarts.
///
/// Built from `u32`s: every one is a felt exactly, so the seed is the entropy that was drawn rather
/// than that entropy silently reduced modulo the field.
fn entropy_seed() -> Word {
    use rand::Rng;

    let mut rng = rand::rng();
    Word::from([
        Felt::from(rng.next_u32()),
        Felt::from(rng.next_u32()),
        Felt::from(rng.next_u32()),
        Felt::from(rng.next_u32()),
    ])
}

/// Builds mint notes for one faucet from the attestations of one remote domain.
///
/// Every identity is validated when the command line is parsed, so an invalid configuration
/// terminates the process before any deposits are handled.
#[derive(Debug)]
pub struct Minter {
    mint_account: AccountId,
    usdcx_faucet: AccountId,
    attester: AttesterPublicKey,
    remote_domain: RemoteDomain,
    rng: RandomCoin,
}

impl Minter {
    /// Builds a minter from the operator configuration. Note serial numbers are drawn from a
    /// generator seeded by the operating system.
    pub fn from_config(config: &Config) -> Self {
        Self {
            mint_account: config.relayer_account_id,
            usdcx_faucet: config.faucet_account_id,
            attester: config.attester_public_key.clone(),
            remote_domain: config.remote_domain,
            rng: RandomCoin::new(entropy_seed()),
        }
    }

    /// The relayer's own account — the notes' producer.
    pub fn mint_account(&self) -> AccountId {
        self.mint_account
    }

    /// Builds the mint notes for one page.
    ///
    /// The attestations are borrowed rather than owned, so a caller that is minting a subset of a
    /// page does not have to copy it first.
    ///
    /// An attestation that cannot be decoded or built is logged and skipped. Each successful note
    /// receives a fresh serial number, so rebuilding the same deposit produces a distinct note.
    #[instrument(name = "build_notes", skip_all, fields(attestations = attestations.len()))]
    pub fn build_notes(&mut self, attestations: &[&Attestation]) -> Vec<XUsdcMintNote> {
        attestations
            .iter()
            .filter_map(|attestation| {
                self.build_note(attestation)
                    .map_err(|error| {
                        error!(
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
    /// Failures depend only on the attestation and the configured identities, so retrying the
    /// same input cannot make it build successfully.
    fn build_note(&mut self, attestation: &Attestation) -> Result<XUsdcMintNote> {
        let intent = DepositIntent::try_from(attestation.payload.as_slice())
            .context("the payload is not a deposit intent")?;

        XUsdcMintNote::builder()
            .sender(self.mint_account)
            .target(self.usdcx_faucet)
            .remote_domain(self.remote_domain.into())
            .deposit_intent(intent)
            .attestation(DepositAttestation::new(
                attestation.signature,
                self.attester.0.clone(),
            ))
            .generate_serial_number(&mut self.rng)
            .build()
            .context("building the mint note")
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
    use miden_protocol::crypto::utils::Serializable;
    use miden_protocol::note::{Note, NoteId};
    use rstest::rstest;

    use xusdc_encoding::vectors::load;
    use xusdc_encoding::xreserve::encoding::{
        DepositIntent, DepositIntentHeader, DepositNonce, Signature,
    };

    use super::{AttesterPublicKey, Minter, XUsdcMintNote};
    use crate::circle::{Attestation, MessageHash, PageSize, RemoteDomain};
    use crate::config::Config;
    use crate::miden::{ExpirationDelta, NotesPerTransaction};

    /// The Miden destination domain these tests address payloads to — a placeholder value, since
    /// the real identifier is a Circle-owned decision that is still open.
    const REMOTE_DOMAIN: RemoteDomain = RemoteDomain::new(10001);

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
            .remote_domain(REMOTE_DOMAIN.into())
            .remote_token(faucet)
            .remote_recipient(header.remote_recipient())
            .local_token(header.local_token())
            .local_depositor(header.local_depositor())
            .max_fee(header.max_fee())
            .nonce(DepositNonce::new(nonce))
            .build();

        DepositIntent::new(rebuilt, base.hook_data().clone())
    }

    impl Config {
        /// A valid config over the dummy identities.
        fn test() -> Self {
            Self {
                circle_url: "https://circle.test".parse().unwrap(),
                page_size: PageSize::try_from(100).unwrap(),
                request_timeout: std::time::Duration::from_secs(30),
                poll_interval: std::time::Duration::from_secs(5),
                remote_domain: REMOTE_DOMAIN,
                miden_node_url: "http://127.0.0.1:57291".parse().unwrap(),
                miden_data_dir: "unused".into(),
                notes_per_transaction: NotesPerTransaction::try_from(64).unwrap(),
                expiration_delta: ExpirationDelta::try_from(64).unwrap(),
                faucet_account_id: xusdc_dummy_faucet_id(),
                relayer_account_id: dummy_account_id(0x11),
                attester_public_key: ATTESTER_PUBKEY_HEX.parse().unwrap(),
                state_file: "unused".into(),
            }
        }
    }

    impl Minter {
        /// A minter over the test config.
        fn test() -> Self {
            Self::from_config(&Config::test())
        }
    }

    impl Attestation {
        /// The feed form of an arbitrary intent. The signature bytes are shape-only: nothing
        /// off-chain verifies them.
        fn for_intent(intent: &DepositIntent) -> Self {
            Self {
                payload: intent.to_bytes(),
                message_hash: MessageHash::new([0u8; 32]),
                signature: Signature::new([0xAB; 65]),
            }
        }

        /// A buildable attestation for a deposit with this nonce seed, addressed to the dummy
        /// xUSDC faucet.
        fn buildable(seed: u8) -> Self {
            Self::for_intent(&deposit_intent([seed; 32], xusdc_dummy_faucet_id()))
        }

        /// An attestation whose payload is not a DepositIntent at all.
        fn undecodable() -> Self {
            Self {
                payload: vec![0xFF; 16],
                message_hash: MessageHash::new([0u8; 32]),
                signature: Signature::new([0xAB; 65]),
            }
        }
    }

    /// Every valid attestation on a page becomes a note.
    #[test]
    fn valid_attestations_build_notes() {
        let notes =
            Minter::test().build_notes(&[&Attestation::buildable(1), &Attestation::buildable(2)]);
        assert_eq!(notes.len(), 2);
    }

    /// A malformed attestation is skipped while the valid attestations in the page still build.
    #[test]
    fn a_malformed_attestation_is_skipped_not_fatal() {
        let notes = Minter::test().build_notes(&[
            &Attestation::buildable(1),
            &Attestation::undecodable(),
            &Attestation::buildable(3),
        ]);
        assert_eq!(notes.len(), 2, "the two good deposits still build");
    }

    /// A deposit addressed to another faucet is skipped while the rest of the page still builds.
    #[test]
    fn a_deposit_for_another_faucet_is_skipped() {
        let elsewhere = Attestation::for_intent(&deposit_intent([9; 32], other_dummy_faucet_id()));
        let notes = Minter::test().build_notes(&[&elsewhere, &Attestation::buildable(2)]);
        assert_eq!(notes.len(), 1);
    }

    /// The protocol note identifier of the one note a page was expected to build. Converting is
    /// the caller's job, so these tests do it where they need an identifier.
    fn only_note_id(notes: Vec<XUsdcMintNote>) -> NoteId {
        Note::from(notes.into_iter().next().expect("the page built one note")).id()
    }

    /// Rebuilding the same deposit twice yields distinct notes because each receives a new serial
    /// number.
    #[test]
    fn a_rebuilt_deposit_is_a_distinct_note() {
        let mut minter = Minter::test();
        let first = minter.build_notes(&[&Attestation::buildable(1)]);
        let second = minter.build_notes(&[&Attestation::buildable(1)]);
        assert_ne!(only_note_id(first), only_note_id(second));
    }

    /// The `0x` prefix is optional and does not change the key.
    #[test]
    fn the_attester_key_accepts_an_optional_prefix() {
        let bare: AttesterPublicKey = ATTESTER_PUBKEY_HEX.parse().unwrap();
        let prefixed: AttesterPublicKey = format!("0x{ATTESTER_PUBKEY_HEX}").parse().unwrap();
        assert_eq!(bare, prefixed);
    }

    /// A malformed attester key is refused when it is parsed.
    #[rstest]
    #[case::not_hex("nothex")]
    #[case::too_short("0xdeadbeef")]
    #[case::not_a_point("03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
    fn a_malformed_attester_key_is_refused(#[case] value: &str) {
        let error = format!("{:#}", value.parse::<AttesterPublicKey>().unwrap_err());
        assert!(
            error.contains("attester public key"),
            "unexpected error: {error}"
        );
    }

    /// A key carrying bytes past the compressed form is refused. Reading it would stop at the 33rd
    /// byte and ignore the rest, so without the length check a mistyped key would be accepted as
    /// whatever its opening bytes spell.
    #[test]
    fn an_attester_key_with_trailing_bytes_is_refused() {
        let trailing = format!("{ATTESTER_PUBKEY_HEX}ab");
        let error = format!("{:#}", trailing.parse::<AttesterPublicKey>().unwrap_err());
        assert!(
            error.contains("is 34 bytes, not 33"),
            "unexpected error: {error}"
        );
    }
}
