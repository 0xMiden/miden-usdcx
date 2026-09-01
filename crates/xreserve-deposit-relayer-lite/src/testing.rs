//! Fixtures shared by the unit tests: dummy identities, a valid configuration, and attestations
//! whose payloads come from the canonical golden-vector artifact.

use miden_protocol::account::{AccountId, AccountIdVersion, AccountType, AssetCallbackFlag};
use miden_protocol::crypto::utils::Serializable;

use xusdc_encoding::vectors::load;
use xusdc_encoding::xreserve::encoding::{DepositIntent, DepositIntentHeader, DepositNonce};

use crate::circle::{Attestation, PageSize};
use crate::config::Config;

/// The Miden destination domain these tests address payloads to — a placeholder value, since the
/// real identifier is a Circle-owned decision that is still open.
pub const TEST_REMOTE_DOMAIN: u32 = 10001;

/// A valid 33-byte compressed SEC1 attester key (the pinned partner-fixture key). These tests
/// never verify a signature, so it only has to be a real curve point.
pub const ATTESTER_PUBKEY_HEX: &str =
    "03a13f9dcab6e20fe08b99362d9be1771810cff0b4e242dee574ce696630780d3f";

/// The xUSDC faucet the notes are routed at — public, because the routing attachment can bind
/// nothing else.
pub fn xusdc_dummy_faucet_id() -> AccountId {
    AccountId::dummy(
        [0x22; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// A second public faucet, for proving a note addressed elsewhere will not build.
pub fn other_dummy_faucet_id() -> AccountId {
    AccountId::dummy(
        [0x33; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// The relayer's own account — the notes' producer.
pub fn dummy_relayer_id() -> AccountId {
    AccountId::dummy(
        [0x11; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

impl Config {
    /// A valid config over the dummy identities.
    pub fn test() -> Self {
        Self {
            circle_url: "https://circle.test".parse().unwrap(),
            page_size: PageSize::try_from(100).unwrap(),
            request_timeout: std::time::Duration::from_secs(30),
            remote_domain: TEST_REMOTE_DOMAIN,
            faucet_account_id: xusdc_dummy_faucet_id(),
            relayer_account_id: dummy_relayer_id(),
            attester_public_key: ATTESTER_PUBKEY_HEX.to_string(),
            state_file: "unused".into(),
        }
    }
}

/// A DepositIntent carrying the canonical golden vector's amounts and hook data, with `faucet` as
/// the remote token and `nonce` as the deposit nonce. It is assembled through the encoding
/// crate's header builder, never by editing the vector's bytes.
pub fn deposit_intent(nonce: [u8; 32], faucet: AccountId) -> DepositIntent {
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
        .remote_domain(TEST_REMOTE_DOMAIN)
        .remote_token(faucet)
        .remote_recipient(header.remote_recipient())
        .local_token(header.local_token())
        .local_depositor(header.local_depositor())
        .max_fee(header.max_fee())
        .nonce(DepositNonce::new(nonce))
        .build();

    DepositIntent::new(rebuilt, base.hook_data().clone())
}

/// A buildable attestation for a deposit with this nonce seed, addressed to the dummy xUSDC
/// faucet. The signature bytes are shape-only: nothing off-chain verifies them.
pub fn attestation(seed: u8) -> Attestation {
    attestation_for(&deposit_intent([seed; 32], xusdc_dummy_faucet_id()))
}

/// The feed form of an arbitrary intent.
pub fn attestation_for(intent: &DepositIntent) -> Attestation {
    Attestation {
        payload: intent.to_bytes(),
        message_hash: [0u8; 32],
        signature: [0xAB; 65],
    }
}

/// An attestation whose payload is not a DepositIntent at all.
pub fn undecodable_attestation() -> Attestation {
    Attestation {
        payload: vec![0xFF; 16],
        message_hash: [0u8; 32],
        signature: [0xAB; 65],
    }
}
