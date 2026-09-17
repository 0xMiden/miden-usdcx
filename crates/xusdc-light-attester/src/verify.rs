//! Checks Circle's prepared authorization against the burns, without signing or storing it.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{eip712_domain, SolStruct};
use miden_protocol::note::NoteId;
use miden_protocol::transaction::TransactionId;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use xusdc_encoding::xreserve::MIDEN_DOMAIN;

use crate::burn::ValidatedBurn;
use crate::circle::{BurnIntent, UnverifiedPrepareResponse};
use crate::config::Config;

const BURN_INTENT_MAGIC: [u8; 4] = 0x070a_fbc2u32.to_be_bytes();
const BURN_INTENT_SET_MAGIC: [u8; 4] = 0xe999_239bu32.to_be_bytes();

// Names and field order are part of Circle's EIP-712 type hashes.
mod eip712 {
    alloy_sol_types::sol! {
        struct TransferSpec {
            uint32 version;
            uint32 sourceDomain;
            uint32 destinationDomain;
            bytes32 sourceContract;
            bytes32 destinationContract;
            bytes32 sourceToken;
            bytes32 destinationToken;
            bytes32 sourceDepositor;
            bytes32 destinationRecipient;
            bytes32 sourceSigner;
            bytes32 destinationCaller;
            uint256 value;
            bytes32 salt;
            bytes hookData;
        }

        struct BurnIntent {
            uint256 maxBlockHeight;
            uint256 maxFee;
            TransferSpec spec;
        }

        struct BurnIntentSet {
            BurnIntent[] intents;
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum VerifyError {
    #[error("Circle returned a different number of batches or intents")]
    WrongCount,
    #[error("Circle returned an unknown salt")]
    UnknownSalt,
    #[error("Circle changed the burn's {0}")]
    WrongBurnField(&'static str),
    #[error("Circle's payout and fee do not account for the burn")]
    BadAmount,
    #[error("Circle's fee exceeds the configured ceiling")]
    FeeTooHigh,
    #[error("Circle's source signer and depositor differ")]
    WrongSigner,
    #[error("Circle restricted the destination caller")]
    CallerRestricted,
    #[error("forwarded withdrawals are not supported yet")]
    Forwarding,
    #[error("Circle's signing hash differs from the checked fields")]
    DigestMismatch,
    #[error("Circle's encoded intent differs from the checked fields")]
    EncodedMismatch,
    #[error("Circle returned a malformed {0}")]
    MalformedField(&'static str),
}

/// Only this module can construct or change a verified authorization.
#[derive(Debug)]
pub(crate) struct VerifiedWithdrawal {
    batch: VerifiedBatch,
}

impl VerifiedWithdrawal {
    pub(crate) fn note_id(&self) -> NoteId {
        self.batch.note_id
    }
}

#[derive(Debug)]
struct VerifiedBatch {
    // Several notes may share a transaction ID; the note ID identifies the burn's store row.
    note_id: NoteId,
    burn_tx_id: TransactionId,
    intent: BurnIntent,
    digest: B256,
}

pub(crate) fn verify_prepared_response(
    burn: &ValidatedBurn,
    response: UnverifiedPrepareResponse,
    config: &Config,
) -> Result<VerifiedWithdrawal, VerifyError> {
    let mut batches = response.batches.into_iter();
    let (Some(batch), None) = (batches.next(), batches.next()) else {
        return Err(VerifyError::WrongCount);
    };
    let mut intents = batch.burn_intents.into_iter();
    let (Some(raw), None) = (intents.next(), intents.next()) else {
        return Err(VerifyError::WrongCount);
    };
    let (intent, hook) = parse_intent(&raw)?;
    let spec = &intent.spec;

    let remote_token =
        B256::from(EthEmbeddedAccountId::from_account_id(config.faucet_account_id()).to_bytes32());
    let fee_ceiling = U256::from(config.max_withdrawal_fee().as_u64());

    if B256::from(burn.burn.note.as_note().serial_num().as_bytes()) != spec.salt {
        return Err(VerifyError::UnknownSalt);
    }
    if spec.destinationDomain != burn.items.dest_domain {
        return Err(VerifyError::WrongBurnField("destinationDomain"));
    }
    if spec.destinationRecipient.as_slice() != burn.items.dest_recipient.as_bytes() {
        return Err(VerifyError::WrongBurnField("destinationRecipient"));
    }
    if hook.remote_domain != MIDEN_DOMAIN {
        return Err(VerifyError::WrongBurnField("remoteDomain"));
    }
    // The Miden sender belongs in the hook, not Circle's sourceDepositor field.
    let sender =
        EthEmbeddedAccountId::from_account_id(burn.burn.note.as_note().metadata().sender());
    if hook.remote_depositor != B256::from(sender.to_bytes32()) {
        return Err(VerifyError::WrongBurnField("remoteDepositor"));
    }
    if hook.remote_token != remote_token {
        return Err(VerifyError::WrongBurnField("remoteToken"));
    }
    let burned_amount = U256::from(burn.amount);
    // Circle deducts the fee from the burn; the payout alone is smaller than the burn.
    if spec.value.is_zero() || spec.value.checked_add(intent.maxFee) != Some(burned_amount) {
        return Err(VerifyError::BadAmount);
    }
    if intent.maxFee > fee_ceiling.min(burned_amount) {
        return Err(VerifyError::FeeTooHigh);
    }
    if spec.sourceSigner != spec.sourceDepositor {
        return Err(VerifyError::WrongSigner);
    }
    if spec.destinationCaller != B256::ZERO {
        return Err(VerifyError::CallerRestricted);
    }
    if hook.forwarding_contract != Address::ZERO || !hook.forwarding_calldata.is_empty() {
        return Err(VerifyError::Forwarding);
    }

    let supplied_bytes: Bytes = parse(&batch.encoded, "encoded")?;
    let as_set = framing(&supplied_bytes)?;
    if supplied_bytes.as_ref() != encode_framed_intent(&intent, as_set)? {
        return Err(VerifyError::EncodedMismatch);
    }
    let digest = signing_hash(intent, as_set);
    if digest != parse::<B256>(&batch.message_hash_to_sign, "messageHashToSign")? {
        return Err(VerifyError::DigestMismatch);
    }
    Ok(VerifiedWithdrawal {
        batch: VerifiedBatch {
            note_id: burn.burn.note_id(),
            burn_tx_id: burn.burn.burn_tx_id,
            intent: raw,
            digest,
        },
    })
}

struct HookData {
    remote_domain: u32,
    remote_token: B256,
    remote_depositor: B256,
    forwarding_contract: Address,
    forwarding_calldata: Bytes,
}

fn parse<T: std::str::FromStr>(text: &str, field: &'static str) -> Result<T, VerifyError> {
    text.parse().map_err(|_| VerifyError::MalformedField(field))
}

fn decimal(text: &str, field: &'static str) -> Result<U256, VerifyError> {
    U256::from_str_radix(text, 10).map_err(|_| VerifyError::MalformedField(field))
}

fn parse_intent(raw: &BurnIntent) -> Result<(eip712::BurnIntent, HookData), VerifyError> {
    let spec = &raw.spec;
    let hook = &spec.hook_data;
    let hook = HookData {
        remote_domain: hook.remote_domain,
        remote_token: parse(&hook.remote_token, "remoteToken")?,
        remote_depositor: parse(&hook.remote_depositor, "remoteDepositor")?,
        forwarding_contract: parse(
            &hook.forwarding_contract_address,
            "forwardingContractAddress",
        )?,
        forwarding_calldata: parse(&hook.forwarding_calldata, "forwardingCalldata")?,
    };
    let intent = eip712::BurnIntent {
        maxBlockHeight: decimal(&raw.max_block_height, "maxBlockHeight")?,
        maxFee: decimal(&raw.max_fee, "maxFee")?,
        spec: eip712::TransferSpec {
            version: spec.version,
            sourceDomain: spec.source_domain,
            destinationDomain: spec.destination_domain,
            sourceContract: parse(&spec.source_contract, "sourceContract")?,
            destinationContract: parse(&spec.destination_contract, "destinationContract")?,
            sourceToken: parse(&spec.source_token, "sourceToken")?,
            destinationToken: parse(&spec.destination_token, "destinationToken")?,
            sourceDepositor: parse(&spec.source_depositor, "sourceDepositor")?,
            destinationRecipient: parse(&spec.destination_recipient, "destinationRecipient")?,
            sourceSigner: parse(&spec.source_signer, "sourceSigner")?,
            destinationCaller: parse(&spec.destination_caller, "destinationCaller")?,
            value: decimal(&spec.value, "value")?,
            salt: parse(&spec.salt, "salt")?,
            hookData: encode_hook(&hook)?.into(),
        },
    };
    Ok((intent, hook))
}

fn append_with_length(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), VerifyError> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| VerifyError::MalformedField("encoded length"))?;
    output.extend(length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_hook(hook: &HookData) -> Result<Vec<u8>, VerifyError> {
    // JSON omits the binary magic/version; its 20-byte address is left-padded to bytes32.
    let mut bytes = 0x6b20_f62au32.to_be_bytes().to_vec();
    bytes.extend(1u32.to_be_bytes());
    bytes.extend(hook.remote_domain.to_be_bytes());
    bytes.extend_from_slice(hook.remote_token.as_slice());
    bytes.extend_from_slice(hook.remote_depositor.as_slice());
    bytes.extend_from_slice(hook.forwarding_contract.into_word().as_slice());
    append_with_length(&mut bytes, &hook.forwarding_calldata)?;
    Ok(bytes)
}

fn encode_transfer_spec(spec: &eip712::TransferSpec) -> Result<Vec<u8>, VerifyError> {
    let mut bytes = 0xca85_def7u32.to_be_bytes().to_vec();
    bytes.extend(spec.version.to_be_bytes());
    bytes.extend(spec.sourceDomain.to_be_bytes());
    bytes.extend(spec.destinationDomain.to_be_bytes());
    for field in [
        spec.sourceContract,
        spec.destinationContract,
        spec.sourceToken,
        spec.destinationToken,
        spec.sourceDepositor,
        spec.destinationRecipient,
        spec.sourceSigner,
        spec.destinationCaller,
    ] {
        bytes.extend_from_slice(field.as_slice());
    }
    bytes.extend(spec.value.to_be_bytes::<32>());
    bytes.extend_from_slice(spec.salt.as_slice());
    append_with_length(&mut bytes, &spec.hookData)?;
    Ok(bytes)
}

fn encode_burn_intent(intent: &eip712::BurnIntent) -> Result<Vec<u8>, VerifyError> {
    let mut bytes = BURN_INTENT_MAGIC.to_vec();
    bytes.extend(intent.maxBlockHeight.to_be_bytes::<32>());
    bytes.extend(intent.maxFee.to_be_bytes::<32>());
    append_with_length(&mut bytes, &encode_transfer_spec(&intent.spec)?)?;
    Ok(bytes)
}

fn encode_framed_intent(intent: &eip712::BurnIntent, as_set: bool) -> Result<Vec<u8>, VerifyError> {
    let intent = encode_burn_intent(intent)?;
    if !as_set {
        return Ok(intent);
    }
    let mut set = BURN_INTENT_SET_MAGIC.to_vec();
    set.extend(1u32.to_be_bytes());
    set.extend(intent);
    Ok(set)
}

fn framing(encoded: &[u8]) -> Result<bool, VerifyError> {
    if encoded.starts_with(&BURN_INTENT_SET_MAGIC) {
        Ok(true)
    } else if encoded.starts_with(&BURN_INTENT_MAGIC) {
        Ok(false)
    } else {
        Err(VerifyError::MalformedField("encoded"))
    }
}

fn signing_hash(intent: eip712::BurnIntent, as_set: bool) -> B256 {
    // Circle omits chainId/verifyingContract. This digest is NOT keccak256(encoded).
    let domain = eip712_domain! { name: "GatewayWallet", version: "1", };
    if as_set {
        let set = eip712::BurnIntentSet {
            intents: vec![intent],
        };
        set.eip712_signing_hash(&domain)
    } else {
        intent.eip712_signing_hash(&domain)
    }
}

// Keeps semantic test mutations self-consistent; this is not an independent reference vector.
#[cfg(test)]
pub(crate) fn rebuild_for_test(
    batch: &mut crate::circle::UnverifiedPrepareBatch,
    as_set: bool,
) -> Result<(), VerifyError> {
    let (intent, _) = parse_intent(&batch.burn_intents[0])?;
    batch.encoded = format!("0x{}", hex::encode(encode_framed_intent(&intent, as_set)?));
    let digest = signing_hash(intent, as_set);
    batch.message_hash_to_sign = format!("{digest:#x}");
    Ok(())
}

#[cfg(test)]
pub(crate) fn canonical_values_for_test(
    batch: &crate::circle::UnverifiedPrepareBatch,
) -> Result<(Vec<u8>, B256), VerifyError> {
    let [raw] = batch.burn_intents.as_slice() else {
        return Err(VerifyError::WrongCount);
    };
    let (intent, _) = parse_intent(raw)?;
    let supplied: Bytes = parse(&batch.encoded, "encoded")?;
    let as_set = framing(&supplied)?;
    let encoded = encode_framed_intent(&intent, as_set)?;
    let digest = signing_hash(intent, as_set);
    Ok((encoded, digest))
}
