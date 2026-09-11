//! Checks Circle's prepared authorization against the burns, then signs only the checked digest.

use alloy_primitives::{keccak256, Address, Bytes, Signature, B256, U256};
use alloy_sol_types::{eip712_domain, SolStruct};
use miden_protocol::note::NoteId;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use serde::Deserialize;
use serde_json::json;
use xusdc_encoding::xreserve::MIDEN_DOMAIN;

use crate::burn::ValidatedBurn;
use crate::circle::{BurnIntent, StructuredHookData, UnverifiedPrepareResponse};
use crate::config::Config;
use crate::signer::{Signer, SignerError};
use crate::submission::{SavedSubmission, SubmissionStatus, SubmitError};

// Circle's Gateway contracts (BurnIntents.sol) start an encoded burn intent with
// bytes4(keccak256("circle.gateway.BurnIntent")).
const BURN_INTENT_MAGIC: [u8; 4] = 0x070a_fbc2u32.to_be_bytes();
// Circle's Gateway contracts (TransferSpec.sol) start an encoded transfer spec with
// bytes4(keccak256("circle.gateway.TransferSpec")).
const TRANSFER_SPEC_MAGIC: [u8; 4] = 0xca85_def7u32.to_be_bytes();
// Circle's xReserve contracts (WithdrawHookData.sol) start the withdrawal hook data with
// bytes4(keccak256("circle.xReserve.WithdrawHookData")), followed by this format version.
const WITHDRAW_HOOK_DATA_MAGIC: [u8; 4] = 0x6b20_f62au32.to_be_bytes();
const WITHDRAW_HOOK_DATA_VERSION: u32 = 1;

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
    use_circle_forwarding: bool,
}

impl VerifiedWithdrawal {
    pub(crate) fn note_id(&self) -> NoteId {
        self.batch.note_id
    }

    /// Keep the checked batch with both signatures; return no partial result on failure. The
    /// signatures are ordered by signer address, ascending, the only order Circle's attester
    /// contract accepts.
    pub(crate) async fn sign(
        self,
        signers: [&dyn Signer; 2],
    ) -> Result<SignedWithdrawal, SignerError> {
        let mut signers = signers;
        let addresses = [
            signer_address(signers[0]).await?,
            signer_address(signers[1]).await?,
        ];
        if addresses[0] == addresses[1] {
            return Err(SignerError);
        }
        if addresses[1] < addresses[0] {
            signers.swap(0, 1);
        }
        let first = signers[0].sign_digest(self.batch.digest).await?;
        let second = signers[1].sign_digest(self.batch.digest).await?;
        Ok(SignedWithdrawal {
            batch: SignedBatch {
                batch: self.batch,
                signatures: [first, second],
            },
            use_circle_forwarding: self.use_circle_forwarding,
        })
    }
}

async fn signer_address(signer: &dyn Signer) -> Result<Address, SignerError> {
    let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&signer.public_key().await?.0)
        .map_err(|_| SignerError)?;
    Ok(Address::from_public_key(&key))
}

#[derive(Debug)]
struct VerifiedBatch {
    // Circle's request key and the local ledger key are both the burn note ID.
    note_id: NoteId,
    intent: BurnIntent,
    digest: B256,
}

#[derive(Debug)]
pub(crate) struct SignedWithdrawal {
    batch: SignedBatch,
    use_circle_forwarding: bool,
}

impl SignedWithdrawal {
    pub(crate) fn submission(&self, endpoint: String) -> Result<SavedSubmission, SubmitError> {
        let signed = &self.batch;
        let batch = &signed.batch;
        let (intent, _) = parse_intent(&batch.intent).map_err(|_| SubmitError::InvalidRequest)?;
        let transfer_spec_hash =
            transfer_spec_hash(&intent.spec).map_err(|_| SubmitError::InvalidRequest)?;
        let body = serde_json::to_vec(&json!({
            "batches": [{
                "burnIntents": [&batch.intent],
                "burnSignatures": signed.signatures.map(|signature| signature.to_string()),
                // For Miden, Circle's burnTxId is the burn note ID, not the transaction ID.
                "burnTxId": batch.note_id.to_hex(),
                "useCircleForwarding": self.use_circle_forwarding,
            }],
        }))
        .map_err(SubmitError::Encoding)?;
        Ok(SavedSubmission {
            note_id: batch.note_id,
            endpoint,
            body,
            transfer_spec_hash,
            use_circle_forwarding: self.use_circle_forwarding,
            status: SubmissionStatus::Submitting,
            withdrawal_id: None,
            hold_reason: None,
            last_http_status: None,
            last_response: None,
            last_error: None,
        })
    }
}

pub(crate) fn validate_saved_request(saved: &SavedSubmission) -> bool {
    #[derive(Deserialize)]
    struct Request {
        batches: [Batch; 1],
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Batch {
        #[serde(rename = "burnTxId")]
        burn_note_id: String,
        use_circle_forwarding: bool,
    }
    let Ok(Request { batches: [batch] }) = serde_json::from_slice(&saved.body) else {
        return false;
    };
    batch.burn_note_id == saved.note_id.to_hex()
        && batch.use_circle_forwarding == saved.use_circle_forwarding
}

#[derive(Debug)]
struct SignedBatch {
    batch: VerifiedBatch,
    signatures: [Signature; 2],
}

impl UnverifiedPrepareResponse {
    pub(crate) fn verify(
        self,
        burn: &ValidatedBurn,
        config: &Config,
    ) -> Result<VerifiedWithdrawal, VerifyError> {
        let Ok([batch]) = <[_; 1]>::try_from(self.batches) else {
            return Err(VerifyError::WrongCount);
        };
        let Ok([raw]) = <[_; 1]>::try_from(batch.burn_intents) else {
            return Err(VerifyError::WrongCount);
        };
        let (intent, hook) = parse_intent(&raw)?;
        let spec = &intent.spec;

        let remote_token = B256::from(
            EthEmbeddedAccountId::from_account_id(config.faucet_account_id()).to_bytes32(),
        );
        let fee_ceiling = U256::from(config.max_withdrawal_fee().as_u64());

        if B256::from(burn.burn.note().as_note().serial_num().as_bytes()) != spec.salt {
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
        // Circle's prepare API takes the burner as remoteDepositor and returns it in the hook data,
        // where xReserve's withdrawal contract reads it, for example for its blocklist check.
        // Circle fills in sourceDepositor and sourceSigner itself.
        let sender =
            EthEmbeddedAccountId::from_account_id(burn.burn.note().as_note().metadata().sender());
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
        if intent.maxFee > fee_ceiling {
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

        // Circle sends the encoded bytes and the hash to sign; we rebuild both from the checked
        // fields and sign only if both match exactly.
        let supplied_bytes: Bytes = parse(&batch.encoded, "encoded")?;
        if supplied_bytes.as_ref() != intent.encode()? {
            return Err(VerifyError::EncodedMismatch);
        }
        let digest = intent.signing_hash();
        if digest != parse::<B256>(&batch.message_hash_to_sign, "messageHashToSign")? {
            return Err(VerifyError::DigestMismatch);
        }
        Ok(VerifiedWithdrawal {
            batch: VerifiedBatch {
                note_id: burn.burn.note_id(),
                intent: raw,
                digest,
            },
            use_circle_forwarding: config.use_circle_forwarding(),
        })
    }
}

struct HookData {
    remote_domain: u32,
    remote_token: B256,
    remote_depositor: B256,
    forwarding_contract: Address,
    forwarding_calldata: Bytes,
}

impl HookData {
    fn parse(raw: &StructuredHookData) -> Result<Self, VerifyError> {
        Ok(Self {
            remote_domain: raw.remote_domain,
            remote_token: parse(&raw.remote_token, "remoteToken")?,
            remote_depositor: parse(&raw.remote_depositor, "remoteDepositor")?,
            forwarding_contract: parse(
                &raw.forwarding_contract_address,
                "forwardingContractAddress",
            )?,
            forwarding_calldata: parse(&raw.forwarding_calldata, "forwardingCalldata")?,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, VerifyError> {
        // JSON omits the binary magic/version; its 20-byte address is left-padded to bytes32.
        let mut bytes = WITHDRAW_HOOK_DATA_MAGIC.to_vec();
        bytes.extend(WITHDRAW_HOOK_DATA_VERSION.to_be_bytes());
        bytes.extend(self.remote_domain.to_be_bytes());
        bytes.extend_from_slice(self.remote_token.as_slice());
        bytes.extend_from_slice(self.remote_depositor.as_slice());
        bytes.extend_from_slice(self.forwarding_contract.into_word().as_slice());
        append_with_length(&mut bytes, &self.forwarding_calldata)?;
        Ok(bytes)
    }
}

fn parse<T: std::str::FromStr>(text: &str, field: &'static str) -> Result<T, VerifyError> {
    text.parse().map_err(|_| VerifyError::MalformedField(field))
}

fn decimal(text: &str, field: &'static str) -> Result<U256, VerifyError> {
    U256::from_str_radix(text, 10).map_err(|_| VerifyError::MalformedField(field))
}

fn parse_intent(raw: &BurnIntent) -> Result<(eip712::BurnIntent, HookData), VerifyError> {
    let spec = &raw.spec;
    let hook = HookData::parse(&spec.hook_data)?;
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
            hookData: hook.encode()?.into(),
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

impl eip712::TransferSpec {
    fn encode(&self) -> Result<Vec<u8>, VerifyError> {
        let mut bytes = TRANSFER_SPEC_MAGIC.to_vec();
        bytes.extend(self.version.to_be_bytes());
        bytes.extend(self.sourceDomain.to_be_bytes());
        bytes.extend(self.destinationDomain.to_be_bytes());
        for field in [
            self.sourceContract,
            self.destinationContract,
            self.sourceToken,
            self.destinationToken,
            self.sourceDepositor,
            self.destinationRecipient,
            self.sourceSigner,
            self.destinationCaller,
        ] {
            bytes.extend_from_slice(field.as_slice());
        }
        bytes.extend(self.value.to_be_bytes::<32>());
        bytes.extend_from_slice(self.salt.as_slice());
        append_with_length(&mut bytes, &self.hookData)?;
        Ok(bytes)
    }
}

impl eip712::BurnIntent {
    fn encode(&self) -> Result<Vec<u8>, VerifyError> {
        let mut bytes = BURN_INTENT_MAGIC.to_vec();
        bytes.extend(self.maxBlockHeight.to_be_bytes::<32>());
        bytes.extend(self.maxFee.to_be_bytes::<32>());
        append_with_length(&mut bytes, &self.spec.encode()?)?;
        Ok(bytes)
    }

    fn signing_hash(&self) -> B256 {
        // Circle omits chainId/verifyingContract. This digest is NOT keccak256(encoded).
        let domain = eip712_domain! { name: "GatewayWallet", version: "1", };
        self.eip712_signing_hash(&domain)
    }
}

fn transfer_spec_hash(spec: &eip712::TransferSpec) -> Result<B256, VerifyError> {
    // Circle's TransferSpecLib.encodeTransferSpec/getHash define this packed transfer ID.
    // Its correspondence to REST transferSpecHashes still awaits a live withdrawal response.
    // https://github.com/circlefin/evm-gateway-contracts/blob/ee628dc35ee67bc8ad30ba0606cc70888688a3f1/src/lib/TransferSpecLib.sol#L372-L466
    Ok(keccak256(spec.encode()?))
}

// Keeps semantic test mutations self-consistent; this is not an independent reference vector.
#[cfg(test)]
pub(crate) fn rebuild_for_test(
    batch: &mut crate::circle::UnverifiedPrepareBatch,
) -> Result<(), VerifyError> {
    let (intent, _) = parse_intent(&batch.burn_intents[0])?;
    batch.encoded = format!("0x{}", hex::encode(intent.encode()?));
    let digest = intent.signing_hash();
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
    let encoded = intent.encode()?;
    let digest = intent.signing_hash();
    Ok((encoded, digest))
}

#[cfg(test)]
mod signing_tests;
