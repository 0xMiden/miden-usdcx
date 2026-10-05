use std::time::Duration;

use alloy_primitives::{Signature, B256};
use aws_config::BehaviorVersion;
use aws_sdk_kms::config::{retry::RetryConfig, timeout::TimeoutConfig, Region};
use aws_sdk_kms::operation::get_public_key::GetPublicKeyOutput;
use aws_sdk_kms::operation::sign::{builders::SignInputBuilder, SignOutput};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{
    KeyMetadata, KeySpec, KeyState, KeyUsageType, MessageType, SigningAlgorithmSpec,
};
use aws_sdk_kms::Client;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, VerifyingKey};
use k256::pkcs8::DecodePublicKey;

use super::{Signer, SignerError, SignerFuture, SigningPublicKey};

/// A secp256k1 key in AWS KMS, pinned when the signer connects.
pub struct KmsSigner {
    client: Client,
    key_arn: String,
    /// The pinned key: every signature KMS returns must verify with it.
    public_key: VerifyingKey,
}

impl KmsSigner {
    /// Creates the AWS KMS connection that both signing keys share. A request to KMS is tried at
    /// most three times, and `operation_timeout` limits the total time for all tries.
    pub async fn client(region: &str, operation_timeout: Duration) -> Client {
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.to_owned()))
            .retry_config(RetryConfig::standard().with_max_attempts(3))
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(operation_timeout)
                    .build(),
            )
            .load()
            .await;
        Client::new(&config)
    }

    /// Checks that `key_arn` is an enabled secp256k1 signing key and pins the public key KMS
    /// returns for it. A key that fails a check never signs.
    pub async fn connect(client: Client, key_arn: &str) -> Result<Self, SignerError> {
        let description = client
            .describe_key()
            .key_id(key_arn)
            .send()
            .await
            .map_err(|source| {
                SignerError::with_source("AWS KMS DescribeKey request failed", source)
            })?;
        check_key_metadata(description.key_metadata(), key_arn)?;
        let response = client
            .get_public_key()
            .key_id(key_arn)
            .send()
            .await
            .map_err(|source| {
                SignerError::with_source("AWS KMS GetPublicKey request failed", source)
            })?;
        let public_key = public_key_from_response(&response, key_arn)?;
        Ok(Self {
            client,
            key_arn: key_arn.to_owned(),
            public_key,
        })
    }
}

impl Signer for KmsSigner {
    fn public_key(&self) -> SignerFuture<'_, SigningPublicKey> {
        // The key pinned at startup; KMS is not asked again.
        Box::pin(async move {
            let encoded = self.public_key.to_encoded_point(true);
            let bytes = encoded
                .as_bytes()
                .try_into()
                .map_err(|source| SignerError::with_source("public key is not 33 bytes", source))?;
            Ok(SigningPublicKey(bytes))
        })
    }

    fn sign_digest(&self, digest: B256) -> SignerFuture<'_, Signature> {
        Box::pin(async move {
            let response = sign_request(&self.key_arn, digest)
                .send_with(&self.client)
                .await
                .map_err(|source| {
                    SignerError::with_source("AWS KMS Sign request failed", source)
                })?;
            signature_from_response(&response, &self.key_arn, digest, &self.public_key)
        })
    }
}

/// DescribeKey must show the enabled secp256k1 signing key with exactly this ARN.
fn check_key_metadata(metadata: Option<&KeyMetadata>, key_arn: &str) -> Result<(), SignerError> {
    let metadata = metadata
        .ok_or_else(|| SignerError::new("AWS KMS described the key without its metadata"))?;
    if metadata.arn() != Some(key_arn)
        || !metadata.enabled()
        || metadata.key_state() != Some(&KeyState::Enabled)
        || metadata.key_spec() != Some(&KeySpec::EccSecgP256K1)
        || metadata.key_usage() != Some(&KeyUsageType::SignVerify)
    {
        return Err(SignerError::new(
            "AWS KMS key is not the enabled secp256k1 signing key with this ARN",
        ));
    }
    Ok(())
}

/// Reads the key from GetPublicKey's answer, which must describe the secp256k1 signing key with
/// this ARN.
fn public_key_from_response(
    response: &GetPublicKeyOutput,
    key_arn: &str,
) -> Result<VerifyingKey, SignerError> {
    if response.key_id() != Some(key_arn)
        || response.key_spec() != Some(&KeySpec::EccSecgP256K1)
        || response.key_usage() != Some(&KeyUsageType::SignVerify)
        || !response
            .signing_algorithms()
            .contains(&SigningAlgorithmSpec::EcdsaSha256)
    {
        return Err(SignerError::new(
            "AWS KMS public key is not the secp256k1 signing key with this ARN",
        ));
    }
    let spki = response
        .public_key()
        .ok_or_else(|| SignerError::new("AWS KMS returned no public key"))?;
    // KMS returns the key as a DER-encoded SubjectPublicKeyInfo.
    k256::PublicKey::from_public_key_der(spki.as_ref())
        .map(VerifyingKey::from)
        .map_err(|source| {
            SignerError::with_source("AWS KMS public key is not a secp256k1 key", source)
        })
}

/// The Sign request for `digest`. In digest mode KMS signs the 32 bytes as given; as a message,
/// it would hash them again and sign something else.
fn sign_request(key_arn: &str, digest: B256) -> SignInputBuilder {
    SignInputBuilder::default()
        .key_id(key_arn)
        .message(Blob::new(digest.as_slice()))
        .message_type(MessageType::Digest)
        .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
}

/// Checks that KMS signed with this key and algorithm, and turns its signature into the
/// recoverable form.
fn signature_from_response(
    response: &SignOutput,
    key_arn: &str,
    digest: B256,
    key: &VerifyingKey,
) -> Result<Signature, SignerError> {
    if response.key_id() != Some(key_arn)
        || response.signing_algorithm() != Some(&SigningAlgorithmSpec::EcdsaSha256)
    {
        return Err(SignerError::new(
            "AWS KMS signed with another key or algorithm",
        ));
    }
    let der = response
        .signature()
        .ok_or_else(|| SignerError::new("AWS KMS returned no signature"))?;
    signature_from_der(digest, der.as_ref(), key)
}

/// Turns KMS's DER signature into a recoverable, low-s signature that verifies with the pinned
/// key.
fn signature_from_der(
    digest: B256,
    der: &[u8],
    key: &VerifyingKey,
) -> Result<Signature, SignerError> {
    let signature = k256::ecdsa::Signature::from_der(der)
        .map_err(|source| SignerError::with_source("AWS KMS signature is not DER", source))?;
    // KMS may return either of the two valid s values; a signer must return the low one.
    let signature = signature.normalize_s().unwrap_or(signature);
    key.verify_prehash(digest.as_slice(), &signature)
        .map_err(|source| {
            SignerError::with_source("AWS KMS signature does not verify with its key", source)
        })?;
    // KMS returns no recovery ID, so find the one that recovers the pinned key. Normalize before
    // recovering: changing s also changes the required recovery parity.
    let recovery = RecoveryId::trial_recovery_from_prehash(key, digest.as_slice(), &signature)
        .map_err(|source| {
            SignerError::with_source("AWS KMS signature has no recovery ID", source)
        })?;
    // The recoverable form keeps only the y parity, so an x-reduced recovery ID cannot be written.
    if recovery.is_x_reduced() {
        return Err(SignerError::new("signature has an x-reduced recovery ID"));
    }
    Ok(Signature::from_signature_and_parity(
        signature,
        recovery.is_y_odd(),
    ))
}

#[cfg(test)]
mod tests;
