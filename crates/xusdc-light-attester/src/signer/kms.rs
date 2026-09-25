use std::future::Future;
use std::pin::Pin;
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

use super::{Signer, SignerError, SigningPublicKey};

type KmsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SignerError>> + Send + 'a>>;

/// A secp256k1 key in AWS KMS, pinned at startup to an independently configured public key.
pub struct KmsSigner {
    client: Client,
    key_arn: String,
    /// The pinned key: every signature KMS returns must verify with it.
    public_key: VerifyingKey,
    compressed_public_key: SigningPublicKey,
}

impl KmsSigner {
    /// The KMS client both signers share. Credentials come from the SDK's default chain. Each
    /// operation gets at most three attempts, and `operation_timeout` bounds all of them together.
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

    /// Checks that `key_arn` is an enabled secp256k1 signing key whose public key is
    /// `expected_public_key`, and pins that key. A key that fails a check never signs.
    pub async fn connect(
        client: Client,
        key_arn: &str,
        expected_public_key: &str,
    ) -> Result<Self, SignerError> {
        let mut expected = [0; 33];
        hex::decode_to_slice(
            expected_public_key
                .strip_prefix("0x")
                .unwrap_or(expected_public_key),
            &mut expected,
        )
        .map_err(|_| SignerError)?;
        let expected = SigningPublicKey::from_compressed(expected)?;
        let description = client
            .describe_key()
            .key_id(key_arn)
            .send()
            .await
            .map_err(|_| SignerError)?;
        check_key_metadata(description.key_metadata(), key_arn)?;
        let response = client
            .get_public_key()
            .key_id(key_arn)
            .send()
            .await
            .map_err(|_| SignerError)?;
        let public_key = pinned_public_key(&response, key_arn, expected)?;
        Ok(Self {
            client,
            key_arn: key_arn.to_owned(),
            public_key,
            compressed_public_key: expected,
        })
    }
}

impl Signer for KmsSigner {
    fn public_key(&self) -> KmsFuture<'_, SigningPublicKey> {
        // The key pinned at startup; KMS is not asked again.
        Box::pin(async { Ok(self.compressed_public_key) })
    }

    fn sign_digest(&self, digest: B256) -> KmsFuture<'_, Signature> {
        Box::pin(async move {
            let response = sign_request(&self.key_arn, digest)
                .send_with(&self.client)
                .await
                .map_err(|_| SignerError)?;
            signature_from_response(&response, &self.key_arn, digest, &self.public_key)
        })
    }
}

/// DescribeKey must show the enabled secp256k1 signing key with exactly this ARN.
fn check_key_metadata(metadata: Option<&KeyMetadata>, key_arn: &str) -> Result<(), SignerError> {
    let metadata = metadata.ok_or(SignerError)?;
    if metadata.arn() != Some(key_arn)
        || !metadata.enabled()
        || metadata.key_state() != Some(&KeyState::Enabled)
        || metadata.key_spec() != Some(&KeySpec::EccSecgP256K1)
        || metadata.key_usage() != Some(&KeyUsageType::SignVerify)
    {
        return Err(SignerError);
    }
    Ok(())
}

/// Reads the key from GetPublicKey's answer and pins it: it must equal the configured public key,
/// so a replaced or misconfigured KMS key is refused before it signs anything.
fn pinned_public_key(
    response: &GetPublicKeyOutput,
    key_arn: &str,
    expected: SigningPublicKey,
) -> Result<VerifyingKey, SignerError> {
    if response.key_id() != Some(key_arn)
        || response.key_spec() != Some(&KeySpec::EccSecgP256K1)
        || response.key_usage() != Some(&KeyUsageType::SignVerify)
        || !response
            .signing_algorithms()
            .contains(&SigningAlgorithmSpec::EcdsaSha256)
    {
        return Err(SignerError);
    }
    let spki = response.public_key().ok_or(SignerError)?;
    // KMS returns the key as a DER-encoded SubjectPublicKeyInfo.
    let public_key = k256::PublicKey::from_public_key_der(spki.as_ref())
        .map(VerifyingKey::from)
        .map_err(|_| SignerError)?;
    let compressed_public_key = SigningPublicKey(
        public_key
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| SignerError)?,
    );
    if compressed_public_key != expected {
        return Err(SignerError);
    }
    Ok(public_key)
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
        return Err(SignerError);
    }
    let der = response.signature().ok_or(SignerError)?;
    signature_from_der(digest, der.as_ref(), key)
}

/// Turns KMS's DER signature into a recoverable, low-s signature that verifies with the pinned
/// key.
fn signature_from_der(
    digest: B256,
    der: &[u8],
    key: &VerifyingKey,
) -> Result<Signature, SignerError> {
    let signature = k256::ecdsa::Signature::from_der(der).map_err(|_| SignerError)?;
    // KMS may return either of the two valid s values; a signer must return the low one.
    let signature = signature.normalize_s().unwrap_or(signature);
    key.verify_prehash(digest.as_slice(), &signature)
        .map_err(|_| SignerError)?;
    // KMS returns no recovery ID, so find the one that recovers the pinned key. Normalize before
    // recovering: changing s also changes the required recovery parity.
    let recovery = RecoveryId::trial_recovery_from_prehash(key, digest.as_slice(), &signature)
        .map_err(|_| SignerError)?;
    // The recoverable form keeps only the y parity, so an x-reduced recovery ID cannot be written.
    if recovery.is_x_reduced() {
        return Err(SignerError);
    }
    Ok(Signature::from_signature_and_parity(
        signature,
        recovery.is_y_odd(),
    ))
}

#[cfg(test)]
mod tests;
