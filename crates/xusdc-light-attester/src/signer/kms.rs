use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Signature, B256};
use aws_config::BehaviorVersion;
use aws_sdk_kms::config::{retry::RetryConfig, timeout::TimeoutConfig, Region};
use aws_sdk_kms::operation::{
    describe_key::{builders::DescribeKeyInputBuilder, DescribeKeyOutput},
    get_public_key::{builders::GetPublicKeyInputBuilder, GetPublicKeyOutput},
    sign::{builders::SignInputBuilder, SignOutput},
};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeySpec, KeyState, KeyUsageType, MessageType, SigningAlgorithmSpec};
use aws_sdk_kms::Client;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, VerifyingKey};
use k256::pkcs8::DecodePublicKey;

use super::{Signer, SignerError, SigningPublicKey};

type KmsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SignerError>> + Send + 'a>>;

// The seam accepts the same SDK builders production sends, so tests inspect the actual request.
trait KmsBackend: Send + Sync {
    fn describe_key(&self, input: DescribeKeyInputBuilder) -> KmsFuture<'_, DescribeKeyOutput>;
    fn get_public_key(&self, input: GetPublicKeyInputBuilder) -> KmsFuture<'_, GetPublicKeyOutput>;
    fn sign(&self, input: SignInputBuilder) -> KmsFuture<'_, SignOutput>;
}

impl KmsBackend for Client {
    fn describe_key(&self, input: DescribeKeyInputBuilder) -> KmsFuture<'_, DescribeKeyOutput> {
        Box::pin(async move { input.send_with(self).await.map_err(|_| SignerError) })
    }

    fn get_public_key(&self, input: GetPublicKeyInputBuilder) -> KmsFuture<'_, GetPublicKeyOutput> {
        Box::pin(async move { input.send_with(self).await.map_err(|_| SignerError) })
    }

    fn sign(&self, input: SignInputBuilder) -> KmsFuture<'_, SignOutput> {
        Box::pin(async move { input.send_with(self).await.map_err(|_| SignerError) })
    }
}

/// A secp256k1 KMS key pinned to an independently configured public identity.
pub struct KmsSigner {
    backend: Arc<dyn KmsBackend>,
    key_arn: String,
    public_key: VerifyingKey,
    compressed_public_key: SigningPublicKey,
}

impl KmsSigner {
    /// Share this client between both signers. Credentials come from the SDK's default chain.
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

    pub async fn connect(
        client: Client,
        key_arn: &str,
        expected_public_key: &str,
    ) -> Result<Self, SignerError> {
        Self::connect_with(Arc::new(client), key_arn, expected_public_key).await
    }

    async fn connect_with(
        backend: Arc<dyn KmsBackend>,
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

        let description = backend
            .describe_key(DescribeKeyInputBuilder::default().key_id(key_arn))
            .await?;
        let metadata = description.key_metadata().ok_or(SignerError)?;
        if metadata.arn() != Some(key_arn)
            || !metadata.enabled()
            || metadata.key_state() != Some(&KeyState::Enabled)
            || metadata.key_spec() != Some(&KeySpec::EccSecgP256K1)
            || metadata.key_usage() != Some(&KeyUsageType::SignVerify)
        {
            return Err(SignerError);
        }
        let response = backend
            .get_public_key(GetPublicKeyInputBuilder::default().key_id(key_arn))
            .await?;
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
        Ok(Self {
            backend,
            key_arn: key_arn.to_owned(),
            public_key,
            compressed_public_key,
        })
    }
}

impl Signer for KmsSigner {
    fn public_key(&self) -> KmsFuture<'_, SigningPublicKey> {
        Box::pin(async { Ok(self.compressed_public_key) })
    }

    fn sign_digest(&self, digest: B256) -> KmsFuture<'_, Signature> {
        Box::pin(async move {
            let response = self
                .backend
                .sign(
                    SignInputBuilder::default()
                        .key_id(&self.key_arn)
                        .message(Blob::new(digest.as_slice()))
                        .message_type(MessageType::Digest)
                        .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256),
                )
                .await?;
            if response.key_id() != Some(self.key_arn.as_str())
                || response.signing_algorithm() != Some(&SigningAlgorithmSpec::EcdsaSha256)
            {
                return Err(SignerError);
            }
            let der = response.signature().ok_or(SignerError)?;
            signature_from_der(digest, der.as_ref(), &self.public_key)
        })
    }
}

fn signature_from_der(
    digest: B256,
    der: &[u8],
    key: &VerifyingKey,
) -> Result<Signature, SignerError> {
    let signature = k256::ecdsa::Signature::from_der(der).map_err(|_| SignerError)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    key.verify_prehash(digest.as_slice(), &signature)
        .map_err(|_| SignerError)?;
    // Normalize before recovering: changing s also changes the required recovery parity.
    let recovery = RecoveryId::trial_recovery_from_prehash(key, digest.as_slice(), &signature)
        .map_err(|_| SignerError)?;
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
