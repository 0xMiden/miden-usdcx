//! Signing-provider boundary; AWS KMS is not connected yet.

use std::future::Future;
use std::pin::Pin;

use alloy_primitives::{Signature, B256};
use k256::ecdsa::{SigningKey, VerifyingKey};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigningPublicKey(pub(crate) [u8; 33]);

impl SigningPublicKey {
    /// Validate a compressed SEC1 secp256k1 public key.
    pub fn from_compressed(bytes: [u8; 33]) -> Result<Self, SignerError> {
        VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| SignerError)?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("signer operation failed")]
pub struct SignerError;

pub trait Signer: Send + Sync {
    fn public_key(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, SignerError>> + Send + '_>>;

    /// Sign this digest unchanged, without another hash or personal-message prefix.
    /// The provider must return a recoverable, low-s secp256k1 signature.
    fn sign_digest(
        &self,
        digest: B256,
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignerError>> + Send + '_>>;
}

/// A local secp256k1 signer for development.
pub struct DevelopmentSigner {
    key: SigningKey,
}

impl DevelopmentSigner {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SignerError> {
        let key = SigningKey::from_bytes(&bytes.into()).map_err(|_| SignerError)?;
        Ok(Self { key })
    }
}

impl Signer for DevelopmentSigner {
    fn public_key(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, SignerError>> + Send + '_>> {
        Box::pin(async move {
            let encoded = self.key.verifying_key().to_encoded_point(true);
            let bytes = encoded.as_bytes().try_into().map_err(|_| SignerError)?;
            Ok(SigningPublicKey(bytes))
        })
    }

    fn sign_digest(
        &self,
        digest: B256,
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignerError>> + Send + '_>> {
        Box::pin(async move {
            let (signature, recovery_id) = self
                .key
                .sign_prehash_recoverable(digest.as_slice())
                .map_err(|_| SignerError)?;
            // Alloy cannot represent the recovery ID's x-reduction bit.
            if recovery_id.is_x_reduced() {
                return Err(SignerError);
            }
            Ok(Signature::from_signature_and_parity(
                signature,
                recovery_id.is_y_odd(),
            ))
        })
    }
}
