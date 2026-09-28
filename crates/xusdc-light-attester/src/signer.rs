//! Signing-provider boundary; AWS KMS is not connected yet.

use std::error::Error;
use std::future::Future;
use std::pin::Pin;

use alloy_primitives::{Signature, B256};
use anyhow::Context;
use k256::ecdsa::{SigningKey, VerifyingKey};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigningPublicKey(pub(crate) [u8; 33]);

impl SigningPublicKey {
    /// Parses a compressed SEC1 secp256k1 public key written as hex, with or without `0x`.
    pub fn from_hex(value: &str) -> Result<Self, SignerError> {
        let bytes = decode_hex(value).map_err(|source| {
            SignerError::with_source("public key is not 33 bytes of hex", source)
        })?;
        Self::from_compressed(bytes)
    }

    /// Validate a compressed SEC1 secp256k1 public key.
    pub fn from_compressed(bytes: [u8; 33]) -> Result<Self, SignerError> {
        VerifyingKey::from_sec1_bytes(&bytes).map_err(|source| {
            SignerError::with_source("public key is not a valid secp256k1 point", source)
        })?;
        Ok(Self(bytes))
    }
}

/// What a signer could not do, and the error behind it when there is one.
#[derive(Debug, thiserror::Error)]
#[error("{context}")]
pub struct SignerError {
    context: &'static str,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl SignerError {
    pub fn new(context: &'static str) -> Self {
        Self {
            context,
            source: None,
        }
    }

    pub fn with_source(context: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            context,
            source: Some(Box::new(source)),
        }
    }
}

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

/// The two independent signers, checked at startup against the configured public keys.
pub(crate) struct SignerPair([Box<dyn Signer>; 2]);

impl SignerPair {
    pub(crate) async fn new(
        signers: [Box<dyn Signer>; 2],
        expected_hex: &[String],
    ) -> anyhow::Result<Self> {
        let [first, second] = expected_hex else {
            anyhow::bail!("exactly two distinct, valid signing public keys are required");
        };
        let parse_key = |value: &str| {
            SigningPublicKey::from_hex(value).context("configured signing public key is invalid")
        };
        let expected = [parse_key(first)?, parse_key(second)?];
        let loaded = [
            signers[0]
                .public_key()
                .await
                .context("could not read a signing provider's public key")?,
            signers[1]
                .public_key()
                .await
                .context("could not read a signing provider's public key")?,
        ];
        if expected[0] == expected[1] || loaded[0] == loaded[1] {
            anyhow::bail!("exactly two distinct, valid signing public keys are required");
        }
        if !loaded.iter().all(|key| expected.contains(key)) {
            anyhow::bail!("loaded signing public keys do not match configuration");
        }
        Ok(Self(signers))
    }

    pub(crate) fn as_refs(&self) -> [&dyn Signer; 2] {
        [self.0[0].as_ref(), self.0[1].as_ref()]
    }
}

/// A local secp256k1 signer for development.
pub struct DevelopmentSigner {
    key: SigningKey,
}

impl DevelopmentSigner {
    /// Reads a 32-byte private key written as hex, with or without `0x`. A malformed key is
    /// refused without the hex decoder's error, which can quote a character of the key.
    pub fn from_hex(value: &str) -> Result<Self, SignerError> {
        let bytes = decode_hex(value)
            .map_err(|_| SignerError::new("private key is not 32 bytes of hex"))?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SignerError> {
        let key = SigningKey::from_bytes(&bytes.into()).map_err(|source| {
            SignerError::with_source("private key is not a valid secp256k1 scalar", source)
        })?;
        Ok(Self { key })
    }
}

impl Signer for DevelopmentSigner {
    fn public_key(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, SignerError>> + Send + '_>> {
        Box::pin(async move {
            let encoded = self.key.verifying_key().to_encoded_point(true);
            let bytes = encoded
                .as_bytes()
                .try_into()
                .map_err(|source| SignerError::with_source("public key is not 33 bytes", source))?;
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
                .map_err(|source| SignerError::with_source("development signing failed", source))?;
            // Alloy cannot represent the recovery ID's x-reduction bit.
            if recovery_id.is_x_reduced() {
                return Err(SignerError::new("signature has an x-reduced recovery ID"));
            }
            Ok(Signature::from_signature_and_parity(
                signature,
                recovery_id.is_y_odd(),
            ))
        })
    }
}

/// Decodes `N` bytes written as hex, with or without `0x`.
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], hex::FromHexError> {
    let mut bytes = [0; N];
    hex::decode_to_slice(value.strip_prefix("0x").unwrap_or(value), &mut bytes)?;
    Ok(bytes)
}
