//! Pinned AWS KMS digest signing shared by independent USDCx services.

mod kms;
pub use kms::KmsSigner;

use std::error::Error;
use std::future::Future;
use std::pin::Pin;

use alloy_primitives::{Address, Signature, B256};
use k256::ecdsa::VerifyingKey;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigningPublicKey([u8; 33]);

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

    /// The Ethereum address of this key, which is how Circle's attester contract names a signer.
    pub fn address(&self) -> Result<Address, SignerError> {
        let key = VerifyingKey::from_sec1_bytes(&self.0).map_err(|source| {
            SignerError::with_source("signer public key is not a valid secp256k1 point", source)
        })?;
        Ok(Address::from_public_key(&key))
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

/// The future every [`Signer`] method returns.
pub type SignerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SignerError>> + Send + 'a>>;

pub trait Signer: Send + Sync {
    fn public_key(&self) -> SignerFuture<'_, SigningPublicKey>;

    /// Sign this digest unchanged, without another hash or personal-message prefix.
    /// The provider must return a recoverable, low-s secp256k1 signature.
    fn sign_digest(&self, digest: B256) -> SignerFuture<'_, Signature>;
}

/// Decodes `N` bytes written as hex, with or without `0x`.
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], hex::FromHexError> {
    let mut bytes = [0; N];
    hex::decode_to_slice(value.strip_prefix("0x").unwrap_or(value), &mut bytes)?;
    Ok(bytes)
}
