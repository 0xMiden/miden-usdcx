//! Signing-provider boundary; AWS KMS is not connected yet.

use std::future::Future;
use std::pin::Pin;

use alloy_primitives::{Signature, B256};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigningPublicKey(pub(crate) [u8; 33]);

#[derive(Debug)]
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
