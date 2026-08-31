//! Signing-key boundary used during startup.

use std::future::Future;
use std::pin::Pin;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigningPublicKey(pub(crate) [u8; 33]);

#[derive(Debug)]
pub struct SignerError;

pub trait Signer: Send + Sync {
    fn public_key(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, SignerError>> + Send + '_>>;
}
