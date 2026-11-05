//! Withdrawal signer ordering and test signing, backed by the shared KMS provider.

pub use usdcx_kms_signer::{KmsSigner, Signer, SignerError, SignerFuture, SigningPublicKey};

#[cfg(test)]
use alloy_primitives::{Signature, B256};
use anyhow::Context;
#[cfg(test)]
use k256::ecdsa::SigningKey;

/// The two independent signers, with the public keys they reported when the pair was built. Both
/// are kept in ascending order of signer address, the only order Circle's attester contract accepts
/// signatures in.
pub struct SignerPair {
    signers: [Box<dyn Signer>; 2],
    public_keys: [SigningPublicKey; 2],
}

impl SignerPair {
    /// Reads each signer's public key once and orders the pair by signer address; the two keys
    /// must differ.
    pub async fn new(mut signers: [Box<dyn Signer>; 2]) -> Result<Self, SignerError> {
        let read = |source| {
            SignerError::with_source("could not read a signing provider's public key", source)
        };
        let mut public_keys = [
            signers[0].public_key().await.map_err(read)?,
            signers[1].public_key().await.map_err(read)?,
        ];
        if public_keys[0] == public_keys[1] {
            return Err(SignerError::new(
                "the two signing providers hold the same key",
            ));
        }
        if public_keys[1].address()? < public_keys[0].address()? {
            signers.swap(0, 1);
            public_keys.swap(0, 1);
        }
        Ok(Self {
            signers,
            public_keys,
        })
    }

    /// Checks that the pair holds exactly the two configured public keys, in either order, using
    /// the keys read when the pair was built.
    pub(crate) fn check_expected(&self, expected_hex: &[String]) -> anyhow::Result<()> {
        let [first, second] = expected_hex else {
            anyhow::bail!("exactly two signing public keys must be configured");
        };
        let expected = [
            SigningPublicKey::from_hex(first)
                .context("configured signing public key is invalid")?,
            SigningPublicKey::from_hex(second)
                .context("configured signing public key is invalid")?,
        ];
        if expected[0] == expected[1] {
            anyhow::bail!("the two configured signing public keys must differ");
        }
        if !self.public_keys.iter().all(|key| expected.contains(key)) {
            anyhow::bail!("loaded signing public keys do not match configuration");
        }
        Ok(())
    }

    /// The two signers, in ascending order of signer address.
    pub(crate) fn signers(&self) -> [&dyn Signer; 2] {
        [self.signers[0].as_ref(), self.signers[1].as_ref()]
    }
}

/// A local secp256k1 signer for tests.
#[cfg(test)]
pub struct DevelopmentSigner {
    key: SigningKey,
}

#[cfg(test)]
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

#[cfg(test)]
impl Signer for DevelopmentSigner {
    fn public_key(&self) -> SignerFuture<'_, SigningPublicKey> {
        Box::pin(async move {
            let encoded = self.key.verifying_key().to_encoded_point(true);
            let bytes = encoded
                .as_bytes()
                .try_into()
                .map_err(|source| SignerError::with_source("public key is not 33 bytes", source))?;
            SigningPublicKey::from_compressed(bytes)
        })
    }

    fn sign_digest(&self, digest: B256) -> SignerFuture<'_, Signature> {
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

#[cfg(test)]
/// Decodes `N` bytes written as hex, with or without `0x`.
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], hex::FromHexError> {
    let mut bytes = [0; N];
    hex::decode_to_slice(value.strip_prefix("0x").unwrap_or(value), &mut bytes)?;
    Ok(bytes)
}
