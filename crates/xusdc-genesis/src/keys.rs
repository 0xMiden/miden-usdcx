//! Per-role authentication material: either an externally-supplied public key (the holder keeps
//! the secret) or a key pair generated deterministically from the role's seed.

use miden_protocol::account::auth::{AuthSecretKey, PublicKey};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::config::AccountEntry;

/// A role's resolved authentication: a supplied public key, or a generated key pair whose secret
/// is written into that role's `.mac` file.
#[derive(Debug, Clone)]
pub enum RoleAuth {
    /// The key holder supplied only the public key; no secret material exists in this tool.
    Supplied(PublicKey),
    /// The tool generated the key pair deterministically from the role's seed (seeded ChaCha20,
    /// the protocol's rand generation), so the same config always yields the same key.
    Generated(AuthSecretKey),
}

impl RoleAuth {
    /// Resolves the auth for one role entry: the supplied public key when present, otherwise a
    /// deterministic Falcon512-Poseidon2 key pair seeded by the role's account seed.
    pub fn resolve(entry: &AccountEntry) -> Self {
        match &entry.public_key {
            Some(key) => Self::Supplied(key.as_public_key().clone()),
            None => {
                let mut rng = ChaCha20Rng::from_seed(entry.seed.as_bytes());
                Self::Generated(AuthSecretKey::new_falcon512_poseidon2_with_rng(&mut rng))
            }
        }
    }

    /// Returns the public key the wallet's approver commits to.
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Supplied(key) => key.clone(),
            Self::Generated(secret) => secret.public_key(),
        }
    }

    /// Returns the secret keys to embed in the account's `.mac` file: the generated secret, or
    /// nothing when the key was supplied.
    pub fn secret_keys(&self) -> Vec<AuthSecretKey> {
        match self {
            Self::Supplied(_) => Vec::new(),
            Self::Generated(secret) => vec![secret.clone()],
        }
    }
}
