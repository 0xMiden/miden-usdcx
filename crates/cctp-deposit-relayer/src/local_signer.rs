//! Explicit Arc Testnet credential adapter. Transaction policy remains in ArcSender.
use crate::config::Config;
use alloy_primitives::{Address, Signature, B256};
use anyhow::{ensure, Result};
use k256::{ecdsa::SigningKey, elliptic_curve::zeroize::Zeroizing};
use std::{fs::OpenOptions, io::Read};
use usdcx_kms_signer::{Signer, SignerError, SignerFuture, SigningPublicKey};

const VARIABLE: &str = "CCTP_RELAYER_PRIVATE_KEY";

// Deliberately no Debug/serde implementation or method exposing the private key.
pub(crate) struct LocalEnvSigner(SigningKey);

impl LocalEnvSigner {
    pub fn load(config: &Config) -> Result<Self> {
        ensure!(
            config.chain_id == 5_042_002,
            "local signer requires Arc Testnet"
        );
        ensure!(config.kms.is_none(), "local signer cannot use KMS settings");
        let local = config
            .local_env
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("local signer not selected"))?;
        ensure!(
            local.dotenv.is_absolute(),
            "local dotenv path must be absolute"
        );
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Nonregular files must reach the descriptor check without waiting
            // for a FIFO writer. Regular-file reads retain their normal behavior.
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(&local.dotenv)
            .map_err(|_| anyhow::anyhow!("local dotenv unavailable"))?;
        let metadata = file
            .metadata()
            .map_err(|_| anyhow::anyhow!("local dotenv unavailable"))?;
        ensure!(
            metadata.is_file() && metadata.len() <= 4096,
            "invalid local dotenv file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // The effective OS user is the owner whose signing authority this process uses.
            let owner = unsafe { libc::geteuid() };
            ensure!(
                metadata.mode() & 0o7777 == 0o600 && metadata.uid() == owner,
                "local dotenv requires owner-only mode 0600"
            );
        }
        let mut contents = Zeroizing::new(String::new());
        file.take(4097)
            .read_to_string(&mut contents)
            .map_err(|_| anyhow::anyhow!("invalid local dotenv file"))?;
        ensure!(
            contents.len() <= 4096 && !contents.contains('$'),
            "local dotenv must contain a literal key"
        );
        let mut key = None;
        // The iterator does not install variables in the process environment. Discard all
        // parser errors: dotenv parsers may include the offending secret line in them.
        for entry in dotenvy::from_read_iter(contents.as_bytes()) {
            let (name, value) =
                entry.map_err(|_| anyhow::anyhow!("invalid local dotenv syntax"))?;
            let value = Zeroizing::new(value);
            ensure!(name == VARIABLE, "unexpected local dotenv variable");
            ensure!(key.is_none(), "duplicate local private key variable");
            let value = value.strip_prefix("0x").unwrap_or(&value);
            let mut bytes = Zeroizing::new([0u8; 32]);
            hex::decode_to_slice(value, &mut *bytes)
                .map_err(|_| anyhow::anyhow!("invalid local private key"))?;
            key = Some(
                SigningKey::from_slice(&*bytes)
                    .map_err(|_| anyhow::anyhow!("invalid local private key"))?,
            );
        }
        let signer =
            Self(key.ok_or_else(|| anyhow::anyhow!("local private key variable missing"))?);
        ensure!(
            Address::from_private_key(&signer.0) == config.signer,
            "loaded signer mismatch"
        );
        Ok(signer)
    }
}

impl Signer for LocalEnvSigner {
    fn public_key(&self) -> SignerFuture<'_, SigningPublicKey> {
        Box::pin(async move {
            let point = self.0.verifying_key().to_encoded_point(true);
            let bytes = point
                .as_bytes()
                .try_into()
                .map_err(|_| SignerError::new("local public key invalid"))?;
            SigningPublicKey::from_compressed(bytes)
        })
    }

    fn sign_digest(&self, digest: B256) -> SignerFuture<'_, Signature> {
        Box::pin(async move {
            let (signature, recovery) = self
                .0
                .sign_prehash_recoverable(digest.as_slice())
                .map_err(|_| SignerError::new("local digest signing failed"))?;
            if recovery.is_x_reduced() {
                return Err(SignerError::new("local signature recovery unavailable"));
            }
            Ok(Signature::from_signature_and_parity(
                signature,
                recovery.is_y_odd(),
            ))
        })
    }
}
