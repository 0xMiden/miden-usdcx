//! Generates disposable wallet and attester keys for local validation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey};
use miden_client::auth::{Approver, AuthSchemeId, AuthSecretKey, AuthSingleSig};
use miden_client::keystore::Keystore;
use miden_crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_crypto::utils::Deserializable;
use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::Word;
use miden_standards::account::inspection::AccountBuilderSchemaCommitmentExt;
use miden_standards::account::wallets::BasicWallet;
use rand::rngs::OsRng;
use sha3::{Digest, Keccak256};
use xusdc_encoding::note::xreserve_mint::DepositAttestation;
use xusdc_encoding::xreserve::encoding::Signature;

use crate::client::{os_seed, HarnessClient};

/// The locally generated secp256k1 test attester. The SECRET (the `SigningKey`) is held in memory
/// for signing during the run and its scalar is also written to a file under the gitignored run
/// root (never in git, never in the evidence JSON); the public forms are recorded. This is the
/// harness twin of the `gen_attester` MockChain fixture — same keccak256(payload) + SEC1 recipe,
/// the `PublicKey::to_commitment` allowlist key — but signing REAL production `XUsdcMintNote`
/// attestations against the deployed faucet. NEVER Circle's keys.
pub struct AttesterKey {
    /// The secp256k1 signing key (kept in memory to sign mint attestations during the run).
    signing_key: SigningKey,
    /// SEC1-compressed public key (33 bytes).
    pub pubkey_sec1: [u8; 33],
    /// The same key, decoded — what the mint note carries.
    pub public_key: PublicKey,
    /// SEC1-compressed public key (33 bytes), hex.
    pub pubkey_sec1_hex: String,
    /// `PublicKey::to_commitment()` — the attester-allowlist storage key the faucet stores.
    pub commitment: Word,
    /// The same commitment, hex (recorded in the evidence).
    pub commitment_hex: String,
    /// Where the secret scalar was written (gitignored run root).
    pub secret_path: PathBuf,
}

impl AttesterKey {
    /// The `xReserveAttesters` allowlist key for this attester (the `set_attester` commitment).
    pub fn commitment_word(&self) -> Word {
        self.commitment
    }

    /// Signs `keccak256(payload)` with this attester and bundles the raw 65-byte `r‖s‖v` signature
    /// with the decoded pubkey into the production [`DepositAttestation`] the relayer hands
    /// [`xusdc_encoding::note::xreserve_mint::XUsdcMintNote::create`] (same recipe as the
    /// `gen_attester` MockChain fixture).
    pub fn attestation_for(&self, payload: &[u8]) -> DepositAttestation {
        let mut hasher = Keccak256::new();
        hasher.update(payload);
        let digest: [u8; 32] = hasher.finalize().into();
        let (sig, recid): (K256Signature, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(&digest)
            .expect("secp256k1 prehash signing over a 32-byte keccak digest");
        let mut sig65 = [0u8; 65];
        sig65[..64].copy_from_slice(sig.to_bytes().as_slice());
        sig65[64] = recid.to_byte();
        DepositAttestation::new(Signature::new(sig65), self.public_key.clone())
    }

    /// Signs an ARBITRARY 32-byte `digest` with this attester's key and bundles it with this
    /// attester's REAL compressed pubkey. Used for the forged-signature Row-E negative: signing a
    /// digest that is NOT `keccak256(payload)` yields a WELL-FORMED ECDSA signature that
    /// `verify_prehash` runs to completion and rejects as invalid over the payload's true digest —
    /// so the mint traps at `ERR_XRESERVE_SIG_INVALID` (the signature check), not the earlier
    /// commitment gate (the pubkey stays this allowlisted attester's). A well-formed-but-wrong
    /// signature is deliberate: a byte-mangled signature could instead trap inside `verify_prehash`
    /// on a malformed scalar rather than returning "invalid".
    pub fn attestation_over_digest(&self, digest: [u8; 32]) -> DepositAttestation {
        let (sig, recid): (K256Signature, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(&digest)
            .expect("secp256k1 prehash signing over a 32-byte digest");
        let mut sig65 = [0u8; 65];
        sig65[..64].copy_from_slice(sig.to_bytes().as_slice());
        sig65[64] = recid.to_byte();
        DepositAttestation::new(Signature::new(sig65), self.public_key.clone())
    }
}

/// The six wallets + two attesters (A and B — the C1 rotation seam).
pub struct Actors {
    pub owner: Account,
    pub pauser: Account,
    pub manager: Account,
    /// The F4-reversal BLK_MANAGER holder — the EXTERNAL transfer-blocklist administrator (distinct
    /// from the owner; capability-isolated to block/unblock only).
    pub blk_manager: Account,
    pub recipient: Account,
    pub holder: Account,
    /// The C5 rotation target: DOM_MANAGER grants it DOM_PAUSER, then revokes it.
    pub new_pauser: Account,
    /// The FIRST attester (allowlisted first; rotated OUT in C1).
    pub attester: AttesterKey,
    /// The SECOND attester (rotated IN in C1) — a distinct key with a distinct commitment.
    pub attester_b: AttesterKey,
}

/// Builds one Falcon-keyed public `BasicWallet`, registering its key with the keystore and the
/// account with the client. The wallet materializes on-chain with its first transaction.
async fn create_wallet(hc: &mut HarnessClient) -> Result<Account> {
    let key = AuthSecretKey::new_falcon512_poseidon2();
    // v16: `AuthSingleSig::new` now takes an `Approver` (pubkey commitment + auth scheme) rather
    // than the two loose args (miden-standards 0.16 auth/singlesig.rs; approver.rs `Approver::new`).
    let auth = AuthSingleSig::new(Approver::new(
        key.public_key().to_commitment(),
        AuthSchemeId::Falcon512Poseidon2,
    ));

    let account = AccountBuilder::new(os_seed())
        .account_type(AccountType::Public)
        .with_auth_component(auth)
        .with_component(BasicWallet)
        .build_with_schema_commitment()
        .context("building a wallet account")?;

    hc.keystore
        .add_key(&key, account.id())
        .await
        .map_err(|e| anyhow::anyhow!("adding the wallet key to the keystore: {e}"))?;
    hc.client
        .add_account(&account, false)
        .await
        .context("registering the wallet with the client")?;
    Ok(account)
}

/// Generates a locally-random secp256k1 attester and persists the secret under `run_root` as
/// `attester-<label>.secret.hex`. Keeps the `SigningKey` in memory so the harness can sign real
/// mint attestations during the run.
fn create_attester(run_root: &Path, label: &str) -> Result<AttesterKey> {
    // Throwaway local key — persisted (0600) so a run can be reproduced/inspected.
    AttesterKey::from_signing_key(SigningKey::random(&mut OsRng), run_root, label, true)
}

impl AttesterKey {
    /// Builds an [`AttesterKey`] from an explicit secp256k1 `signing_key`, deriving the SEC1 pubkey +
    /// `to_commitment` allowlist key. When `persist` is true the secret scalar is written under
    /// `run_root` as `attester-<label>.secret.hex` with **owner-only (0600)** permissions (throwaway
    /// local keys); the SUPPLIED devnet key is NEVER persisted (`persist = false`) — it stays only in
    /// memory for the run, so a mint-authorizing secret is not copied to disk.
    fn from_signing_key(
        signing_key: SigningKey,
        run_root: &Path,
        label: &str,
        persist: bool,
    ) -> Result<Self> {
        let sec1 = signing_key.verifying_key().to_encoded_point(true);
        let pubkey_sec1: [u8; 33] = sec1
            .as_bytes()
            .try_into()
            .map_err(|_| anyhow::anyhow!("compressed secp256k1 pubkey must be 33 bytes"))?;
        let pubkey_sec1_hex = hex_lower(&pubkey_sec1);

        let public_key = PublicKey::read_from_bytes(&pubkey_sec1)
            .map_err(|e| anyhow::anyhow!("parsing the SEC1 pubkey into miden-crypto: {e}"))?;
        let commitment: Word = public_key.to_commitment();
        let commitment_hex = commitment.to_hex();

        let secret_path = run_root.join(format!("attester-{label}.secret.hex"));
        if persist {
            // Created 0600 ATOMICALLY (never briefly group/world-readable in the shared run root).
            write_secret_file(&secret_path, hex_lower(&signing_key.to_bytes()).as_bytes())?;
        }

        Ok(AttesterKey {
            signing_key,
            pubkey_sec1,
            public_key,
            pubkey_sec1_hex,
            commitment,
            commitment_hex,
            secret_path,
        })
    }

    /// Reconstructs an attester from a supplied 32-byte secp256k1 secret scalar (the DEVNET re-run:
    /// the deployed faucet's ALREADY-ALLOWLISTED attester key, provided by the operator out of band —
    /// so the same mint checks authenticate against a real faucet). NEVER used for the local gate
    /// (which generates a throwaway key). `label` names the persisted copy under `run_root`.
    pub fn from_secret_scalar(scalar: &[u8; 32], run_root: &Path, label: &str) -> Result<Self> {
        let signing_key = SigningKey::from_slice(scalar).map_err(|e| {
            anyhow::anyhow!("the supplied attester secret is not a valid secp256k1 scalar: {e}")
        })?;
        // NEVER persist the operator's real, allowlisted devnet key to disk.
        Self::from_signing_key(signing_key, run_root, label, false)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes `bytes` to `path` as a FRESH file with owner-only (0600) permissions, and REFUSES to
/// overwrite an existing target — fails CLOSED. A secret is never written over (or through) a
/// pre-existing regular file or symlink, so a stale bundle, an attacker-planted path, or an operator
/// typo returns an error instead of clobbering unrelated data or inheriting foreign permissions. On
/// Unix the file is created with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode `0600`: `O_EXCL` fails if
/// the path already exists at all (regular file OR symlink), `O_NOFOLLOW` additionally refuses a
/// final-component symlink, and the fresh inode is `0600` from creation (never briefly
/// group/world-readable in the umask-0002 shared run root). To REWRITE, the caller must remove the
/// old path first, deliberately.
pub(crate) fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // Linux O_NOFOLLOW = 0o400000 — refuse to follow a symlink as the final path component.
        const O_NOFOLLOW: i32 = 0o400000;
        let mut f = match std::fs::OpenOptions::new()
            .write(true)
            // O_CREAT | O_EXCL: a FRESH inode only (so mode 0600 is honored), and fail closed if
            // ANYTHING already occupies the path — never overwrite an existing target.
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                anyhow::bail!(
                    "refusing to write a secret to {} — the path already exists (a secret is never \
                     written over an existing file or symlink). Remove it deliberately or choose a \
                     fresh path.",
                    path.display()
                );
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("creating {} fresh with mode 0600", path.display()));
            }
        };
        f.write_all(bytes)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        if path.symlink_metadata().is_ok() {
            anyhow::bail!(
                "refusing to write a secret to {} — the path already exists.",
                path.display()
            );
        }
        std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
    }
}

/// Generates all actors (fresh keys). All wallets are throwaway local test identities — NEVER Circle
/// keys. On the fresh-deploy path they are the faucet's own roles (owner / DOM_PAUSER / DOM_MANAGER)
/// exercised by the full admin suite; on the existing-faucet non-destructive subset the admin surface
/// never runs against the deployed faucet, so the role wallets are simply unused for mutation.
pub async fn create_actors(hc: &mut HarnessClient, run_root: &Path) -> Result<Actors> {
    let owner = create_wallet(hc)
        .await
        .context("creating the owner wallet")?;
    let pauser = create_wallet(hc)
        .await
        .context("creating the DOM_PAUSER wallet")?;
    let manager = create_wallet(hc)
        .await
        .context("creating the DOM_MANAGER wallet")?;
    let blk_manager = create_wallet(hc)
        .await
        .context("creating the BLK_MANAGER wallet")?;
    let recipient = create_wallet(hc)
        .await
        .context("creating the recipient wallet")?;
    let holder = create_wallet(hc)
        .await
        .context("creating the holder wallet")?;
    let new_pauser = create_wallet(hc)
        .await
        .context("creating the C5 new-pauser wallet")?;
    let attester = create_attester(run_root, "a").context("creating local test attester A")?;
    let attester_b = create_attester(run_root, "b").context("creating local test attester B")?;
    Ok(Actors {
        owner,
        pauser,
        manager,
        blk_manager,
        recipient,
        holder,
        new_pauser,
        attester,
        attester_b,
    })
}
