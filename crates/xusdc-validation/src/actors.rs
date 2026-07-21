//! Local test identities (actor keygen).
//!
//! Five keyed PUBLIC wallets — owner, DOM_PAUSER holder, DOM_MANAGER holder, recipient, holder
//! (burner) — each `AuthSingleSig` (Falcon512) + `BasicWallet`, keys in the run's filesystem
//! keystore; plus ONE locally generated secp256k1 attester keypair (the `gen_vectors` pattern:
//! k256 keypair, `PublicKey::to_commitment` allowlist key). These are all throwaway local test
//! identities — NEVER Circle's keys, endpoints, or anything derived from them. The attester is
//! GENERATED and RECORDED here (harness foundation); its first on-chain use (`set_attester`) is
//! LNV-2 scope.

use std::fs;
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
use xusdc_encoding::note::xreserve_mint::MintAttestation;

use crate::client::{os_seed, HarnessClient};

/// The locally generated secp256k1 test attester. The SECRET (the `SigningKey`) is held in memory
/// for signing during the run and its scalar is also written to a file under the gitignored run
/// root (never in git, never in the evidence JSON); the public forms are recorded. This is the
/// harness twin of the `gen_attester` MockChain fixture — same keccak256(payload) + SEC1 recipe,
/// the `PublicKey::to_commitment` allowlist key — but signing REAL production `XReserveMintNote`
/// attestations against the deployed faucet. NEVER Circle's keys.
pub struct AttesterKey {
    /// The secp256k1 signing key (kept in memory to sign mint attestations during the run).
    signing_key: SigningKey,
    /// SEC1-compressed public key (33 bytes).
    pub pubkey_sec1: [u8; 33],
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
    /// with the 33-byte compressed pubkey into the production [`MintAttestation`] the relayer hands
    /// [`xusdc_encoding::note::xreserve_mint::XReserveMintNote::create`] (same recipe as the
    /// `gen_attester` MockChain fixture).
    pub fn attestation_for(&self, payload: &[u8]) -> MintAttestation {
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
        MintAttestation::new(sig65, self.pubkey_sec1)
    }

    /// Signs an ARBITRARY 32-byte `digest` with this attester's key and bundles it with this
    /// attester's REAL compressed pubkey. Used for the forged-signature Row-E negative: signing a
    /// digest that is NOT `keccak256(payload)` yields a WELL-FORMED ECDSA signature that
    /// `verify_prehash` runs to completion and rejects as invalid over the payload's true digest —
    /// so the mint traps at `ERR_XRESERVE_SIG_INVALID` (the signature check), not the earlier
    /// commitment gate (the pubkey stays this allowlisted attester's). A well-formed-but-wrong
    /// signature is deliberate: a byte-mangled signature could instead trap inside `verify_prehash`
    /// on a malformed scalar rather than returning "invalid".
    pub fn attestation_over_digest(&self, digest: [u8; 32]) -> MintAttestation {
        let (sig, recid): (K256Signature, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(&digest)
            .expect("secp256k1 prehash signing over a 32-byte digest");
        let mut sig65 = [0u8; 65];
        sig65[..64].copy_from_slice(sig.to_bytes().as_slice());
        sig65[64] = recid.to_byte();
        MintAttestation::new(sig65, self.pubkey_sec1)
    }
}

/// The six wallets + two attesters (A and B — the C1 rotation seam).
pub struct Actors {
    pub owner: Account,
    pub pauser: Account,
    pub manager: Account,
    pub recipient: Account,
    pub holder: Account,
    /// The C5 rotation target: DOM_MANAGER grants it DOM_PAUSER, then revokes it.
    pub new_pauser: Account,
    /// The FIRST attester (allowlisted first; rotated OUT in C1).
    pub attester: AttesterKey,
    /// The SECOND attester (rotated IN in C1) — a distinct key with a distinct commitment.
    pub attester_b: AttesterKey,
}

/// Builds one Falcon-keyed public `BasicWallet`, registers its key with the keystore and the
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
    let signing_key = SigningKey::random(&mut OsRng);
    let sec1 = signing_key.verifying_key().to_encoded_point(true);
    let pubkey_sec1: [u8; 33] = sec1
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("compressed secp256k1 pubkey must be 33 bytes"))?;
    let pubkey_sec1_hex = hex_lower(&pubkey_sec1);

    // The canonical allowlist keying primitive (the gen_vectors / TV-DUAL-5 oracle): miden-crypto's
    // PublicKey parsed from the SEC1 bytes, then its commitment word.
    let public_key = PublicKey::read_from_bytes(&pubkey_sec1)
        .map_err(|e| anyhow::anyhow!("parsing the SEC1 pubkey into miden-crypto: {e}"))?;
    let commitment: Word = public_key.to_commitment();
    let commitment_hex = commitment.to_hex();

    let secret_path = run_root.join(format!("attester-{label}.secret.hex"));
    fs::write(&secret_path, hex_lower(&signing_key.to_bytes()))
        .with_context(|| format!("writing {}", secret_path.display()))?;

    Ok(AttesterKey {
        signing_key,
        pubkey_sec1,
        pubkey_sec1_hex,
        commitment,
        commitment_hex,
        secret_path,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generates all actors: five Falcon-keyed public wallets registered with the client + keystore
/// (their on-chain materialization happens with their first transaction), and the secp256k1
/// attester persisted under `run_root`.
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
        recipient,
        holder,
        new_pauser,
        attester,
        attester_b,
    })
}
