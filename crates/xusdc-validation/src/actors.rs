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
use k256::ecdsa::SigningKey;
use miden_client::auth::{AuthSchemeId, AuthSecretKey, AuthSingleSig};
use miden_client::keystore::Keystore;
use miden_crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_crypto::utils::Deserializable;
use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_standards::account::metadata::AccountBuilderSchemaCommitmentExt;
use miden_standards::account::wallets::BasicWallet;
use rand::rngs::OsRng;

use crate::client::{os_seed, HarnessClient};

/// The locally generated secp256k1 test attester. The SECRET stays in a file under the gitignored
/// run root (never in git, never in the evidence JSON); the public forms are recorded.
pub struct AttesterKey {
    /// SEC1-compressed public key (33 bytes), hex.
    pub pubkey_sec1_hex: String,
    /// `PublicKey::to_commitment()` — the attester-allowlist storage key the faucet stores, hex.
    pub commitment_hex: String,
    /// Where the secret scalar was written (gitignored run root).
    pub secret_path: PathBuf,
}

/// The five wallets + the attester.
pub struct Actors {
    pub owner: Account,
    pub pauser: Account,
    pub manager: Account,
    pub recipient: Account,
    pub holder: Account,
    pub attester: AttesterKey,
}

/// Builds one Falcon-keyed public `BasicWallet`, registers its key with the keystore and the
/// account with the client. The wallet materializes on-chain with its first transaction.
async fn create_wallet(hc: &mut HarnessClient) -> Result<Account> {
    let key = AuthSecretKey::new_falcon512_poseidon2();
    let auth = AuthSingleSig::new(key.public_key().to_commitment(), AuthSchemeId::Falcon512Poseidon2);

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

/// Generates the locally-random secp256k1 attester and persists the secret under `run_root`.
fn create_attester(run_root: &Path) -> Result<AttesterKey> {
    let signing_key = SigningKey::random(&mut OsRng);
    let sec1 = signing_key.verifying_key().to_encoded_point(true);
    let pubkey_sec1_hex = hex_lower(sec1.as_bytes());

    // The canonical allowlist keying primitive (the gen_vectors / TV-DUAL-5 oracle): miden-crypto's
    // PublicKey parsed from the SEC1 bytes, then its commitment word.
    let public_key = PublicKey::read_from_bytes(sec1.as_bytes())
        .map_err(|e| anyhow::anyhow!("parsing the SEC1 pubkey into miden-crypto: {e}"))?;
    let commitment_hex = public_key.to_commitment().to_hex();

    let secret_path = run_root.join("attester.secret.hex");
    fs::write(&secret_path, hex_lower(&signing_key.to_bytes()))
        .with_context(|| format!("writing {}", secret_path.display()))?;

    Ok(AttesterKey { pubkey_sec1_hex, commitment_hex, secret_path })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generates all actors: five Falcon-keyed public wallets registered with the client + keystore
/// (their on-chain materialization happens with their first transaction), and the secp256k1
/// attester persisted under `run_root`.
pub async fn create_actors(hc: &mut HarnessClient, run_root: &Path) -> Result<Actors> {
    let owner = create_wallet(hc).await.context("creating the owner wallet")?;
    let pauser = create_wallet(hc).await.context("creating the DOM_PAUSER wallet")?;
    let manager = create_wallet(hc).await.context("creating the DOM_MANAGER wallet")?;
    let recipient = create_wallet(hc).await.context("creating the recipient wallet")?;
    let holder = create_wallet(hc).await.context("creating the holder wallet")?;
    let attester = create_attester(run_root).context("creating the local test attester")?;
    Ok(Actors { owner, pauser, manager, recipient, holder, attester })
}
