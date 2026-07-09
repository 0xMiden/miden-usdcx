//! Local test identities (actor keygen).
//!
//! Five keyed PUBLIC wallets — owner, DOM_PAUSER holder, DOM_MANAGER holder, recipient, holder
//! (burner) — each `AuthSingleSig` (Falcon512) + `BasicWallet`, keys in the run's filesystem
//! keystore; plus ONE locally generated secp256k1 attester keypair (the `gen_vectors` pattern:
//! k256 keypair, keccak SEC1 digest, `PublicKey::to_commitment` allowlist key). These are all
//! throwaway local test identities — NEVER Circle's keys, endpoints, or anything derived from
//! them. The attester is GENERATED and RECORDED here (harness foundation); its first on-chain use
//! (`set_attester`) is LNV-2 scope.

use std::path::{Path, PathBuf};

use anyhow::Result;
use miden_protocol::account::Account;

use crate::client::HarnessClient;

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

/// Generates all actors: five Falcon-keyed public wallets registered with the client + keystore
/// (their on-chain materialization happens with their first transaction), and the secp256k1
/// attester persisted under `run_root`.
pub async fn create_actors(hc: &mut HarnessClient, run_root: &Path) -> Result<Actors> {
    let _ = (hc, run_root);
    todo!("LNV-1 driver: wallet keygen + attester keygen")
}
