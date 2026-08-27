use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct Config {
    /// Circle's API root. No credential anywhere — Circle's auth scheme is OPEN, and the injection
    /// point returns when Circle confirms one.
    pub circle_base_url: Url,
    /// The remote-domain id Circle assigns Miden. OPEN (`REQUIRES CIRCLE CONFIRMATION`).
    pub remote_domain: u32,
    /// The xUSDC faucet the mint notes are routed at. Must be a PUBLIC network account.
    pub faucet_account_id: String,
    /// The relayer's own account — the notes' producer.
    pub relayer_account_id: String,
    /// The attester key that travels beside every signature, 33-byte compressed SEC1 hex. A KEY,
    /// not an authority: whether it is allowlisted is the faucet's to say, on-chain.
    pub attester_pubkey_hex: String,
    /// Where the feed cursor is persisted.
    pub store_path: PathBuf,
}

impl Config {
    /// Reads and validates the config at `path` — the ONE place the file is read.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the config file `{}`", path.display()))?;

        toml::from_str(&text)
            .with_context(|| format!("parsing the config file `{}`", path.display()))
    }
}
