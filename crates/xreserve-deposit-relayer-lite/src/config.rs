//! The operator's config file, and the range checks it must pass before the service runs.

use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use tracing::instrument;

/// Circle documents `pageSize` as 1–1000; a value outside that is a request the API answers with a
/// 400, so it is refused at startup instead.
const MAX_PAGE_SIZE: u16 = 1000;

fn default_auth_header() -> String {
    "Authorization".to_string()
}
fn default_page_size() -> u16 {
    100
}
fn default_poll_interval_ms() -> u64 {
    5_000
}
fn default_request_timeout_ms() -> u64 {
    30_000
}
fn default_max_response_bytes() -> usize {
    8 * 1024 * 1024
}

/// Everything the relayer is configured with.
///
/// `deny_unknown_fields` is deliberate: a mistyped key is a setting that silently keeps its default,
/// which is how an operator ends up debugging a relayer that ignored the value they set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct Config {
    /// Circle's API root. No credential is baked in anywhere — Circle's auth scheme is OPEN.
    pub circle_base_url: String,
    /// The remote-domain id Circle assigns Miden. OPEN (`REQUIRES CIRCLE CONFIRMATION`).
    pub remote_domain: u32,
    /// The xUSDC faucet the notes are routed at. Must be a PUBLIC network account.
    pub faucet_account_id: String,
    /// The relayer's own account — the note's producer.
    pub relayer_account_id: String,
    /// The attester key that travels beside every signature, 33-byte compressed SEC1 hex. It is a
    /// KEY, not an authority: whether it is allowlisted is the faucet's to say, on-chain.
    pub attester_pubkey_hex: String,
    /// The SQLite file holding the submitted-nonce set and the cursor.
    pub store_path: PathBuf,

    /// The credential value, if Circle's (still OPEN) scheme needs one. Never logged.
    #[serde(default)]
    pub api_auth_token: Option<String>,
    /// The header the credential is sent in.
    #[serde(default = "default_auth_header")]
    pub api_auth_header: String,
    #[serde(default = "default_page_size")]
    pub poll_page_size: u16,
    /// How long to wait once the scan has reached the end of the feed. A deposit intent has no
    /// expiry, so polling harder buys nothing but rate-limit pressure.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// The response-size ceiling, so a runaway body cannot exhaust memory.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
}

impl Config {
    /// Reads and validates the config at `path`.
    ///
    /// This is the ONE place the file is read, so the type stays testable without a filesystem.
    #[instrument(name = "config.load", fields(path = %path.display()))]
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the config file `{}`", path.display()))?;

        let config: Self = toml::from_str(&text)
            .with_context(|| format!("parsing the config file `{}`", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Refuses a value the service cannot run with — here, at startup, rather than at the first
    /// deposit.
    #[instrument(level = "debug", name = "config.validate", skip_all)]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.circle_base_url.trim().is_empty(),
            "circle_base_url is empty"
        );
        ensure!(
            (1..=MAX_PAGE_SIZE).contains(&self.poll_page_size),
            "poll_page_size is {}, but circle documents 1-{MAX_PAGE_SIZE}",
            self.poll_page_size
        );
        ensure!(
            self.max_response_bytes > 0,
            "max_response_bytes is 0, so every response would be refused"
        );
        ensure!(
            self.request_timeout_ms > 0,
            "request_timeout_ms is 0, so every request would time out"
        );
        Ok(())
    }
}
