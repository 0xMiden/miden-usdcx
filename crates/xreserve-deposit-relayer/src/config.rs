//! `RelayerConfig` — the operational parameters the relayer holds. Parse-only: this module does no
//! I/O (no env reads, no file/network access); it is a serde-(de)serializable struct a later slice
//! populates from a config source. Fields are PRIVATE with read-only accessors (encapsulation) — a
//! caller cannot mutate live configuration out of band; construction is via [`Default`] (the
//! package-default baseline) or serde deserialization (the operator's config file). Every
//! Circle-owned value carried here stays OPEN (`REQUIRES CIRCLE CONFIRMATION`): the auth token
//! (Q-API-AUTH), the Miden remote domain (Q-DOM-1), and the xUSDC identifier / its encoding
//! (DEV-10) are package-default placeholders, never settled decisions.

use serde::{Deserialize, Serialize};

/// All operational parameters, held with no I/O (§4 single-responsibility: `config`). Private
/// fields + read-only accessors; adding a field is non-breaking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerConfig {
    circle_base_url: String,
    remote_domain: u32,
    xusdc_identifier: [u8; 32],
    faucet_account_id: String,
    #[serde(default)]
    api_auth_token: Option<String>,
    rate_qps_per_ip: u32,
    rate_qps_global: u32,
    max_retry_attempts: u32,
    backoff_base_ms: u64,
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            circle_base_url: "https://xreserve-api-testnet.circle.com".to_string(),
            remote_domain: 0,
            xusdc_identifier: [0u8; 32],
            faucet_account_id: String::new(),
            api_auth_token: None,
            rate_qps_per_ip: 5,
            rate_qps_global: 35,
            max_retry_attempts: 5,
            backoff_base_ms: 250,
        }
    }
}

impl RelayerConfig {
    /// Circle xReserve REST base URL (the testnet host is the default; production is a separate
    /// host). No credential is embedded — Q-API-AUTH stays OPEN (REQUIRES CIRCLE CONFIRMATION).
    pub fn circle_base_url(&self) -> &str {
        &self.circle_base_url
    }

    /// The configured Miden remote domain the relayer accepts in the OPTIONAL domain fast-fail. The
    /// authoritative compare is on-chain at D5a; this value is Q-DOM-1 (REQUIRES CIRCLE
    /// CONFIRMATION).
    pub fn remote_domain(&self) -> u32 {
        self.remote_domain
    }

    /// The configured 32-byte xUSDC identifier for the OPTIONAL token fast-fail. Both the value and
    /// its AccountId↔bytes32 encoding are owned by DEV-10 (REQUIRES CIRCLE CONFIRMATION).
    pub fn xusdc_identifier(&self) -> &[u8; 32] {
        &self.xusdc_identifier
    }

    /// Faucet recipient account id, carried as an opaque string until the Miden-facing slice pins
    /// the `miden-client` `AccountId` type (RIV against the v0.15 baseline).
    pub fn faucet_account_id(&self) -> &str {
        &self.faucet_account_id
    }

    /// Optional out-of-band API auth token. NEVER hardcoded; `None` builds requests against the
    /// documented no-auth contract. Q-API-AUTH (REQUIRES CIRCLE CONFIRMATION).
    pub fn api_auth_token(&self) -> Option<&str> {
        self.api_auth_token.as_deref()
    }

    /// Circle rate ceiling: 5 QPS per IP (CIR-API-4).
    pub fn rate_qps_per_ip(&self) -> u32 {
        self.rate_qps_per_ip
    }

    /// Circle rate ceiling: 35 QPS global (CIR-API-4).
    pub fn rate_qps_global(&self) -> u32 {
        self.rate_qps_global
    }

    /// Max retry attempts for retryable failures (404 not-yet-published, HTTP 500, transient Miden
    /// submit).
    pub fn max_retry_attempts(&self) -> u32 {
        self.max_retry_attempts
    }

    /// Exponential-backoff base delay, in milliseconds.
    pub fn backoff_base_ms(&self) -> u64 {
        self.backoff_base_ms
    }
}
