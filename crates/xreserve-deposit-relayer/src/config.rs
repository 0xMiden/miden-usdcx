//! `RelayerConfig` — the operational parameters the relayer holds. Parse-only: this module does no
//! I/O (no env reads, no file/network access); it is a serde-(de)serializable struct a later slice
//! populates from a config source. Fields are PRIVATE with read-only accessors (encapsulation) — a
//! caller cannot mutate live configuration out of band; construction is via [`Default`] (the
//! package-default baseline) or serde deserialization (the operator's config file). Every
//! Circle-owned value carried here stays OPEN (`REQUIRES CIRCLE CONFIRMATION`): the auth token
//! (Q-API-AUTH), the Miden remote domain (Q-DOM-1), and the xUSDC identifier / its encoding
//! (DEV-10) are package-default placeholders, never settled decisions.

use core::fmt;

use serde::{Deserialize, Serialize};

/// A configured credential — held, used, and NEVER rendered.
///
/// `Debug` and `Display` both print `<redacted>`. That is the whole type: the credential the
/// operator supplies out of band lives inside the config object, and a config object is the single
/// most likely thing to be `{:?}`-logged at startup or swept into a panic message. Redacting the
/// auth *posture* and the *client* while leaving the config printable would have left the front door
/// open — the plaintext key would still reach the first log line that dumped its own configuration.
///
/// Only [`Self::expose`] hands the plaintext out, and it is deliberately awkward to type, so every
/// place the secret escapes is greppable.
///
/// serde is TRANSPARENT: the operator's config file holds (and round-trips) the real value. The
/// redaction is a property of the HUMAN-facing renderings, not of the wire format — a "redaction"
/// that also blanked the serialized form would silently drop the key on the next config reload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// Hands out the plaintext. The ONE deliberate exit — used by the auth-header injection point.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl From<String> for SecretString {
    fn from(secret: String) -> Self {
        Self(secret)
    }
}

/// All operational parameters, held with no I/O (§4 single-responsibility: `config`). Private
/// fields + read-only accessors; adding a field is non-breaking.
///
/// `Debug` is DERIVED and safe to derive: the only credential it carries is a [`SecretString`],
/// which renders as `<redacted>`. Keep it that way — a plain `String` token here would be printed
/// verbatim by this derive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerConfig {
    circle_base_url: String,
    remote_domain: u32,
    xusdc_identifier: [u8; 32],
    faucet_account_id: String,
    #[serde(default)]
    api_auth_token: Option<SecretString>,
    #[serde(default = "default_api_auth_header")]
    api_auth_header: String,
    rate_qps_per_ip: u32,
    rate_qps_global: u32,
    max_retry_attempts: u32,
    backoff_base_ms: u64,
    #[serde(default = "default_alert_after_attempts")]
    alert_after_attempts: u32,
    #[serde(default = "default_connect_timeout_ms")]
    connect_timeout_ms: u64,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
    #[serde(default = "default_max_response_bytes")]
    max_response_bytes: usize,
}

/// How long one connect may take. reqwest's default is "forever"; a relayer that waits forever on a
/// peer that never completes a handshake never reaches its retry budget and never alerts.
fn default_connect_timeout_ms() -> u64 {
    10_000
}

/// How long ONE attempt may take, end to end (the retry policy bounds the number of attempts). The
/// deposit attestation has no expiry, so the relayer can afford to give up on a stalled attempt and
/// come back — what it cannot afford is to wait indefinitely.
fn default_request_timeout_ms() -> u64 {
    30_000
}

/// The largest response body the relayer will buffer. A Circle attestation page is kilobytes; 8 MiB
/// is orders of magnitude of headroom, and still a bound — an unbounded read is a memory-exhaustion
/// lever for anything on the path.
fn default_max_response_bytes() -> usize {
    8 * 1024 * 1024
}

/// The header an out-of-band key would ride in, IF Circle requires one. `Authorization` is the
/// commonest convention, so it is the package default — but Q-API-AUTH is OPEN (`REQUIRES CIRCLE
/// CONFIRMATION`): the OpenAPI declares no security scheme at all, so this is a configurable
/// placeholder, not an implemented scheme. With no token set (the default) NO auth header is sent.
fn default_api_auth_header() -> String {
    "Authorization".to_string()
}

/// Consecutive failed attempts before a retryable failure alerts (§8.4: HTTP 500 "alerts after a
/// threshold").
fn default_alert_after_attempts() -> u32 {
    3
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            circle_base_url: "https://xreserve-api-testnet.circle.com".to_string(),
            remote_domain: 0,
            xusdc_identifier: [0u8; 32],
            faucet_account_id: String::new(),
            api_auth_token: None,
            api_auth_header: default_api_auth_header(),
            rate_qps_per_ip: 5,
            rate_qps_global: 35,
            max_retry_attempts: 5,
            backoff_base_ms: 250,
            alert_after_attempts: default_alert_after_attempts(),
            connect_timeout_ms: default_connect_timeout_ms(),
            request_timeout_ms: default_request_timeout_ms(),
            max_response_bytes: default_max_response_bytes(),
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
    ///
    /// This EXPOSES the secret (the auth-header injection point needs the plaintext). It is the one
    /// deliberate exit; the token is a [`SecretString`] everywhere else, so no `Debug`/`Display` of
    /// this config — or of anything holding it — can print it.
    pub fn api_auth_token(&self) -> Option<&str> {
        self.api_auth_token.as_ref().map(SecretString::expose)
    }

    /// The header name the optional out-of-band token is injected under. Configurable because the
    /// production scheme is Q-API-AUTH (REQUIRES CIRCLE CONFIRMATION) — the client must not presume
    /// an `Authorization`/`Bearer` scheme. Irrelevant when no token is set (no header is sent at
    /// all).
    pub fn api_auth_header(&self) -> &str {
        &self.api_auth_header
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

    /// Consecutive failed attempts before a RETRYABLE failure alerts the operator (§8.4: a 500
    /// "alerts after a threshold"; a 404 does not alert until its attempts are exhausted).
    pub fn alert_after_attempts(&self) -> u32 {
        self.alert_after_attempts
    }

    /// Connect deadline for one attempt.
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
    }

    /// End-to-end deadline for one attempt — the bound that keeps an unresponsive peer from stalling
    /// the relayer forever.
    pub fn request_timeout_ms(&self) -> u64 {
        self.request_timeout_ms
    }

    /// The response-body ceiling — the bound that keeps an endless body from exhausting memory.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}
