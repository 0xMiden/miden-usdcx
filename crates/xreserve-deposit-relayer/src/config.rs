//! `RelayerConfig` — the operational parameters the relayer holds. Parse-only: this module does no
//! I/O (no env reads, no file/network access); it is a serde-(de)serializable struct a later slice
//! populates from a config source. Fields are PRIVATE with read-only accessors (encapsulation) — a
//! caller cannot mutate live configuration out of band; construction is via [`Default`] (the
//! package-default baseline) or serde deserialization (the operator's config file). Every
//! Circle-owned value carried here stays OPEN (`REQUIRES CIRCLE CONFIRMATION`): the auth token,
//! the Miden remote domain, and the xUSDC identifier / its encoding are package-default
//! placeholders, never settled decisions.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::error::RelayerError;

/// The crash-recovery parameters, VALIDATED — the one place `retry_batch_size` and
/// `stale_claim_secs` are checked for the two values that would silently defeat recovery.
///
/// It is a validated type rather than two loose config fields because both defaults an operator
/// might reach for are unsafe: a zero batch makes the retry work list return nothing forever (every
/// deposit stranded behind the forward cursor), and a too-small stale threshold reclaims another
/// process's LIVE `Pending` claim mid-submit. Construction ([`Self::new`]) enforces the bounds, so
/// a relayer cannot hold an unsafe recovery policy — the binary fails at startup on an invalid one,
/// and a directly invoked cycle fails closed on it, rather than running with a policy that cannot
/// recover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryPolicy {
    retry_batch_size: usize,
    stale_claim_secs: u64,
}

impl RecoveryPolicy {
    /// The ABSOLUTE smallest `stale_claim_secs` the relayer will run under, independent of how fast
    /// a submit is. Even a sub-second submit envelope does not make a sub-minute reclaim threshold
    /// safe: clock skew between two relayer hosts, a GC/scheduler pause, or a slow fsync can leave
    /// a claim's timestamp looking older than it is. One minute is the floor; the BINDING minimum
    /// is the larger of this and one second beyond the submit envelope
    /// ([`RelayerConfig::submit_worst_case_secs`]).
    pub const MIN_STALE_CLAIM_SECS: u64 = 60;

    /// Validates and builds a recovery policy against a minimum stale threshold. The EFFECTIVE
    /// minimum is `max([`Self::MIN_STALE_CLAIM_SECS`], min_stale_claim_secs)` — the absolute floor
    /// ALWAYS binds, even for a caller who passes a smaller minimum, so the type's invariant that
    /// [`Self::stale_claim_secs`] is `>= MIN_STALE_CLAIM_SECS` holds for every constructed value.
    /// The production path ([`RelayerConfig::recovery_policy`]) supplies one second beyond the
    /// submit envelope as the caller minimum.
    ///
    /// # Errors
    /// [`RelayerError::BadRecoveryPolicy`] — `retry_batch_size == 0`, or `stale_claim_secs` below the
    /// effective minimum (which includes 0). The value is refused, never clamped: an unsafe operator
    /// value must fail loudly rather than become a different policy than the one written. The error
    /// carries `required_min_stale_secs` (the effective minimum) so the operator knows what to set.
    pub fn new(
        retry_batch_size: usize,
        stale_claim_secs: u64,
        min_stale_claim_secs: u64,
    ) -> Result<Self, RelayerError> {
        let required_min_stale_secs = Self::MIN_STALE_CLAIM_SECS.max(min_stale_claim_secs);
        if retry_batch_size == 0 || stale_claim_secs < required_min_stale_secs {
            return Err(RelayerError::BadRecoveryPolicy {
                retry_batch_size,
                stale_claim_secs,
                required_min_stale_secs,
            });
        }
        Ok(Self {
            retry_batch_size,
            stale_claim_secs,
        })
    }

    /// How many stranded (`Failed`) records one cycle re-drives — always >= 1.
    pub fn retry_batch_size(&self) -> usize {
        self.retry_batch_size
    }

    /// How old a `Pending` claim must be before it is reclaimed — always >=
    /// [`Self::MIN_STALE_CLAIM_SECS`].
    pub fn stale_claim_secs(&self) -> u64 {
        self.stale_claim_secs
    }
}

/// A configured credential — held, used, and NEVER rendered.
///
/// `Debug` and `Display` both print `<redacted>`. That is the whole type: the credential the
/// operator supplies out of band lives inside the config object, and a config object is the single
/// most likely thing to be `{:?}`-logged at startup or swept into a panic message. Redacting the
/// auth *posture* and the *client* while leaving the config printable would have left the front
/// door open — the plaintext key would still reach the first log line that dumped its own
/// configuration.
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

/// All operational parameters, held with no I/O — configuration only, no I/O. Private
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
    #[serde(default = "default_store_path")]
    store_path: String,
    #[serde(default)]
    relayer_account_id: String,
    #[serde(default)]
    attester_pubkey_hex: String,
    #[serde(default = "default_poll_page_size")]
    poll_page_size: u16,
    #[serde(default = "default_poll_interval_ms")]
    poll_interval_ms: u64,
    #[serde(default)]
    domain_token_fast_fail: bool,
    #[serde(default = "default_retry_batch_size")]
    retry_batch_size: usize,
    #[serde(default = "default_stale_claim_secs")]
    stale_claim_secs: u64,
    #[serde(default = "default_submit_deadline_ms")]
    submit_deadline_ms: u64,
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
/// commonest convention, so it is the package default — but the scheme is `REQUIRES CIRCLE
/// CONFIRMATION`: the OpenAPI declares no security scheme at all, so this is a configurable
/// placeholder, not an implemented scheme. With no token set (the default) NO auth header is sent.
fn default_api_auth_header() -> String {
    "Authorization".to_string()
}

/// Consecutive failed attempts before a retryable failure alerts (an HTTP 500 "alerts after a
/// threshold").
fn default_alert_after_attempts() -> u32 {
    3
}

/// Where the idempotency store lives. A relative FILE path — never `:memory:` and never a `file:`
/// URI, both of which `IdempotencyStore::open` refuses outright: a store that vanishes on restart
/// would re-scan the window and re-attempt every mint in it.
fn default_store_path() -> String {
    "relayer-store.sqlite3".to_string()
}

/// Attestations per batch poll. The documented `pageSize` range is 1..=1000; 100 is a page an
/// operator can read in a log and a request the relayer can finish inside its deadline.
fn default_poll_page_size() -> u16 {
    100
}

/// How long the loop waits after a cycle that reached the end of the scan. A deposit intent has no
/// expiry, so polling harder buys nothing but rate-limit pressure (Circle's ceiling is 5 QPS/IP).
fn default_poll_interval_ms() -> u64 {
    5_000
}

/// How many stranded (`Failed`) records one cycle re-drives from the retry work list. A bound, so a
/// large backlog is drained across cycles rather than starving the forward poll in one; the queue
/// rotates (each retry re-stamps its row), so no fixed head can monopolize the batch.
fn default_retry_batch_size() -> usize {
    100
}

/// How old a `Pending` claim must be before the cycle reclaims it (→ `Failed`, re-claimable). It
/// must exceed the longest a legitimate submit can be in flight, so a live attempt is never
/// reclaimed out from under itself; five minutes is far past a synchronous submit and still bounds
/// how long a crash-stranded claim sits before it is retried.
fn default_stale_claim_secs() -> u64 {
    300
}

/// The per-attempt DEADLINE for one Miden submit. It is what makes the submit envelope FINITE:
/// without it, a hung node keeps a claim `Pending` forever and no reclaim threshold is safe. A
/// submit that exceeds it is treated as a transient failure and retried. 30 s mirrors the Circle
/// per-attempt request deadline — generous for a healthy node, bounded for a hung one.
fn default_submit_deadline_ms() -> u64 {
    30_000
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
            store_path: default_store_path(),
            relayer_account_id: String::new(),
            attester_pubkey_hex: String::new(),
            poll_page_size: default_poll_page_size(),
            poll_interval_ms: default_poll_interval_ms(),
            domain_token_fast_fail: false,
            retry_batch_size: default_retry_batch_size(),
            stale_claim_secs: default_stale_claim_secs(),
            submit_deadline_ms: default_submit_deadline_ms(),
        }
    }
}

impl RelayerConfig {
    /// Circle xReserve REST base URL (the testnet host is the default; production is a separate
    /// host). No credential is embedded — the credential scheme stays OPEN (REQUIRES CIRCLE
    /// CONFIRMATION).
    pub fn circle_base_url(&self) -> &str {
        &self.circle_base_url
    }

    /// The configured Miden remote domain the relayer accepts in the OPTIONAL domain fast-fail. The
    /// authoritative compare is on-chain in the faucet's deposit-intent parse; which remote-domain
    /// id Circle assigns Miden is still OPEN (REQUIRES CIRCLE CONFIRMATION), so this value is a
    /// placeholder.
    pub fn remote_domain(&self) -> u32 {
        self.remote_domain
    }

    /// The configured 32-byte xUSDC identifier for the OPTIONAL token fast-fail. Both the value and
    /// its AccountId↔bytes32 encoding are Circle-owned and OPEN (REQUIRES CIRCLE CONFIRMATION).
    pub fn xusdc_identifier(&self) -> &[u8; 32] {
        &self.xusdc_identifier
    }

    /// Faucet recipient account id, carried as an opaque string until the Miden-facing slice pins
    /// the `miden-client` `AccountId` type (RIV against the v0.15 baseline).
    pub fn faucet_account_id(&self) -> &str {
        &self.faucet_account_id
    }

    /// Optional out-of-band API auth token. NEVER hardcoded; `None` builds requests against the
    /// documented no-auth contract. The scheme is `REQUIRES CIRCLE CONFIRMATION`.
    ///
    /// This EXPOSES the secret (the auth-header injection point needs the plaintext). It is the one
    /// deliberate exit; the token is a [`SecretString`] everywhere else, so no `Debug`/`Display` of
    /// this config — or of anything holding it — can print it.
    pub fn api_auth_token(&self) -> Option<&str> {
        self.api_auth_token.as_ref().map(SecretString::expose)
    }

    /// The header name the optional out-of-band token is injected under. Configurable because the
    /// production scheme is `REQUIRES CIRCLE CONFIRMATION` — the client must not presume
    /// an `Authorization`/`Bearer` scheme. Irrelevant when no token is set (no header is sent at
    /// all).
    pub fn api_auth_header(&self) -> &str {
        &self.api_auth_header
    }

    /// Circle's documented rate ceiling: 5 QPS per IP.
    pub fn rate_qps_per_ip(&self) -> u32 {
        self.rate_qps_per_ip
    }

    /// Circle's documented rate ceiling: 35 QPS global.
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

    /// Consecutive failed attempts before a RETRYABLE failure alerts the operator (the documented
    /// policy: a 500 "alerts after a threshold"; a 404 does not alert until its attempts are
    /// exhausted).
    pub fn alert_after_attempts(&self) -> u32 {
        self.alert_after_attempts
    }

    /// Connect deadline for one attempt.
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
    }

    /// End-to-end deadline for one attempt — the bound that keeps an unresponsive peer from
    /// stalling the relayer forever.
    pub fn request_timeout_ms(&self) -> u64 {
        self.request_timeout_ms
    }

    /// The response-body ceiling — the bound that keeps an endless body from exhausting memory.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// The idempotency store's file path. `IdempotencyStore::open` refuses a path SQLite would open
    /// as an in-memory database, so an operator's typo cannot spell a store that forgets.
    pub fn store_path(&self) -> &str {
        &self.store_path
    }

    /// The relayer's OWN Miden account — the mint note's sender/producer. An opaque string here;
    /// `cycle::MintIdentities::from_config` parses it, so a bad id is refused at startup.
    pub fn relayer_account_id(&self) -> &str {
        &self.relayer_account_id
    }

    /// The operator-configured attester public key (33-byte compressed SEC1, hex).
    ///
    /// It is CONFIGURATION, not a Circle wire field: Circle's attestation object carries `payload`
    /// / `messageHash` / `attestation` and no key, but the faucet's on-chain attestation check
    /// needs the candidate pubkey inside the note. This is the key whose Poseidon2 commitment the
    /// operator was told is in the faucet's `xReserveAttesters` allowlist — a claim only the chain
    /// can check.
    pub fn attester_pubkey_hex(&self) -> &str {
        &self.attester_pubkey_hex
    }

    /// Attestations per batch poll (`pageSize`, 1..=1000 — `BatchQuery::new` is the judge).
    pub fn poll_page_size(&self) -> u16 {
        self.poll_page_size
    }

    /// The wait between cycles once a scan has reached its end.
    pub fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms
    }

    /// Whether the OPTIONAL domain/token fast-fail (the optional domain/token fast-fail) runs.
    ///
    /// **Default OFF, and that is not laziness.** Its expected values are [`Self::remote_domain`]
    /// and [`Self::xusdc_identifier`], and both are OPEN (`REQUIRES CIRCLE CONFIRMATION`): a
    /// fast-fail comparing against a placeholder would refuse every honest deposit on the grounds
    /// that it does not match a value nobody has decided. The check is a LIVENESS optimization —
    /// the authoritative compare is on-chain in the faucet's deposit-intent parse — so leaving it
    /// off costs a block per deposit and nothing else. An operator turns it on when Circle answers.
    ///
    /// With it ON, the cycle also fetches `GET /v1/info` once per cycle to corroborate that Circle
    /// advertises the configured domain at all.
    pub fn domain_token_fast_fail(&self) -> bool {
        self.domain_token_fast_fail
    }

    /// How many stranded (`Failed`) records one cycle re-drives from the retry work list.
    pub fn retry_batch_size(&self) -> usize {
        self.retry_batch_size
    }

    /// How old a `Pending` claim must be before the cycle reclaims it (→ re-claimable `Failed`) —
    /// the crash-recovery threshold, set past the longest a legitimate submit can be in flight.
    pub fn stale_claim_secs(&self) -> u64 {
        self.stale_claim_secs
    }

    /// The per-attempt Miden submit deadline, in milliseconds.
    pub fn submit_deadline_ms(&self) -> u64 {
        self.submit_deadline_ms
    }

    /// The WORST-CASE duration of one `submit_with_retry`, in whole seconds (rounded up) — the
    /// "longest legitimate submit" the stale-claim threshold must exceed.
    ///
    /// It is `max_retry_attempts` attempts, each bounded by [`Self::submit_deadline_ms`], plus the
    /// exponential backoff between them (`base · 2^(n-1)` per gap, the same curve the submit loop
    /// applies, capped like it). This is what turns "the threshold must exceed the longest submit"
    /// from prose into a computed bound that [`Self::recovery_policy`] validates against — so a
    /// config that permits a longer submit (more retries, a longer deadline, more backoff) demands
    /// a correspondingly larger threshold, rather than trusting a fixed constant.
    pub fn submit_worst_case_secs(&self) -> u64 {
        let attempts = u64::from(self.max_retry_attempts.max(1));
        let submit_ms = attempts.saturating_mul(self.submit_deadline_ms);

        // an UPPER bound on the backoff sum: `attempts - 1` gaps, each at most `base · 2^(shift)` where
        // the shift is capped exactly as the submit loop caps it. Over-estimating is safe here — it can
        // only demand a larger (safer) threshold.
        let gaps = attempts.saturating_sub(1);
        let shift = gaps.min(20) as u32;
        let max_gap_ms = self.backoff_base_ms.saturating_mul(1u64 << shift);
        let backoff_ms = max_gap_ms.saturating_mul(gaps);

        submit_ms.saturating_add(backoff_ms).div_ceil(1_000)
    }

    /// The VALIDATED crash-recovery policy — the safe form of [`Self::retry_batch_size`] and
    /// [`Self::stale_claim_secs`]. The binary calls this at startup and fails on an invalid
    /// operator value; the cycle calls it and fails closed. There is no path that runs the recovery
    /// machinery with an unvalidated batch size or threshold.
    ///
    /// The stale threshold is validated STRICTLY beyond the submit envelope
    /// ([`Self::submit_worst_case_secs`]) — so a claim can never be reclaimed while its submit is
    /// legitimately still in flight — and never below the absolute floor
    /// ([`RecoveryPolicy::MIN_STALE_CLAIM_SECS`]). The binding minimum is the larger of the two.
    ///
    /// # Errors
    /// [`RelayerError::BadSubmitDeadline`] — `submit_deadline_ms == 0` (which would defer every deposit
    /// forever). Checked FIRST, because the submit envelope is meaningless without a non-zero deadline.
    /// [`RelayerError::BadRecoveryPolicy`] — see [`RecoveryPolicy::new`].
    pub fn recovery_policy(&self) -> Result<RecoveryPolicy, RelayerError> {
        if self.submit_deadline_ms == 0 {
            return Err(RelayerError::BadSubmitDeadline {
                submit_deadline_ms: self.submit_deadline_ms,
            });
        }
        // one second STRICTLY beyond the submit envelope; `RecoveryPolicy::new` then applies the
        // absolute floor on top, so the effective minimum is `max(60, envelope + 1)`.
        let min_stale_claim_secs = self.submit_worst_case_secs().saturating_add(1);
        RecoveryPolicy::new(
            self.retry_batch_size,
            self.stale_claim_secs,
            min_stale_claim_secs,
        )
    }
}
