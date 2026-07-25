//! The Circle-facing half (§3): the HTTP transport and everything that turns a Circle response into
//! a [`ValidatedAttestation`] — or into a logged rejection.
//!
//! | module | single responsibility |
//! |---|---|
//! | [`client`] | the request: base URL, auth-header injection, deadline, size ceiling, the policy stack |
//! | [`transport`] | what executes a request (`reqwest` in production; the mock in tests) + its bounds |
//! | [`auth`] | the auth posture (`Q-API-AUTH`, OPEN): an injection point, not a scheme |
//! | [`rate`] | the rate governor (5 QPS/IP, 35 QPS global — CIR-API-4) |
//! | [`retry`] | exponential backoff + the §8.4 never-drop / alert obligations |
//! | [`status`] | the HTTP-status policy (404 retry, 400 reject, 5xx retry+alert, 3xx reject) |
//! | [`schema`] | serde types deserialized exactly per the OpenAPI + the validated forms |
//! | [`pagination`] | the `BatchQuery` surface + the `Link`-header cursors |
//! | [`attestation_fetch`] | the three fetch shapes (`CMP-D3`/`CMP-D4`) |
//! | [`info`] | `GET /v1/info` discovery (`CMP-D1`) |
//!
//! This half NEVER touches Miden. It produces a validated triple (payload + attestation + the
//! candidate pubkey the config holds) or a rejection, and the seam — the idempotency store — is what
//! a validated triple must cross before the Miden half sees it. Nothing here decides whether a mint
//! is AUTHORIZED: the ECDSA verify, the attester allowlist, the nonce, and the amount reduction are
//! all on-chain (§1.2), which is why a bug in this half can withhold a mint but never cause one.
//!
//! **Mock-only, by design (§11).** Every live Circle leg is `REQUIRES CIRCLE CONFIRMATION`
//! (`Q-API-AUTH` for the credential, `Q-DOM-1` for the domain, `Q-INFO-PARAM` for the info shape), so
//! this half is exercised end-to-end against a schema-exact mock server and no Circle endpoint is
//! contacted live. No credential is hardcoded; the base URL and the optional out-of-band key are
//! configuration.

pub mod attestation_fetch;
pub mod auth;
pub mod client;
pub mod info;
pub mod pagination;
pub mod rate;
pub mod retry;
pub mod schema;
pub mod status;
pub mod transport;

pub use attestation_fetch::{
    fetch_attestation_by_message_hash, fetch_attestations_by_tx_hash,
    poll_remote_domain_attestations,
};
pub use auth::AuthPosture;
pub use client::CircleClient;
pub use info::fetch_info;
pub use pagination::{BatchQuery, PageCursor, PageCursors, PageLink};
pub use rate::RateGovernor;
pub use retry::{with_backoff, RetryContext, RetryPolicy};
pub use schema::{
    AttestationByTxHash, AttestationListResponse, AttestationObject, AttestationPage,
    AttestationResponse, AttestationsByTxHashResponse, InfoResponse, RemoteDomain, RemoteToken,
    SourceDomain, ValidatedAttestation, ValidatedAttestationByTxHash,
};
pub use status::{classify_status, StatusClass};
pub use transport::{
    check_not_redirected, collect_bounded, BodyLimit, ChunkSource, HttpTransport, RawResponse,
    RedirectPolicy, ReqwestTransport, TransportLimits,
};
