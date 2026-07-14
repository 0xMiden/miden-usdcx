//! The `ListenerError` taxonomy — STARTED in this scaffold slice with the configuration family (the
//! base URL, the auth-header injection point, the transport bounds) and the transport failure the
//! Circle seam surfaces.
//!
//! The Circle-facing families (HTTP status, schema decode, the 409 conflict), the Miden-facing ones
//! (tag scan, note retrieval, evidence reads), the validation family (the B3/B5 checklists and the
//! "DO NOT SIGN" abort) and the quorum family land with their slices. The enum is `#[non_exhaustive]`
//! so those additions are not breaking changes.
//!
//! Errors are hand-rolled — the repo does not depend on `thiserror` — with lowercase, unpunctuated
//! messages (the Rust convention), and every variant preserves its underlying cause through
//! [`Error::source`](core::error::Error) rather than flattening it to a string.

use core::fmt;
use std::sync::Arc;

/// A preserved lower-level cause whose own type is neither `Clone` nor `PartialEq` (a
/// `reqwest::Error`, a header/URL parse error). Wrapping it keeps [`ListenerError`]'s `Clone` +
/// `PartialEq` contract intact while still handing the ORIGINAL typed error to
/// [`Error::source`](core::error::Error) — so a caller can `downcast_ref` it and ask the concrete
/// question (`is_timeout()`, say). Flattening the cause to a `String` would discard exactly the
/// information an operator needs.
///
/// The idiom mirrors the deposit relayer's `Cause`. It is duplicated rather than shared because it
/// is an error-plumbing convention, not a wire format — the single-owner rule binds the formats and
/// codecs the two services must agree on (all of which live in `xusdc-encoding` and are consumed by
/// reference here), and a cross-dependency between two sibling services just to share twelve lines
/// of `Arc<dyn Error>` would couple them for no protection.
#[derive(Debug, Clone)]
pub struct Cause(Arc<dyn core::error::Error + Send + Sync + 'static>);

impl Cause {
    /// Preserves `error` as an error source.
    pub fn new(error: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self(Arc::new(error))
    }

    /// The preserved cause, as a `dyn Error` — `downcast_ref` recovers its concrete type.
    pub fn as_error(&self) -> &(dyn core::error::Error + 'static) {
        &*self.0
    }
}

impl PartialEq for Cause {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.0.to_string() == other.0.to_string()
    }
}

impl Eq for Cause {}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Everything the listener/attester can refuse to do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenerError {
    /// The configured Circle base URL is not a usable `http`/`https` URL. Refused when the config is
    /// built, not on the first request.
    BadBaseUrl { url: String, source: Cause },

    /// An out-of-band API key is configured against a base URL that cannot protect it. A credential
    /// sent in the clear is a credential disclosed — and `Q-API-AUTH` being OPEN means the key could
    /// ride under any header name, so no transport-level convention will save it.
    InsecureAuthTransport { base_url: String },

    /// The configured auth header is not a legal header: an illegal NAME, or a value carrying a
    /// control character (a header-injection attempt). Rejected at construction, so a misconfigured
    /// key can never silently degrade into an unauthenticated request stream.
    ///
    /// The credential VALUE never appears in this error — only the header name.
    BadAuthHeader { name: String, source: Cause },

    /// An out-of-band API key is configured with no header name to send it under.
    ///
    /// `Q-API-AUTH` is OPEN: the OpenAPI documents NO auth scheme, so there is no header this crate
    /// could pick that would not be an invention (§10.12: "do NOT invent an auth header"). A key with
    /// nowhere documented to go is therefore a configuration error, not a prompt to guess
    /// `Authorization`. When Circle answers, the operator writes the answer into the config.
    AuthHeaderNameRequired,

    /// A configured faucet account id that is not an account id at all.
    BadFaucetId { value: String, source: Cause },

    /// A request that produced NO HTTP status — a connection failure, a timeout, a body that could
    /// not be read. Transient: the retry policy (a later slice) treats it as such.
    Transport(Cause),

    /// The response exceeded the configured body ceiling. NOT transient — a peer that returns an
    /// oversized body will do it again, and the bytes past the ceiling are never buffered.
    ResponseTooLarge { limit: usize, actual: usize },
}

impl fmt::Display for ListenerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadBaseUrl { url, .. } => {
                write!(f, "circle base url `{url}` is not a valid http(s) url")
            }
            Self::InsecureAuthTransport { base_url } => write!(
                f,
                "an out-of-band api key is configured, but the circle base url `{base_url}` is not \
                 https — the credential would be sent in the clear"
            ),
            Self::BadAuthHeader { name, .. } => {
                write!(f, "auth header `{name}` is not a legal http header")
            }
            Self::AuthHeaderNameRequired => write!(
                f,
                "an out-of-band api key is configured but no auth header name is set, and no scheme \
                 is documented to fall back on (q-api-auth is open)"
            ),
            Self::BadFaucetId { value, .. } => {
                write!(f, "faucet id `{value}` is not a valid account id")
            }
            Self::Transport(cause) => write!(f, "circle request failed: {cause}"),
            Self::ResponseTooLarge { limit, actual } => write!(
                f,
                "circle response of {actual} bytes exceeds the {limit}-byte ceiling"
            ),
        }
    }
}

impl core::error::Error for ListenerError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BadBaseUrl { source, .. }
            | Self::BadAuthHeader { source, .. }
            | Self::BadFaucetId { source, .. }
            | Self::Transport(source) => Some(source.as_error()),
            Self::InsecureAuthTransport { .. }
            | Self::AuthHeaderNameRequired
            | Self::ResponseTooLarge { .. } => None,
        }
    }
}
