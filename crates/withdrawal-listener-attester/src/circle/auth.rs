//! The auth posture (`Q-API-AUTH` — **OPEN**, `REQUIRES CIRCLE CONFIRMATION`).
//!
//! The OpenAPI declares **no security scheme at all**: no top-level `security`, no
//! `components.securitySchemes`, no per-operation `security` (verified against the raw 1026-line
//! YAML — `CIRCLE-API-SURFACE.md`). So the contract this crate implements is the one Circle
//! published — *no auth* — and whether production access needs an out-of-band key is a question for
//! Circle, not one to answer by picking a header and hoping.
//!
//! What ships is therefore an *injection point*, not a scheme. [`AuthPosture::None`] (the default)
//! builds requests against the documented no-auth contract; [`AuthPosture::Header`] attaches an
//! operator-supplied key under an operator-supplied header NAME — the name is configurable precisely
//! because presuming `Authorization: Bearer` would presume the answer.
//!
//! Three properties hold whatever Circle answers, and each is pinned by a test in
//! `tests/auth_posture.rs` (T-LA-14):
//!
//! 1. **No credential is hardcoded** anywhere in this crate.
//! 2. **No credential is rendered.** `Debug` redacts the value here, and the token is a
//!    [`SecretString`](crate::config::SecretString) in the config, so no `{:?}` of a config can print
//!    it.
//! 3. **No credential crosses a transport that cannot protect it.** A configured key requires an
//!    HTTPS base URL, enforced when the config is built.
//!
//! The posture mirrors the deposit relayer's, deliberately: the two services face the same Circle
//! API under the same open question, and answering it differently in each would guarantee that one of
//! them is wrong.

use core::fmt;

use reqwest::header::{HeaderName, HeaderValue};

use crate::config::ListenerConfig;
use crate::error::{Cause, ListenerError};

/// How (or whether) the client authenticates.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthPosture {
    /// The DOCUMENTED contract: no auth header at all. This is what a request against the published
    /// API looks like, and it is the default.
    None,

    /// An out-of-band key, injected under an operator-chosen header name. The value is a credential:
    /// never logged, never rendered by `Debug`, never baked into the source, and never sent over a
    /// plaintext transport.
    Header { name: String, value: String },
}

impl AuthPosture {
    /// An out-of-band key injected under `name`.
    pub fn header(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Header {
            name: name.into(),
            value: value.into(),
        }
    }

    /// The posture the operator's config asks for: a header injection iff a token AND the header name
    /// to carry it are configured, otherwise the documented no-auth contract. A *missing* token is not
    /// an error — it is the documented case.
    ///
    /// A token with no header name cannot reach here: [`ListenerConfig`] refuses to exist in that
    /// state ([`ListenerError::AuthHeaderNameRequired`]). Should it ever slip through, this falls back
    /// to the DOCUMENTED no-auth contract rather than inventing a header — failing toward the
    /// published API, never toward a guessed scheme.
    pub fn from_config(config: &ListenerConfig) -> Self {
        match (config.api_auth_token(), config.api_auth_header()) {
            (Some(token), Some(name)) => Self::header(name, token),
            _ => Self::None,
        }
    }

    /// Whether this posture carries a credential — and therefore requires a transport that can
    /// protect it.
    pub fn carries_credential(&self) -> bool {
        matches!(self, Self::Header { .. })
    }

    /// The validated header pair to attach to every request, or `None` for the no-auth contract.
    ///
    /// # Errors
    /// [`ListenerError::BadAuthHeader`] — an illegal header name, or a value carrying a control
    /// character (a header-injection attempt). Rejected here rather than at request time, so a
    /// misconfigured key can never silently degrade into an unauthenticated request stream.
    pub fn to_header(&self) -> Result<Option<(HeaderName, HeaderValue)>, ListenerError> {
        let Self::Header { name, value } = self else {
            return Ok(None);
        };

        let header_name =
            HeaderName::try_from(name.as_str()).map_err(|source| ListenerError::BadAuthHeader {
                name: name.clone(),
                source: Cause::new(source),
            })?;
        let mut header_value = HeaderValue::try_from(value.as_str()).map_err(|source| {
            // the VALUE never appears in the error — it is the credential
            ListenerError::BadAuthHeader {
                name: name.clone(),
                source: Cause::new(source),
            }
        })?;
        header_value.set_sensitive(true);

        Ok(Some((header_name, header_value)))
    }
}

/// Renders the header NAME — an operator needs to see WHICH header is configured — and redacts the
/// VALUE. `Debug` is how a credential ends up in a log line or a panic message; the derive would have
/// printed the key.
impl fmt::Debug for AuthPosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "AuthPosture::None"),
            Self::Header { name, .. } => f
                .debug_struct("AuthPosture::Header")
                .field("name", name)
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}
