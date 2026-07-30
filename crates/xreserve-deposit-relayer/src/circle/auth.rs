//! The auth posture — still Circle's to confirm, so this module parameterizes it rather than
//! choosing one.
//!
//! The OpenAPI declares **no security scheme at all** (no `security`, no `securitySchemes`).
//! Whether production needs an out-of-band key is `REQUIRES CIRCLE CONFIRMATION`. The relayer
//! therefore ships an *injection point*, not a scheme: [`AuthPosture::None`] (the default) builds
//! requests against the documented no-auth contract, and [`AuthPosture::Header`] attaches an
//! operator-supplied key under an operator-supplied header NAME — the name is configurable
//! precisely because presuming an `Authorization`/`Bearer` scheme would be presuming an answer
//! Circle has not given.
//!
//! Three properties hold whatever Circle answers, and each is pinned by a test:
//!
//! 1. **No credential is hardcoded** anywhere in this crate.
//! 2. **No credential is rendered.** `Debug` redacts the value here, and the token is a
//!    [`SecretString`](crate::config::SecretString) in the config, so no `{:?}` of a client or a
//!    config can print it.
//! 3. **No credential crosses a transport that cannot protect it.** A configured key requires an
//!    HTTPS base URL (enforced at client construction) and the relayer never follows a redirect, so
//!    there is no path on which the key is re-sent to a peer-chosen origin.

use core::fmt;

use reqwest::header::{HeaderName, HeaderValue};

use crate::config::RelayerConfig;
use crate::error::{Cause, RelayerError};

/// How (or whether) the client authenticates.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthPosture {
    /// The DOCUMENTED contract: no auth header at all. The OpenAPI declares no security scheme, so
    /// this is what a request against the published API looks like, and it is the default.
    None,
    /// An out-of-band key, injected under an operator-chosen header name. The value is a
    /// credential: it is never logged, never rendered by `Debug`, never baked into the source, and
    /// never sent over a plaintext transport.
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

    /// The posture the operator's config asks for: a header injection iff a token is configured,
    /// otherwise the documented no-auth contract. A *missing* token is not an error — it is the
    /// documented case.
    pub fn from_config(config: &RelayerConfig) -> Self {
        match config.api_auth_token() {
            Some(token) => Self::header(config.api_auth_header(), token),
            None => Self::None,
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
    /// [`RelayerError::BadAuthHeader`] — an illegal header name, or a value carrying a control
    /// character (a header-injection attempt). Rejected at construction, so a misconfigured key can
    /// never silently degrade into an unauthenticated request stream.
    pub(crate) fn to_header(&self) -> Result<Option<(HeaderName, HeaderValue)>, RelayerError> {
        let Self::Header { name, value } = self else {
            return Ok(None);
        };

        let header_name =
            HeaderName::try_from(name.as_str()).map_err(|source| RelayerError::BadAuthHeader {
                name: name.clone(),
                source: Cause::new(source),
            })?;
        let mut header_value = HeaderValue::try_from(value.as_str()).map_err(|source| {
            // the VALUE never appears in the error — it is the credential
            RelayerError::BadAuthHeader {
                name: name.clone(),
                source: Cause::new(source),
            }
        })?;
        header_value.set_sensitive(true);

        Ok(Some((header_name, header_value)))
    }
}

/// Renders the header NAME (an operator needs to see WHICH header is configured) and redacts the
/// VALUE. `Debug` is how a credential ends up in a log line or a panic message; the derive would
/// have printed the key.
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
