//! `ListenerConfig` — the static operational parameters the listener/attester holds (the documented
//! policy: "PURE — static config: faucet_id, fixed burn tag (u32), Miden domain, Circle base URL,
//! attester key handles").
//!
//! Parse-only: this module does no I/O. It is a serde-(de)serializable struct an operator's config
//! file populates, with PRIVATE fields and read-only accessors — live configuration cannot be
//! mutated out of band — and it is **valid by construction**: [`ListenerConfig::builder`] refuses a
//! base URL that is not a usable `http(s)` URL, and refuses an out-of-band credential paired with a
//! base URL that cannot protect it.
//!
//! Every Circle-owned value carried here stays OPEN (`REQUIRES CIRCLE CONFIRMATION`): the auth
//! token, the Miden domain and forwarding scope, and the burn-evidence field are
//! package-default placeholders, never settled decisions.
//!
//! **Key material never lives here.** The attester keys are held as [`AttesterKeyHandle`]s —
//! identifiers naming a key in a KMS or HSM, never the key bytes. Custody — rotation, the two-key minimum, the HSM boundary — is the
//! operations owner's concern; this crate owns the *signing interface*, not the custody SOP.

use core::fmt;

use bon::Builder;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::attester::AttesterAllowlist;
use crate::error::{Cause, ListenerError};

/// The documented Circle testnet host (`CIRCLE-API-SURFACE.md`, "Base URLs & transport"). Mainnet
/// is `https://xreserve-api.circle.com`. Mirrored, never invented.
pub const CIRCLE_TESTNET_BASE_URL: &str = "https://xreserve-api-testnet.circle.com";
pub const CIRCLE_MAINNET_BASE_URL: &str = "https://xreserve-api.circle.com";

/// The package-default faucet id is a **placeholder** — a real
/// deployment overrides it from the operator's config file, and the default exists so a test or a
/// dev run has a parseable, genuinely-valid id rather than a fabricated one.
const PLACEHOLDER_FAUCET_ID: &str = "0xbb405fd9fe431bd1135a292de098cb";

/// A configured credential — held, used, and NEVER rendered.
///
/// `Debug` and `Display` both print `<redacted>`. A config object is the single most likely thing
/// to be `{:?}`-logged at startup or swept into a panic message, so the redaction lives on the
/// value itself rather than on the things that hold it.
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

/// An attester key **handle**: the identifier of a key held somewhere else (a KMS/HSM URI, a slot
/// name). Never key material.
///
/// The distinction is the custody boundary. The attester signs `messageHashToSign` with a secp256k1
/// key — the signing happens off-chain — and Circle requires ≥2 signatures; but where those keys
/// live, how they rotate, and who can reach them is `P4-OPS`'s problem. What this config holds is
/// the *name* of a key, which is why the type renders itself in `Debug` instead of hiding: a handle
/// is not a secret, and an operator needs to see which key is configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttesterKeyHandle(String);

impl AttesterKeyHandle {
    pub fn new(handle: impl Into<String>) -> Self {
        Self(handle.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// All static operational parameters. Built through [`ListenerConfig::builder`] (validating) or
/// deserialized from the operator's config file; fields are private, so a live config cannot be
/// mutated out from under the service.
///
/// `Debug` is DERIVED and safe to derive: the only credential it carries is a [`SecretString`],
/// which renders as `<redacted>`. Keep it that way — a plain `String` token here would be printed
/// verbatim by this derive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
// TWO things here are load-bearing.
//
// `finish_fn = build_internal` renames bon's generated (infallible) finisher, leaving the name
// `build` free for the VALIDATING one below, so the unchecked constructor is private.
//
// `try_from = "ListenerConfigRaw"` is what makes that mean anything. A derived `Deserialize` would
// populate the private fields DIRECTLY, and an operator's config file — the path production actually
// uses — could then hold a state the builder refuses: a real API key over a plaintext `http://` base
// URL, handed straight to the header injector. Routing serde through the same
// `validate` closes that door. The invariant is not "the builder validates"; it is "every
// ListenerConfig that exists is valid, however it was made".
#[serde(try_from = "ListenerConfigRaw")]
#[builder(on(String, into), finish_fn(vis = "", name = build_internal), builder_type(vis = "pub", doc {
    /// Builds a validated [`ListenerConfig`]. Every field has a documented package default, so a
    /// test or a dev run can build one with none of them set; a real deployment sets them all.
}))]
#[non_exhaustive]
pub struct ListenerConfig {
    /// The xUSDC faucet whose burn notes this listener watches.
    #[builder(default = default_faucet_id())]
    #[serde(with = "account_id_hex")]
    faucet_id: AccountId,

    /// The fixed, well-known **full-32-bit** xUSDC burn-note tag.
    ///
    /// `SyncNotes` matches tags by exact full-32-bit equality, **never by prefix** — the 16-bit
    /// prefix belongs to `SyncNullifiers`. A "use-case prefix + per-note payload" tag scheme
    /// expecting the node to prefix-scan it is a trap worth naming, so this is one `u32`, carried
    /// whole.
    #[builder(default = 0)]
    burn_tag: u32,

    /// Miden's remote domain, as Circle assigns it. Which domain id Circle assigns Miden, and the
    /// forwarding scope, are OPEN (`REQUIRES CIRCLE CONFIRMATION`) — the value is discovered from
    /// `GET /v1/info`, never assumed, and the default here is a placeholder.
    #[builder(default = 0)]
    miden_domain: u32,

    /// The largest `burnIntents[].maxFee` this deployment will sign for a withdrawal, in the same
    /// smallest-unit scale as the burn payload amount. The default is zero: unless an operator
    /// configures an explicit fee ceiling, a response that would let Circle take a withdrawal fee is
    /// refused before signing.
    #[builder(default = AssetAmount::ZERO)]
    #[serde(default = "default_max_withdrawal_fee", with = "asset_amount_u64")]
    max_withdrawal_fee: AssetAmount,

    /// Circle xReserve REST base URL. The documented testnet host is the default; production is a
    /// separate host ([`CIRCLE_MAINNET_BASE_URL`]). No credential is embedded.
    #[builder(default = default_circle_base_url())]
    circle_base_url: String,

    /// The attester keys, by handle. Circle requires `burnSignatures.len >= 2` on any
    /// `/v1/withdraw` submission, so production runs ≥2 — but the *count* is an operational
    /// property, enforced at quorum assembly (a later slice), not a shape this config can assert.
    #[builder(default)]
    #[serde(default)]
    attester_key_handles: Vec<AttesterKeyHandle>,

    /// The **registered attester addresses** — the off-chain mirror of Circle's on-chain
    /// `attesters[addr]` registry. The pre-submit fund-safety gate
    /// ([`authorize_submission`](crate::withdrawal_api::authorize_submission)) checks every
    /// recovered `burnSignatures` signer against this set BEFORE any `POST /v1/withdraw`: a
    /// signature from a key that is not a registered attester is refused off-chain, not left to
    /// Circle's source-chain `require(attesters[addr])` alone.
    ///
    /// The default is EMPTY, and that is deliberate — an empty allowlist makes the submit gate fail
    /// closed (it refuses to submit with an unbounded signer set) rather than authorize everything.
    /// A real deployment lists its attester addresses; a `[handle]` in `attester_key_handles` is a
    /// KMS identifier, NOT an address, so the two are distinct fields.
    #[builder(default)]
    #[serde(default, skip_serializing_if = "AttesterAllowlist::is_empty")]
    attester_allowlist: AttesterAllowlist,

    /// The optional out-of-band API auth token. NEVER hardcoded; `None` (the default) builds
    /// requests against the DOCUMENTED no-auth contract. The credential scheme itself is
    /// `REQUIRES CIRCLE CONFIRMATION`.
    #[serde(default)]
    api_auth_token: Option<SecretString>,

    /// The header name an out-of-band token is injected under — supplied by the OPERATOR, with **no
    /// package default**, because Circle has not documented an auth scheme.
    ///
    /// The OpenAPI declares no security scheme at all. A default here (this crate shipped
    /// `Authorization` once) does not merely pick a convention: it means that configuring a *token*
    /// silently SELECTS an undocumented scheme, which is exactly what Circle's documentation
    /// forbids — "do NOT invent an auth header". So a token without a header name is a
    /// configuration ERROR ([`ListenerError::AuthHeaderNameRequired`]), not an invitation to guess.
    /// When Circle answers, the operator writes the answer down; until then, nothing is presumed.
    ///
    /// With no token set, no auth header is sent at all and this value is irrelevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_auth_header: Option<String>,
}

/// The undecorated shape serde parses into, before `ListenerConfig::validate` runs. It exists so
/// `try_from` has somewhere to land — see the note on the derive above for why the direct derive
/// was a credential-disclosure path.
#[derive(Deserialize)]
struct ListenerConfigRaw {
    #[serde(default = "default_faucet_id", with = "account_id_hex")]
    faucet_id: AccountId,
    #[serde(default)]
    burn_tag: u32,
    #[serde(default)]
    miden_domain: u32,
    #[serde(default = "default_max_withdrawal_fee", with = "asset_amount_u64")]
    max_withdrawal_fee: AssetAmount,
    #[serde(default = "default_circle_base_url")]
    circle_base_url: String,
    #[serde(default)]
    attester_key_handles: Vec<AttesterKeyHandle>,
    #[serde(default)]
    attester_allowlist: AttesterAllowlist,
    #[serde(default)]
    api_auth_token: Option<SecretString>,
    #[serde(default)]
    api_auth_header: Option<String>,
}

impl TryFrom<ListenerConfigRaw> for ListenerConfig {
    type Error = ListenerError;

    fn try_from(raw: ListenerConfigRaw) -> Result<Self, Self::Error> {
        let config = Self {
            faucet_id: raw.faucet_id,
            burn_tag: raw.burn_tag,
            miden_domain: raw.miden_domain,
            max_withdrawal_fee: raw.max_withdrawal_fee,
            circle_base_url: raw.circle_base_url,
            attester_key_handles: raw.attester_key_handles,
            attester_allowlist: raw.attester_allowlist,
            api_auth_token: raw.api_auth_token,
            api_auth_header: raw.api_auth_header,
        };
        config.validate()?;
        Ok(config)
    }
}

fn default_circle_base_url() -> String {
    CIRCLE_TESTNET_BASE_URL.to_string()
}

fn default_faucet_id() -> AccountId {
    AccountId::from_hex(PLACEHOLDER_FAUCET_ID)
        .expect("the package-default placeholder faucet id is a valid account id")
}

fn default_max_withdrawal_fee() -> AssetAmount {
    AssetAmount::ZERO
}

impl Default for ListenerConfig {
    fn default() -> Self {
        ListenerConfig::builder()
            .build()
            .expect("the package-default config is valid by construction")
    }
}

impl<S: listener_config_builder::IsComplete> ListenerConfigBuilder<S> {
    /// Builds the config, validating it — the same `ListenerConfig::validate` serde runs.
    ///
    /// # Errors
    /// Every variant `ListenerConfig::validate` can return.
    pub fn build(self) -> Result<ListenerConfig, ListenerError> {
        let config = self.build_internal();
        config.validate()?;
        Ok(config)
    }
}

impl ListenerConfig {
    /// The config's invariants. ONE implementation, reached from BOTH construction paths (the
    /// builder and `Deserialize`), so neither can be the lenient one.
    ///
    /// None of the three is ceremony:
    ///
    /// * A base URL that cannot be parsed fails on the first Circle call — in production, at the
    ///   worst moment — instead of at startup.
    /// * An out-of-band key over a plaintext base URL is a credential DISCLOSED the first time the
    ///   service runs. Circle documents no auth scheme, so the key may ride under any header name at
    ///   all, and
    ///   no HTTP library's strip-on-redirect list of standard header names would cover it.
    /// * A key with no header name has nowhere documented to go. Guessing `Authorization` is
    ///   inventing the scheme.
    ///
    /// # Errors
    /// * [`ListenerError::BadBaseUrl`] — the base URL is not a usable `http`/`https` URL.
    /// * [`ListenerError::InsecureAuthTransport`] — a credential over a non-HTTPS base URL.
    /// * [`ListenerError::AuthHeaderNameRequired`] — a credential with no header name.
    fn validate(&self) -> Result<(), ListenerError> {
        let url = reqwest::Url::parse(&self.circle_base_url).map_err(|source| {
            ListenerError::BadBaseUrl {
                url: self.circle_base_url.clone(),
                source: Cause::new(source),
            }
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ListenerError::BadBaseUrl {
                url: self.circle_base_url.clone(),
                source: Cause::new(UnsupportedScheme(url.scheme().to_string())),
            });
        }

        if self.api_auth_token.is_some() {
            if url.scheme() != "https" {
                return Err(ListenerError::InsecureAuthTransport {
                    base_url: self.circle_base_url.clone(),
                });
            }
            if self.api_auth_header.is_none() {
                return Err(ListenerError::AuthHeaderNameRequired);
            }
        }

        Ok(())
    }
}

/// The cause behind a [`ListenerError::BadBaseUrl`] that parsed cleanly but named a scheme the
/// client cannot speak (`ftp://…`). `Url::parse` accepts it; this crate does not.
#[derive(Debug)]
struct UnsupportedScheme(String);

impl fmt::Display for UnsupportedScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported url scheme `{}` (expected http or https)",
            self.0
        )
    }
}

impl core::error::Error for UnsupportedScheme {}

impl ListenerConfig {
    /// The xUSDC faucet whose burn notes are watched.
    pub fn faucet_id(&self) -> AccountId {
        self.faucet_id
    }

    /// The fixed full-32-bit burn-note tag. Matched by EXACT equality — never a prefix.
    pub fn burn_tag(&self) -> u32 {
        self.burn_tag
    }

    /// Miden's Circle-assigned remote domain (which id Circle assigns is still OPEN).
    pub fn miden_domain(&self) -> u32 {
        self.miden_domain
    }

    /// The configured withdrawal fee ceiling, in smallest units. The default is zero, so fee-bearing
    /// responses are refused unless a deployment explicitly opts into a non-zero ceiling.
    pub fn max_withdrawal_fee(&self) -> AssetAmount {
        self.max_withdrawal_fee
    }

    /// The Circle xReserve REST base URL.
    pub fn circle_base_url(&self) -> &str {
        &self.circle_base_url
    }

    /// The configured attester key handles — identifiers only, never key material.
    pub fn attester_key_handles(&self) -> &[AttesterKeyHandle] {
        &self.attester_key_handles
    }

    /// The registered attester addresses the pre-submit fund-safety gate checks signers against. An
    /// EMPTY allowlist (the default) makes that gate fail closed.
    pub fn attester_allowlist(&self) -> &AttesterAllowlist {
        &self.attester_allowlist
    }

    /// The optional out-of-band API auth token (the scheme is still Circle's to confirm). `None` is
    /// the documented case,
    /// not an error.
    ///
    /// This EXPOSES the secret — the auth-header injection point needs the plaintext. It is the one
    /// deliberate exit; the token is a [`SecretString`] everywhere else, so no `Debug`/`Display` of
    /// this config, or of anything holding it, can print it.
    pub fn api_auth_token(&self) -> Option<&str> {
        self.api_auth_token.as_ref().map(SecretString::expose)
    }

    /// The header name an out-of-band token is injected under, if the operator named one. `None` is
    /// the default, and — while Circle documents no scheme — the only honest one: this crate names
    /// no
    /// header. The config invariant guarantees this is `Some` whenever a token is set.
    pub fn api_auth_header(&self) -> Option<&str> {
        self.api_auth_header.as_deref()
    }
}

/// `AccountId` has no serde impl of its own, so the config renders it the way an operator writes
/// it: the canonical hex (`0x` + 30 digits). Deserialization goes through `AccountId::from_hex`, so
/// a config file naming a malformed id FAILS TO LOAD rather than silently defaulting — a listener
/// watching the wrong faucet would see no burns at all.
mod account_id_hex {
    use super::*;

    pub fn serialize<S: Serializer>(id: &AccountId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&id.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<AccountId, D::Error> {
        let hex = String::deserialize(d)?;
        AccountId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

/// Serde for [`AssetAmount`] as a config-file `u64`. The type owns the upper bound, so an operator
/// cannot load a fee ceiling that the burn payload amount type itself cannot represent.
mod asset_amount_u64 {
    use super::*;

    pub fn serialize<S: Serializer>(amount: &AssetAmount, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(amount.as_u64())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<AssetAmount, D::Error> {
        let value = u64::deserialize(d)?;
        AssetAmount::new(value).map_err(serde::de::Error::custom)
    }
}
