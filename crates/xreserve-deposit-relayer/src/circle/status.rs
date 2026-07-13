//! The HTTP-status policy (§8.1 check 1, §8.4) — stated once, for the whole relayer.
//!
//! | status | class | behavior |
//! |---|---|---|
//! | 2xx | [`StatusClass::Success`] | proceed to decode |
//! | 404 | [`StatusClass::RetryPending`] | Circle has not published the attestation *yet* → back off and retry; log `Pending`; alert only if the attempts run out |
//! | 429 | [`StatusClass::RetryThrottle`] | throttled → back off and retry under the same ceilings |
//! | 5xx | [`StatusClass::RetryAlert`] | Circle is unhealthy → back off and retry; ALERT once the threshold is crossed |
//! | everything else — 400, every other 4xx, **and every 3xx** | [`StatusClass::Reject`] | permanent → reject, **NO retry**, alert |
//!
//! Two consequences worth naming.
//!
//! **No error body is ever parsed.** The OpenAPI documents status codes only — it defines no
//! error-body schema — so the status alone decides, and a 400 whose body is an HTML proxy page is
//! handled identically to one whose body is JSON. Inventing a schema for it would be fiction.
//!
//! **A redirect is a rejection, not a hop.** The relayer does not follow redirects (the production
//! transport is built with `redirect::Policy::none()`), so a 3xx arrives here and is refused. That is
//! deliberate: following one would re-issue the request at an origin the PEER chose, carrying the
//! credential with it — and since `Q-API-AUTH` is OPEN, that credential may ride in a header of any
//! name, which no HTTP stack's cross-origin strip list covers. Circle's documented API redirects
//! nowhere, so nothing legitimate is lost.

/// What a Circle HTTP status means for the relayer. See the module table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// 2xx — proceed.
    Success,
    /// 404 — the attestation is not published yet. Retry; log `Pending`; do not alert until the
    /// attempts are exhausted (a just-landed deposit is *expected* to 404 for a while).
    RetryPending,
    /// 429 — throttled. Retry under the same ceilings.
    RetryThrottle,
    /// 5xx — Circle is unhealthy. Retry, and alert once the threshold is crossed.
    RetryAlert,
    /// Every other status (400 and every 3xx included) — permanent. Reject, do not retry, alert.
    Reject,
}

/// Classifies an HTTP status. THE retry decision for the whole relayer, so no call site can invent
/// its own.
pub fn classify_status(status: u16) -> StatusClass {
    match status {
        200..=299 => StatusClass::Success,
        404 => StatusClass::RetryPending,
        429 => StatusClass::RetryThrottle,
        500..=599 => StatusClass::RetryAlert,
        _ => StatusClass::Reject,
    }
}
