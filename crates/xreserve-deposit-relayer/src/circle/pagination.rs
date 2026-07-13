//! Pagination for the batch poll (`CMP-D4`): the query the relayer sends, the `Link`-header cursors
//! Circle answers with, and the rule that keeps a broken header from silently ending a scan.
//!
//! # Malformed metadata is not a final page
//!
//! The forward scan terminates on `next == None`. That makes "no next link" a LOAD-BEARING signal —
//! and it is exactly why a `Link` header the relayer cannot parse must not be quietly discarded:
//! discarding it produces the same `next == None` as a legitimate final page, so a corrupted,
//! truncated, or hostile header would stop the relayer mid-stream. Attestations already published
//! would simply never be minted, and nothing would be logged — the silent drop §8.4 forbids.
//!
//! So the rule is: an **absent** `Link` header is the documented final page. A **present** one must
//! parse, must carry at least one relation the relayer understands, and — if it advertises `next` —
//! must carry a cursor that can actually advance the scan. Anything else is
//! [`RelayerError::BadPaginationMetadata`]: a typed rejection, logged and alerted.

use reqwest::Url;

use crate::error::RelayerError;

/// `pageSize` is documented as 1–1000 (`CIRCLE-API-SURFACE.md:57`).
const PAGE_SIZE_MIN: u16 = 1;
const PAGE_SIZE_MAX: u16 = 1000;

/// THE pagination cursor of one batch request — forward (`pageAfter`) or backward (`pageBefore`),
/// **never both**.
///
/// Circle's list-attestations endpoint is explicit: `pageAfter` must not be used with `pageBefore`,
/// and vice versa. A pair of independent `Option<String>` fields would let a caller build that
/// forbidden request — and a real endpoint may answer it with 400. An enum makes the invalid state
/// unrepresentable: there is one cursor slot, so setting either cursor replaces the other and no
/// request carrying both can exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageCursor {
    /// `pageAfter` — the forward cursor; the relayer's steady-state poll.
    After(String),
    /// `pageBefore` — the backward cursor; modeled for fidelity, unused by the forward poll.
    Before(String),
}

impl PageCursor {
    /// The wire parameter name (`pageAfter` / `pageBefore`) and its value.
    fn as_param(&self) -> (&'static str, &str) {
        match self {
            Self::After(cursor) => ("pageAfter", cursor),
            Self::Before(cursor) => ("pageBefore", cursor),
        }
    }
}

/// The FULL documented query surface of `GET /v1/remote-domains/{remoteDomain}/attestations`:
/// `pageSize` (1–1000), `pageAfter` (base64 cursor), `pageBefore` (base64 cursor), `from`
/// (ISO-8601), `to` (ISO-8601) — `CIRCLE-API-SURFACE.md:57`,`:94`.
///
/// All five are modeled even though the relayer's steady-state forward poll ([`Self::forward`]) sets
/// only `pageSize` + `pageAfter`. `from`/`to`/`pageBefore` are INTENTIONALLY UNUSED by that poll, and
/// modeling them anyway is the point: the type and the mock fixtures cover the whole documented
/// surface, so a fixture cannot quietly drift away from the OpenAPI and a later slice that needs a
/// bounded window does not have to re-derive the parameter names.
///
/// The two cursors share ONE slot ([`PageCursor`]) because Circle forbids sending them together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchQuery {
    page_size: u16,
    cursor: Option<PageCursor>,
    from: Option<String>,
    to: Option<String>,
}

impl BatchQuery {
    /// A query with only `pageSize` set.
    ///
    /// # Errors
    /// [`RelayerError::BadPageSize`] — `page_size` outside the documented `1..=1000`. Validated here,
    /// in the constructor, so an out-of-range page size cannot reach the wire (a 400 the relayer
    /// would have earned for itself).
    pub fn new(page_size: u16) -> Result<Self, RelayerError> {
        if !(PAGE_SIZE_MIN..=PAGE_SIZE_MAX).contains(&page_size) {
            return Err(RelayerError::BadPageSize { actual: page_size });
        }

        Ok(Self {
            page_size,
            cursor: None,
            from: None,
            to: None,
        })
    }

    /// THE steady-state poll shape: forward-only, `pageSize` + an optional `pageAfter` cursor (the
    /// persisted last-cursor). Leaves `pageBefore`/`from`/`to` unset by design.
    ///
    /// # Errors
    /// [`RelayerError::BadPageSize`] — as [`Self::new`].
    pub fn forward(page_size: u16, page_after: Option<&str>) -> Result<Self, RelayerError> {
        let query = Self::new(page_size)?;

        Ok(match page_after {
            Some(cursor) => query.with_page_after(cursor),
            None => query,
        })
    }

    /// Sets `pageAfter` (the forward cursor), REPLACING any `pageBefore` — the two are mutually
    /// exclusive on this endpoint, so one request can carry only one of them.
    #[must_use]
    pub fn with_page_after(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(PageCursor::After(cursor.into()));
        self
    }

    /// Sets `pageBefore` (the backward cursor), REPLACING any `pageAfter` — see
    /// [`Self::with_page_after`].
    #[must_use]
    pub fn with_page_before(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(PageCursor::Before(cursor.into()));
        self
    }

    /// Sets `from` (ISO-8601 — modeled for fidelity; unused by the forward poll).
    #[must_use]
    pub fn with_from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Sets `to` (ISO-8601 — modeled for fidelity; unused by the forward poll).
    #[must_use]
    pub fn with_to(mut self, to: impl Into<String>) -> Self {
        self.to = Some(to.into());
        self
    }

    pub fn page_size(&self) -> u16 {
        self.page_size
    }

    /// The cursor this request carries, if any — at most one, by construction.
    pub fn cursor(&self) -> Option<&PageCursor> {
        self.cursor.as_ref()
    }

    /// The `pageAfter` cursor — `None` if the query carries a `pageBefore` (or no cursor).
    pub fn page_after(&self) -> Option<&str> {
        match &self.cursor {
            Some(PageCursor::After(cursor)) => Some(cursor),
            _ => None,
        }
    }

    /// The `pageBefore` cursor — `None` if the query carries a `pageAfter` (or no cursor).
    pub fn page_before(&self) -> Option<&str> {
        match &self.cursor {
            Some(PageCursor::Before(cursor)) => Some(cursor),
            _ => None,
        }
    }

    pub fn from(&self) -> Option<&str> {
        self.from.as_deref()
    }

    pub fn to(&self) -> Option<&str> {
        self.to.as_deref()
    }

    /// The query as wire parameters, under their EXACT OpenAPI names. An unset optional param is
    /// omitted entirely — never sent as an empty string, which is a different request. At most ONE
    /// cursor appears, because at most one exists.
    pub(crate) fn query_params(&self) -> Vec<(&'static str, String)> {
        let mut params = vec![("pageSize", self.page_size.to_string())];
        if let Some(cursor) = &self.cursor {
            let (name, value) = cursor.as_param();
            params.push((name, value.to_string()));
        }
        for (name, value) in [("from", &self.from), ("to", &self.to)] {
            if let Some(value) = value {
                params.push((name, value.clone()));
            }
        }
        params
    }
}

/// One `Link`-header relation: the href Circle returned, and the pagination cursor extracted from it.
///
/// Both are kept deliberately. The relayer PERSISTS the cursor (`pageAfter`/`pageBefore` — an opaque
/// base64 token) as its restart point, so it must be able to hand back the token itself, not a URL.
/// But an href with no cursor (`rel="first"`) is still a real link, and collapsing it to `None` would
/// lose the fact that the relation exists at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageLink {
    href: String,
    cursor: Option<String>,
}

impl PageLink {
    pub(crate) fn new(href: String, cursor: Option<String>) -> Self {
        Self { href, cursor }
    }

    /// The link target, as Circle sent it.
    pub fn href(&self) -> &str {
        &self.href
    }

    /// The pagination cursor carried in the href's `pageAfter` / `pageBefore` query param, if any —
    /// the value to feed back into the next [`BatchQuery`] and to persist as the last-cursor.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}

/// The four `Link`-header relations Circle documents: `self`, `first`, `next`, `prev`
/// (`CIRCLE-API-SURFACE.md:58`). Absent relations are `None` — and `next == None` is what TERMINATES
/// a forward scan, which is why a header that cannot be parsed is an ERROR rather than an empty
/// `PageCursors` (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PageCursors {
    self_: Option<PageLink>,
    first: Option<PageLink>,
    next: Option<PageLink>,
    prev: Option<PageLink>,
}

impl PageCursors {
    pub fn self_(&self) -> Option<&PageLink> {
        self.self_.as_ref()
    }

    pub fn first(&self) -> Option<&PageLink> {
        self.first.as_ref()
    }

    pub fn next(&self) -> Option<&PageLink> {
        self.next.as_ref()
    }

    pub fn prev(&self) -> Option<&PageLink> {
        self.prev.as_ref()
    }

    /// The forward cursor: the `pageAfter` token of the `next` link. `None` means the scan is
    /// complete — the caller stops (§8.2 pagination boundary).
    pub fn next_cursor(&self) -> Option<&str> {
        self.next.as_ref().and_then(PageLink::cursor)
    }
}

/// Parses a PRESENT `Link` header into the four documented relations.
///
/// `<https://…/attestations?pageSize=2&pageAfter=Y3Vyc29yLTI%3D>; rel="next", <…>; rel="self"`
///
/// Each href yields its pagination CURSOR — the `pageAfter` (or `pageBefore`) query param — which is
/// what the relayer feeds back and persists; the href is kept alongside it. A relative href is
/// resolved against the client's base URL (RFC 8288 permits one, and a parser that only handled
/// absolute URLs would silently lose the cursor).
///
/// # Errors
/// [`RelayerError::BadPaginationMetadata`] — the header does not parse, an href is not a URL, the
/// header carries no relation the relayer understands, or it advertises `next` without a cursor the
/// scan could follow. Every one of these would otherwise degrade into "no next link" — i.e. into a
/// silently truncated scan (see the module docs). An ABSENT header is not this function's business:
/// the caller treats it as the terminal page.
pub(crate) fn parse_link_header(header: &str, base: &Url) -> Result<PageCursors, RelayerError> {
    let entries = split_links(header);
    if entries.is_empty() {
        return Err(malformed("the Link header is present but empty"));
    }

    let mut cursors = PageCursors::default();
    let mut recognized = 0usize;

    for entry in entries {
        let (href, rel) = parse_link_entry(&entry)
            .ok_or_else(|| malformed(format!("cannot parse the Link entry `{entry}`")))?;
        let url = resolve(&href, base)
            .ok_or_else(|| malformed(format!("the Link href `{href}` is not a url")))?;
        let link = PageLink::new(href, cursor_of(&url));

        match rel.as_str() {
            "self" => cursors.self_ = Some(link),
            "first" => cursors.first = Some(link),
            "prev" => cursors.prev = Some(link),
            "next" => {
                if link.cursor().is_none() {
                    // it says there are more pages and gives us no way to reach them: treating that
                    // as the end of the scan would strand every page after this one
                    return Err(malformed(format!(
                        "the `next` link `{}` carries no pageAfter/pageBefore cursor — the scan \
                         cannot advance",
                        link.href()
                    )));
                }
                cursors.next = Some(link);
            }
            // an unrecognized relation is not itself an error — but a header made of nothing else is
            _ => continue,
        }
        recognized += 1;
    }

    if recognized == 0 {
        return Err(malformed(
            "the Link header carries no relation the relayer understands (self/first/next/prev)",
        ));
    }

    Ok(cursors)
}

fn malformed(detail: impl Into<String>) -> RelayerError {
    RelayerError::BadPaginationMetadata {
        detail: detail.into(),
    }
}

/// Splits a `Link` header on the commas that separate ENTRIES — not on the commas that may appear
/// inside an `<href>` (a query value can legally contain one).
fn split_links(header: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut current = String::new();
    let mut in_angle = false;

    for character in header.chars() {
        match character {
            '<' => {
                in_angle = true;
                current.push(character);
            }
            '>' => {
                in_angle = false;
                current.push(character);
            }
            ',' if !in_angle => entries.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        entries.push(current);
    }

    entries.retain(|entry| !entry.trim().is_empty());
    entries
}

/// One `Link` entry → `(href, rel)`.
fn parse_link_entry(entry: &str) -> Option<(String, String)> {
    let entry = entry.trim();
    let open = entry.find('<')?;
    let close = entry[open..].find('>')? + open;
    let href = entry[open + 1..close].trim().to_string();

    let rel = entry[close..]
        .split(';')
        .filter_map(|parameter| {
            let (name, value) = parameter.split_once('=')?;
            (name.trim().eq_ignore_ascii_case("rel"))
                .then(|| value.trim().trim_matches('"').trim().to_ascii_lowercase())
        })
        .next()?;

    Some((href, rel))
}

/// An absolute href, or a relative one resolved against the client's base URL.
fn resolve(href: &str, base: &Url) -> Option<Url> {
    Url::parse(href).or_else(|_| base.join(href)).ok()
}

/// The pagination cursor inside a link href: its `pageAfter` (else `pageBefore`) query param,
/// percent-decoded by the URL parser.
fn cursor_of(url: &Url) -> Option<String> {
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();

    ["pageAfter", "pageBefore"].iter().find_map(|wanted| {
        pairs
            .iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value.clone())
    })
}
