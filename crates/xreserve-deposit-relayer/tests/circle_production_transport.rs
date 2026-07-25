//! `tests/circle_production_transport.rs` — the two behaviors that live INSIDE the production
//! transport, bound to tests that a regression cannot survive.
//!
//! Both were previously shadowed by the mock: the contract suite installs `MockTransport`, so a
//! change to `ReqwestTransport`'s body-streaming loop, or to the redirect policy the production
//! `reqwest::Client` is built with, left every test green. That is over-mocking, and it is exactly
//! where a memory-exhaustion lever and a credential-exfiltration path would hide.
//!
//! **Why not just drive the real client at a real server?** Because it cannot be done here: this
//! sandbox denies `bind()` (`EPERM`), so no listener — TCP or Unix — can exist, and reqwest offers no
//! way to hand it a connection (`connect::Conn` is sealed; `redirect::Attempt` cannot be
//! constructed). The answer is not to fake the behavior in a test but to move it out of the
//! unreachable layer:
//!
//! * the response-size ceiling is now enforced by [`collect_bounded`] over an **injectable**
//!   [`ChunkSource`] — the same function the production transport streams through — so a test feeds
//!   it a hostile body (endless, or with a lying `Content-Length`) and asserts it stops READING, not
//!   merely that it rejects afterwards;
//! * the redirect decision is now a named seam ([`RedirectPolicy`]) whose reqwest value is asserted,
//!   and the transport additionally refuses any response whose final URL is not the one it requested
//!   ([`check_not_redirected`]) — so a policy regression fails closed instead of silently following a
//!   peer's `Location` with the credential attached.
//!
//! What remains outside these tests is the adapter that pulls chunks out of a `reqwest::Response`:
//! plumbing with no policy in it.

use std::future::Future;
use std::pin::Pin;

use assert_matches::assert_matches;
use reqwest::Url;
use rstest::rstest;

use xreserve_deposit_relayer::circle::{
    check_not_redirected, collect_bounded, ChunkSource, RedirectPolicy,
};
use xreserve_deposit_relayer::error::{Cause, RelayerError};

// A SCRIPTED BODY STREAM — the shape a hostile peer sends
// ================================================================================================

/// A chunk source under the test's control. It counts what the collector actually PULLED, which is
/// the property under test: an oversized body must be stopped mid-read, not buffered and then
/// rejected. A collector that drained this source would have already allocated the memory the
/// ceiling exists to deny it.
struct ScriptedBody {
    /// Chunks still to hand out.
    remaining: Vec<Vec<u8>>,
    /// What `Content-Length` claims — possibly a lie, possibly absent.
    advertised: Option<u64>,
    /// How many chunks the collector pulled.
    pulls: usize,
    /// A transport failure to raise instead of the next chunk.
    fail_after: Option<usize>,
}

impl ScriptedBody {
    fn new(chunks: Vec<Vec<u8>>, advertised: Option<u64>) -> Self {
        Self {
            remaining: chunks,
            advertised,
            pulls: 0,
            fail_after: None,
        }
    }

    /// `count` chunks of `size` bytes each.
    fn of(count: usize, size: usize, advertised: Option<u64>) -> Self {
        Self::new(vec![vec![b'x'; size]; count], advertised)
    }

    fn failing_after(mut self, pulls: usize) -> Self {
        self.fail_after = Some(pulls);
        self
    }

    fn pulls(&self) -> usize {
        self.pulls
    }

    fn undrained(&self) -> usize {
        self.remaining.len()
    }
}

impl ChunkSource for ScriptedBody {
    fn advertised_len(&self) -> Option<u64> {
        self.advertised
    }

    fn next_chunk(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, RelayerError>> + Send + '_>> {
        Box::pin(async move {
            if self.fail_after == Some(self.pulls) {
                return Err(RelayerError::Transport(Cause::new(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "connection reset mid-body",
                ))));
            }
            if self.remaining.is_empty() {
                return Ok(None);
            }
            self.pulls += 1;
            Ok(Some(self.remaining.remove(0)))
        })
    }
}

// THE RESPONSE-SIZE CEILING — enforced while READING, not after
// ================================================================================================

/// The requirement is to stop an oversized response **before collecting it**. A body with no
/// `Content-Length` (chunked transfer encoding — what an attacker sends) can only be stopped by
/// checking as it streams.
///
/// So this asserts more than "an oversized body is rejected": it asserts the collector STOPPED
/// PULLING once the ceiling was crossed, and left the rest of the body unread. A collector that
/// buffered everything and rejected afterwards would have already made the allocation.
#[tokio::test]
async fn collect_bounded_stops_reading_once_the_ceiling_is_crossed() {
    const CEILING: usize = 512;
    const CHUNK: usize = 64;
    // 200 × 64 B = 12,800 bytes of body behind a 512-byte ceiling, and no Content-Length to warn us
    let mut body = ScriptedBody::of(200, CHUNK, None);

    let err = collect_bounded(&mut body, CEILING)
        .await
        .expect_err("the body is 25x the ceiling");

    assert_matches!(err, RelayerError::ResponseTooLarge { limit: CEILING, actual } => {
        assert!(actual > CEILING, "the observed size is reported: {actual}");
        assert!(
            actual <= CEILING + CHUNK,
            "it stopped at the chunk that crossed the line, having buffered {actual} bytes — not the \
             whole 12,800-byte body"
        );
    });

    // the collector STOPPED READING: it pulled only enough chunks to cross the ceiling
    let ceiling_in_chunks = CEILING / CHUNK + 1; // 9
    assert_eq!(
        body.pulls(),
        ceiling_in_chunks,
        "it must stop pulling the moment the ceiling is crossed"
    );
    assert!(
        body.undrained() > 100,
        "most of the body was never read — {} chunks left unread",
        body.undrained()
    );
}

/// A `Content-Length` that lies. The pre-check waves it through, so the only thing standing between
/// the relayer and the real (huge) body is the per-chunk accounting.
#[tokio::test]
async fn collect_bounded_rejects_a_body_whose_content_length_lied() {
    const CEILING: usize = 512;
    // claims 10 bytes, sends 8 KiB
    let mut body = ScriptedBody::of(128, 64, Some(10));

    let err = collect_bounded(&mut body, CEILING)
        .await
        .expect_err("the advertised length was a lie; the ceiling still holds");

    assert_matches!(err, RelayerError::ResponseTooLarge { limit: CEILING, .. });
    assert!(
        body.pulls() <= CEILING / 64 + 1,
        "it stopped mid-stream rather than trusting the advertised length"
    );
    assert!(body.undrained() > 100);
}

/// An honest `Content-Length` over the ceiling is refused before a single byte is read — no
/// allocation at all.
#[tokio::test]
async fn collect_bounded_rejects_an_advertised_oversize_without_reading_a_byte() {
    let mut body = ScriptedBody::of(200, 64, Some(12_800));

    let err = collect_bounded(&mut body, 512)
        .await
        .expect_err("advertised 12,800 bytes against a 512-byte ceiling");

    assert_matches!(
        err,
        RelayerError::ResponseTooLarge {
            limit: 512,
            actual: 12_800
        }
    );
    assert_eq!(
        body.pulls(),
        0,
        "an advertised oversize is refused BEFORE the body is read"
    );
}

/// The ceiling rejects the oversized, not the merely large: a body of exactly the ceiling's size is
/// collected in full.
#[rstest]
#[case::exactly_at_the_ceiling(8, 64, 512)]
#[case::one_chunk_short(7, 64, 512)]
#[case::single_byte_body(1, 1, 512)]
#[tokio::test]
async fn collect_bounded_accepts_a_body_within_the_ceiling(
    #[case] chunks: usize,
    #[case] size: usize,
    #[case] ceiling: usize,
) {
    let expected = chunks * size;
    let mut body = ScriptedBody::of(chunks, size, Some(expected as u64));

    let collected = collect_bounded(&mut body, ceiling)
        .await
        .expect("a body within the ceiling is collected in full");

    assert_eq!(collected.len(), expected);
    assert_eq!(body.pulls(), chunks, "every chunk was read");
    assert_eq!(body.undrained(), 0);
}

/// A body that dies mid-read surfaces as the transport error it is — not as an oversize, and not as
/// a truncated success (a half-read body silently returned would decode into nonsense, or worse,
/// into a valid-looking prefix).
#[tokio::test]
async fn collect_bounded_propagates_a_stream_failure() {
    let mut body = ScriptedBody::of(10, 64, Some(640)).failing_after(3);

    let err = collect_bounded(&mut body, 4096)
        .await
        .expect_err("the connection died mid-body");

    assert_matches!(err, RelayerError::Transport(_));
    assert!(err.is_retryable(), "a broken read is transient");
}

/// An empty body is fine (a 204, or a 200 with nothing in it).
#[tokio::test]
async fn collect_bounded_accepts_an_empty_body() {
    let mut body = ScriptedBody::new(Vec::new(), Some(0));
    assert!(collect_bounded(&mut body, 512)
        .await
        .expect("an empty body is not an error")
        .is_empty());
}

// REDIRECTS — the production policy, and the transport's fail-closed backstop
// ================================================================================================

/// The value the production `reqwest::Client` is actually built with. A redirect is the cheapest way
/// to move a credential to an origin that should not have it: the client re-issues the request at the
/// `Location` the PEER chose, and reqwest strips only a fixed set of standard header names on a
/// cross-origin hop (`Authorization`, `Cookie`, `Proxy-Authorization`, `WWW-Authenticate`).
/// `Q-API-AUTH` is OPEN, so the relayer's credential header may be called anything at all
/// (`X-Circle-Api-Key`, …) — a name that list does not cover. So the relayer follows NO redirect, and
/// this pins the policy object itself: `Policy::limited(n)` (or reqwest's default, which follows up
/// to 10) renders differently and fails here.
#[test]
fn the_production_redirect_policy_follows_nothing() {
    let rendered = format!("{:?}", RedirectPolicy::Never.to_reqwest());

    assert_eq!(
        rendered, "Policy(None)",
        "the client must be built with reqwest's no-follow policy, not a limited/default one that \
         would carry the credential to a peer-chosen origin: got {rendered}"
    );
    assert!(!rendered.contains("Limit"));
}

/// The policy is used in exactly one place, and nothing else builds an HTTP client — so a redirect
/// policy cannot be reintroduced by a second `Client::builder()` somewhere else in the crate, and the
/// call site cannot quietly inline a different policy than the one asserted above.
#[test]
fn the_crate_builds_exactly_one_http_client_and_it_takes_the_no_redirect_policy() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut builders = 0usize;
    let mut redirect_calls: Vec<String> = Vec::new();

    for file in rust_sources(&src) {
        let text = std::fs::read_to_string(&file).expect("readable source");
        builders += text.matches("reqwest::Client::builder()").count();
        for line in text.lines() {
            if let Some(index) = line.find(".redirect(") {
                redirect_calls.push(line[index..].trim().to_string());
            }
        }
    }

    assert_eq!(
        builders, 1,
        "exactly one reqwest client is built in this crate (found {builders}) — a second one could \
         carry a different redirect policy"
    );
    assert_eq!(
        redirect_calls.len(),
        1,
        "one redirect policy, one call site"
    );
    assert!(
        redirect_calls[0].starts_with(".redirect(RedirectPolicy::Never.to_reqwest())"),
        "the client must take THE pinned policy, not an inline one: {}",
        redirect_calls[0]
    );
}

/// The fail-closed backstop. `Policy::none()` is what PREVENTS a redirect being followed; this is
/// what happens if that policy is ever weakened: the transport compares the URL it asked for with the
/// URL the response actually came from (`reqwest::Response::url()` is the FINAL url, after any
/// redirect chain) and refuses anything that moved. The relayer then rejects and alerts instead of
/// trusting a body served by an origin it never chose.
#[rstest]
#[case::same_url(
    "https://xreserve-api.circle.com/v1/info",
    "https://xreserve-api.circle.com/v1/info",
    true
)]
#[case::different_host(
    "https://xreserve-api.circle.com/v1/info",
    "https://not-circle.example/v1/info",
    false
)]
#[case::different_scheme(
    "https://xreserve-api.circle.com/v1/info",
    "http://xreserve-api.circle.com/v1/info",
    false
)]
#[case::different_path(
    "https://xreserve-api.circle.com/v1/info",
    "https://xreserve-api.circle.com/v1/elsewhere",
    false
)]
#[case::different_query(
    "https://xreserve-api.circle.com/v1/attestations?txHash=0x01",
    "https://xreserve-api.circle.com/v1/attestations?txHash=0x02",
    false
)]
fn a_response_that_came_from_a_url_we_did_not_request_is_refused(
    #[case] requested: &str,
    #[case] responded: &str,
    #[case] accepted: bool,
) {
    let requested = Url::parse(requested).expect("valid url");
    let responded = Url::parse(responded).expect("valid url");

    let result = check_not_redirected(&requested, &responded);

    if accepted {
        result.expect("the response came from exactly the url that was requested");
    } else {
        assert_matches!(
            result.expect_err("the response came from somewhere else — a redirect was followed"),
            RelayerError::RedirectFollowed { .. }
        );
    }
}

/// The backstop is a permanent rejection, not a retry: re-issuing the request would just be
/// redirected again, and each attempt is another chance for the credential to land somewhere it
/// should not.
#[test]
fn a_followed_redirect_is_permanent_and_never_retried() {
    let error = RelayerError::RedirectFollowed {
        requested: "https://xreserve-api.circle.com/v1/info".to_string(),
        followed: "https://not-circle.example/v1/info".to_string(),
    };

    assert!(!error.is_retryable());
    let rendered = error.to_string();
    assert!(
        rendered.contains("not-circle.example"),
        "the operator must see WHERE the response came from: {rendered}"
    );
}

fn rust_sources(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("src/ is readable") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}
