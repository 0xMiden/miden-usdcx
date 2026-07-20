//! Schema-exact Circle response bodies (`CIRCLE-API-SURFACE.md`).
//!
//! Every body here is built to the exact OpenAPI shape — in particular the by-`depositMessageHash`
//! endpoint's **wrapper** (`{"attestation": {...}}`, live OpenAPI YAML L391–398) versus the
//! `?txHash=` and `/v1/remote-domains/{d}/attestations` **list** shapes (`{"attestations": [...]}`),
//! and camelCase wire keys (`messageHash`, `remoteDomain`, `pageSize`, `pageAfter`, …). A divergent
//! fixture is a defect: it would let a wrong decoder pass, which is the one thing a contract test
//! exists to prevent.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

use serde_json::{json, Value};

use crate::fixtures::AttestationVector;

/// The Miden remote domain used by the fixtures. **Placeholder — `Q-DOM-1` is OPEN (`REQUIRES
/// CIRCLE CONFIRMATION`)**: Circle has not assigned Miden a domain id. A fixture value, never a
/// settled decision.
pub const FIXTURE_MIDEN_DOMAIN: u32 = 10001;

/// The xUSDC remote-token identifier used by the fixtures. **Placeholder — `DEV-10` is OPEN
/// (`REQUIRES CIRCLE CONFIRMATION`)**: the AccountId↔bytes32 encoding is not settled.
pub const FIXTURE_XUSDC_IDENTIFIER: &str =
    "0x00000000000000000000000000000000000000000000000000000000c0ffee01";

/// The `AttestationObject` — `{payload, messageHash, attestation}`, camelCase, `0x`-hex
/// (CIRCLE-API-SURFACE.md:44). The inner object of the by-hash wrapper and the element of both list
/// shapes.
pub fn attestation_object(vector: &AttestationVector) -> Value {
    json!({
        "payload": vector.payload_hex(),
        "messageHash": vector.message_hash_hex(),
        "attestation": vector.attestation_hex(),
    })
}

/// `GET /v1/attestations/{depositMessageHash}` — the WRAPPER: the attestation object nested under a
/// top-level `attestation` key. ONLY this endpoint is wrapped.
pub fn by_hash_wrapper(vector: &AttestationVector) -> Value {
    json!({ "attestation": attestation_object(vector) })
}

/// The by-hash wrapper with exactly one field of the INNER object mutated. Every malformed fixture
/// is produced this way — it differs from the valid body in exactly the one way its case name
/// states, so a rejection can only be attributed to that field.
pub fn wrapper_with(vector: &AttestationVector, mutate: impl FnOnce(&mut Value)) -> Value {
    let mut object = attestation_object(vector);
    mutate(&mut object);
    json!({ "attestation": object })
}

/// `GET /v1/attestations?txHash=` — a LIST (no wrapper) whose elements carry `remoteDomain` (≥ 1)
/// in addition to the three attestation fields (CIRCLE-API-SURFACE.md:51).
pub fn by_tx_hash_list(items: &[(&AttestationVector, u32)]) -> Value {
    let attestations: Vec<Value> = items
        .iter()
        .map(|(vector, remote_domain)| {
            let mut object = attestation_object(vector);
            object["remoteDomain"] = json!(remote_domain);
            object
        })
        .collect();
    json!({ "attestations": attestations })
}

/// `GET /v1/remote-domains/{remoteDomain}/attestations` — a LIST (no wrapper, no `remoteDomain` on
/// the elements); pagination travels in the `Link` header (CIRCLE-API-SURFACE.md:58).
pub fn attestation_page(items: &[&AttestationVector]) -> Value {
    let attestations: Vec<Value> = items.iter().map(|v| attestation_object(v)).collect();
    json!({ "attestations": attestations })
}

/// A `Link` header, RFC-8288 form, as the batch endpoint returns it:
/// `<{base}/…?pageAfter=…>; rel="next", <…>; rel="self"`. `{base}` is substituted with the mock's
/// origin when the response is served.
pub fn link_header(rels: &[(&str, &str)]) -> String {
    rels.iter()
        .map(|(rel, href)| format!("<{href}>; rel=\"{rel}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A batch-endpoint href for the `Link` header, with an optional cursor query param.
pub fn batch_href(
    remote_domain: u32,
    page_size: u16,
    cursor_param: Option<(&str, &str)>,
) -> String {
    match cursor_param {
        Some((name, value)) => format!(
            "{{base}}/v1/remote-domains/{remote_domain}/attestations?pageSize={page_size}&{name}={value}"
        ),
        None => {
            format!("{{base}}/v1/remote-domains/{remote_domain}/attestations?pageSize={page_size}")
        }
    }
}

/// [`info_body`], advertising an arbitrary remote domain + xUSDC identifier — so a test can point
/// discovery at the domain/token a fixture DepositIntent actually carries. Both values are
/// placeholders (`Q-DOM-1` / `DEV-10` are OPEN — `REQUIRES CIRCLE CONFIRMATION`); parameterizing
/// them is what keeps a fixture from reading as a settled assignment.
pub fn info_body_for(remote_domain: u32, xusdc_identifier_hex: &str) -> Value {
    let mut body = info_body();
    body["remoteDomains"][0]["domain"] = json!(remote_domain);
    body["remoteDomains"][0]["tokens"][0]["remoteTokenIdentifier"] = json!(xusdc_identifier_hex);
    body
}

/// `GET /v1/info` — `sourceDomains[]` + `remoteDomains[]` with the exact nested token shape
/// (CIRCLE-API-SURFACE.md:30).
pub fn info_body() -> Value {
    json!({
        "sourceDomains": [
            {
                "chain": "Ethereum",
                "network": "testnet",
                "domain": 0,
                "contractAddress": "0x0000000000000000000000000000000000001234",
                "tokens": ["USDC"],
            }
        ],
        "remoteDomains": [
            {
                "chain": "Miden",
                "network": "devnet",
                "domain": FIXTURE_MIDEN_DOMAIN,
                "tokens": [
                    {
                        "remoteToken": "xUSDC",
                        "remoteTokenIdentifier": FIXTURE_XUSDC_IDENTIFIER,
                        "associatedNativeToken": "USDC",
                    }
                ],
            }
        ],
    })
}
