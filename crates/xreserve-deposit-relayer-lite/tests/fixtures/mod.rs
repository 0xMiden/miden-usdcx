//! Shared test fixtures for Circle response decoding.

use xreserve_deposit_relayer_lite::circle::Attestation;

/// Encodes these attestations as a Circle list response body.
pub fn page_body(attestations: &[Attestation]) -> Vec<u8> {
    let items: Vec<_> = attestations
        .iter()
        .map(|attestation| {
            serde_json::json!({
                "payload": attestation.payload,
                "messageHash": attestation.message_hash,
                "attestation": attestation.attestation,
            })
        })
        .collect();

    serde_json::json!({ "attestations": items })
        .to_string()
        .into_bytes()
}

/// Builds a `Link` header carrying the next cursor.
pub fn next_link(cursor: &str) -> String {
    format!(
        "<https://circle.test/v1/remote-domains/1/attestations?pageSize=100&pageAfter={cursor}>; rel=\"next\""
    )
}

/// A syntactically valid wire attestation whose fields are arbitrary hex.
pub fn wire_attestation(seed: u8) -> Attestation {
    Attestation {
        payload: format!("0x{}", hex_bytes(&[seed; 8])),
        message_hash: format!("0x{}", hex_bytes(&[seed; 32])),
        attestation: format!("0x{}", hex_bytes(&[seed; 65])),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
