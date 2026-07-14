//! (shared across test targets — each uses a subset, hence the allow)
#![allow(dead_code)]

//! Shared test support: the fixture loader and the OpenAPI pattern predicates.
//!
//! The predicates are hand-rolled rather than pulled from a regex crate — the patterns in
//! `CIRCLE-API-SURFACE.md` are simple enough to express directly, and a new dependency would have to
//! clear the offline-cache gate for no gain. Each one names the exact OpenAPI pattern it enforces, so
//! a reader can diff it against the schema table without leaving the file.

use std::path::PathBuf;

use serde_json::Value;

/// Every fixture in `tests/fixtures/`, by stem. The count is pinned by `fixture_fidelity.rs`: 13 —
/// 3 happy-path + 10 error/malformed (§11.2).
pub const HAPPY_PATH_FIXTURES: [&str; 3] = [
    "prepare_withdrawal_200",
    "withdraw_201",
    "withdrawal_status_200",
];

pub const ERROR_FIXTURES: [&str; 10] = [
    "prepare_withdrawal_400",
    "prepare_withdrawal_validation_mismatch",
    "prepare_withdrawal_missing_hash",
    "withdraw_400",
    "withdraw_409",
    "withdraw_500",
    "withdraw_failed_status",
    "withdrawal_status_404",
    "withdraw_threshold_violating_sigs",
    "malformed_body",
];

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// The fixture's raw text, exactly as it sits on disk.
pub fn fixture_text(stem: &str) -> String {
    let path = fixtures_dir().join(format!("{stem}.json"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The fixture parsed as untyped JSON — what the fidelity sweep checks the schema against, and the
/// comparand a round-trip is judged by.
pub fn fixture_json(stem: &str) -> Value {
    serde_json::from_str(&fixture_text(stem))
        .unwrap_or_else(|e| panic!("{stem}.json is not valid JSON: {e}"))
}

// OPENAPI PATTERN PREDICATES
// ================================================================================================

/// `^0x[a-fA-F0-9]{64}$` — the 32-byte hex every identifier/hash field uses
/// (`CIRCLE-API-SURFACE.md` §`TransferSpec`/`WithdrawalResponse`).
pub fn is_hex32(s: &str) -> bool {
    is_prefixed_hex_of_len(s, 64)
}

/// `^0x[a-fA-F0-9]{40}$` — the 20-byte `forwardingContractAddress` (JSON `StructuredHookData`; the
/// binary `WithdrawHookData.forwardingContract` is 32 bytes — do not conflate).
pub fn is_hex20(s: &str) -> bool {
    is_prefixed_hex_of_len(s, 40)
}

/// `^0x[a-fA-F0-9]*$` — an unbounded hex string (`burnSignatures[]`, `attestation`,
/// `attestationPayload`, `hookData`). The empty body (`"0x"`) is legal.
pub fn is_hex_any(s: &str) -> bool {
    s.strip_prefix("0x")
        .is_some_and(|body| body.chars().all(|c| c.is_ascii_hexdigit()))
}

/// `^0x[a-fA-F0-9]+$` — `burnTxId`: hex, at least one digit, no length bound (a Miden tx id, DEV-7).
pub fn is_hex_nonempty(s: &str) -> bool {
    is_hex_any(s) && s.len() > 2
}

/// `^0x([a-fA-F0-9]{8}[a-fA-F0-9]*)?$` — `forwardingCalldata`: `0x`, or `0x` + a 4-byte selector +
/// optional data.
pub fn is_calldata(s: &str) -> bool {
    match s.strip_prefix("0x") {
        None => false,
        Some("") => true,
        Some(body) => body.len() >= 8 && body.chars().all(|c| c.is_ascii_hexdigit()),
    }
}

/// `^\d+$` — a smallest-unit integer string (`value`, `maxFee`, `maxBlockHeight`).
pub fn is_decimal_uint(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// `^\d+(\.\d+)?$` — the request's decimal amount (`valueExcludingFees` / `valueIncludingFees`).
pub fn is_decimal_amount(s: &str) -> bool {
    match s.split_once('.') {
        None => is_decimal_uint(s),
        Some((whole, frac)) => is_decimal_uint(whole) && is_decimal_uint(frac),
    }
}

/// `format: uuid` — 8-4-4-4-12 lowercase-or-uppercase hex, hyphen-separated (`withdrawalId`).
pub fn is_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12] == groups.iter().map(|g| g.len()).collect::<Vec<_>>()[..]
        && groups
            .iter()
            .all(|g| g.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_prefixed_hex_of_len(s: &str, hex_digits: usize) -> bool {
    s.strip_prefix("0x")
        .is_some_and(|body| body.len() == hex_digits && body.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The six-member `status` enum, verbatim (`CIRCLE-API-SURFACE.md`: "Status enum: `created,
/// verified, confirmed, finalized, expired, failed`").
pub const STATUS_ENUM: [&str; 6] = [
    "created",
    "verified",
    "confirmed",
    "finalized",
    "expired",
    "failed",
];

// JSON NAVIGATION HELPERS
// ================================================================================================

/// The string at `key`, or a panic naming the fixture — a missing required field is a fixture defect,
/// not a soft failure.
pub fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .unwrap_or_else(|| panic!("missing required field `{key}` in {v}"))
        .as_str()
        .unwrap_or_else(|| panic!("field `{key}` is not a string in {v}"))
}

/// Walks every string value in a JSON tree, yielding `(key, value)` pairs — the sweep that proves a
/// forbidden key (`sourceDepositor` on a request) appears nowhere at any depth.
pub fn walk_keys(v: &Value, f: &mut impl FnMut(&str, &Value)) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                f(k, child);
                walk_keys(child, f);
            }
        }
        Value::Array(items) => {
            for child in items {
                walk_keys(child, f);
            }
        }
        _ => {}
    }
}
