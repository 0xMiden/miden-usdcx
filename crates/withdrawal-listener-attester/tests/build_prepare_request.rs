//! Builds the `PrepareWithdrawalRequest` — the API JSON the partner authors — and pins the
//! `remoteDepositor` vs `sourceDepositor` distinctness (an exact match, never a prefix).
//!
//! Every assertion here is about the REQUEST the partner SENDS — never the binary
//! `TransferSpec`/`BurnIntent` (Circle encodes those server-side) and never Circle's returned data
//! (that is the pre-signing gate in `validate.rs`). The oracle is deliberately non-vacuous: the
//! serialized JSON is asserted at the STRING level (the `sourceDepositor` key is absent as text,
//! not merely absent from the struct), and `remoteDepositor` is pinned to the `0x`-hex of the
//! shared encoding crate's `EthEmbeddedAccountId::from_account_id(sender).to_bytes32()` on a golden pair.
//!
//! The builder takes ONE `DiscoveredBurn` — the discovery gate's own output — rather than a payload
//! and a sender as independent arguments, so "burn A's payload under burn B's depositor" is not a
//! pairing this API can express. Every case below therefore mints its burn through the real
//! `validate_discovery` gate (`discovered_burn`), which also means the fixtures here are burns a
//! real discovery pass could have produced rather than hand-assembled structs.
//!
//! What is enforced:
//! * the top-level `{ batches: [..] }` wrapper is real (never a bare batch);
//! * `remoteDepositor` == `encode(metadata.sender)` via the shared `AccountId↔bytes32` helper,
//!   `^0x[a-fA-F0-9]{64}$`;
//! * `sourceDepositor` is structurally AND textually absent;
//! * exactly one of `valueExcludingFees`/`valueIncludingFees` is set (the value XOR);
//! * `remoteDomain >= 1` and `remoteDomain != finalDestinationDomain` — else an exact `Err`;
//! * a supplied `salt` is STABLE across rebuilds of the same burn (idempotency);
//! * no binary/response-only artifact (`encoded`, `messageHashToSign`, `spec`, …) is ever emitted.

use assert_matches::assert_matches;

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use withdrawal_listener_attester::circle::schema::PrepareBurnIntentInput;
use withdrawal_listener_attester::circle::wire::{DecimalAmount, Hex32, SchemaError};
use withdrawal_listener_attester::config::ListenerConfig;
use withdrawal_listener_attester::types::BurnPayload;
use withdrawal_listener_attester::validate::{
    validate_discovery, DiscoveredBurn, DiscoveredDetails, DiscoveryRecord,
};
use withdrawal_listener_attester::withdrawal_api::build_prepare_request;

// ================================================================================================
// FIXTURES
// ================================================================================================

/// A concrete, genuinely-valid burner account id (the same well-formed id the config's placeholder
/// faucet uses — any canonical `AccountId` serves as the `metadata.sender` under test).
fn a_sender() -> AccountId {
    AccountId::from_hex("0xbb405fd9fe431bd1135a292de098cb").expect("a valid account id")
}

/// A distinct 32-byte value, so a swapped field (recipient ↔ salt, sender ↔ recipient) is caught.
const DEST_RECIPIENT: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x2d, 0x35, 0xcc,
    0x66, 0x34, 0xc0, 0x53, 0x29, 0x25, 0xa3, 0xb8, 0x44, 0xbc, 0x45, 0x4e, 0x44, 0x38, 0xf4, 0x4e,
];
const SALT: [u8; 32] = [0x11; 32];

const AMOUNT: u64 = 10_000_000;
/// The user's `finalDestinationDomain`, from the burn note payload. Distinct from `MIDEN_DOMAIN`.
const DEST_DOMAIN: u32 = 0;
/// Miden's remote domain (from config). `>= 1` and `!= DEST_DOMAIN`, so the happy path validates.
const MIDEN_DOMAIN: u32 = 99_999;

/// The burn payload the burn note wrote, in the shape Circle's documentation describes —
/// `(amount, destDomain, destRecipient, salt)`.
fn a_payload() -> BurnPayload {
    BurnPayload {
        amount: AssetAmount::new(AMOUNT).unwrap(),
        dest_domain: DEST_DOMAIN,
        dest_recipient: DEST_RECIPIENT,
        salt: SALT,
    }
}

/// A config carrying a given Miden remote domain (every other field is the package default).
fn cfg_with_domain(miden_domain: u32) -> ListenerConfig {
    ListenerConfig::builder()
        .miden_domain(miden_domain)
        .build()
        .expect("a config with only miden_domain set is valid")
}

fn cfg() -> ListenerConfig {
    cfg_with_domain(MIDEN_DOMAIN)
}

/// `0x` + lowercase hex of 32 bytes — the wire rendering the builder must produce for the
/// `AccountId↔bytes32` codec.
fn hex32_str(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// The `DiscoveredBurn` for `(payload, sender)` — minted through the REAL discovery gate, because
/// that is the only way to mint one.
///
/// `build_prepare_request` takes a `DiscoveredBurn` rather than a payload and a sender precisely so
/// that a caller cannot pair burn A's payload with burn B's depositor (the fund-safety property the
/// orchestration depends on). This helper is therefore not a shortcut around that: it encodes the
/// payload with the shared encoding crate's own burn-note codec, carries `sender` as the raw
/// `metadata.sender` felt pair, and runs `validate_discovery` — so the burn under test here is one
/// a real discovery pass could have produced, and the two halves provably came off one note.
fn discovered_burn(
    payload: &BurnPayload,
    sender: AccountId,
    cfg: &ListenerConfig,
) -> DiscoveredBurn {
    let (prefix, suffix) = (sender.prefix().as_felt(), sender.suffix());
    let record = DiscoveryRecord::new(
        cfg.burn_tag(),
        Some(DiscoveredDetails::from_raw_sender(
            payload.encode(),
            prefix,
            suffix,
        )),
    );
    validate_discovery(&record, cfg).expect("a well-formed public burn note passes B3")
}

/// The one `PrepareBurnIntentInput` inside a freshly built request (asserting the wrapper carries
/// exactly one batch on the way).
fn only_input(
    payload: &BurnPayload,
    sender: AccountId,
    cfg: &ListenerConfig,
) -> PrepareBurnIntentInput {
    let request = build_prepare_request(&discovered_burn(payload, sender, cfg), cfg)
        .expect("a valid request builds");
    assert_eq!(
        request.batches().len(),
        1,
        "the DC-9 request wraps the single PrepareBurnIntentInput in the top-level batches[]"
    );
    request.batches()[0].clone()
}

// ================================================================================================
// HAPPY PATH — every field mapped per the request-schema table
// ================================================================================================

#[test]
fn happy_path_maps_every_field() {
    let payload = a_payload();
    let sender = a_sender();
    let input = only_input(&payload, sender, &cfg());

    // token — the one enum member.
    assert_eq!(input.token().as_str(), "USDC");

    // remoteDomain from config; finalDestinationDomain from the burn payload; they differ.
    assert_eq!(input.remote_domain(), MIDEN_DOMAIN);
    assert_eq!(input.final_destination_domain(), DEST_DOMAIN);
    assert_ne!(input.remote_domain(), input.final_destination_domain());

    // finalDestinationRecipient is the burn payload's destRecipient, 0x-hex 32B.
    assert_eq!(
        input.final_destination_recipient(),
        hex32_str(&DEST_RECIPIENT)
    );

    // useCircleForwarding is a concrete bool (the forwarding scope is OPEN → no forwarding invented).
    assert!(!input.use_circle_forwarding());

    // optional fields the burn does not dictate are ABSENT, not defaulted to a fabricated value.
    assert_eq!(input.final_destination_caller(), None);
    assert!(input.forwarding_options().is_none());
}

/// The golden depositor mapping: `remoteDepositor` is `EthEmbeddedAccountId::from_account_id(sender).to_bytes32()` rendered
/// 0x-hex, and it matches the OpenAPI's `^0x[a-fA-F0-9]{64}$`.
#[test]
fn remote_depositor_is_dc6_of_sender() {
    let sender = a_sender();
    let input = only_input(&a_payload(), sender, &cfg());

    let expected = hex32_str(&EthEmbeddedAccountId::from_account_id(sender).to_bytes32());
    assert_eq!(
        input.remote_depositor(),
        expected,
        "remoteDepositor must be the DC-6 encoding of metadata.sender"
    );

    // ^0x[a-fA-F0-9]{64}$ — 32-byte hex, and it round-trips through the wire newtype.
    let d = input.remote_depositor();
    assert!(d.starts_with("0x"), "remoteDepositor is 0x-prefixed");
    assert_eq!(d.len(), 66, "0x + 64 hex digits");
    assert!(
        d[2..].bytes().all(|b| b.is_ascii_hexdigit()),
        "remoteDepositor body is hex"
    );
    Hex32::new(d).expect("remoteDepositor satisfies the Hex32 regex");
}

/// A supplied `salt` comes from the burn payload, so it renders 0x-hex 32B and is NOT a fresh
/// random.
#[test]
fn salt_is_the_burn_payload_salt() {
    let payload = a_payload();
    let input = only_input(&payload, a_sender(), &cfg());
    assert_eq!(
        input.salt(),
        Some(hex32_str(&SALT).as_str()),
        "the request salt is the burn note's salt, rendered 0x-hex"
    );
}

// ================================================================================================
// THE VALUE XOR — exactly one fee field, never both, never neither
// ================================================================================================

/// Exactly one of the two value fields is set — the `valueIncludingFees` leg (the burned amount is
/// the total debited on Miden; the smallest-unit⇄decimal scale is Circle-owned and OPEN, so the
/// amount is passed through unscaled).
#[test]
fn exactly_one_value_field_is_set() {
    let input = only_input(&a_payload(), a_sender(), &cfg());

    assert_eq!(
        input.value_including_fees(),
        Some(AMOUNT.to_string().as_str()),
        "the burned amount is carried in valueIncludingFees, unscaled (DEV-5 OPEN)"
    );
    assert_eq!(
        input.value_excluding_fees(),
        None,
        "valueExcludingFees is unset — the value XOR is satisfied by exactly one field"
    );
}

/// The value XOR is a hard schema rule (foreclosing the both/neither forbidden impls): the
/// `PrepareBurnIntentInput` builder itself refuses both-set and neither-set with the exact
/// `SchemaError::ValueXor`. (The builder used by `build_prepare_request` always sets exactly one,
/// so this pins the rule at its single owner.)
#[test]
fn value_xor_rejects_both_and_neither() {
    let recipient = Hex32::new(hex32_str(&DEST_RECIPIENT)).unwrap();
    let depositor = Hex32::new(hex32_str(
        &EthEmbeddedAccountId::from_account_id(a_sender()).to_bytes32(),
    ))
    .unwrap();

    // both set → ValueXor
    let both = PrepareBurnIntentInput::builder()
        .value_excluding_fees(DecimalAmount::new("10.00").unwrap())
        .value_including_fees(DecimalAmount::new("10.00").unwrap())
        .remote_domain(MIDEN_DOMAIN)
        .remote_depositor(depositor.clone())
        .final_destination_domain(DEST_DOMAIN)
        .final_destination_recipient(recipient.clone())
        .use_circle_forwarding(false)
        .build();
    assert_matches!(both, Err(SchemaError::ValueXor));

    // neither set → ValueXor
    let neither = PrepareBurnIntentInput::builder()
        .remote_domain(MIDEN_DOMAIN)
        .remote_depositor(depositor)
        .final_destination_domain(DEST_DOMAIN)
        .final_destination_recipient(recipient)
        .use_circle_forwarding(false)
        .build();
    assert_matches!(neither, Err(SchemaError::ValueXor));
}

// ================================================================================================
// sourceDepositor DISTINCTNESS (the same trap) — string-level, not only struct-shape
// ================================================================================================

/// The serialized request carries NO `sourceDepositor` key as TEXT — Circle fills it
/// server-side. This is the non-vacuity oracle: a struct with no such field could still, in
/// principle, serialize one under a rename; asserting on the JSON string forecloses that.
#[test]
fn serialized_request_has_no_source_depositor_key() {
    let request =
        build_prepare_request(&discovered_burn(&a_payload(), a_sender(), &cfg()), &cfg()).unwrap();
    let json = serde_json::to_string(&request).expect("the request serializes");

    let lower = json.to_lowercase();
    assert!(
        !lower.contains("sourcedepositor"),
        "sourceDepositor must never appear in the partner-built request: {json}"
    );
    assert!(
        !json.contains("source_depositor"),
        "not under a snake_case rename either: {json}"
    );

    // and remoteDepositor IS present, carrying the encoded-sender hex — the swap's positive control.
    assert!(
        json.contains("remoteDepositor"),
        "remoteDepositor key present"
    );
    let expected = hex32_str(&EthEmbeddedAccountId::from_account_id(a_sender()).to_bytes32());
    assert!(
        json.contains(&expected),
        "the serialized remoteDepositor is the DC-6 hex {expected}: {json}"
    );
}

/// The partner builds ONLY the API JSON, never the binary form: no binary/response-only artifact
/// (`encoded`, `messageHashToSign`, a nested `spec`, `sourceSigner`, `version`) is emitted.
/// Foreclosing "local binary TransferSpec/BurnIntent construction".
#[test]
fn serialized_request_has_no_binary_or_response_artifacts() {
    let request =
        build_prepare_request(&discovered_burn(&a_payload(), a_sender(), &cfg()), &cfg()).unwrap();
    let json = serde_json::to_string(&request).expect("the request serializes");

    for banned in [
        "encoded",
        "messageHashToSign",
        "\"spec\"",
        "sourceSigner",
        "\"version\"",
        "transferSpecHash",
    ] {
        assert!(
            !json.contains(banned),
            "the DC-9 request must carry no `{banned}` (binary/response-only): {json}"
        );
    }
}

// ================================================================================================
// SALT STABILITY / IDEMPOTENCY — same burn ⇒ identical request
// ================================================================================================

/// Rebuilding from the same payload + sender + config is DETERMINISTIC, salt included (the salt is
/// derived from the burn, not freshly randomized). Both the struct and its serialization are equal.
#[test]
fn rebuild_is_stable_including_salt() {
    let payload = a_payload();
    let sender = a_sender();
    let cfg = cfg();

    let first = build_prepare_request(&discovered_burn(&payload, sender, &cfg), &cfg).unwrap();
    let second = build_prepare_request(&discovered_burn(&payload, sender, &cfg), &cfg).unwrap();

    assert_eq!(
        first, second,
        "the same burn rebuilds to an identical request (salt is stable, not re-randomized)"
    );
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap(),
        "and identical on the wire"
    );
}

// ================================================================================================
// REJECTS — exact SchemaError variants (the domain rules reachable from payload + config)
// ================================================================================================

/// `remoteDomain == finalDestinationDomain` → exact `DomainsMustDiffer` (a withdrawal to the domain
/// it came from is not a withdrawal). anti-collision.
#[test]
fn rejects_when_domains_are_equal() {
    // both domains equal AND >= 1, so the collision (not the minimum) is what fires.
    let mut payload = a_payload();
    payload.dest_domain = 5;
    let cfg = cfg_with_domain(5); // remoteDomain forced equal to finalDestinationDomain
    let result = build_prepare_request(&discovered_burn(&payload, a_sender(), &cfg), &cfg);
    assert_matches!(result, Err(SchemaError::DomainsMustDiffer(5)));
}

/// `remoteDomain < 1` → exact `RemoteDomainBelowMinimum`. The config's default Miden domain is the
/// `0` placeholder (the Circle-assigned domain id is OPEN), so a request built against it is
/// refused rather than shipped with an out-of-range domain.
#[test]
fn rejects_when_remote_domain_below_minimum() {
    let mut payload = a_payload();
    payload.dest_domain = 7; // distinct, so the failure is the minimum, not the collision
    let cfg = cfg_with_domain(0);
    let result = build_prepare_request(&discovered_burn(&payload, a_sender(), &cfg), &cfg);
    assert_matches!(result, Err(SchemaError::RemoteDomainBelowMinimum(0)));
}

/// A different sender maps to a different `remoteDepositor` — the mapping is not a constant.
#[test]
fn distinct_senders_yield_distinct_depositors() {
    let a = only_input(&a_payload(), a_sender(), &cfg());
    let other =
        AccountId::from_hex("0x9b405fd9fe431bd1135a292de098cb").expect("a second valid account id");
    let b = only_input(&a_payload(), other, &cfg());
    assert_ne!(
        a.remote_depositor(),
        b.remote_depositor(),
        "remoteDepositor tracks the sender, it is not a fixed string"
    );
    assert_eq!(
        b.remote_depositor(),
        hex32_str(&EthEmbeddedAccountId::from_account_id(other).to_bytes32()),
        "and the second depositor is DC-6 of the second sender"
    );
}
