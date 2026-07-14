//! The Circle wire's **constrained scalars** — the OpenAPI's regexes and enums, as types.
//!
//! Every field in `CIRCLE-API-SURFACE.md`'s schema tables carries a pattern (`^0x[a-fA-F0-9]{64}$`,
//! `^\d+$`, `format: uuid`, `enum: ["USDC"]`, …). Modelling them all as `String` makes the wire types
//! check JSON *shape* and nothing else: a `token` of `"DAI"`, a 31-byte `transferSpecHash`, a
//! `remoteDomain` of `0`, an amount of `"10.00"` where the smallest-unit `"10000000"` belongs — all
//! decode, and the first anyone hears of it is Circle's 400, or (worse) a settlement for the wrong
//! amount.
//!
//! So each pattern is a newtype whose ONLY constructor validates, and whose `Deserialize` runs that
//! same constructor. There is no way to hold one of these that does not satisfy its regex — the
//! parse, not a downstream check, is what establishes it (domain-newtypes-over-primitives,
//! validate-in-constructor).
//!
//! # What is deliberately NOT constrained
//!
//! A constraint the OpenAPI does not document is not invented here — that is the same defect as
//! inventing a field. `encoded` and `messageHashToSign` are typed `string` with **no pattern** (Circle
//! encodes them server-side and the partner treats them as opaque), and the **request-side**
//! `burnTxId` likewise has no documented pattern, even though the *response-side* one is
//! `^0x[a-fA-F0-9]+$`. That asymmetry is the OpenAPI's; this module reproduces it rather than
//! tidying it up.
//!
//! Nor is *semantic* validation here. Whether a returned burn intent matches the burn note's
//! amount/domain/recipient is the B5 gate (`INV-CIRCLE-CANONICAL-WITHDRAWAL`, T-LA-06) — a schema-valid
//! response can still be a lie, and catching that is a different job from catching a malformed one.

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A value that violates the schema Circle published.
///
/// Each variant names ONE rule, so a test — and an operator reading a log line — can tell exactly
/// which constraint bit, rather than getting a generic "invalid input". The offending value is
/// carried in the error: these are wire-format fields (hashes, amounts, domains), never credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchemaError {
    /// Not `^0x[a-fA-F0-9]{64}$` — a 32-byte hex identifier/hash.
    BadHex32(String),
    /// Not `^0x[a-fA-F0-9]{40}$` — the JSON hook's 20-byte forwarding address. (The 32-byte form is
    /// the BINARY `WithdrawHookData.forwardingContract`; the two must not be conflated.)
    BadHex20(String),
    /// Not `^0x[a-fA-F0-9]*$` — an unbounded hex string.
    BadHex(String),
    /// Not `^0x[a-fA-F0-9]+$` — hex with at least one digit. The bare `0x` is legal for a signature
    /// body but not for a burn tx id: an empty burn tx id is evidence of nothing.
    EmptyHex(String),
    /// Not `^0x([a-fA-F0-9]{8}[a-fA-F0-9]*)?$` — `0x`, or `0x` + a 4-byte selector + optional data.
    BadCalldata(String),
    /// Not `^\d+$` — the smallest-unit integer form (`value`, `maxFee`, `maxBlockHeight`).
    BadDecimalUint(String),
    /// Not `^\d+(\.\d+)?$` — the request's decimal amount form.
    BadDecimalAmount(String),
    /// Not `^\d+(\.\d{1,6})?$` — `forwardingOptions.maxFee`. USDC has six decimals; a seventh cannot
    /// be represented.
    BadForwardingFee(String),
    /// Not a uuid (`8-4-4-4-12` hex).
    BadUuid(String),
    /// Not the one member of `enum: ["USDC"]`.
    UnknownToken(String),
    /// `valueExcludingFees` XOR `valueIncludingFees` — "pass one, not both". Both, or neither, leaves
    /// the amount ambiguous in the field that decides how much USDC is released.
    ValueXor,
    /// `remoteDomain: minimum 1`.
    RemoteDomainBelowMinimum(u32),
    /// "`remoteDomain` must differ from `finalDestinationDomain`" — a withdrawal to the domain it came
    /// from is not a withdrawal.
    DomainsMustDiffer(u32),
    /// `WithdrawRequest.batches`: `minItems 1`, `maxItems 5`.
    BatchCountOutOfRange(usize),
    /// `WithdrawBatch.burnIntents`: `minItems 1`, `maxItems 10`.
    BurnIntentCountOutOfRange(usize),
    /// `WithdrawBatch.burnSignatures`: `minItems 2` — the partner's 2-of-n attester quorum. (The
    /// ORDERING rules — ascending signer address, no duplicates — are not expressible in the schema
    /// and stay with the quorum assembler.)
    SignatureCountBelowThreshold(usize),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHex32(v) => write!(f, "`{v}` is not a 32-byte 0x-hex string"),
            Self::BadHex20(v) => write!(f, "`{v}` is not a 20-byte 0x-hex string"),
            Self::BadHex(v) => write!(f, "`{v}` is not a 0x-hex string"),
            Self::EmptyHex(v) => write!(f, "`{v}` is 0x-hex but carries no digits"),
            Self::BadCalldata(v) => write!(
                f,
                "`{v}` is not `0x` or `0x` followed by a 4-byte selector and optional data"
            ),
            Self::BadDecimalUint(v) => {
                write!(
                    f,
                    "`{v}` is not a decimal integer in the smallest token unit"
                )
            }
            Self::BadDecimalAmount(v) => write!(f, "`{v}` is not a decimal amount"),
            Self::BadForwardingFee(v) => {
                write!(f, "`{v}` is not a decimal amount with at most 6 decimals")
            }
            Self::BadUuid(v) => write!(f, "`{v}` is not a uuid"),
            Self::UnknownToken(v) => write!(f, "`{v}` is not a supported token (expected `USDC`)"),
            Self::ValueXor => write!(
                f,
                "exactly one of `valueExcludingFees` and `valueIncludingFees` must be set"
            ),
            Self::RemoteDomainBelowMinimum(d) => {
                write!(
                    f,
                    "`remoteDomain` is {d}, below the documented minimum of 1"
                )
            }
            Self::DomainsMustDiffer(d) => write!(
                f,
                "`remoteDomain` and `finalDestinationDomain` must differ, both are {d}"
            ),
            Self::BatchCountOutOfRange(n) => {
                write!(f, "a withdraw request carries 1 to 5 batches, got {n}")
            }
            Self::BurnIntentCountOutOfRange(n) => {
                write!(f, "a withdraw batch carries 1 to 10 burn intents, got {n}")
            }
            Self::SignatureCountBelowThreshold(n) => write!(
                f,
                "`burnSignatures` needs at least 2 signatures to meet the threshold, got {n}"
            ),
        }
    }
}

impl core::error::Error for SchemaError {}

/// Defines a validated string newtype: one constructor, which validates, and a `Deserialize` that
/// runs it. Serialization is transparent — the value is already known good.
macro_rules! wire_string {
    ($(#[$meta:meta])* $name:ident, $check:expr, $err:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// # Errors
            /// The variant of [`SchemaError`] naming the pattern this value failed.
            pub fn new(value: impl Into<String>) -> Result<Self, SchemaError> {
                let value = value.into();
                let check: fn(&str) -> bool = $check;
                if check(&value) {
                    Ok(Self(value))
                } else {
                    let err: fn(String) -> SchemaError = $err;
                    Err(err(value))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        /// Deserialization runs the SAME constructor. That is the whole point: there is no path — not
        /// a config file, not a Circle response — that yields one of these without the check.
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                Self::new(raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn hex_body_of_len(value: &str, digits: usize) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|body| body.len() == digits && body.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_hex(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|body| body.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_decimal_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// `^\d+(\.\d{1,max})?$` — a decimal amount whose fractional part is at most `max` digits. `None`
/// means unbounded.
fn is_decimal_amount(value: &str, max_places: Option<usize>) -> bool {
    match value.split_once('.') {
        None => is_decimal_digits(value),
        Some((whole, frac)) => {
            is_decimal_digits(whole)
                && is_decimal_digits(frac)
                && max_places.is_none_or(|max| frac.len() <= max)
        }
    }
}

wire_string!(
    /// `^0x[a-fA-F0-9]{64}$` — the 32-byte hex every identifier/hash field on the Circle wire uses.
    Hex32,
    |v| hex_body_of_len(v, 64),
    SchemaError::BadHex32
);

wire_string!(
    /// `^0x[a-fA-F0-9]{40}$` — the JSON `StructuredHookData.forwardingContractAddress`, a 20-byte EVM
    /// address.
    ///
    /// Note the size. The **binary** `WithdrawHookData.forwardingContract` is `bytes32`, and the JSON
    /// form is `bytes20`; Circle left-pads during its server-side encoding
    /// (`CIRCLE-DATA-SCHEMAS.md` §3.4, "DO NOT CONFLATE"). And note that the OpenAPI's own prose —
    /// "if you are not forwarding funds, set to `0x0`" — does not satisfy its own regex: the zero
    /// address here is forty zero digits. Where prose and regex disagree, the regex is the schema.
    Hex20,
    |v| hex_body_of_len(v, 40),
    SchemaError::BadHex20
);

wire_string!(
    /// `^0x[a-fA-F0-9]*$` — an unbounded hex string (`burnSignatures[]`, `attestation`,
    /// `attestationPayload`, `forwardingOptions.hookData`). The empty body `0x` is legal.
    HexBytes,
    is_hex,
    SchemaError::BadHex
);

wire_string!(
    /// `^0x[a-fA-F0-9]+$` — the RESPONSE-side `burnTxId`: hex, at least one digit, no length bound (a
    /// Miden transaction id; whether that is what Circle will accept is `DEV-7`, OPEN).
    ///
    /// The request-side `burnTxId` has NO documented pattern and is therefore a plain `String` — the
    /// asymmetry is the OpenAPI's.
    HexTxId,
    |v| is_hex(v) && v.len() > 2,
    SchemaError::EmptyHex
);

wire_string!(
    /// `^0x([a-fA-F0-9]{8}[a-fA-F0-9]*)?$` — `forwardingCalldata`: bare `0x` when not forwarding, else
    /// a 4-byte selector plus optional data.
    Calldata,
    |v: &str| match v.strip_prefix("0x") {
        None => false,
        Some("") => true,
        Some(body) => body.len() >= 8 && body.bytes().all(|b| b.is_ascii_hexdigit()),
    },
    SchemaError::BadCalldata
);

wire_string!(
    /// `^\d+$` — an amount in the smallest token unit (`TransferSpec.value`, `BurnIntent.maxFee`,
    /// `maxBlockHeight`), as a decimal STRING: a `uint256` does not survive a JSON number.
    ///
    /// This is NOT the request's decimal form. `"10.00"` and `"10000000"` are the same amount written
    /// two ways, and mixing them up is a 10^6 error in a money field.
    DecimalUint,
    is_decimal_digits,
    SchemaError::BadDecimalUint
);

wire_string!(
    /// `^\d+(\.\d+)?$` — the request's `valueExcludingFees` / `valueIncludingFees`.
    DecimalAmount,
    |v| is_decimal_amount(v, None),
    SchemaError::BadDecimalAmount
);

wire_string!(
    /// `^\d+(\.\d{1,6})?$` — `forwardingOptions.maxFee`, capped at USDC's six decimals.
    ForwardingFee,
    |v| is_decimal_amount(v, Some(6)),
    SchemaError::BadForwardingFee
);

wire_string!(
    /// `format: uuid` — `withdrawalId`, the handle a status poll is keyed on.
    Uuid,
    |v: &str| {
        let groups: Vec<&str> = v.split('-').collect();
        groups.len() == 5
            && [8, 4, 4, 4, 12] == groups.iter().map(|g| g.len()).collect::<Vec<_>>()[..]
            && groups.iter().all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()))
    },
    SchemaError::BadUuid
);

/// `enum: ["USDC"]` — the one token the schema permits.
///
/// A closed enum, not a `String`: a `token` of `"DAI"` is a request Circle rejects, and it should
/// never leave this process.
///
/// It is deliberately NOT `#[non_exhaustive]`. The repo's non-exhaustive-public-types rule exempts
/// protocol/schema enums whose closed set is contractual: adding a member here would be a CIRCLE WIRE
/// CHANGE, not a compatible library extension, and downstream code should be forced to confront it —
/// an exhaustive `match` that stops compiling is exactly the alarm you want when the wire contract
/// moves. The same reasoning applies to `WithdrawalStatusKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Token {
    #[default]
    Usdc,
}

impl Token {
    /// # Errors
    /// [`SchemaError::UnknownToken`] — anything but the exact string `USDC`. Case-sensitive: the enum
    /// member is the uppercase ticker.
    pub fn new(value: &str) -> Result<Self, SchemaError> {
        match value {
            "USDC" => Ok(Self::Usdc),
            other => Err(SchemaError::UnknownToken(other.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Usdc => "USDC",
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Token {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::new(&raw).map_err(serde::de::Error::custom)
    }
}

/// Deserializes an optional property that is **not nullable**: absent is legal, present-and-`null` is
/// not.
///
/// Serde's plain `Option<T>` conflates the two — it reads `null` as `None`, i.e. as absence. The
/// OpenAPI does not: these properties may be OMITTED, and when they are PRESENT they must carry a
/// value of their type. Reading `{"salt": null}` as "no salt" means a caller who set salt to null
/// believing it meaningful silently gets a Circle-generated random salt instead, with no error
/// anywhere on the path.
///
/// Used as `#[serde(default, deserialize_with = "present_non_null")]`: when the key is absent serde
/// takes the `default` (`None`) and never calls this; when the key is present this deserializes `T`
/// itself, so a `null` fails as a type error rather than collapsing to absence.
pub(crate) fn present_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
