//! Frozen `EncodingError` surface (`COMPONENT-SPEC.md §6.1`) plus the MASM error-constant
//! mirror (human decision D-2: string `MasmError` constants per the v0.15 protocol
//! pattern; the frozen `u32` code type is not realizable against v0.15 — recorded in the
//! approved plan). Deferred-family variants (burn-note / Circle JSON / binary) are part
//! of the one frozen enum and stay unconstructed in this slice.

use core::fmt;

use miden_protocol::errors::MasmError;

use super::deposit_intent::DepositIntentField;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingError {
    LimbOutOfField,
    AmountTooLarge,
    AmountOverCap,
    ScaleExpTooLarge,
    BadMagic,
    BadVersion,
    ZeroField { field: DepositIntentField },
    TruncatedHeader,
    LengthMismatch,
    HookDataTooLarge,
    AccountIdOutOfRange,
    NonCanonicalAccountId,
    BurnItemsMalformed,
    JsonSchema(String),
    BinaryMagic,
    BinaryLength,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimbOutOfField => write!(f, "a u64 limb is not a valid field element"),
            Self::AmountTooLarge => write!(f, "larger than 2**128"),
            Self::AmountOverCap => write!(f, "post-scale quotient exceeds the asset amount maximum"),
            Self::ScaleExpTooLarge => write!(f, "scale exponent exceeds 18"),
            Self::BadMagic => write!(f, "deposit intent magic mismatch"),
            Self::BadVersion => write!(f, "deposit intent version mismatch"),
            Self::ZeroField { field } => write!(f, "deposit intent field {field:?} is zero"),
            Self::TruncatedHeader => write!(f, "deposit intent header is shorter than 240 bytes"),
            Self::LengthMismatch => write!(f, "deposit intent length relation violated"),
            Self::HookDataTooLarge => write!(f, "hook data exceeds the note storage felt bound"),
            Self::AccountIdOutOfRange => {
                write!(f, "bytes set outside the 15-byte account id region")
            },
            Self::NonCanonicalAccountId => {
                write!(f, "bytes do not decode to a canonical account id")
            },
            Self::BurnItemsMalformed => write!(f, "burn note items have the wrong length or shape"),
            Self::JsonSchema(msg) => write!(f, "circle json does not match the schema: {msg}"),
            Self::BinaryMagic => write!(f, "circle binary decoder magic mismatch"),
            Self::BinaryLength => write!(f, "circle binary length reconciliation failed"),
        }
    }
}

impl core::error::Error for EncodingError {}

// MASM ERROR CONSTANTS (D-2)
// ================================================================================================
// Names per the frozen spec's intent list plus the two plan-flagged additions
// (`ERR_AMOUNT_OVER_CAP`, `ERR_SCALE_EXP_TOO_LARGE`, each 1:1 with a frozen enum variant).
// The MASM side must declare identical strings; `tests/constant_parity.rs` enforces it.

/// Single source for every MASM error name/message pair: the named constants, the
/// name→constant lookup (MASM execution tests), and the name→message table (the
/// constant-parity test) are all generated from one list.
macro_rules! masm_errors {
    ($( $name:ident => $msg:literal ),+ $(,)?) => {
        $( pub const $name: MasmError = MasmError::from_static_str($msg); )+

        /// Name → constant lookup used by the MASM execution tests (vectors carry the
        /// constant NAME; the value lives here exactly once).
        pub static ERR_TABLE: [(&str, &MasmError); 8] = [ $( (stringify!($name), &$name) ),+ ];

        /// Name → message table consumed by the constant-parity test (the MASM side
        /// must declare identical strings).
        pub static ERR_MESSAGES: [(&str, &str); 8] = [ $( (stringify!($name), $msg) ),+ ];
    };
}

masm_errors! {
    ERR_X_TOO_LARGE => "larger than 2**128",
    ERR_AMOUNT_OVER_CAP => "post-scale quotient exceeds the asset amount maximum",
    ERR_SCALE_EXP_TOO_LARGE => "scale exponent exceeds 18",
    ERR_FELT_OUT_OF_FIELD => "supplied limb is not a valid u32",
    ERR_DI_BAD_MAGIC => "deposit intent magic mismatch",
    ERR_DI_BAD_VERSION => "deposit intent version mismatch",
    ERR_DI_ZERO_FIELD => "deposit intent amount, local token, or local depositor is zero",
    ERR_DI_LENGTH => "deposit intent length relation violated",
}

/// Looks up a MASM error constant by its `ERR_*` name (vector `masm_err` field).
pub fn masm_error_by_name(name: &str) -> Option<&'static MasmError> {
    ERR_TABLE.iter().find(|(n, _)| *n == name).map(|(_, e)| *e)
}
