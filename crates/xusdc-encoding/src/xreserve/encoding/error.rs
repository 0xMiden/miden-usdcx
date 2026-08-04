//! The error type every encoding routine returns, and its MASM counterparts.
//!
//! One enum covers the whole encoding surface so a caller handles failures from the amount reducer,
//! the intent parser, and the codecs uniformly.
//!
//! Alongside the enum are the MASM error constants the faucet raises. They are strings rather than
//! numeric codes, matching how the protocol's own MASM declares errors, and the assertion messages
//! here are the same text as the ones in the `.masm` files. That matters for diagnosis: a
//! transaction that trapped on-chain reports the same wording an off-chain rejection would.

use core::fmt;

use miden_protocol::errors::MasmError;

use super::deposit_intent::DepositIntentField;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingError {
    LimbOutOfField,
    /// A u32-LE-packed felt limb exceeds `u32::MAX` (the `packed_felts_to_bytes32` guard on the
    /// burn-note item decode, distinct from `LimbOutOfField`'s 8-byte/felt `>= p` Word-packing check).
    LimbNotU32,
    AmountTooLarge,
    AmountOverCap,
    ScaleExpTooLarge,
    BadMagic,
    BadVersion,
    ZeroField {
        field: DepositIntentField,
    },
    TruncatedHeader,
    LengthMismatch,
    HookDataTooLarge,
    AccountIdOutOfRange,
    NonCanonicalAccountId,
    BurnItemsMalformed,
    /// The 33-byte compressed SEC1 attester pubkey does not decode to a secp256k1 curve point
    /// (the SEC1→affine decompression the on-chain affine commitment format requires;
    /// such a key could never verify on-chain either).
    InvalidPubkey,
    JsonSchema(String),
    BinaryMagic,
    BinaryLength,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimbOutOfField => write!(f, "a u64 limb is not a valid field element"),
            Self::LimbNotU32 => write!(f, "packed felt exceeds u32 range"),
            Self::AmountTooLarge => write!(f, "larger than 2**128"),
            Self::AmountOverCap => {
                write!(f, "post-scale quotient exceeds the asset amount maximum")
            }
            Self::ScaleExpTooLarge => write!(f, "scale exponent exceeds 18"),
            Self::BadMagic => write!(f, "deposit intent magic mismatch"),
            Self::BadVersion => write!(f, "deposit intent version mismatch"),
            Self::ZeroField { field } => write!(f, "deposit intent field {field:?} is zero"),
            Self::TruncatedHeader => write!(f, "deposit intent header is shorter than 240 bytes"),
            Self::LengthMismatch => write!(f, "deposit intent length relation violated"),
            Self::HookDataTooLarge => write!(f, "hook data exceeds the note storage felt bound"),
            Self::AccountIdOutOfRange => {
                // The right-aligned (Agglayer-mirroring) layout: the account id region is the
                // 16 bytes `bytes[16..32]` (prefix u64 BE + suffix u64 BE) behind a 16-byte zero
                // pad — the message names the 16-byte region of the shipped layout.
                write!(f, "bytes set outside the 16-byte account id region")
            }
            Self::NonCanonicalAccountId => {
                write!(f, "bytes do not decode to a canonical account id")
            }
            Self::BurnItemsMalformed => write!(f, "burn note items have the wrong length or shape"),
            Self::InvalidPubkey => {
                write!(f, "pubkey bytes do not decode to a secp256k1 curve point")
            }
            Self::JsonSchema(msg) => write!(f, "circle json does not match the schema: {msg}"),
            Self::BinaryMagic => write!(f, "circle binary decoder magic mismatch"),
            Self::BinaryLength => write!(f, "circle binary length reconciliation failed"),
        }
    }
}

impl core::error::Error for EncodingError {}

// MASM ERROR CONSTANTS
// ================================================================================================

/// Single source for every MASM error name/message pair: the named constants, the
/// name→constant lookup, and the name→message table are all generated from one list.
macro_rules! masm_errors {
    ($( $name:ident => $msg:literal ),+ $(,)?) => {
        $( pub const $name: MasmError = MasmError::from_static_str($msg); )+

        /// Name → constant lookup, for callers that hold only the `ERR_*` name.
        pub static ERR_TABLE: [(&str, &MasmError); 5] = [ $( (stringify!($name), &$name) ),+ ];

        /// Name → message table, for comparing against the strings the MASM declares.
        pub static ERR_MESSAGES: [(&str, &str); 5] = [ $( (stringify!($name), $msg) ),+ ];
    };
}

masm_errors! {
    ERR_FELT_OUT_OF_FIELD => "supplied limb is not a valid u32",
    ERR_DI_BAD_MAGIC => "deposit intent magic mismatch",
    ERR_DI_BAD_VERSION => "deposit intent version mismatch",
    ERR_DI_ZERO_FIELD => "deposit intent amount, local token, or local depositor is zero",
    ERR_DI_LENGTH => "deposit intent length relation violated",
}

/// Errors raised inside procedures the MASM links from the protocol's `miden-standards`
/// library (`miden::standards::utils` / `assets::asset_amount` / `interop::eth`) rather than
/// declaring locally. The strings are the standards library's own, not this repo's.
pub static STANDARDS_ERR_TABLE: [(&str, MasmError); 7] = [
    // the standards pow10 scale bound (both its u32 guard and its <= 18 bound)
    (
        "ERR_SCALE_AMOUNT_EXCEEDED_LIMIT",
        MasmError::from_static_str("maximum scaling factor is 18"),
    ),
    // the standards merge_u32_limbs lossless round-trip check (build_felt's no-reduction proof)
    (
        "ERR_MERGE_OVERFLOW",
        MasmError::from_static_str("merged u32 limbs do not fit in a field element"),
    ),
    // the standards eth::build_felt u32 limb guard
    (
        "ERR_NOT_U32",
        MasmError::from_static_str("address limb is not u32"),
    ),
    // the conversion verifier's x < 2^128 bound; STD-prefixed because the shell declares its
    // own ERR_X_TOO_LARGE for the maxFee/fee staging
    (
        "STD_ERR_X_TOO_LARGE",
        MasmError::from_static_str(
            "the u256 value is larger than 2**128 and cannot be verifiably scaled to u64",
        ),
    ),
    // the conversion verifier's witness bound: y within the fungible asset maximum
    (
        "ERR_Y_TOO_LARGE",
        MasmError::from_static_str("y exceeds max fungible token amount"),
    ),
    // the conversion verifier's no-underflow subtract (an over-claimed witness)
    (
        "ERR_UNDERFLOW",
        MasmError::from_static_str("x < y*10^s (underflow detected)"),
    ),
    // the conversion verifier's remainder bound (an under-claimed witness)
    (
        "ERR_REMAINDER_TOO_LARGE",
        MasmError::from_static_str("remainder z must be < 10^s"),
    ),
];

/// Looks up a MASM error constant by its `ERR_*` name (vector `masm_err` field), covering
/// both the locally-declared constants and the linked standards-library ones.
pub fn masm_error_by_name(name: &str) -> Option<&'static MasmError> {
    ERR_TABLE
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, e)| *e)
        .or_else(|| {
            STANDARDS_ERR_TABLE
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, e)| e)
        })
}
