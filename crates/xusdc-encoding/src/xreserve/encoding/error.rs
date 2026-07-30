//! The error type every encoding routine returns, and its MASM counterparts.
//!
//! One enum covers the whole encoding surface so a caller handles failures from the amount reducer,
//! the intent parser, and the codecs uniformly. Some variants exist for paths this crate does not
//! yet construct — the burn-note and Circle wire families — and are kept here rather than added
//! later, so the enum's shape does not change under consumers as those paths land.
//!
//! Alongside the enum are the MASM error constants the faucet raises. They are strings rather than
//! numeric codes, matching how the protocol's own MASM declares errors; the assertion messages here
//! and the ones in the `.masm` files are the same text, and the parity test is what keeps them
//! that way. That matters for diagnosis: a transaction that trapped on-chain reports the same
//! wording an off-chain rejection would.

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
// Names per the frozen spec's intent list plus one addition (`ERR_AMOUNT_OVER_CAP`, 1:1 with a
// frozen enum variant). The MASM side must declare byte-identical strings, and a parity test
// fails if one of them drifts.

/// Single source for every MASM error name/message pair: the named constants, the
/// name→constant lookup (MASM execution tests), and the name→message table (the
/// constant-parity test) are all generated from one list.
macro_rules! masm_errors {
    ($( $name:ident => $msg:literal ),+ $(,)?) => {
        $( pub const $name: MasmError = MasmError::from_static_str($msg); )+

        /// Name → constant lookup used by the MASM execution tests (vectors carry the
        /// constant NAME; the value lives here exactly once).
        pub static ERR_TABLE: [(&str, &MasmError); 7] = [ $( (stringify!($name), &$name) ),+ ];

        /// Name → message table consumed by the constant-parity test (the MASM side
        /// must declare identical strings).
        pub static ERR_MESSAGES: [(&str, &str); 7] = [ $( (stringify!($name), $msg) ),+ ];
    };
}

masm_errors! {
    ERR_X_TOO_LARGE => "larger than 2**128",
    ERR_AMOUNT_OVER_CAP => "post-scale quotient exceeds the asset amount maximum",
    ERR_FELT_OUT_OF_FIELD => "supplied limb is not a valid u32",
    ERR_DI_BAD_MAGIC => "deposit intent magic mismatch",
    ERR_DI_BAD_VERSION => "deposit intent version mismatch",
    ERR_DI_ZERO_FIELD => "deposit intent amount, local token, or local depositor is zero",
    ERR_DI_LENGTH => "deposit intent length relation violated",
}

/// Errors raised inside procedures the MASM links from the protocol's `miden-standards`
/// library (`miden::standards::utils` / `assets::asset_amount` / `interop::eth`) rather than
/// declaring locally. The strings are the standards library's own — they are pinned
/// FUNCTIONALLY by the execution tests that trap on them, not by the local declaration parity
/// sweep (which covers only constants declared in this repo's MASM sources).
pub static STANDARDS_ERR_TABLE: [(&str, MasmError); 3] = [
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
