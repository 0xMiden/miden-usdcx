//! The error type every encoding routine returns.
//!
//! One enum covers the whole encoding surface so a caller handles failures from the amount reducer,
//! the intent parser, and the codecs uniformly.

use core::fmt;

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
    /// A field the mint note must carry as a single `AssetAmount` felt holds a wire value outside
    /// that range, so the note cannot express it. The faucet rebuilds the signed message from what
    /// the note carries, so an unrepresentable field makes the deposit unmintable rather than
    /// merely rejected on-chain.
    FieldNotAssetAmount {
        field: DepositIntentField,
    },
    /// A bytes32 field the mint note carries as a 20-byte address holds something wider. Whether
    /// every source domain Circle enables keeps these fields address-shaped is still Circle's to
    /// confirm.
    FieldNotEvmAddress {
        field: DepositIntentField,
    },
    /// The intent is addressed to a different destination domain than the faucet's.
    RemoteDomainMismatch {
        expected: u32,
        actual: u32,
    },
    /// The intent's `remoteToken` is not this faucet's account id.
    RemoteTokenMismatch,
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
            Self::FieldNotAssetAmount { field } => {
                write!(
                    f,
                    "deposit intent field {field:?} is not a valid asset amount"
                )
            }
            Self::FieldNotEvmAddress { field } => {
                write!(
                    f,
                    "deposit intent field {field:?} is not a right-aligned evm address"
                )
            }
            Self::RemoteDomainMismatch { expected, actual } => {
                write!(
                    f,
                    "deposit intent remote domain {actual} is not the faucet domain {expected}"
                )
            }
            Self::RemoteTokenMismatch => {
                write!(
                    f,
                    "deposit intent remote token is not the faucet account id"
                )
            }
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
