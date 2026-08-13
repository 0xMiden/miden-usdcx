//! Decoding and structurally validating a DepositIntent before it is relayed.
//!
//! This is a LIVENESS check, not a safety one. The faucet re-derives the message on-chain and
//! re-runs every field assert before it mints; a bug here can only stop a legitimate deposit from
//! being relayed, never cause an illegitimate one to be minted. What it buys is a fast, local
//! rejection with a precise reason, instead of a transaction that fails on-chain.
//!
//! The decoded value is the shared `xusdc-encoding` crate's own [`DepositIntent`] — this module
//! keeps no field model, no offsets and no codec of its own. Its whole job is to map the shared
//! codec's rejections onto the field-specific [`RelayerError`], so an operator sees which rule the
//! payload broke. That single ownership is what keeps the off-chain and on-chain views of the same
//! bytes from drifting.
//!
//! One arithmetic trap is worth naming, because it is easy to get wrong and silently wrong: the
//! 240-byte header packs to 60 field elements, not 30. Each element holds four bytes, not eight.

use xusdc_encoding::xreserve::encoding::DepositIntent;

use crate::error::RelayerError;

/// Decodes and structurally validates a DepositIntent payload — the off-chain fast-fail mirror of
/// the checks the faucet performs on-chain.
///
/// The checks, all performed by the shared codec: `magic == 0x5a2e0acd`, `version == 1`, `len ==
/// 240 + hookDataLen`, `amount != 0`, `localToken != 0`, `localDepositor != 0`, and that hookData
/// fits the `NoteStorage` felt bound. Returns the exact failed-field variant on rejection.
///
/// # Errors
///
/// The field-specific [`RelayerError`] the shared codec's [`EncodingError`] maps to — see
/// [`RelayerError::from_deposit_intent`].
///
/// [`EncodingError`]: xusdc_encoding::xreserve::encoding::EncodingError
pub fn decode_and_validate_deposit_intent(payload: &[u8]) -> Result<DepositIntent, RelayerError> {
    DepositIntent::try_from(payload).map_err(RelayerError::from_deposit_intent)
}
