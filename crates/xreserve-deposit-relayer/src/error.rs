//! The `RelayerError` taxonomy — STARTED in this scaffold slice with the DepositIntent
//! structural-reject family (the off-chain mirror of D5a; INV-DEPOSITINTENT-PARSE) plus the
//! NoteStorage felt-count guard. Later slices extend it with the Circle-facing variants (HTTP
//! status, schema decode, `messageHash` mismatch, attestation/tx-hash shape) and the Miden-facing
//! variants (note build, submit) named in COMPONENT-SPEC §7/§8.8. The enum is `#[non_exhaustive]`
//! so those additions are not breaking changes.

use core::fmt;

use xusdc_encoding::xreserve::encoding::{DepositIntentField, EncodingError};

/// Relayer error taxonomy. Every DepositIntent field violation carries its OWN named variant so
/// callers (and the tests) assert the exact failed field, never a coarse `is_err()`. Each variant
/// also carries the originating unit-04 [`EncodingError`] as its error source — the field-specific
/// relayer name never discards the underlying cause (G-RUST preserve-error-source).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayerError {
    /// `magic != 0x5a2e0acd` (DC-1 field 0).
    BadMagic(EncodingError),
    /// `version != 1` (DC-1 field 1).
    BadVersion(EncodingError),
    /// `payload.len() != 240 + hookDataLen` (DC-1 total-length relation).
    LengthMismatch(EncodingError),
    /// `amount == 0` (DC-1 field 2).
    ZeroAmount(EncodingError),
    /// `localToken == 0` (DC-1 field 6).
    ZeroLocalToken(EncodingError),
    /// `localDepositor == 0` (DC-1 field 7).
    ZeroLocalDepositor(EncodingError),
    /// payload shorter than the fixed 240-byte DepositIntent header.
    ShortHeader(EncodingError),
    /// the u32-LE preimage (60 header felts + `ceil(hookDataLen / 4)`) exceeds the 1024-felt
    /// NoteStorage bound (INV-NOTE-MODEL-CURRENT; anti-ASG-16 — the header is 60 felts, not 30).
    PreimageTooLarge(EncodingError),
    /// An encoding-layer error the DepositIntent path does not map to a specific field. Defensive
    /// catch-all; unit-04's DepositIntent parser/packer only emit the mapped variants above, so in
    /// practice this is never constructed by [`Self::from_deposit_intent`].
    DepositIntentCodec(EncodingError),
}

impl RelayerError {
    /// Maps a unit-04 [`EncodingError`] from the DepositIntent parse/pack path onto the
    /// field-specific relayer taxonomy, KEEPING the original error as the mapped variant's source.
    /// The mapping is DepositIntent-context-specific (hence a named function, not a blanket
    /// `From`): `TruncatedHeader → ShortHeader` and `HookDataTooLarge → PreimageTooLarge`.
    pub(crate) fn from_deposit_intent(err: EncodingError) -> Self {
        // Select the variant constructor by inspecting the error (borrow only), then move the
        // error into it — the field-specific name AND the underlying cause are both retained.
        let variant: fn(EncodingError) -> Self = match &err {
            EncodingError::BadMagic => Self::BadMagic,
            EncodingError::BadVersion => Self::BadVersion,
            EncodingError::LengthMismatch => Self::LengthMismatch,
            EncodingError::TruncatedHeader => Self::ShortHeader,
            EncodingError::HookDataTooLarge => Self::PreimageTooLarge,
            EncodingError::ZeroField {
                field: DepositIntentField::Amount,
            } => Self::ZeroAmount,
            EncodingError::ZeroField {
                field: DepositIntentField::LocalToken,
            } => Self::ZeroLocalToken,
            EncodingError::ZeroField {
                field: DepositIntentField::LocalDepositor,
            } => Self::ZeroLocalDepositor,
            _ => Self::DepositIntentCodec,
        };
        variant(err)
    }

    /// The originating unit-04 [`EncodingError`] preserved by every DepositIntent-path variant — a
    /// typed view of the same value returned through the std [`Error::source`](core::error::Error)
    /// chain, so callers can inspect the exact underlying cause without a `downcast`.
    pub fn encoding_source(&self) -> &EncodingError {
        match self {
            Self::BadMagic(e)
            | Self::BadVersion(e)
            | Self::LengthMismatch(e)
            | Self::ZeroAmount(e)
            | Self::ZeroLocalToken(e)
            | Self::ZeroLocalDepositor(e)
            | Self::ShortHeader(e)
            | Self::PreimageTooLarge(e)
            | Self::DepositIntentCodec(e) => e,
        }
    }
}

impl fmt::Display for RelayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic(_) => write!(f, "deposit intent magic mismatch"),
            Self::BadVersion(_) => write!(f, "deposit intent version mismatch"),
            Self::LengthMismatch(_) => write!(f, "deposit intent length relation violated"),
            Self::ZeroAmount(_) => write!(f, "deposit intent amount is zero"),
            Self::ZeroLocalToken(_) => write!(f, "deposit intent local token is zero"),
            Self::ZeroLocalDepositor(_) => write!(f, "deposit intent local depositor is zero"),
            Self::ShortHeader(_) => write!(f, "deposit intent payload is shorter than 240 bytes"),
            Self::PreimageTooLarge(_) => write!(
                f,
                "deposit intent preimage exceeds the 1024-felt note storage bound"
            ),
            Self::DepositIntentCodec(e) => write!(f, "deposit intent codec error: {e}"),
        }
    }
}

impl core::error::Error for RelayerError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.encoding_source())
    }
}
