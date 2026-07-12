//! The `RelayerError` taxonomy — STARTED in the scaffold slice with the DepositIntent
//! structural-reject family (the off-chain mirror of D5a; INV-DEPOSITINTENT-PARSE) plus the
//! NoteStorage felt-count guard, and EXTENDED here with the attestation-envelope family (DC-2,
//! INV-DEPOSIT-ATTESTATION-RAW-KECCAK): wire-hex decode, `messageHash` shape + raw-keccak binding,
//! and attestation shape. Later slices add the remaining Circle-facing variants (HTTP status,
//! schema decode, tx-hash shape) and the Miden-facing ones (note build, submit). The enum is
//! `#[non_exhaustive]` so those additions are not breaking changes.

use core::fmt;

use xusdc_encoding::xreserve::encoding::{DepositIntentField, EncodingError};

/// Which Circle-facing wire field failed to hex-decode. Named (not a string) so a caller — and a
/// test — asserts the EXACT field, never a coarse "some hex was bad".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HexField {
    /// The DepositIntent `payload` hex.
    Payload,
    /// The attestation envelope's `messageHash` hex.
    MessageHash,
    /// The `attestation` (`r‖s‖v`) hex.
    Attestation,
}

impl fmt::Display for HexField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Payload => write!(f, "payload"),
            Self::MessageHash => write!(f, "messageHash"),
            Self::Attestation => write!(f, "attestation"),
        }
    }
}

// The originating hex failure is CARRIED, not mirrored: `RelayerError::MalformedHex` holds the
// `hex::FromHexError` itself, so `Error::source()` traverses to it and a caller can `downcast_ref`
// the typed cause (G-RUST preserve-error-source). This costs the enum its `Eq` derive — the hex
// error is `PartialEq` but not `Eq` — which is the right trade: no caller compares relayer errors
// for total equality, but a Circle-input rejection must never discard WHY the input was malformed.

/// Relayer error taxonomy. Every DepositIntent field violation carries its OWN named variant so
/// callers (and the tests) assert the exact failed field, never a coarse `is_err()`. Each variant
/// also carries the originating unit-04 [`EncodingError`] as its error source — the field-specific
/// relayer name never discards the underlying cause (G-RUST preserve-error-source).
// `Eq` is deliberately absent: `MalformedHex` carries the originating `hex::FromHexError` (which is
// `PartialEq` but not `Eq`) so the typed cause survives in the `source()` chain. `PartialEq` is
// retained, so errors still compare by value.
#[derive(Debug, Clone, PartialEq)]
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

    // ATTESTATION-ENVELOPE FAMILY (DC-2; INV-DEPOSIT-ATTESTATION-RAW-KECCAK)
    // --------------------------------------------------------------------------------------------
    /// A Circle-facing wire field is not valid hex. Names WHICH field, and PRESERVES the originating
    /// [`hex::FromHexError`] as its source (the exact character and index) — reachable through the
    /// typed [`Self::hex_source`] accessor and the std [`Error::source`](core::error::Error) chain.
    MalformedHex {
        field: HexField,
        source: hex::FromHexError,
    },
    /// `messageHash` is not 32 bytes (a keccak256 digest is exactly 32). A SHAPE error, reported as
    /// such — never reclassified as a binding mismatch.
    BadMessageHashLength { actual: usize },
    /// `messageHash != keccak256(payload)` — the envelope does not bind the payload it claims to
    /// (INV-DEPOSIT-ATTESTATION-RAW-KECCAK). `expected` is the true RAW keccak256 of the full
    /// payload; `actual` is the digest Circle presented. Carrying both makes an operator's
    /// "which hash family did they send?" answerable straight from the log line.
    MessageHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// The attestation is not exactly 65 bytes (`r‖s‖v`). Note 64 bytes — a `v`-less signature — is
    /// rejected here, not silently zero-extended.
    BadAttestationLength { actual: usize },
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
    ///
    /// `None` for the envelope family — no unit-04 codec is involved on that path. (A malformed-hex
    /// rejection still preserves ITS cause: see [`Self::hex_source`].)
    pub fn encoding_source(&self) -> Option<&EncodingError> {
        match self {
            Self::BadMagic(e)
            | Self::BadVersion(e)
            | Self::LengthMismatch(e)
            | Self::ZeroAmount(e)
            | Self::ZeroLocalToken(e)
            | Self::ZeroLocalDepositor(e)
            | Self::ShortHeader(e)
            | Self::PreimageTooLarge(e)
            | Self::DepositIntentCodec(e) => Some(e),
            Self::MalformedHex { .. }
            | Self::BadMessageHashLength { .. }
            | Self::MessageHashMismatch { .. }
            | Self::BadAttestationLength { .. } => None,
        }
    }

    /// The originating [`hex::FromHexError`] preserved by [`Self::MalformedHex`] — the typed view of
    /// the same value the std [`Error::source`](core::error::Error) chain returns, so a caller can
    /// see WHICH character at WHICH index broke the decode without a `downcast`.
    ///
    /// `None` for every other variant (nothing was hex-decoded).
    pub fn hex_source(&self) -> Option<&hex::FromHexError> {
        match self {
            Self::MalformedHex { source, .. } => Some(source),
            _ => None,
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
            // the cause is also reachable via source(); it is inlined here so a single logged line
            // is self-explanatory
            Self::MalformedHex { field, source } => {
                write!(f, "malformed {field} hex: {source}")
            }
            Self::BadMessageHashLength { actual } => write!(
                f,
                "message hash must be 32 bytes (keccak256), got {actual}"
            ),
            // the digests are the whole point of the diagnostic, so they are rendered in full
            Self::MessageHashMismatch { expected, actual } => write!(
                f,
                "message hash does not bind the payload: expected keccak256(payload) = 0x{}, got 0x{}",
                hex::encode(expected),
                hex::encode(actual)
            ),
            Self::BadAttestationLength { actual } => write!(
                f,
                "attestation must be 65 bytes (r||s||v), got {actual}"
            ),
        }
    }
}

impl core::error::Error for RelayerError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        // Every variant that HAS a lower-level cause exposes it here, so `source()` traverses to the
        // real typed error (`EncodingError` on the DepositIntent path, `hex::FromHexError` on the
        // wire-decode path) and callers can `downcast_ref` it. The remaining envelope variants
        // (length / binding mismatch) are genuine leaves — the relayer itself is the authority there,
        // so no cause exists and none is invented.
        match self {
            Self::MalformedHex { source, .. } => Some(source),
            _ => self
                .encoding_source()
                .map(|e| e as &(dyn core::error::Error + 'static)),
        }
    }
}
