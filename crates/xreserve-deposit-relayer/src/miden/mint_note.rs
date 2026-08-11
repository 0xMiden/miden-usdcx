//! `build_mint_note` — the DepositIntent-attestation → mint-note translation, and the
//! operator-configured attester index it needs.
//!
//! The builder is thin ON PURPOSE. It bundles the attestation the relayer VALIDATED (a
//! `ValidatedAttestation` has passed the raw-keccak digest binding and the 65-byte shape check)
//! with the attester index the OPERATOR configured, and hands both — plus the DepositIntent payload
//! (as the typed [`DepositIntent`](xusdc_encoding::xreserve::encoding::DepositIntent)) — to the
//! shared encoding crate's typed [`XUsdcMintNote`] builder,
//! which decides every byte of the note's form: the storage, the two attachments, the note type, and
//! the script.
//!
//! **Why the attester index is a parameter and the signature is not.** Circle's attestation object
//! carries `payload`, `messageHash`, and `attestation` (the 65-byte `r‖s‖v`) — but nothing that
//! says WHICH attester signed, and the faucet needs that to pick a key out of its own array. So the
//! index comes from the relayer's own configuration: it is the array position the operator was told
//! the administrator wrote that attester's key at. The payload and the signature are Circle's, and they reach this
//! module only through the validated boundary — there is no entry point that takes them as raw
//! bytes, because a note built from bytes whose `messageHash == keccak256(payload)` binding was
//! never checked is a transaction spent on an envelope the chain will reject.
//!
//! **What the builder can and cannot cause.** It is a liveness component: a bug here withholds a
//! mint (a note the faucet refuses, an error where a note should have been) — it cannot authorize
//! one. The nonce assert-then-set, the amount reduction, the attester-enabled check and the ECDSA
//! verification are all on-chain and faucet-owned. That is also why every failure path below
//! is a typed, NON-retryable error: a payload the codec refuses does not become valid on a retry,
//! and a relayer that looped on one would stop minting everything else.

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::Note;

use xusdc_encoding::note::xreserve_mint::{MintAttestation, XUsdcMintNote};

use crate::circle::schema::ValidatedAttestation;
use crate::error::{Cause, RelayerError};

/// The index of the attester whose key the faucet should verify against: a position in the
/// faucet's on-chain attester key array, travelling in every mint note.
///
/// A newtype rather than a bare `u32` because it is an operator-configured value that reaches the
/// chain unmodified, and nothing downstream would catch a mix-up with any other number. Its
/// validity is not something this crate can judge: an index is well-formed by construction, but
/// whether the ADMINISTRATOR wrote a key at it is known only to the faucet. A wrong index costs
/// every mint until someone reads the logs — the same failure the previous configured-pubkey form
/// had, and for the same reason: only the chain holds the truth.
///
/// It is NOT an authority. Naming an index does not enable an attester; only the administrator's
/// `set_attester` note does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttesterIndex(u32);

impl AttesterIndex {
    /// Wraps an attester key-array index.
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Parses the index as an operator writes it in configuration: a plain decimal `u32`.
    ///
    /// # Errors
    /// * [`RelayerError::MalformedAttesterIndex`] — not a decimal `u32`.
    pub fn parse(text: &str) -> Result<Self, RelayerError> {
        text.parse::<u32>()
            .map(Self)
            .map_err(|source| RelayerError::MalformedAttesterIndex(Cause::new(source)))
    }

    /// The raw index.
    pub const fn get(&self) -> u32 {
        self.0
    }
}

/// Builds the mint note for a validated Circle deposit attestation, by delegation to the shared
/// encoding crate's typed [`XUsdcMintNote`] builder (the DepositIntent crosses as
/// [`DepositIntent`](xusdc_encoding::xreserve::encoding::DepositIntent), handed over by
/// [`ValidatedAttestation::deposit_intent`](crate::circle::schema::ValidatedAttestation::deposit_intent)).
///
/// The parameters:
///
/// * `sender` — the relayer's own account.
/// * `faucet_id` — the xUSDC faucet the note is routed at. It must be a PUBLIC network account:
///   the routing attachment can bind nothing else.
/// * `attestation` — the validated envelope. Its DepositIntent payload and its 65-byte `r‖s‖v`
///   travel together in the merged scheme-4 transport attachment.
/// * `attester` — the operator-configured attester index, travelling beside the signature.
/// * `rng` — the caller's randomness. The serial number is drawn from it, which is what makes a
///   re-mint of the same DepositIntent a distinct note rather than a collision.
///
/// Nothing is ATTACHED to the note as an asset — `note.assets()` is empty — but the attested
/// amount travels all the same: it is embedded in the note's `MintNoteStorage` as the output
/// asset value, and the faucet mints exactly that amount when it consumes the note. The note is
/// public.
///
/// # Errors
/// [`RelayerError::MintNoteBuild`] — the shared encoding crate's factory refused the inputs: the
/// payload is not a structurally valid DepositIntent, or it is addressed to a different
/// faucet, or a field it must carry is unrepresentable (a `maxFee` beyond `AssetAmount::MAX`, a
/// `localToken` / `localDepositor` that is not a 20-byte address), or `faucet_id` is not a public
/// network account. That crate's `NoteError` (and the
/// `EncodingError` beneath it) is preserved as the error's source. The variant is NOT retryable —
/// none of those conditions clears on its own.
pub fn build_mint_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    attestation: &ValidatedAttestation,
    attester: AttesterIndex,
    rng: &mut R,
) -> Result<Note, RelayerError> {
    let mint_attestation = MintAttestation::new(attestation.attestation(), attester.get());

    // Adopt the typed builder at the production boundary: the Circle envelope hands over the typed
    // `DepositIntent`, so no raw `&[u8]` crosses the ingestion boundary.
    XUsdcMintNote::builder()
        .sender(sender)
        .faucet_id(faucet_id)
        .deposit_intent(attestation.deposit_intent())
        .attestation(&mint_attestation)
        .rng(rng)
        .build()
        .map_err(|source| RelayerError::MintNoteBuild(Cause::new(source)))
}
