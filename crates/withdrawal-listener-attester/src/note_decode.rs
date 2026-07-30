//! `note_decode` (PURE) — what a discovered burn note SAYS: its `NoteStorage.items` payload decoded
//! into Circle's documented [`BurnPayload`], and its `metadata.sender` read as the Miden burner.
//!
//! # The codec is the shared encoding crate's, consumed by reference
//!
//! The `(amount, destDomain, destRecipient, salt)` felt layout — `amount` at `[0]`, `destDomain` at
//! `[1]`, `destRecipient` at `[2..10]`, `salt` at `[10..18]`, `BURN_NOTE_ITEMS_FELTS = 18` — is
//! the burn-note payload codec, and that codec is OWNED by `xusdc-encoding`
//! ([`decode_burn_note_items`]). This module calls it; it re-derives no offset,
//! packs no felt, and reads no byte. The layout appears nowhere below, deliberately: the burn note
//! is written on-chain against that codec and read here, and a second implementation of it — even a
//! correct one — is a place where the two can drift, and the units it would drift in are dollars.
//!
//! # What it refuses
//!
//! Both entry points are total: they return a [`DecodeError`], never a partial or defaulted value.
//! A malformed payload yields no [`BurnPayload`]; an absent or zero `metadata.sender` yields no
//! [`AccountId`]. The second one is the one that matters most — the sender read here is the value
//! that later becomes Circle's `remoteDepositor` (`sourceDepositor` is Circle's to assign
//! server-side, and stays OPEN), so fabricating a zero id would tell Circle a real burn was
//! initiated by an account that does not exist. The burner IS exposed by the protocol in
//! `metadata.sender` (a privacy exposure that stays OPEN with Circle — this module reads that
//! exposure; it does not claim to fix it).
//!
//! # NON-GATING here; the node leg is PARKED
//!
//! By design the burn note is `NoteType::Public` with a fixed full-32-bit tag, so `GetNotesById`
//! returns `details = Some(..)` and this decode has felts and a sender to work on at all; a private
//! note returns `details = None` and is unacceptable for Circle observability — the
//! [`BurnNoteMetadata::absent`] case below. PROVING that end-to-end (the exact-tag `SyncNotes`
//! scan, the retrieval, the inclusion proof) needs a real local node through `miden-client`, which
//! has no v0.16 release, so those steps are the GATING ones and they are **PARKED** for the
//! node-backed slice. Everything in this module is pure and node-free, so its own tests are
//! NON-GATING: they prove the decode, not the discovery.

use miden_protocol::account::AccountId;
use miden_protocol::note::NoteMetadata;
use miden_protocol::Felt;
use xusdc_encoding::xreserve::encoding::{account_id_to_felts, decode_burn_note_items};

use crate::error::{Cause, DecodeError};
use crate::types::BurnPayload;

/// The metadata a discovery run has for a candidate burn note — the sender, as REPORTED, before
/// anything vouches for it.
///
/// It is the crate's own type rather than the protocol's [`NoteMetadata`] because the two model
/// different moments. A `NoteMetadata` already contains a *validated* [`AccountId`]: by the time
/// one exists, the questions this module has to answer — was there any metadata at all? is the
/// sender a real id? — have been answered by someone else. What a node hands the listener is a note
/// that may have come back without details (a private or erased note, `details = None`,
/// unobservable to Circle) or with a sender that is not an id at all. This type can hold both, so
/// [`read_sender`] can refuse both instead of being handed a shape in which they are
/// unrepresentable.
///
/// The node-backed discovery leg constructs it from whichever the node gives it:
/// [`Self::from_metadata`] when the note came back public and typed, [`Self::from_raw_sender`] from
/// the raw felt pair, and [`Self::absent`] when it came back with nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurnNoteMetadata {
    /// The reported `metadata.sender` as the felt pair `(prefix, suffix)`, or `None` when the note
    /// carried no metadata at all.
    sender: Option<(Felt, Felt)>,
}

impl BurnNoteMetadata {
    /// The metadata of a note that came back with its details — the public burn note the happy path
    /// discovers.
    pub fn from_metadata(meta: &NoteMetadata) -> Self {
        let [prefix, suffix] = account_id_to_felts(meta.sender());
        Self {
            sender: Some((prefix, suffix)),
        }
    }

    /// The raw `(prefix, suffix)` sender felts, exactly as reported and not yet known to be an
    /// account id.
    pub fn from_raw_sender(prefix: Felt, suffix: Felt) -> Self {
        Self {
            sender: Some((prefix, suffix)),
        }
    }

    /// A note that came back with no metadata — `details = None`, the private/erased case.
    pub fn absent() -> Self {
        Self { sender: None }
    }
}

/// Decodes a burn note's `NoteStorage.items` into Circle's documented [`BurnPayload`]
/// `(amount, dest_domain, dest_recipient, salt)`.
///
/// The decode IS the shared encoding crate's [`decode_burn_note_items`] (single-owner);
/// [`BurnPayload`] is that codec's `XReserveBurnItems`, so the mapping is the identity and there is
/// no field to get wrong here. The only thing this wrapper adds is the crate-level refusal, and it
/// adds it without losing anything: the codec's own
/// [`EncodingError`](xusdc_encoding::xreserve::encoding::EncodingError) is carried through as the
/// preserved source.
///
/// # Errors
///
/// [`DecodeError::BurnItemsMalformed`] if the felts are not a well-formed burn payload — a felt
/// count other than 18, an out-of-range `amount` or `destDomain`, or a non-`u32` bytes32 limb. No
/// partial payload is ever surfaced.
pub fn decode_burn_payload(items: &[Felt]) -> Result<BurnPayload, DecodeError> {
    decode_burn_note_items(items).map_err(|source| DecodeError::BurnItemsMalformed { source })
}

/// Reads `metadata.sender` — the account that created the burn note, i.e. the Miden burner.
///
/// This is the value that becomes Circle's `remoteDepositor` (via the shared encoding crate's
/// `AccountId ↔ bytes32` codec, at the request-building step — the packaging is still OPEN with
/// Circle). It is therefore returned only when it is a genuine, canonical account id.
///
/// # Errors
///
/// [`DecodeError::SenderAbsent`] if the note carried no metadata (a private or erased note),
/// [`DecodeError::SenderZero`] if the reported sender is the zero felt pair, and
/// [`DecodeError::SenderMalformed`] if the felts are not a canonical [`AccountId`]. In every case
/// the answer is a refusal — never a zero or otherwise fabricated depositor.
pub fn read_sender(meta: &BurnNoteMetadata) -> Result<AccountId, DecodeError> {
    let (prefix, suffix) = meta.sender.ok_or(DecodeError::SenderAbsent)?;

    // Checked before the id conversion, and reported as its own variant: a zero sender is not just
    // "some invalid id" — it is the exact shape a fabricated depositor would take, and an operator
    // reading the logs should see it named.
    if prefix == Felt::ZERO && suffix == Felt::ZERO {
        return Err(DecodeError::SenderZero);
    }

    AccountId::try_from_elements(suffix, prefix).map_err(|source| DecodeError::SenderMalformed {
        source: Cause::new(source),
    })
}
