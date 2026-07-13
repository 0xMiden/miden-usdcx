//! `populate_advice` — the advice-map witness for the mint note's attachments.
//!
//! **RIV-ADVICE-KEY — reconciled against the on-chain reader, ADJUDICATED by the human operator on
//! 2026-07-13. The full record is `RIV-ADVICE-KEY.md`; the short version:**
//!
//! The relayer publishes each attachment's content under **the commitment of that content**:
//!
//! ```text
//! advice_map[ attachment.content().to_commitment() ] = attachment.content().to_elements()
//! ```
//!
//! Two consumers read those entries, and neither is free to choose the key:
//!
//! - the **producer** transaction that CREATES the note resolves each attachment's content out of
//!   the advice map by its commitment (`output_note::add_attachment`) — an attachment whose content
//!   is missing from the map cannot be emitted at all, which is why the routing target is published
//!   alongside the attestation;
//! - the **faucet's** `receive_and_mint` shim, consuming the note, loads the scheme-1 attestation's
//!   commitment out of the note-committed attachment-commitments list (by its found index) and calls
//!   `adv.push_mapval` on exactly that word (`xreserve_mint_note_entry.masm`), after hash-verifying
//!   the content against it.
//!
//! The key is therefore a hash of the attested bytes themselves. It is NOT the note commitment —
//! which is what the pre-F5 spec paraphrase named (`COMPONENT-SPEC.md:215`, itself labelled
//! `REQUIRES IMPLEMENTATION VALIDATION`). That contradiction was reported under G5's STOP rule and
//! decided by the human, not by this loop. The 9-felt pubkey and 17-felt signature travel INSIDE the
//! attestation's content, which is what the spec's actual relayer-side contract asks for: "the
//! 9-felt pubkey and 17-felt sig are reachable in advice/attachments at submission time".
//!
//! [`populate_advice`] fails closed on a caller mismatch: the `sig`/`pubkey` it is handed must be
//! the ones the note already commits to. Publishing a witness that disagrees with the note's
//! committed attachment would build a mint the faucet rejects on-chain (the shim's hash check), so
//! the crossed wire surfaces here, off-chain, where it costs nothing.

use miden_client::transaction::TransactionRequestBuilder;
use miden_protocol::{Felt, Word};

use crate::error::RelayerError;
use crate::miden::mint_note_builder::{attestation_attachment_of, BuiltMintNote};

/// The advice-map surface the mint transaction is built through.
///
/// It models `miden-client`'s real builder, which **consumes** `self`
/// (`TransactionRequestBuilder::extend_advice_map(mut self, …) -> Self`, `#[must_use]`) — so the
/// spec's sketched `&mut TransactionRequestBuilder` shape is not expressible against the actual API,
/// and this trait takes and returns the builder instead. [`TransactionRequestBuilder`] is the
/// production implementation; the relayer's tests use a recording fake for fast feedback ONLY
/// (T-RLY-16, explicitly NON-GATING), never as a stand-in for it.
pub trait AdviceMapSink: Sized {
    /// Extends the advice map with `(key, value)` pairs, returning the extended sink.
    fn with_advice_entries(self, entries: Vec<(Word, Vec<Felt>)>) -> Self;
}

/// The production sink: the real `miden-client` transaction-request builder.
impl AdviceMapSink for TransactionRequestBuilder {
    fn with_advice_entries(self, entries: Vec<(Word, Vec<Felt>)>) -> Self {
        self.extend_advice_map(entries)
    }
}

/// The advice entries the mint transaction must carry: every attachment of `note`, keyed by its
/// content commitment (RIV-ADVICE-KEY — see the module docs).
///
/// `sig` and `pubkey` do not BUILD the entries — the note already commits to them. They are the
/// cross-check that the attestation the caller is relaying is the attestation the note carries.
///
/// # Errors
///
/// [`RelayerError::AttestationMismatch`] if the note's scheme-1 attestation attachment is not
/// unit-04's attachment for `sig`/`pubkey`.
pub fn mint_note_advice_entries(
    note: &BuiltMintNote,
    sig: &[u8; 65],
    pubkey: &[u8; 33],
) -> Result<Vec<(Word, Vec<Felt>)>, RelayerError> {
    // The crossed-wire guard, BEFORE anything is produced.
    attestation_attachment_of(note.note(), sig, pubkey)?;

    // Every attachment, keyed by its own content commitment. Values are word-aligned structurally:
    // an attachment's content IS a list of words.
    Ok(note
        .note()
        .attachments()
        .iter()
        .map(|attachment| {
            (
                attachment.content().to_commitment(),
                attachment.content().to_elements(),
            )
        })
        .collect())
}

/// Populates `sink`'s advice map with the mint note's attachment witnesses and returns it.
///
/// Fail-closed: on a mismatch NOTHING is written — the entries are computed and checked in full
/// before the sink is touched, and the sink is returned only on success.
///
/// # Errors
///
/// [`RelayerError::AttestationMismatch`] — see [`mint_note_advice_entries`].
pub fn populate_advice<S: AdviceMapSink>(
    sink: S,
    note: &BuiltMintNote,
    sig: &[u8; 65],
    pubkey: &[u8; 33],
) -> Result<S, RelayerError> {
    // The `?` is what makes this fail-closed: the entries are computed and checked IN FULL before
    // the sink is touched, so a mismatch returns the error and the sink is never extended.
    let entries = mint_note_advice_entries(note, sig, pubkey)?;
    Ok(sink.with_advice_entries(entries))
}
