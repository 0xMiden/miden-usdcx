//! **B3's feed** — the exact-tag `SyncNotes` scan and the `GetNotesById` retrieval, over
//! `miden-client`'s [`NodeRpcClient`].
//!
//! Two RPCs and the translations between them. The RPCs need a node; the translations do not, and
//! they are where a fund-safety mistake would live — so [`exact_tag_matches`], [`discovered_note`]
//! and [`reconcile_retrieval`] are pure functions over the client's own reply types, and the async
//! adapter is the thin thing that calls them.
//!
//! # Every scanned id is accounted for
//!
//! The scan says which notes exist; the retrieval says what they are, and nothing makes the second
//! answer the first. A node that leaves a scanned id out of its `GetNotesById` reply would, if that
//! were absorbed, produce a range that looks complete while a real burn sits inside it unprocessed
//! — and the caller's cursor would move past it. So [`reconcile_retrieval`] requires every scanned
//! id to be answered exactly once and fails the read otherwise: a gap is surfaced with the ids in
//! it, and the range is retried whole rather than reported as done.
//!
//! # Exact tags, never a prefix
//!
//! `SyncNotes` matches note tags by full 32-bit equality; the 16-bit prefix belongs to
//! `SyncNullifiers`. The client's own docs say returned notes are NOT verified to carry a requested
//! tag, so the equality is re-checked here rather than assumed — a note sharing only the burn tag's
//! high 16 bits is a different note, and treating it as a burn is how a stranger's note reaches the
//! withdrawal path.
//!
//! # The retrieval reports; the checklist judges
//!
//! [`discovered_note`] maps a node reply into the record
//! [`validate_discovery`](crate::validate::validate_discovery) validates, and it refuses nothing. A
//! private note becomes `details = None` (the shape the model already expects); a public note's
//! script root and vault are read off the note itself, whatever they are; a note with no withdrawal
//! attachment reports no payload felts rather than a fabricated one. Every one of those is then
//! refused BY THE CHECKLIST, which is what makes the checklist's tests mean something against a real
//! node.

use std::collections::BTreeSet;

use miden_client::rpc::domain::note::{CommittedNote, FetchedNote};
use miden_client::rpc::NodeRpcClient;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteAttachmentScheme, NoteId, NoteTag};
use xusdc_encoding::note::xreserve_burn::{
    XReserveBurnNote, XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME,
};

use crate::error::Cause;
use crate::listener::DiscoveredNote;
use crate::validate::{DiscoveredDetails, DiscoveryRecord};

/// The two RPC names this module can fail on, spelled as the node's API spells them so an operator
/// reading a log can look the call up.
const SYNC_NOTES: &str = "SyncNotes";
const GET_NOTES_BY_ID: &str = "GetNotesById";

/// The withdrawal-payload attachment scheme, taken from the shared encoding crate that assigned it:
/// the burn note WRITES this scheme, so the read side names it by reference rather than by number.
const WITHDRAWAL_ATTACHMENT: NoteAttachmentScheme =
    NoteAttachmentScheme::new_const(XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME);

// THE PORT
// ================================================================================================

/// **B3's feed**: every candidate burn note committed in a block range.
///
/// A port rather than a concrete client, for the reason every other seam in this crate is one — the
/// orchestration's suites drive it without a node, and an operator can put a different transport
/// behind it. [`RpcBurnNoteDiscovery`] is the `miden-client` implementation.
///
/// The range is the caller's: where the cursor lives and how often it advances belongs to the
/// service binary, not to a read adapter.
#[async_trait::async_trait]
pub trait BurnNoteDiscovery {
    /// Every note committed in `block_from..=block_to` carrying the configured burn tag, as
    /// reported. Reported, not validated: the returned notes still go through
    /// [`validate_discovery`](crate::validate::validate_discovery).
    ///
    /// # Errors
    /// [`DiscoveryReadError`] — one of the two reads failed, or the retrieval did not account for
    /// every note the scan matched (a [`RetrievalGap`]). An empty range is an empty answer, not an
    /// error.
    async fn discover(
        &self,
        block_from: BlockNumber,
        block_to: BlockNumber,
    ) -> Result<Vec<DiscoveredNote>, DiscoveryReadError>;
}

// THE PURE TRANSLATIONS
// ================================================================================================

/// The ids of the scanned notes whose tag is EXACTLY `burn_tag`, in the order the node listed them.
///
/// The equality is over the full `u32`. `SyncNotes` does not prefix-scan, and the client does not
/// verify that what came back carries a requested tag, so this is where "the node answered about
/// our tag" is actually established. A `>> 16` comparison here would select every note sharing the
/// burn tag's high half.
pub fn exact_tag_matches<'a>(
    notes: impl IntoIterator<Item = &'a CommittedNote>,
    burn_tag: u32,
) -> Vec<NoteId> {
    notes
        .into_iter()
        .filter(|note| note.tag().as_u32() == burn_tag)
        .map(|note| *note.note_id())
        .collect()
}

/// One `GetNotesById` reply → the [`DiscoveredNote`] B3 validates.
///
/// The id is the note's OWN id, and the record says what the node said:
///
/// * **tag** — straight off the reply's metadata, whatever it is. A wrong tag is
///   [`validate_discovery`](crate::validate::validate_discovery)'s to refuse; dropping it here
///   would make the checklist's first rung unobservable against a real node.
/// * **details** — `Some(..)` for a PUBLIC note, `None` for a private or erased one. A private note
///   comes back without its columns, so there is genuinely nothing to report.
/// * **the payload felts** — the words of the note's withdrawal-payload attachment, truncated to the
///   shared codec's own [`XReserveBurnNote::NUM_PAYLOAD_ITEMS`] (attachments are word-aligned, so
///   the 18 payload felts arrive zero-padded to 20). A note carrying no such attachment reports NO
///   felts, and the decode refuses it — nothing is invented for a note that has none.
/// * **the script root and the vault** — read off the note itself. These are the two facts the
///   fund-safety rungs judge, so a value derived from anything but the note would make them
///   vacuous.
pub fn discovered_note(fetched: &FetchedNote) -> DiscoveredNote {
    let details = match fetched {
        FetchedNote::Public(note, _) => {
            let mut items = note
                .attachments()
                .find(WITHDRAWAL_ATTACHMENT)
                .map(|attachment| attachment.to_elements())
                .unwrap_or_default();
            items.truncate(XReserveBurnNote::NUM_PAYLOAD_ITEMS);

            Some(DiscoveredDetails::from_metadata(
                items,
                note.metadata(),
                note.script().root(),
                note.assets().as_slice().to_vec(),
            ))
        }
        // a private/erased note came back without its columns: no payload, no script, no vault.
        FetchedNote::Private(..) => None,
    };

    DiscoveredNote::new(
        fetched.id(),
        DiscoveryRecord::new(fetched.metadata().tag().as_u32(), details),
    )
}

/// The scan's ids and the retrieval's rows, reconciled into one [`DiscoveredNote`] per SCANNED id —
/// or the gap that stopped it.
///
/// A scanned id is a note the node itself told us exists at the burn tag. Two things can happen to
/// one on the way through `GetNotesById`, and both are the same fund-safety problem — a burn that
/// was SEEN and then never processed, while the caller advances its cursor past the range:
///
/// * **omitted** — a scanned id with no row. That is not "no such note"; the scan just reported it.
/// * **duplicated** — a scanned id with more than one row. Nothing here can choose between two
///   answers to one question, and emitting both would walk one burn down the withdrawal path twice.
///
/// Neither is absorbed. Both fail the read, naming the ids, so an omitted burn leaves a trace an
/// operator can act on instead of disappearing into a successful-looking range.
///
/// A row for an id the scan did NOT select is IGNORED — an unrequested note is not something this
/// scan discovered, and carrying it would let a node inject a candidate the tag filter never
/// selected. Ignored, never counted: an extra row cannot stand in for a missing one, which is the
/// difference between this and comparing the two lengths.
///
/// The same id listed twice by the SCAN is one note, so it is reconciled once — a note repeated
/// across the scanned blocks is not two burns.
///
/// The records come back in scan order, so what the caller sees does not depend on how the node
/// happened to order its rows.
///
/// # Errors
/// [`RetrievalGap`] — at least one scanned id was not answered exactly once.
pub fn reconcile_retrieval(
    scanned: &[NoteId],
    fetched: &[FetchedNote],
) -> Result<Vec<DiscoveredNote>, RetrievalGap> {
    let mut discovered = Vec::with_capacity(scanned.len());
    let mut accounted: Vec<NoteId> = Vec::with_capacity(scanned.len());
    let mut omitted = Vec::new();
    let mut duplicated = Vec::new();

    for id in scanned {
        if accounted.contains(id) {
            continue;
        }
        accounted.push(*id);

        // asked once, so answered once: a second row for the same id is the node answering
        // something other than the question.
        let mut answers = fetched.iter().filter(|note| note.id() == *id);
        match (answers.next(), answers.next()) {
            (Some(note), None) => discovered.push(discovered_note(note)),
            (None, _) => omitted.push(*id),
            (Some(_), Some(_)) => duplicated.push(*id),
        }
    }

    if omitted.is_empty() && duplicated.is_empty() {
        Ok(discovered)
    } else {
        Err(RetrievalGap {
            omitted,
            duplicated,
        })
    }
}

// THE CLIENT-BACKED ADAPTER
// ================================================================================================

/// The `miden-client` [`BurnNoteDiscovery`]: `SyncNotes` for the configured tag, then
/// `GetNotesById` for what it matched.
///
/// It holds the burn tag rather than the whole [`ListenerConfig`](crate::config::ListenerConfig)
/// because the tag is the only thing a scan needs, and a read adapter that could see the attester
/// allowlist or the API credential is a read adapter that eventually logs one.
pub struct RpcBurnNoteDiscovery<R> {
    rpc: R,
    burn_tag: u32,
}

impl<R> RpcBurnNoteDiscovery<R> {
    /// Scans `rpc` for notes carrying the full 32-bit `burn_tag`.
    pub fn new(rpc: R, burn_tag: u32) -> Self {
        Self { rpc, burn_tag }
    }
}

#[async_trait::async_trait]
impl<R> BurnNoteDiscovery for RpcBurnNoteDiscovery<R>
where
    R: NodeRpcClient + Send + Sync,
{
    async fn discover(
        &self,
        block_from: BlockNumber,
        block_to: BlockNumber,
    ) -> Result<Vec<DiscoveredNote>, DiscoveryReadError> {
        // the scan. One tag, asked for whole.
        let tags = BTreeSet::from([NoteTag::new(self.burn_tag)]);
        let blocks = self
            .rpc
            .sync_notes(block_from, block_to, &tags)
            .await
            .map_err(|source| DiscoveryReadError::new(SYNC_NOTES, source))?;

        // …and the exact-tag filter over what came back, because the client does not apply one.
        let ids = exact_tag_matches(
            blocks.iter().flat_map(|block| block.notes.values()),
            self.burn_tag,
        );
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        // the retrieval. Notes the node volunteered that were not asked about are dropped: an
        // unrequested note is not something this scan discovered, and carrying it would let a node
        // inject a candidate the tag filter above never selected.
        let fetched = self
            .rpc
            .get_notes_by_id(&ids)
            .await
            .map_err(|source| DiscoveryReadError::new(GET_NOTES_BY_ID, source))?;

        // …and the accounting, which is what makes the answer above a whole one. A scanned id the
        // retrieval does not answer for exactly once FAILS the read rather than quietly shrinking
        // it: the caller retries the range with its cursor where it was, so no burn the scan saw is
        // lost between the two RPCs.
        Ok(reconcile_retrieval(&ids, &fetched)?)
    }
}

// THE ERRORS
// ================================================================================================

/// A retrieval that did not account for the scan: the ids `GetNotesById` left unanswered, and the
/// ids it answered more than once.
///
/// It is a cause rather than a read failure of its own — it travels inside a
/// [`DiscoveryReadError`] for `GetNotesById`, because from the caller's side that read did not
/// deliver what was asked of it. What makes it worth a type is the payload: an operator
/// reconciling a range needs the ids, not a count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalGap {
    omitted: Vec<NoteId>,
    duplicated: Vec<NoteId>,
}

impl RetrievalGap {
    /// The scanned ids the retrieval returned nothing for — the burns that would have been dropped.
    pub fn omitted(&self) -> &[NoteId] {
        &self.omitted
    }

    /// The scanned ids the retrieval answered more than once.
    pub fn duplicated(&self) -> &[NoteId] {
        &self.duplicated
    }
}

impl core::fmt::Display for RetrievalGap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let hex = |ids: &[NoteId]| {
            ids.iter()
                .map(NoteId::to_hex)
                .collect::<Vec<_>>()
                .join(", ")
        };

        write!(
            f,
            "the retrieval did not account for every note the scan matched"
        )?;
        if !self.omitted.is_empty() {
            write!(f, "; unanswered: {}", hex(&self.omitted))?;
        }
        if !self.duplicated.is_empty() {
            write!(f, "; answered more than once: {}", hex(&self.duplicated))?;
        }
        Ok(())
    }
}

impl core::error::Error for RetrievalGap {}

impl From<RetrievalGap> for DiscoveryReadError {
    /// A gap is a failure OF `GetNotesById`: the retrieval was asked about a set of ids and did not
    /// answer for them. Naming that RPC — and keeping the gap as the error's `source` — is what
    /// puts the unaccounted-for ids in front of the operator who has to reconcile them.
    fn from(gap: RetrievalGap) -> Self {
        Self::new(GET_NOTES_BY_ID, gap)
    }
}

/// A failed discovery read, naming the RPC it failed on and preserving the underlying cause.
///
/// The twin of [`EvidenceReadError`](crate::evidence::EvidenceReadError), and deliberately a
/// separate type: each port owns its own error, so widening one cannot silently widen the other.
#[derive(Debug, Clone)]
pub struct DiscoveryReadError {
    rpc: &'static str,
    cause: Cause,
}

impl DiscoveryReadError {
    /// Preserves `cause` as the reason `rpc` failed.
    pub fn new(rpc: &'static str, cause: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self {
            rpc,
            cause: Cause::new(cause),
        }
    }

    /// The RPC that failed, as the node's API names it.
    pub fn rpc(&self) -> &'static str {
        self.rpc
    }
}

impl core::fmt::Display for DiscoveryReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the {} read failed: {}", self.rpc, self.cause)
    }
}

impl core::error::Error for DiscoveryReadError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.cause.as_error())
    }
}
