//! Burn execution, discovery, and supply observations.
//! Same-block evidence records what the node exposes; Circle's acceptance decision remains OPEN.

use serde::Serialize;

pub use crate::observations_cf::{Verdict, Word4};

/// One **Row G** two-block burn — the Circle read-path proof.
///
/// A holder creates the PRODUCTION `XReserveBurnNote` (committed in block N via its own emit tx),
/// the ntx-builder (path N) consumes it in a strictly-later block N+1 (`token_supply -= amount`),
/// and the committed note + its nullifier PERSIST so Circle's off-chain withdrawal attester can
/// discover the burn: `SyncNotes` filtered by the fixed burn tag finds it and `GetNotesById`
/// returns the full note + inclusion proof (the byte-exact capture is a deliverable).
///
/// Every field is a NODE-fetched read-back or the outcome of a real committed transaction.
#[derive(Debug, Clone, Serialize)]
pub struct BurnTwoBlock {
    /// A human label for the arc (`two-block-burn`).
    pub label: String,
    /// The reduced (on-chain) amount this burn removes from `token_supply` and the note carries.
    pub amount_units: u64,
    /// Committed `token_supply` read from the NODE immediately BEFORE the faucet consumed the burn.
    pub supply_before: u64,
    /// Committed `token_supply` read AFTER the consume committed — must equal
    /// `supply_before - amount_units` (a real supply decrement).
    pub supply_after: u64,
    /// The holder wallet's committed faucet-asset balance BEFORE it emitted the burn note.
    pub holder_balance_before: u64,
    /// The holder's committed balance AFTER emitting the burn note — must equal
    /// `holder_balance_before - amount_units` (the burned funds left the holder's custody into the
    /// note, single-sourced from the note's asset).
    pub holder_balance_after: u64,
    /// The burn note's id (hex).
    pub note_id: String,
    /// The note's tag — must equal the fixed xUSDC burn tag `0x4255524E` (`SyncNotes` exact match).
    pub note_tag: u32,
    /// The block the holder's emit committed the burn note in (block N).
    pub note_commit_block: u32,
    /// The block the faucet's consume committed in (block N+1) — must be strictly greater than
    /// `note_commit_block` (a genuine two-block flow: the consume needs the note's inclusion proof
    /// from a prior committed block).
    pub consume_block: u32,
    /// Whether `GetNotesById` returned the committed note after block N (before consumption) — the
    /// note was a real committed public note, not an ephemeral one.
    pub committed_before_consume: bool,
    /// Whether `SyncNotes` filtered by the fixed burn tag discovered the note (the Circle discovery
    /// path).
    pub discovered_by_syncnotes: bool,
    /// Whether `GetNotesById` STILL returns the note AFTER the faucet consumed it — the durable
    /// burn-event observability the withdrawal attester relies on (the two-block read-path persists,
    /// unlike the same-block-erased note of row H).
    pub found_after_consume: bool,
    /// Whether the note's nullifier is in the node's spent set after the consume — the burn is a
    /// real, committed, non-replayable spend.
    pub nullifier_recorded_after_consume: bool,
    /// The fungible amount the burn note carries (must equal `amount_units`).
    pub note_asset_amount: u64,
    /// Whether the burn note's single asset is issued by THIS faucet.
    pub note_asset_is_faucet: bool,
    /// The byte-exact `Note` half of the `GetNotesById` response, serialized to hex
    /// (`Note::to_bytes`) — the note body of the examples-repo / Njord deliverable. Non-empty on a
    /// captured note.
    pub getnotesbyid_note_bytes_hex: String,
    /// The byte-exact inclusion-proof half of the `GetNotesById` response, serialized to hex
    /// (`NoteInclusionProof::to_bytes`) — the proof envelope the withdrawal attester needs to verify
    /// the note's on-chain inclusion. Non-empty on a captured note; together with
    /// `getnotesbyid_note_bytes_hex` it is the FULL response content (note + inclusion proof), not a
    /// note-only excerpt.
    pub getnotesbyid_inclusion_proof_bytes_hex: String,
    /// The inclusion-proof block height carried by the `GetNotesById` response — must equal
    /// `note_commit_block` (decoded from the same proof whose bytes are captured above).
    pub getnotesbyid_inclusion_block: u32,
}

/// Records local same-block burn execution, submission results, and node discovery responses.
/// Circle's burn-evidence acceptance decision remains OPEN.
#[derive(Debug, Clone, Serialize)]
pub struct BurnSameBlock {
    /// A human label for the RIV (`same-block-erasure`).
    pub label: String,
    /// The reduced (on-chain) amount the same-block burn note carries.
    pub amount_units: u64,
    /// A plain-language description of the mechanism + the real-node constraint (recorded so the
    /// evidence is self-describing).
    pub mechanism: String,
    /// The burn note's tag — the SAME fixed xUSDC burn tag `0x4255524E` as the two-block note (so
    /// the RIV is about the PRODUCTION note, not a variant).
    pub note_tag: u32,
    /// The burn note's id (hex).
    pub note_id: String,
    /// Whether the client-side (unauthenticated) consume EXECUTED without trapping — the production
    /// burn note IS a valid burn, so the RIV subject genuinely exists (a valid burn that simply
    /// leaves no discoverable artifact when its note never commits).
    pub consume_accepted: bool,
    /// The `token_supply` decrement the executed consume applies, read from its account-state delta —
    /// the "supply delta" half of the RIV; must equal `amount_units` (a real burn moves supply by
    /// exactly the burned amount). `None` only if the delta could not be extracted.
    pub executed_supply_delta: Option<u64>,
    /// Whether SUBMITTING the faucet's consume of the never-committed burn note via user RPC was
    /// REJECTED by the node — a REAL-NODE round-trip (not a local execute) proving a COMMITTED
    /// same-block create+consume of the production note is UNREACHABLE on this stack. `true` = the
    /// node refused it (the constraint holds); `false` would be a surprising finding (a committed
    /// same-block WAS possible) worth surfacing.
    pub submit_via_user_rpc_rejected: bool,
    /// The captured node rejection of that submission (the real-node constraint proof). Non-empty
    /// when the submission was rejected.
    pub submit_rejection_error: String,
    /// Committed on-chain `token_supply` read BEFORE the RIV.
    pub onchain_supply_before: u64,
    /// Committed on-chain `token_supply` read AFTER — must be UNCHANGED (`== onchain_supply_before`):
    /// neither the client-side execute nor the rejected submission committed, so no on-chain supply
    /// moved (the delta lives only in the un-committable tx).
    pub onchain_supply_after: u64,
    /// Whether `GetNotesById` on the node found the note as a COMMITTED note — the RIV records this
    /// as `false` (the note never committed).
    pub committed_note_found: bool,
    /// Whether the note's nullifier is recorded on-chain — the RIV records this as `false` (nothing
    /// committed; no nullifier persists).
    pub nullifier_recorded: bool,
    /// Whether `SyncNotes` filtered by the fixed burn tag discovered the note — the RIV records this
    /// as `false` (Circle's discovery path is starved when the note never commits).
    pub discovered_by_syncnotes: bool,
    /// The raw `GetNotesById` response captured for the same-block note (an empty result / not-found
    /// marker) — the raw RPC evidence. Non-empty (the capture was taken).
    pub raw_getnotesbyid_response: String,
}

/// One **Row I** burn negative: a burn that MUST be rejected AND leave the committed state unchanged
/// (`token_supply` fixed).
#[derive(Debug, Clone, Serialize)]
pub struct BurnNegative {
    /// A human label for the negative (`below-min`, `while-paused`, `wrong-asset`).
    pub label: String,
    /// The exact on-chain gate error substring the reject must carry (or, for stock/kernel gates,
    /// whose deterministic `err_code` it must carry).
    pub expected_error: String,
    /// The client-side execute verdict — must be REJECTED with `expected_error`.
    pub verdict: Verdict,
    /// Committed `token_supply` read BEFORE the negative was executed.
    pub supply_before: u64,
    /// Committed `token_supply` read AFTER — must equal `supply_before` (zero state change).
    pub supply_after: u64,
}

/// A single labelled per-step committed-`token_supply` read for the Row-J conservation ledger.
#[derive(Debug, Clone, Serialize)]
pub struct SupplyStep {
    /// What produced this supply read (`after-mint`, `after-two-block-burn`, …).
    pub label: String,
    /// The committed `token_supply` observed at this step.
    pub supply: u64,
}

/// **Row J** — the per-arc conservation ledger.
///
/// After the full rows-G/H/I/J arc: `final_supply == total_minted − total_burned` EXACTLY over the
/// COMMITTED mints and burns of this slice's mint→burn arc (the same-block RIV + the rejected burn
/// negatives never committed, so they contribute nothing). Per-step supply reads are recorded, and
/// the holder's balance is custody-consistent (received the mint, burned it into the two-block note).
#[derive(Debug, Clone, Serialize)]
pub struct ConservationLedger {
    /// The sum of every COMMITTED mint's reduced amount in this arc.
    pub total_minted: u64,
    /// The sum of every COMMITTED burn's reduced amount in this arc.
    pub total_burned: u64,
    /// The final committed on-chain `token_supply` at the end of the arc.
    pub final_supply: u64,
    /// The labelled per-step supply reads across the arc (recorded for the ledger; non-empty).
    pub steps: Vec<SupplyStep>,
    /// The holder wallet's final committed faucet-asset balance — must equal
    /// `total_minted − total_burned` for this single-holder mint→burn arc (it received every mint
    /// and burned every committed burn).
    pub holder_final_balance: u64,
}

/// Burn discovery, rejection probes, and the supply-conservation ledger.
#[derive(Debug, Clone, Serialize)]
pub struct RowsGjObservations {
    /// The `main` commit the run was built from (ledger metadata; recorded, not asserted).
    pub main_commit: String,
    /// The deployed faucet's account id (hex).
    pub faucet_id: String,
    /// The holder (burner) wallet's account id (hex).
    pub holder_id: String,
    /// Row G — the two-block burn read-path proof.
    pub g: BurnTwoBlock,
    /// Row H — the F7 same-block-erasure RIV (evidence only).
    pub h: BurnSameBlock,
    /// Row I — the burn negatives (must include below-min, while-paused, wrong-asset).
    pub i: Vec<BurnNegative>,
    /// Row J — the conservation ledger.
    pub j: ConservationLedger,
}
