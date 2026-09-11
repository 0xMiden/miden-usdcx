//! Mint transaction results and state fetched from the node.
//! Successful mints are committed; rejection probes execute locally without submission.

use serde::Serialize;

pub use crate::observations_cf::{Verdict, Word4, MARKER_CLEAR, MARKER_SET};

/// One **Row D** happy-path mint variant (empty-hookData or hookData-bearing), committed on the real
/// node via path N, with the RECIPIENT then consuming the emitted P2ID note.
///
/// Every field is a NODE-fetched read-back or the outcome of a real committed transaction:
/// `token_supply` before/after the mint, the `usedNonces[nonce]` marker after, the emitted P2ID
/// note's shape (serial == nonce key, canonical P2ID script root, account-target tag, the reduced
/// asset amount + faucet id it carries), the recipient's vault balance before/after its consume, and
/// the two block heights that make the flow provably two-block (the note commits in one block; the
/// recipient consumes it in a strictly later one).
#[derive(Debug, Clone, Serialize)]
pub struct MintHappy {
    /// A human label for the variant (`empty-hookData` / `hookData-bearing`).
    pub label: String,
    /// The hookData byte length carried by the variant's DepositIntent (0 for the empty variant,
    /// >0 for the hookData-bearing variant — the two variants must differ here).
    pub hook_data_len: u32,
    /// The reduced (on-chain) amount this mint raises `token_supply` by and the P2ID note carries.
    pub amount_units: u64,
    /// Committed `token_supply` read from the NODE immediately BEFORE the path-N mint committed.
    pub supply_before: u64,
    /// Committed `token_supply` read AFTER — must equal `supply_before + amount_units`.
    pub supply_after: u64,
    /// The `usedNonces[nonce]` marker read AFTER the mint committed — must be `[1,0,0,0]` (set).
    pub nonce_marker_after: Word4,
    /// The emitted recipient note's serial number (must equal the nonce-derived `bytes32_to_storage_map_key`).
    pub note_serial: Word4,
    /// The nonce-derived key the serial is checked against (`bytes32_to_storage_map_key(nonce)`).
    pub expected_serial: Word4,
    /// Whether the emitted note's script root equals the canonical P2ID script root.
    pub note_is_p2id: bool,
    /// The emitted note's tag (must equal the recipient account-target tag, `0xfffc0000`-masked
    /// prefix HIGH u32).
    pub note_tag: u32,
    /// The recipient account-target tag the note tag is checked against.
    pub expected_tag: u32,
    /// The fungible amount the emitted P2ID note carries (must equal `amount_units`).
    pub note_asset_amount: u64,
    /// Whether the emitted note's single asset is issued by THIS faucet.
    pub note_asset_is_faucet: bool,
    /// The recipient wallet's committed vault balance of the faucet asset BEFORE consuming the note.
    pub recipient_balance_before: u64,
    /// The recipient wallet's committed vault balance AFTER consuming the note — must equal
    /// `recipient_balance_before + amount_units` (custody-traced funds).
    pub recipient_balance_after: u64,
    /// The block the emitted P2ID note was committed in (its inclusion proof height).
    pub note_commit_block: u32,
    /// The block the recipient's consume transaction committed in — must be strictly greater than
    /// `note_commit_block` (the flow is genuinely two-block: consume needs the note's inclusion
    /// proof from a prior block).
    pub recipient_consume_block: u32,
}

/// One **Row E** mint negative: a mint that MUST be rejected AND leave the committed state
/// unchanged (`token_supply` fixed; the relevant `usedNonces` entry unchanged).
///
/// The four fresh-nonce negatives (forged signature, non-allowlisted attester, non-zero feeAmount,
/// tampered payload) each carry a FRESH nonce that was never minted, so the invariant is
/// `nonce_marker_after == [0,0,0,0]` (the rejected consumption never reached the nonce-set write).
/// The replay negative reuses a nonce a Row-D mint already committed, so its invariant is the
/// opposite — `nonce_marker_after == [1,0,0,0]` (already-set, and the reject did not re-write or
/// double-mint). `expects_nonce_set` selects which invariant applies.
#[derive(Debug, Clone, Serialize)]
pub struct MintNegative {
    /// A human label for the negative (`replayed-nonce`, `forged-signature`, …).
    pub label: String,
    /// The exact on-chain gate error substring the reject must carry (or, for stock gates, whose
    /// deterministic `err_code` it must carry).
    pub expected_error: String,
    /// The client-side execute verdict — must be REJECTED with `expected_error`.
    pub verdict: Verdict,
    /// Committed `token_supply` read BEFORE the negative was executed.
    pub supply_before: u64,
    /// Committed `token_supply` read AFTER — must equal `supply_before` (zero state change).
    pub supply_after: u64,
    /// The `usedNonces[nonce]` marker for THIS negative's nonce, read AFTER the reject.
    pub nonce_marker_after: Word4,
    /// Whether this negative's nonce is expected to be SET (`[1,0,0,0]`) — true only for the replay
    /// negative (which reuses an already-committed nonce); false for the fresh-nonce negatives
    /// (whose nonce must remain `[0,0,0,0]`, proving the reject wrote nothing).
    pub expects_nonce_set: bool,
}

/// Successful mints, rejected probes, and committed state read from the node.
#[derive(Debug, Clone, Serialize)]
pub struct RowsDeObservations {
    /// The `main` commit the run was built from (ledger metadata; recorded, not asserted).
    pub main_commit: String,
    /// The deployed faucet's account id (hex).
    pub faucet_id: String,
    /// The recipient wallet's account id (hex).
    pub recipient_id: String,
    /// The Row-D happy-path mint variants (must include both an empty-hookData and a hookData-bearing
    /// mint).
    pub d: Vec<MintHappy>,
    /// The Row-E negatives (must include all five: replay, forged signature, non-allowlisted
    /// attester, non-zero fee, tampered payload).
    pub e: Vec<MintNegative>,
}
