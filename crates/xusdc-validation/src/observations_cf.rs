//! The observation record the rows-C/F driver produces and the rows-C/F assertion suite consumes.
//!
//! Same split as the LNV-1 [`crate::observations`]: drivers OBSERVE (execute probes client-side,
//! commit admin state via the ntx-builder, capture errors + committed read-backs); assertions
//! JUDGE. Every field here is either a *verdict* — the result of a real transaction against the
//! deployed faucet — or a *committed read-back Word/scalar* fetched from the NODE (`GetAccount`)
//! after an admin note committed. Keeping the two apart makes every rows-C/F assertion unit-testable
//! against synthetic observations (the default suite) and keeps the driver free of pass/fail policy.
//!
//! The two real-node execution modes the verdicts come from (LNV-1 §3.2 posture finding):
//! - **path N (ntx-builder)** — the ONLY way to *commit* a post-deploy faucet state change at
//!   v0.15.1 (user RPC rejects post-deploy network-account txs; the client cannot present the
//!   `x-miden-network-tx-auth` header). Every positive admin op (`set_attester`, `set_max_supply`,
//!   `pause`, role grant/revoke, …) is emitted as a routed allowlisted note and the running
//!   ntx-builder auto-executes the faucet's consumption; the driver reads the committed effect.
//! - **client-side execute** — for the accept/reject *probes* (mint/burn) and the negatives the
//!   driver executes the faucet's consumption locally (`execute_transaction`, no submission) and
//!   records [`Verdict::Accepted`] (executed Ok) or [`Verdict::Rejected`] (the exact trap error).
//!   This is the LNV-1 row-B kernel-trap technique; a reject needs no submission path.

use serde::Serialize;

/// The outcome of a faucet consumption against the deployed on-chain state: either it executed
/// (accepted) or it trapped with a captured error (rejected). The driver produces these from a
/// client-side `execute_transaction` (probes/negatives) or from a committed path-N effect (a
/// committed positive is [`Verdict::Accepted`]).
#[derive(Debug, Clone, Serialize)]
pub enum Verdict {
    /// The consumption executed against the real on-chain state with no trap (accepted).
    Accepted,
    /// The consumption trapped; the captured client-side execution error (verbatim).
    Rejected(String),
}

impl Verdict {
    /// Records a `Result` from a client-side execute as a verdict (`Ok` → accepted, `Err` → the
    /// captured error string).
    pub fn from_execute<T>(r: Result<T, String>) -> Self {
        match r {
            Ok(_) => Verdict::Accepted,
            Err(e) => Verdict::Rejected(e),
        }
    }

    pub fn is_accepted(&self) -> bool {
        matches!(self, Verdict::Accepted)
    }

    /// The captured error string when rejected, else `None`.
    pub fn error(&self) -> Option<&str> {
        match self {
            Verdict::Rejected(e) => Some(e),
            Verdict::Accepted => None,
        }
    }
}

/// A four-felt storage word as `[u64; 4]` (map-marker / value-slot read-back), fetched from the
/// NODE after an admin note committed. `[1,0,0,0]` = the enabled/paused/member marker; `[0,0,0,0]`
/// = absent/disabled/unpaused.
pub type Word4 = [u64; 4];

/// The enabled/paused/member marker word `[1,0,0,0]`.
pub const MARKER_SET: Word4 = [1, 0, 0, 0];
/// The absent/disabled/unpaused word `[0,0,0,0]`.
pub const MARKER_CLEAR: Word4 = [0, 0, 0, 0];

/// **C1 — `set_attester` + attester rotation.** Allowlist attester A, then rotate to B (disable A,
/// enable B); a mint attested by A is REJECTED (not allowlisted), by B ACCEPTED.
#[derive(Debug, Clone, Serialize)]
pub struct C1SetAttester {
    /// A's committed allowlist marker right after `set_attester(A, enabled=1)` — must be [1,0,0,0].
    pub a_marker_after_enable: Word4,
    /// A's committed marker after the rotation (`set_attester(A, enabled=0)`) — must be [0,0,0,0].
    pub a_marker_after_rotate: Word4,
    /// B's committed marker after the rotation (`set_attester(B, enabled=1)`) — must be [1,0,0,0].
    pub b_marker_after_rotate: Word4,
    /// A mint whose attestation is signed by the (now-rotated-out) A — must be REJECTED.
    pub mint_by_a: Verdict,
    /// A mint whose attestation is signed by the (now-active) B — must be ACCEPTED.
    pub mint_by_b: Verdict,
}

/// **C2 — `set_min_burn_size`.** Raise the minimum → a below-new-min burn is REJECTED; lower it →
/// an at-min burn PASSES.
#[derive(Debug, Clone, Serialize)]
pub struct C2MinBurn {
    /// The raised minimum the driver committed (the intended value).
    pub raised_min: u64,
    /// The committed `min_burn_size` value slot element 0 after the raise — must equal `raised_min`.
    pub committed_after_raise: u64,
    /// A burn strictly below `raised_min` — must be REJECTED (below the minimum burn size).
    pub burn_below_raised: Verdict,
    /// The lowered minimum the driver committed (the intended value).
    pub lowered_min: u64,
    /// The committed `min_burn_size` value slot element 0 after the lower — must equal `lowered_min`.
    pub committed_after_lower: u64,
    /// A burn exactly at `lowered_min` — must be ACCEPTED.
    pub burn_at_lowered: Verdict,
}

/// **C3 — `set_max_supply`.** Adjust the cap; a mint that would exceed it is REJECTED with the
/// supply-cap error.
#[derive(Debug, Clone, Serialize)]
pub struct C3MaxSupply {
    /// The cap the driver committed (the intended value).
    pub committed_cap: u64,
    /// The committed `max_supply` read back from the faucet's token config — must equal `committed_cap`.
    pub max_supply_readback: u64,
    /// A mint whose reduced amount exceeds `committed_cap` — must be REJECTED (supply cap).
    pub over_cap_mint: Verdict,
    /// A mint whose reduced amount is within `committed_cap` — must be ACCEPTED (baseline).
    pub within_cap_mint: Verdict,
}

/// **C4 — pause / unpause (DOM_PAUSER; F6 semantics).** While paused, mint AND burn consumption are
/// REJECTED, but the owner's `set_attester` / `set_min_burn_size` STILL SUCCEED; unpause restores.
#[derive(Debug, Clone, Serialize)]
pub struct C4Pause {
    /// The committed `is_paused` word after the DOM_PAUSER pause — must be [1,0,0,0].
    pub is_paused_after_pause: Word4,
    /// A mint consumption while paused — must be REJECTED (the contract is paused).
    pub mint_while_paused: Verdict,
    /// A burn consumption while paused — must be REJECTED (the contract is paused).
    pub burn_while_paused: Verdict,
    /// The owner's `set_attester` committed WHILE PAUSED — its marker must be [1,0,0,0] (F6: owner
    /// setters are not halted by pause).
    pub owner_set_attester_while_paused_marker: Word4,
    /// The owner's `set_min_burn_size` committed WHILE PAUSED — the committed value (F6).
    pub owner_set_min_burn_while_paused: u64,
    /// The committed `is_paused` word after the DOM_PAUSER unpause — must be [0,0,0,0].
    pub is_paused_after_unpause: Word4,
    /// A mint consumption after unpause — must be ACCEPTED (the halt lifted).
    pub mint_after_unpause: Verdict,
}

/// **C5 — role rotation (CMP-F5 seam).** DOM_MANAGER grants DOM_PAUSER to a new account (the new
/// pauser can pause); revoke → it cannot.
#[derive(Debug, Clone, Serialize)]
pub struct C5RoleRotation {
    /// The new pauser's committed `DOM_PAUSER` membership after the DOM_MANAGER grant — must be [1,0,0,0].
    pub new_pauser_membership_after_grant: Word4,
    /// The committed `is_paused` word after the NEW pauser pauses — must be [1,0,0,0] (capability proven).
    pub is_paused_after_new_pauser_pause: Word4,
    /// The new pauser's committed membership after the DOM_MANAGER revoke — must be [0,0,0,0].
    pub new_pauser_membership_after_revoke: Word4,
    /// A pause attempt by the REVOKED account — must be REJECTED (does not hold the required role).
    pub revoked_pauser_pause: Verdict,
}

/// One **C6** negative: an admin note from a NON-authorized sender must be rejected at the proc gate.
#[derive(Debug, Clone, Serialize)]
pub struct AdminGateReject {
    /// The admin op (e.g. `set_attester`, `pause`).
    pub op: String,
    /// The unauthorized sender kind (e.g. `non-owner`, `non-DOM_PAUSER`).
    pub sender: String,
    /// The exact gate error substring this op must trap with (e.g. `note sender is not the owner`).
    pub expected_gate: String,
    /// The client-side execute verdict — must be REJECTED with `expected_gate`.
    pub verdict: Verdict,
    /// Node-side belt-and-braces: after a bounded watch window the (allowlisted, routed) note stayed
    /// UNCONSUMED — the ntx-builder attempted and failed the same gate, so nothing committed.
    pub note_unconsumed: bool,
}

/// **Row F — the F5 auth boundary on the real node.** A non-allowlisted note (stock P2ID targeting
/// the faucet) is rejected by `AuthNetworkAccount`; a tx-script transaction is rejected (empty
/// tx-script allowlist).
#[derive(Debug, Clone, Serialize)]
pub struct RowF {
    /// The faucet consuming a stock P2ID note (its script root is NOT allowlisted) — must be
    /// REJECTED (input note script root is not in the note script allowlist).
    pub non_allowlisted_note: Verdict,
    /// A tx-script transaction executed against the faucet — must be REJECTED (transaction script
    /// root is not in the tx script allowlist).
    pub tx_script: Verdict,
}

/// Everything the LNV-2 rows-C/F run observed on the real node. `Verdict`s are real faucet
/// consumptions (path-N-committed positives or client-side-executed probes/negatives); `Word4`
/// read-backs are the NODE's `GetAccount` answers after an admin note committed.
#[derive(Debug, Clone, Serialize)]
pub struct RowsCfObservations {
    /// The `main` commit the run was built from (ledger metadata; recorded, not asserted).
    pub main_commit: String,
    /// The deployed faucet's account id (hex).
    pub faucet_id: String,
    pub c1: C1SetAttester,
    pub c2: C2MinBurn,
    pub c3: C3MaxSupply,
    pub c4: C4Pause,
    pub c5: C5RoleRotation,
    pub c6: Vec<AdminGateReject>,
    pub f: RowF,
}
