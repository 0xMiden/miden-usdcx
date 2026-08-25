//! Rows-D (mint happy path) + row-E (mint negatives) assertion suite — written test-first, before
//! the real-node driver (`crate::rows_de`), judging the [`RowsDeObservations`] it produces.
//!
//! Matrix rows:
//! - **D mint happy path** — a real `XUsdcMintNote` consumption raises `token_supply += amount`,
//!   sets `usedNonces[nonce]`, and emits a recipient P2ID note; the RECIPIENT wallet consumes it
//!   (balance += amount). Two variants: hookData-bearing AND no-hookData; a genuine two-block flow
//!   on the real node.
//! - **E mint negatives** — each REJECTED AND zero state change (supply unchanged, nonce NOT set):
//!   replayed nonce, forged signature, non-allowlisted attester pubkey, tampered payload
//!   (attachment↔commitment mismatch), and a fee ceiling the attestation signed but the faucet
//!   cannot rebuild.
//!
//! Every check reads the NODE-fetched verdicts/read-backs carried by [`RowsDeObservations`] — a green
//! here is a statement about the real chain, not about the client's local store.

use anyhow::{ensure, Result};

use crate::observations_de::{
    MintHappy, MintNegative, RowsDeObservations, Verdict, MARKER_CLEAR, MARKER_SET,
};

// EXACT on-chain error substrings the Row-E rejects must carry (single source of truth in the
// shipped MASM — `mint_intent.masm` and `attestation_verify.masm` — and, for the signature check,
// in the core library's ECDSA verifier, which owns that trap's identity). A reject that does not
// carry ITS error is not the gate the negative proves — the assertion rejects it. Each carries the
// message on a client-side trap (LNV-2 posture: only STOCK miden-standards gates surface
// code-only); the matcher still also accepts the derived `err_code` for robustness against a future
// protocol string/pin drift.
// ================================================================================================

/// R-MINT-12 (replay protection): the deposit intent's nonce is already in `usedNonces` (replay).
pub const ERR_XRESERVE_NONCE_REPLAY: &str = "deposit intent nonce has already been used";
/// R-MINT-14 (attestation verification): the ECDSA signature does not verify over
/// `keccak256(payload)` for the candidate pubkey — a forged signature, a payload tampered after
/// signing, or an intent naming a domain or faucet other than the one the faucet writes into the
/// message it rebuilds. The trap belongs to the core library's verifier, so this is its error.
pub const ERR_XRESERVE_SIG_INVALID: &str = "ECDSA verification failed: x(VERIFY_POINT) != SIG_R";
/// R-MINT-13 (attestation verification): the candidate attester pubkey's commitment is not in the on-chain allowlist.
pub const ERR_XRESERVE_DISALLOWED_PUB_KEY: &str =
    "deposit attester pubkey commitment is not allowlisted";

// SHARED CHECK HELPERS
// ================================================================================================

/// The `err_code` (the deterministic `error_code_from_msg` hash) a MASM assertion of `msg` embeds —
/// the SAME value the assembler bakes into the compiled proc and the executor surfaces. Lets a
/// reject be matched on its code when the message itself is absent.
fn err_code_for(msg: &str) -> u64 {
    miden_protocol::errors::MasmError::new(msg.to_string())
        .code()
        .as_canonical_u64()
}

/// Asserts a verdict is REJECTED and its captured error is the `expected` gate (matched on EITHER
/// the message substring OR the expected error's `err_code`, both derived from the single expected
/// string — never a hardcoded magic number).
fn assert_rejected_with(v: &Verdict, expected: &str, ctx: &str) -> Result<()> {
    match v {
        Verdict::Accepted => {
            anyhow::bail!(
                "{ctx}: expected a REJECT carrying '{expected}', but the consumption was ACCEPTED"
            )
        }
        Verdict::Rejected(err) => {
            let code_marker = format!("err_code: {}", err_code_for(expected));
            anyhow::ensure!(
                err.contains(expected) || err.contains(&code_marker),
                "{ctx}: the consumption was rejected, but NOT with the expected gate error \
                 '{expected}' (nor its {code_marker}); got: {err}",
            );
            Ok(())
        }
    }
}

// ROW ASSERTIONS
// ================================================================================================

/// **Row D — mint happy path.**
///
/// The variants MUST cover BOTH an empty-hookData mint and a hookData-bearing mint (the two the
/// matrix requires). For each committed variant:
/// - `token_supply` rose by EXACTLY the minted amount (a real supply write, neither absent nor
///   over-counted);
/// - `usedNonces[nonce]` is set (`[1,0,0,0]`) — the first atomic state write;
/// - the emitted recipient note is a canonical P2ID whose serial equals the nonce-derived key, whose
///   tag is the recipient account-target tag, and whose single asset is the reduced amount issued by
///   THIS faucet;
/// - the RECIPIENT wallet's vault balance rose by the minted amount (custody-traced funds);
/// - the recipient's consume committed in a STRICTLY later block than the note (a genuine two-block
///   flow — the consume needs the note's inclusion proof from a prior block).
pub fn assert_d(variants: &[MintHappy]) -> Result<()> {
    ensure!(
        variants.iter().any(|v| v.hook_data_len == 0),
        "D: the happy-path variants must include an empty-hookData (hook_data_len == 0) mint",
    );
    ensure!(
        variants.iter().any(|v| v.hook_data_len > 0),
        "D: the happy-path variants must include a hookData-bearing (hook_data_len > 0) mint",
    );
    for v in variants {
        let ctx = format!("D[{}]", v.label);
        ensure!(
            v.amount_units > 0,
            "{ctx}: a happy-path mint must mint a non-zero amount"
        );
        ensure!(
            v.supply_after == v.supply_before + v.amount_units,
            "{ctx}: token_supply must rise by exactly the minted amount ({} + {} = {}, but read \
             back {})",
            v.supply_before,
            v.amount_units,
            v.supply_before + v.amount_units,
            v.supply_after,
        );
        ensure!(
            v.nonce_marker_after == MARKER_SET,
            "{ctx}: usedNonces[nonce] must be set to {MARKER_SET:?} after the mint (got {:?})",
            v.nonce_marker_after,
        );
        ensure!(
            v.note_serial == v.expected_serial,
            "{ctx}: the emitted note serial must equal the nonce-derived key (got {:?}, expected {:?})",
            v.note_serial,
            v.expected_serial,
        );
        ensure!(
            v.note_is_p2id,
            "{ctx}: the emitted recipient note must be a canonical P2ID note"
        );
        ensure!(
            v.note_tag == v.expected_tag,
            "{ctx}: the emitted note tag must equal the recipient account-target tag (got {:#010x}, \
             expected {:#010x})",
            v.note_tag,
            v.expected_tag,
        );
        ensure!(
            v.note_asset_amount == v.amount_units,
            "{ctx}: the emitted note asset amount must equal the minted amount (got {}, expected {})",
            v.note_asset_amount,
            v.amount_units,
        );
        ensure!(
            v.note_asset_is_faucet,
            "{ctx}: the emitted note asset must be issued by THIS faucet",
        );
        ensure!(
            v.recipient_balance_after == v.recipient_balance_before + v.amount_units,
            "{ctx}: the recipient balance must be credited by the minted amount ({} + {} = {}, but \
             read back {})",
            v.recipient_balance_before,
            v.amount_units,
            v.recipient_balance_before + v.amount_units,
            v.recipient_balance_after,
        );
        ensure!(
            v.recipient_consume_block > v.note_commit_block,
            "{ctx}: the recipient consume must commit in a strictly later block than the note (a \
             two-block flow): note block {} vs consume block {}",
            v.note_commit_block,
            v.recipient_consume_block,
        );
    }
    Ok(())
}

/// **Row E — mint negatives.**
///
/// The set MUST cover every negative (replay, forged signature, non-allowlisted attester, tampered
/// payload, tampered max-fee ceiling). For EVERY negative:
/// - the consumption was REJECTED with ITS exact gate error (message OR derived err_code);
/// - the committed `token_supply` is UNCHANGED (`supply_after == supply_before`);
/// - the `usedNonces` marker matches the negative's kind — a FRESH-nonce negative (forged signature /
///   bad attester / either tamper) left its nonce EMPTY (`[0,0,0,0]`, proving the reject wrote
///   nothing), while the replay negative's already-used nonce stayed SET (`[1,0,0,0]`).
pub fn assert_e(negatives: &[MintNegative]) -> Result<()> {
    for n in negatives {
        let ctx = format!("E[{}]", n.label);
        assert_rejected_with(&n.verdict, &n.expected_error, &ctx)?;
        ensure!(
            n.supply_after == n.supply_before,
            "{ctx}: committed token_supply must be UNCHANGED after the reject (was {}, read back {})",
            n.supply_before,
            n.supply_after,
        );
        let (expected_marker, which) = if n.expects_nonce_set {
            (
                MARKER_SET,
                "the replay negative's already-used nonce must stay SET",
            )
        } else {
            (
                MARKER_CLEAR,
                "a rejected fresh-nonce negative must leave usedNonces[nonce] EMPTY",
            )
        };
        ensure!(
            n.nonce_marker_after == expected_marker,
            "{ctx}: {which} (got nonce marker {:?}, expected {expected_marker:?})",
            n.nonce_marker_after,
        );
    }

    // Coverage: the row proves EVERY one of the distinct negative vectors, not a convenient subset.
    // Requiring each by its LABEL (not just its gate error) is deliberate — three of them share the
    // SIG_INVALID gate but are DISTINCT attack surfaces (a corrupted signature, a payload the
    // attestation never signed, and a fee ceiling the faucet cannot rebuild), so an error-only check
    // would let any one satisfy coverage for all three and a driver could silently drop two.
    for label in REQUIRED_NEGATIVES {
        ensure!(
            negatives.iter().any(|n| n.label == label),
            "E: the negatives must include the '{label}' negative — every matrix mint-negative \
             vector is required; the three signature-gate vectors (forged-signature, \
             tampered-payload and tampered-max-fee-ceiling) are DISTINCT attack surfaces and ALL \
             must be present",
        );
    }
    // The replay negative must additionally be a genuine already-used-nonce case (marker set), tying
    // the 'replayed-nonce' label to the invariant the per-negative loop checks.
    ensure!(
        negatives.iter().any(|n| n.label == "replayed-nonce" && n.expects_nonce_set),
        "E: the 'replayed-nonce' negative must reuse an already-committed nonce (expects_nonce_set)",
    );
    Ok(())
}

/// The DISTINCT Row-E mint-negative vectors the matrix requires, by canonical label. Three of them
/// (`forged-signature`, `tampered-payload`, `tampered-max-fee-ceiling`) trap at the SAME signature
/// gate but are different attack surfaces, so coverage is keyed on the label — never on the gate
/// error alone.
const REQUIRED_NEGATIVES: [&str; 5] = [
    "replayed-nonce",
    "forged-signature",
    "non-allowlisted-attester",
    "tampered-payload",
    "tampered-max-fee-ceiling",
];

/// Judges every rows-D/E observation. Returns the first failure; the driver / bin records per-row
/// verdicts separately for the evidence file.
pub fn assert_all(o: &RowsDeObservations) -> Result<()> {
    assert_d(&o.d)?;
    assert_e(&o.e)?;
    Ok(())
}
