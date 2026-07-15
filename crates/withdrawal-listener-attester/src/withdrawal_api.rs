//! `withdrawal_api` (PURE builders) — the two request bodies the partner AUTHORS for Circle: the
//! `DC-9` [`PrepareWithdrawalRequest`] (`CMP-D5`) and the `POST /v1/withdraw` [`WithdrawRequest`]
//! wrapper (`CMP-D6`).
//!
//! # What these build, and — load-bearing — what they do NOT
//!
//! The partner builds **only the API JSON request** ([`build_prepare_request`]). It never constructs
//! the binary Gateway `TransferSpec`/`BurnIntent` — Circle encodes those server-side and RETURNS the
//! canonical `burnIntents[]`/`encoded`/`messageHashToSign`, which the partner then validates
//! (the B5 gate, `validate.rs`) and signs (`INV-CIRCLE-CANONICAL-WITHDRAWAL`). A local binary
//! reconstruction is optional validation only (anti-`ASG-5`), and none happens here: there is no
//! binary encoder in this crate, and these builders emit JSON.
//!
//! # `remoteDepositor` is NOT `sourceDepositor` (`INV-REMOTEDEPOSITOR-VS-SOURCEDEPOSITOR`)
//!
//! `remoteDepositor` is the Miden initiator — the burn note's `metadata.sender`, encoded through
//! unit-04's `DC-6` `AccountId ↔ bytes32` codec ([`account_id_to_bytes32`], consumed by reference,
//! not re-implemented) and rendered as the OpenAPI's `^0x[a-fA-F0-9]{64}$`. It is a **partner-built**
//! field. `sourceDepositor` is a Gateway `TransferSpec` field Circle ASSIGNS server-side (`Q-DOM-3`);
//! [`PrepareBurnIntentInput`] has no such field, so populating it partner-side is not merely avoided
//! here — it is untypeable (anti-`ASG-15`). Swapping the two would name the wrong debtor.
//!
//! # Circle-owned questions this module touches — all still OPEN (parameterized, never resolved)
//!
//! * `DEV-10` — the `AccountId → bytes32` layout behind `remoteDepositor` is unit-04's, a DRAFT that
//!   `REQUIRES CIRCLE CONFIRMATION`; this module consumes it and asserts nothing about its approval.
//! * `Q-DOM-2` — the forwarding scope (xReserve-only vs Gateway/CCTP). This builder does not invent a
//!   forwarding flow: `useCircleForwarding` is set to `false` and `forwardingOptions` is omitted.
//! * `Q-DOM-3` — `sourceDepositor` is Circle-filled; the partner never populates it (above).
//! * `DEV-5` — the smallest-unit⇄decimal `value` scale (and dust/cap) is Circle-owned. The burn
//!   payload's `amount` is in the smallest token unit; this builder passes it through **unscaled** as
//!   a decimal-integer string, applying no `10^n` factor, so the scale stays Circle's to settle. It
//!   is placed in `valueIncludingFees` (the burned amount is the total debited on Miden, out of which
//!   Circle takes its fee), leaving `valueExcludingFees` unset — the value XOR is satisfied by exactly
//!   one field. The exact fee/scale semantics `REQUIRE CIRCLE CONFIRMATION`.

use miden_protocol::account::AccountId;
use xusdc_encoding::xreserve::encoding::account_id_to_bytes32;

use crate::circle::schema::{
    PrepareBurnIntentInput, PrepareWithdrawalRequest, WithdrawBatch, WithdrawRequest,
};
use crate::circle::wire::{DecimalAmount, Hex32, SchemaError};
use crate::config::ListenerConfig;
use crate::types::BurnPayload;

/// Builds the `DC-9` [`PrepareWithdrawalRequest`] — the API JSON the partner sends to
/// `POST /v1/prepare-withdrawal` — from a decoded burn payload, the note's `metadata.sender`, and
/// the static config. The single [`PrepareBurnIntentInput`] is wrapped in the top-level `batches[]`.
///
/// The field mapping (per the `DC-9` table):
/// * `token` = `USDC`;
/// * `valueIncludingFees` = `payload.amount`, the smallest-unit amount as a decimal-integer string
///   (unscaled — `DEV-5` OPEN); `valueExcludingFees` unset;
/// * `remoteDomain` = `cfg.miden_domain()` (Miden's Circle-assigned domain, `Q-DOM-1` OPEN);
/// * `remoteDepositor` = [`account_id_to_bytes32`]`(sender)` as `0x`-hex 32B (`DC-6`);
/// * `finalDestinationDomain` / `finalDestinationRecipient` = the burn payload's `destDomain` /
///   `destRecipient`;
/// * `salt` = the burn payload's `salt` (so a rebuild of the SAME burn is byte-identical, rather than
///   drawing a fresh Circle-random salt);
/// * `useCircleForwarding` = `false`, `forwardingOptions`/`finalDestinationCaller` omitted (`Q-DOM-2`).
///
/// # Errors
/// The cross-field rules [`PrepareBurnIntentInput`] validates, reached through its builder:
/// * [`SchemaError::RemoteDomainBelowMinimum`] — `cfg.miden_domain() < 1` (e.g. the config's `0`
///   placeholder while `Q-DOM-1` is OPEN);
/// * [`SchemaError::DomainsMustDiffer`] — `remoteDomain == finalDestinationDomain`.
pub fn build_prepare_request(
    payload: &BurnPayload,
    sender: AccountId,
    cfg: &ListenerConfig,
) -> Result<PrepareWithdrawalRequest, SchemaError> {
    let value = DecimalAmount::new(payload.amount.as_u64().to_string())
        .expect("a smallest-unit integer is a valid decimal amount");

    let input = PrepareBurnIntentInput::builder()
        // `token` defaults to USDC — the one enum member.
        .value_including_fees(value)
        .remote_domain(cfg.miden_domain())
        .remote_depositor(hex32_of(&account_id_to_bytes32(sender)))
        .final_destination_domain(payload.dest_domain)
        .final_destination_recipient(hex32_of(&payload.dest_recipient))
        .salt(hex32_of(&payload.salt))
        .use_circle_forwarding(false)
        .build()?;

    Ok(PrepareWithdrawalRequest::new(vec![input]))
}

/// Wraps `WithdrawBatch[]` in the top-level [`WithdrawRequest`] `{ batches: [..] }` for
/// `POST /v1/withdraw` (`CMP-D6`) — never a bare array or bare batch.
///
/// The per-batch invariants (`burnIntents` `1..=10`, `burnSignatures >= 2`) are the
/// [`WithdrawBatch`] constructor's, established when each batch is built; this wrapper enforces the
/// batch-list bound.
///
/// # Errors
/// [`SchemaError::BatchCountOutOfRange`] — fewer than 1 or more than 5 batches.
pub fn build_withdraw_request(batches: Vec<WithdrawBatch>) -> Result<WithdrawRequest, SchemaError> {
    WithdrawRequest::new(batches)
}

/// `0x` + lowercase hex of 32 bytes — the `^0x[a-fA-F0-9]{64}$` rendering every 32-byte Circle field
/// uses. A 32-byte array always satisfies the regex, so the newtype construction cannot fail.
fn hex32_of(bytes: &[u8; 32]) -> Hex32 {
    Hex32::new(format!("0x{}", hex::encode(bytes)))
        .expect("32 bytes render to a valid 0x-hex 32-byte string")
}
