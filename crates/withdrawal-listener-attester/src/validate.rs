//! `validate` (PURE) — the ordered discovery checklist, the `validate_returned`
//! field-by-field gate, and the **DO-NOT-SIGN** abort. This is the last check before an attester
//! signature is produced, and this service releases real USDC, so the gate is both field-exact and
//! structural.
//!
//! # Circle's returned spec must match the burn note before signing — validation gates signing
//!
//! The partner builds the API JSON request; Circle RETURNS the canonical
//! `burnIntents[]`/`encoded`/`messageHashToSign`; the partner VALIDATES, then signs. [Local binary
//! reconstruction of the `BurnIntent` is optional validation only, and it is deliberately absent
//! here — building it as the required path is the trap this module exists to avoid.]
//! [`validate_returned`] compares Circle's returned `burnIntents[]` against the discovered burn and
//! request terms before signing.
//!
//! # The signer is reachable ONLY behind validation (structural, not by convention)
//!
//! [`validate_returned`] returns a [`ValidatedWithdrawal`] — a proof-of-validation token whose only
//! constructor is this module's full-match path. The withdrawal flow's signer, [`sign_validated`],
//! consumes that token. There is no way to obtain the per-batch digests a Circle response clears
//! for signing except by passing that gate, so "sign a response that failed validation" is not a
//! state this API can represent. The raw `attester::sign` primitive (which signs any 32 bytes, by
//! design) still exists for unit use, but the withdrawal path never reaches it except through a
//! token.
//!
//! # Circle-owned questions this module touches — all still OPEN
//!
//! * **The digest's derivation** — `messageHashToSign` is treated as an OPAQUE digest (no local
//!   EIP-712 re-derivation, no Poseidon2). The gate only checks it is present and a signable 32
//!   bytes; whether it equals the Gateway pipeline's final digest is Circle's to confirm.
//!   Parameterized, never resolved here.
//! * **`sourceDepositor`** — Circle-assigned and appears on the RETURNED `TransferSpec` only; the
//!   partner never supplies it and the gate never compares it against the discovered burn.

use miden_protocol::account::AccountId;
use miden_protocol::note::NoteMetadata;
use miden_protocol::Felt;
use miden_standards::interop::eth::EthEmbeddedAccountId;

use crate::attester::{sign, SecretKey, Signature65};
use crate::circle::schema::{
    BurnIntent, PrepareWithdrawalResponse, StructuredHookData, TransferSpec,
};
use crate::config::ListenerConfig;
use crate::error::{DiscoveryReject, SignError, ValidationMismatch};
use crate::note_decode::{decode_burn_payload, read_sender, BurnNoteMetadata};
use crate::types::BurnPayload;

// ================================================================================================
// DISCOVERY
// ================================================================================================

/// A candidate burn note as a discovery run (`GetNotesById`) reports it — the crate's own model of
/// that response, so discovery can refuse the shapes a node can hand back.
///
/// It is deliberately the raw report, not a validated note: the `tag` is a full 32-bit `u32`
/// (matched by exact equality, never a prefix), and `details` is `None` for a PRIVATE or erased
/// note that came back without its columns, unobservable to Circle. The real feed — the exact-tag
/// `SyncNotes` scan and the retrieval — is PARKED to a later slice, once a usable `miden-client`
/// exists; this type is the model discovery validates against in the meantime.
#[derive(Debug, Clone)]
pub struct DiscoveryRecord {
    tag: u32,
    details: Option<DiscoveredDetails>,
}

impl DiscoveryRecord {
    /// A discovery record with `tag` and, for a public note, its decoded `details` (or `None` for a
    /// private/erased note).
    pub fn new(tag: u32, details: Option<DiscoveredDetails>) -> Self {
        Self { tag, details }
    }

    /// The note's full 32-bit tag, as reported.
    pub fn tag(&self) -> u32 {
        self.tag
    }

    /// The note's details, or `None` for a private/erased note (`details = None`).
    pub fn details(&self) -> Option<&DiscoveredDetails> {
        self.details.as_ref()
    }
}

/// The details a PUBLIC discovered note carries: its withdrawal-payload attachment felts and its
/// `metadata.sender`. Present exactly when `GetNotesById` returned `details = Some(..)`.
#[derive(Debug, Clone)]
pub struct DiscoveredDetails {
    items: Vec<Felt>,
    sender: BurnNoteMetadata,
}

impl DiscoveredDetails {
    /// From the raw withdrawal-payload attachment felts and an already-modelled sender.
    pub fn new(items: Vec<Felt>, sender: BurnNoteMetadata) -> Self {
        Self { items, sender }
    }

    /// From the raw items and a public note's `NoteMetadata` (the happy-path discovery shape).
    pub fn from_metadata(items: Vec<Felt>, meta: &NoteMetadata) -> Self {
        Self::new(items, BurnNoteMetadata::from_metadata(meta))
    }

    /// From the raw items and the reported `(prefix, suffix)` sender felts — the shape a node hands
    /// back before the sender is known to be an account id.
    pub fn from_raw_sender(items: Vec<Felt>, prefix: Felt, suffix: Felt) -> Self {
        Self::new(items, BurnNoteMetadata::from_raw_sender(prefix, suffix))
    }
}

/// A burn that PASSED discovery — its decoded payload and the depositor (`metadata.sender`) that
/// later becomes Circle's `remoteDepositor`. Only [`validate_discovery`] constructs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredBurn {
    payload: BurnPayload,
    depositor: AccountId,
}

impl DiscoveredBurn {
    /// The decoded `(amount, destDomain, destRecipient, salt)` payload.
    pub fn payload(&self) -> &BurnPayload {
        &self.payload
    }

    /// The Miden burner (`metadata.sender`) — a genuine, canonical account id, never a fabricated
    /// zero.
    pub fn depositor(&self) -> AccountId {
        self.depositor
    }
}

/// The discovery checklist (order load-bearing).
///
/// 1. **Tag** — exact full-32-bit equality against the configured burn tag, NEVER a prefix
///    (`SyncNotes` does not prefix-scan — an exact match, never a prefix).
/// 2. **Observability** — `details = Some(..)`; a `details = None` (private/erased) note is refused
///    as unobservable for Circle.
/// 3. **Payload** — the `(amount, destDomain, destRecipient, salt)` felts are decoded by the shared
///    encoding crate's codec (consumed by reference — no re-parse here).
/// 4. **Sender** — `metadata.sender` is read as the Miden burner; an absent/zero/malformed sender
///    is refused, never defaulted.
///
/// # Errors
/// [`DiscoveryReject::TagMismatch`], [`DiscoveryReject::PrivateNoteUnobservable`], or
/// [`DiscoveryReject::Decode`] (wrapping the codec's / sender read's [`DecodeError`]).
///
/// [`DecodeError`]: crate::error::DecodeError
pub fn validate_discovery(
    record: &DiscoveryRecord,
    cfg: &ListenerConfig,
) -> Result<DiscoveredBurn, DiscoveryReject> {
    // 1. exact full-32-bit tag match (never a prefix).
    if record.tag != cfg.burn_tag() {
        return Err(DiscoveryReject::TagMismatch {
            expected: cfg.burn_tag(),
            actual: record.tag,
        });
    }

    // 2. a public note (details = Some) is observable to Circle; a private/erased note is not.
    let details = record
        .details
        .as_ref()
        .ok_or(DiscoveryReject::PrivateNoteUnobservable)?;

    // 3. decode the four-field payload through the shared encoding crate's codec (single-owner;
    // no re-parse).
    let payload = decode_burn_payload(&details.items).map_err(DiscoveryReject::Decode)?;

    // 4. read metadata.sender as the Miden burner (refused, never defaulted).
    let depositor = read_sender(&details.sender).map_err(DiscoveryReject::Decode)?;

    Ok(DiscoveredBurn { payload, depositor })
}

// ================================================================================================
// VALIDATE THE RETURNED SPEC — the gate before signing
// ================================================================================================

/// Proof that a Circle `prepare-withdrawal` response passed the field-by-field gate against a
/// burn payload — and, with it, the per-batch digests cleared to sign.
///
/// Its ONLY constructor is [`validate_returned`]'s full-match path, and its digests are private, so
/// the sole way to feed the withdrawal signer a digest is to have passed validation. This is what
/// makes "signed anyway" untypeable rather than merely unreached: [`sign_validated`] cannot be
/// called without one of these, and one of these cannot exist without a full field-by-field match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWithdrawal {
    digests: Vec<[u8; 32]>,
}

impl ValidatedWithdrawal {
    /// The per-batch `messageHashToSign` digests cleared for signing, in batch order.
    pub fn digests(&self) -> &[[u8; 32]] {
        &self.digests
    }

    /// How many batches (and therefore digests) were validated.
    pub fn batch_count(&self) -> usize {
        self.digests.len()
    }
}

/// Validates every returned intent against the discovered burn and configured withdrawal terms.
/// Returns the validated batch digests for signing.
///
/// # Errors
/// A [`ValidationMismatch`] naming the batch and the field that diverged. On any `Err`, no
/// [`ValidatedWithdrawal`] is produced — so no signature over the mismatching data can follow.
pub fn validate_returned(
    resp: &PrepareWithdrawalResponse,
    burn: &DiscoveredBurn,
    cfg: &ListenerConfig,
) -> Result<ValidatedWithdrawal, ValidationMismatch> {
    let batches = resp.batches();
    if batches.is_empty() {
        return Err(ValidationMismatch::NoBatches);
    }

    let mut digests = Vec::with_capacity(batches.len());
    for (batch, prepared) in batches.iter().enumerate() {
        let intents = prepared.burn_intents();
        if intents.is_empty() {
            return Err(ValidationMismatch::EmptyBurnIntents { batch });
        }
        for intent in intents {
            check_intent(batch, intent, burn, cfg)?;
        }
        // The digest must be present and signable BEFORE the batch is cleared.
        digests.push(decode_digest(batch, prepared.message_hash_to_sign())?);
    }

    Ok(ValidatedWithdrawal { digests })
}

fn check_intent(
    batch: usize,
    intent: &BurnIntent,
    burn: &DiscoveredBurn,
    cfg: &ListenerConfig,
) -> Result<(), ValidationMismatch> {
    let payload = burn.payload();
    let max_fee = check_max_fee(batch, intent.max_fee(), payload, cfg)?;
    check_spec(batch, intent.spec(), max_fee, burn, cfg)
}

fn check_spec(
    batch: usize,
    spec: &TransferSpec,
    max_fee: u128,
    burn: &DiscoveredBurn,
    cfg: &ListenerConfig,
) -> Result<(), ValidationMismatch> {
    let payload = burn.payload();
    // Circle returns the net value and fee separately, both in smallest token units.
    let expected_amount = payload.amount.as_u64();
    let amount_matches = spec.value().parse::<u128>().is_ok_and(|value| {
        value > 0 && value.checked_add(max_fee) == Some(u128::from(expected_amount))
    });
    if !amount_matches {
        return Err(ValidationMismatch::Amount {
            batch,
            expected: expected_amount,
            returned: spec.value().to_string(),
        });
    }

    // destinationDomain
    if spec.destination_domain() != payload.dest_domain {
        return Err(ValidationMismatch::DestinationDomain {
            batch,
            expected: payload.dest_domain,
            returned: spec.destination_domain(),
        });
    }

    // destinationRecipient — compared as bytes, so hex casing is irrelevant.
    let recipient_matches = decode_hex32(spec.destination_recipient())
        .is_some_and(|bytes| &bytes == payload.dest_recipient.as_bytes());
    if !recipient_matches {
        return Err(ValidationMismatch::DestinationRecipient {
            batch,
            expected: to_hex32(payload.dest_recipient.as_bytes()),
            returned: spec.destination_recipient().to_string(),
        });
    }

    if !hex32_eq(spec.destination_caller(), &ZERO_BYTES32) {
        return Err(ValidationMismatch::DestinationCaller {
            batch,
            expected: to_hex32(&ZERO_BYTES32),
            returned: spec.destination_caller().to_string(),
        });
    }

    check_hook_data(batch, spec.hook_data(), burn, cfg)?;

    Ok(())
}

fn check_hook_data(
    batch: usize,
    hook: &StructuredHookData,
    burn: &DiscoveredBurn,
    cfg: &ListenerConfig,
) -> Result<(), ValidationMismatch> {
    if hook.remote_domain() != cfg.miden_domain() {
        return Err(ValidationMismatch::HookData {
            batch,
            field: "remoteDomain",
            expected: cfg.miden_domain().to_string(),
            returned: hook.remote_domain().to_string(),
        });
    }

    let expected_depositor = EthEmbeddedAccountId::from_account_id(burn.depositor()).to_bytes32();
    if !hex32_eq(hook.remote_depositor(), &expected_depositor) {
        return Err(ValidationMismatch::HookData {
            batch,
            field: "remoteDepositor",
            expected: to_hex32(&expected_depositor),
            returned: hook.remote_depositor().to_string(),
        });
    }

    let expected_token = EthEmbeddedAccountId::from_account_id(cfg.faucet_id()).to_bytes32();
    if !hex32_eq(hook.remote_token(), &expected_token) {
        return Err(ValidationMismatch::HookData {
            batch,
            field: "remoteToken",
            expected: to_hex32(&expected_token),
            returned: hook.remote_token().to_string(),
        });
    }

    if !hook
        .forwarding_contract_address()
        .eq_ignore_ascii_case(ZERO_HEX20)
    {
        return Err(ValidationMismatch::HookData {
            batch,
            field: "forwardingContractAddress",
            expected: ZERO_HEX20.to_string(),
            returned: hook.forwarding_contract_address().to_string(),
        });
    }

    if hook.forwarding_calldata() != NO_FORWARDING_CALLDATA {
        return Err(ValidationMismatch::HookData {
            batch,
            field: "forwardingCalldata",
            expected: NO_FORWARDING_CALLDATA.to_string(),
            returned: hook.forwarding_calldata().to_string(),
        });
    }

    Ok(())
}

fn check_max_fee(
    batch: usize,
    max_fee: &str,
    payload: &BurnPayload,
    cfg: &ListenerConfig,
) -> Result<u128, ValidationMismatch> {
    let ceiling = cfg.max_withdrawal_fee().as_u64();
    let amount = payload.amount.as_u64();
    let limit = u128::from(ceiling.min(amount));
    max_fee
        .parse::<u128>()
        .ok()
        .filter(|fee| *fee <= limit)
        .ok_or_else(|| ValidationMismatch::MaxFee {
            batch,
            ceiling,
            amount,
            returned: max_fee.to_string(),
        })
}

/// Decodes a batch's `messageHashToSign` into the 32-byte digest the attester signs. Empty ⇒
/// [`ValidationMismatch::MissingMessageHash`]; present-but-not-32-bytes ⇒
/// [`ValidationMismatch::MalformedMessageHash`] (a non-signable digest is refused before signing).
fn decode_digest(batch: usize, hash: &str) -> Result<[u8; 32], ValidationMismatch> {
    if hash.is_empty() {
        return Err(ValidationMismatch::MissingMessageHash { batch });
    }
    let body = hash.strip_prefix("0x").unwrap_or(hash);
    let bytes = hex::decode(body).map_err(|_| ValidationMismatch::MalformedMessageHash {
        batch,
        len: hash.len(),
    })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ValidationMismatch::MalformedMessageHash {
        batch,
        len: bytes.len(),
    })
}

/// `0x…`-hex → 32 bytes, or `None` if it is not exactly that.
fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let body = s.strip_prefix("0x")?;
    let bytes = hex::decode(body).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

fn hex32_eq(s: &str, expected: &[u8; 32]) -> bool {
    decode_hex32(s).is_some_and(|bytes| &bytes == expected)
}

/// 32 bytes → `0x…`-hex (lowercase) — for naming the expected recipient in a mismatch error.
fn to_hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

const ZERO_BYTES32: [u8; 32] = [0u8; 32];
const ZERO_HEX20: &str = "0x0000000000000000000000000000000000000000";
const NO_FORWARDING_CALLDATA: &str = "0x";

// ================================================================================================
// THE GATED SIGNER
// ================================================================================================

/// Signs every cleared digest of a [`ValidatedWithdrawal`] with `key`, one 65-byte `r‖s‖v`
/// signature per validated batch — the withdrawal flow's ONLY signing entry.
///
/// It cannot be called without a [`ValidatedWithdrawal`], which only a full-match
/// [`validate_returned`] mints; there is therefore no path from a mismatching Circle response to a
/// signature (validation gates signing, structurally). Each digest was checked to be exactly 32
/// bytes at the gate, so `attester::sign`'s length precondition holds for every one.
///
/// # Errors
/// [`SignError`] if the curve refuses a digest (not reachable for a valid key and a 32-byte
/// prehash) — surfaced as a typed error rather than a panic.
pub fn sign_validated(
    validated: &ValidatedWithdrawal,
    key: &SecretKey,
) -> Result<Vec<Signature65>, SignError> {
    validated
        .digests
        .iter()
        .map(|digest| sign(digest, key))
        .collect()
}
