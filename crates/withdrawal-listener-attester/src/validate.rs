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
//! [`validate_returned`] compares Circle's returned `spec` against the burn-note payload field by
//! field, for EVERY batch, and only a full match may proceed to signing.
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
//!   partner never supplies it and the gate never compares it against the burn payload. The domain
//!   cross-checks that would consume the config are gated on the still-open domain-id and
//!   `sourceDepositor` questions; wiring one now would hard-code an unconfirmed decision, so
//!   [`ListenerConfig`] is accepted as the reserved seam for them and not yet read.

use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::note::{NoteMetadata, NoteScriptRoot};
use miden_protocol::Felt;
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;

use crate::attester::{sign, SecretKey, Signature65};
use crate::circle::schema::{PrepareWithdrawalResponse, TransferSpec};
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
/// note that came back without its columns, unobservable to Circle. What the node said goes in
/// here; [`validate_discovery`] is what judges it. The real feed — the exact-tag `SyncNotes` scan
/// and the `GetNotesById` retrieval — fills this type in
/// [`miden::discovery`](crate::miden::discovery).
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

/// The details a PUBLIC discovered note carries, as REPORTED: its withdrawal-payload attachment
/// felts, its `metadata.sender`, the root of the script that will consume it, and the assets in its
/// vault. Present exactly when `GetNotesById` returned `details = Some(..)`.
///
/// # Why the script root and the vault are here
///
/// They are the two facts a burn cannot be judged without, and until they were carried the two
/// checks that use them were not merely missing — they were **unrepresentable**.
///
/// * `metadata.tag` is a routing hint anyone can write, so the tag alone does not say a note is a
///   burn. The `script_root` is what says the faucet's burn path runs on consumption.
/// * The chain reduces supply by what is in `assets`; the withdrawal payload in `items` is what
///   Circle is asked to release. Two numbers, written by the same note author, that nothing forced
///   to agree.
///
/// This type still REPORTS rather than judges: it holds whatever the node handed back — a vault of
/// any size, an asset from any faucet, any script root at all — and [`validate_discovery`] is what
/// refuses. A constructor that filled in the canonical root, or derived the asset from the payload,
/// would make both checks vacuous for every value built through it.
#[derive(Debug, Clone)]
pub struct DiscoveredDetails {
    items: Vec<Felt>,
    sender: BurnNoteMetadata,
    script_root: NoteScriptRoot,
    assets: Vec<Asset>,
}

impl DiscoveredDetails {
    /// From the raw withdrawal-payload attachment felts, an already-modelled sender, the reported
    /// script root, and the reported vault.
    pub fn new(
        items: Vec<Felt>,
        sender: BurnNoteMetadata,
        script_root: NoteScriptRoot,
        assets: Vec<Asset>,
    ) -> Self {
        Self {
            items,
            sender,
            script_root,
            assets,
        }
    }

    /// From the raw items and a public note's `NoteMetadata` (the happy-path discovery shape).
    pub fn from_metadata(
        items: Vec<Felt>,
        meta: &NoteMetadata,
        script_root: NoteScriptRoot,
        assets: Vec<Asset>,
    ) -> Self {
        Self::new(
            items,
            BurnNoteMetadata::from_metadata(meta),
            script_root,
            assets,
        )
    }

    /// From the raw items and the reported `(prefix, suffix)` sender felts — the shape a node hands
    /// back before the sender is known to be an account id.
    pub fn from_raw_sender(
        items: Vec<Felt>,
        prefix: Felt,
        suffix: Felt,
        script_root: NoteScriptRoot,
        assets: Vec<Asset>,
    ) -> Self {
        Self::new(
            items,
            BurnNoteMetadata::from_raw_sender(prefix, suffix),
            script_root,
            assets,
        )
    }

    /// The reported withdrawal-payload attachment felts.
    pub fn items(&self) -> &[Felt] {
        &self.items
    }

    /// The reported `metadata.sender`.
    pub fn sender(&self) -> &BurnNoteMetadata {
        &self.sender
    }

    /// The reported root of the script that consumes this note.
    pub fn script_root(&self) -> NoteScriptRoot {
        self.script_root
    }

    /// The reported contents of the note's vault — what consuming the note would actually burn.
    pub fn assets(&self) -> &[Asset] {
        &self.assets
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
/// 3. **Script root** — the note is consumed by the xUSDC burn script and by nothing else. The tag
///    above is a routing hint anyone can write; this is the rung that says the faucet's burn path
///    actually runs. Pinned to [`XReserveBurnNote::script_root()`], read from the shared encoding
///    crate at every call so the check moves with the note rather than with a digest copied here.
/// 4. **Payload** — the `(amount, destDomain, destRecipient, salt)` felts are decoded by the shared
///    encoding crate's codec (consumed by reference — no re-parse here).
/// 5. **Sender** — `metadata.sender` is read as the Miden burner; an absent/zero/malformed sender
///    is refused, never defaulted.
/// 6. **Asset** — the note carries exactly one fungible asset, issued by the configured xUSDC
///    faucet, in exactly the amount the payload claims, and that amount is not zero. This is the
///    rung that ties what Miden BURNS to what Circle is asked to RELEASE; without it the two
///    numbers are independent, and only one of them costs the reserve.
///
/// The order puts the two cheap structural rungs (tag, script root) ahead of the decode, so a note
/// that is not a burn at all is refused without its payload ever being parsed — and puts the asset
/// rung after the decode, because it has nothing to compare against until the payload exists.
///
/// # Errors
/// [`DiscoveryReject::TagMismatch`], [`DiscoveryReject::PrivateNoteUnobservable`],
/// [`DiscoveryReject::ScriptRootMismatch`], [`DiscoveryReject::Decode`] (wrapping the codec's /
/// sender read's [`DecodeError`]), or one of the asset refusals —
/// [`DiscoveryReject::AssetCount`], [`DiscoveryReject::AssetNotFungible`],
/// [`DiscoveryReject::AssetFaucetMismatch`], [`DiscoveryReject::AssetAmountMismatch`],
/// [`DiscoveryReject::ZeroAmount`].
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

    // 3. the note is consumed by the burn script. Checked here, BEFORE the decode, because a note
    // that merely borrowed the tag is not this listener's note and its payload is not worth
    // parsing. The expected root is read from the shared encoding crate on every call — a digest
    // literal here would keep passing this check on the day the burn policy moves the script.
    let expected_root = XReserveBurnNote::script_root();
    if details.script_root != expected_root {
        return Err(DiscoveryReject::ScriptRootMismatch {
            expected: expected_root,
            actual: details.script_root,
        });
    }

    // 4. decode the four-field payload through the shared encoding crate's codec (single-owner;
    // no re-parse).
    let payload = decode_burn_payload(&details.items).map_err(DiscoveryReject::Decode)?;

    // 5. read metadata.sender as the Miden burner (refused, never defaulted).
    let depositor = read_sender(&details.sender).map_err(DiscoveryReject::Decode)?;

    // 6. what the note actually burns must be what the payload claims.
    check_carried_asset(&details.assets, &payload, cfg)?;

    Ok(DiscoveredBurn { payload, depositor })
}

/// Weighs the note's vault against its withdrawal payload — the check that makes "burned" and
/// "claimed" one number rather than two.
///
/// Consuming the note moves `assets` to the faucet and reduces supply by that much; nothing
/// on-chain reads the payload, and nothing off-chain read the vault before this. Each rung below is
/// a way the two can disagree, and each is a refusal rather than a reconciliation: there is no
/// honest way to pick which of two numbers a user meant.
fn check_carried_asset(
    assets: &[Asset],
    payload: &BurnPayload,
    cfg: &ListenerConfig,
) -> Result<(), DiscoveryReject> {
    // exactly one asset. An empty vault burns nothing; a multi-asset vault has no single amount,
    // and picking the one that agrees is how dust beside a worthless token reads as a full burn.
    let [asset] = assets else {
        return Err(DiscoveryReject::AssetCount {
            count: assets.len(),
        });
    };

    // …and it is fungible: a withdrawal is denominated in an amount, which a non-fungible asset
    // does not have.
    let Asset::Fungible(carried) = asset else {
        return Err(DiscoveryReject::AssetNotFungible);
    };

    // …issued by the configured xUSDC faucet. Another faucet's token is not xUSDC however exactly
    // its amount matches, which is precisely the case a bare amount check would wave through.
    if carried.faucet_id() != cfg.faucet_id() {
        return Err(DiscoveryReject::AssetFaucetMismatch {
            expected: cfg.faucet_id(),
            actual: carried.faucet_id(),
        });
    }

    // …in exactly the claimed amount. Compared as the same `u64` on both sides, so no rounding,
    // scaling or tolerance can open a gap between the burn and the release.
    let carried_amount = carried.amount().as_u64();
    let claimed_amount = payload.amount.as_u64();
    if carried_amount != claimed_amount {
        return Err(DiscoveryReject::AssetAmountMismatch {
            carried: carried_amount,
            payload: claimed_amount,
        });
    }

    // …and it is not zero. The two halves AGREE at zero, so the equality above passes and this is
    // the rung that catches a withdrawal with no burn behind it.
    if carried_amount == 0 {
        return Err(DiscoveryReject::ZeroAmount);
    }

    Ok(())
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

/// The gate: validate Circle's returned data against the burn-note `payload`, field by
/// field, for EVERY batch — and, on a full match, mint the [`ValidatedWithdrawal`] that clears
/// signing. A mismatch in ANY batch (not just `batches[0]`) is a hard `Err` that MUST abort before
/// signing.
///
/// For each batch, every returned `burnIntents[].spec` must match the payload on:
/// * `value` (the amount, in the smallest token unit) == `payload.amount`;
/// * `destinationDomain` == `payload.dest_domain`;
/// * `destinationRecipient` == `payload.dest_recipient`.
///
/// and the batch's `messageHashToSign` must be present and a signable 32-byte digest. A batch with
/// an EMPTY `burnIntents` array is refused (`EmptyBurnIntents`) — with no `spec` to compare,
/// clearing it would bind the digest to nothing. The `encoded` binary blob is treated as OPAQUE and
/// never decoded — the optional local reconstruction is off the critical path (anti-`the
/// do-not-sign trap`).
///
/// `cfg` is the reserved seam for the source-domain / `sourceDepositor` cross-checks that land when
/// the still-open domain-id and `sourceDepositor` questions resolve; wiring one now would hard-code
/// an unconfirmed Circle decision, so it is accepted but not yet read.
///
/// # Errors
/// A [`ValidationMismatch`] naming the batch and the field that diverged. On any `Err`, no
/// [`ValidatedWithdrawal`] is produced — so no signature over the mismatching data can follow.
pub fn validate_returned(
    resp: &PrepareWithdrawalResponse,
    payload: &BurnPayload,
    _cfg: &ListenerConfig,
) -> Result<ValidatedWithdrawal, ValidationMismatch> {
    let batches = resp.batches();
    if batches.is_empty() {
        return Err(ValidationMismatch::NoBatches);
    }

    let mut digests = Vec::with_capacity(batches.len());
    for (batch, prepared) in batches.iter().enumerate() {
        // A batch with no burn intents has nothing to compare against the payload — clearing it
        // would bind its digest to no amount/domain/recipient and mint a signing token vacuously.
        // Refuse it BEFORE the per-intent loop, which would otherwise be skippable straight into Ok.
        let intents = prepared.burn_intents();
        if intents.is_empty() {
            return Err(ValidationMismatch::EmptyBurnIntents { batch });
        }
        // Every burn intent in the batch must match the payload — not merely the first.
        for intent in intents {
            check_spec(batch, intent.spec(), payload)?;
        }
        // The digest must be present and signable BEFORE the batch is cleared.
        digests.push(decode_digest(batch, prepared.message_hash_to_sign())?);
    }

    Ok(ValidatedWithdrawal { digests })
}

/// Compares one returned `TransferSpec` against the burn payload on the three compared fields, in
/// order.
fn check_spec(
    batch: usize,
    spec: &TransferSpec,
    payload: &BurnPayload,
) -> Result<(), ValidationMismatch> {
    // amount — spec.value is a smallest-unit decimal string; the payload amount fits in u64.
    let expected_amount = payload.amount.as_u64();
    let amount_matches = spec
        .value()
        .parse::<u128>()
        .is_ok_and(|v| v == u128::from(expected_amount));
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

    Ok(())
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

/// 32 bytes → `0x…`-hex (lowercase) — for naming the expected recipient in a mismatch error.
fn to_hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

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
