//! Builds mint and burn probes for the local-node harness.
//! Payloads use the shared vectors and a locally generated attester key.

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::crypto::SequentialCommit;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteRecipient,
    NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::{Felt, Word};
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_standards::note::{
    MintNote, MintNoteStorage, NetworkAccountTarget, NoteExecutionHint, P2idNoteStorage,
};
use xusdc_encoding::note::xreserve_burn::{XReserveBurnNote, XUsdcBurnAttachment};
use xusdc_encoding::note::xreserve_mint::{
    DepositAttestation, XUsdcMintNote, XUSDC_DEPOSIT_SCALE_EXP,
    XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME, XUSDC_MINT_ATTESTATION_NUM_WORDS,
    XUSDC_MINT_INTENT_ATTACHMENT_SCHEME,
};
use xusdc_encoding::vectors::{load, parse_hex32, DiFields, DiVector};
use xusdc_encoding::xreserve::encoding::{
    bytes32_to_storage_map_key, deposit_intent_field_offset, deposit_intent_to_packed_felts,
    parse_deposit_intent_header, DepositIntentField, EthEmbeddedAccountIdExt, ForeignChainAddress,
    XReserveBurnItems,
};

use crate::actors::AttesterKey;
use crate::config::DomainParams;

/// Base deposit vector with an empty hook-data field.
pub const BASE_VECTOR: &str = "di-pos-empty-hookdata";

/// The canonical accept vector carrying a NON-empty hookData tail (`hook_data_len == 10`; a 250-byte
/// payload = the 240-byte header + 10 hookData bytes). Shares `remoteDomain` 7 and the SAME
/// `remoteToken` as [`BASE_VECTOR`], so ONE domain config validates BOTH the empty-hookData and the
/// hookData-bearing Row-D mints — the second variant (bounded hookData) the mint matrix requires.
pub const HOOKDATA_VECTOR: &str = "di-pos-hookdata";

/// Fixture destination domain. Circle's domain assignment remains OPEN.
pub const MINT_DOMAIN: u32 = 7;

/// Scale exponent used by the legacy mint fixture.
pub const SCALE_EXP: u32 = XUSDC_DEPOSIT_SCALE_EXP;
const SCALE: u64 = 1; // 10^SCALE_EXP

// Byte offsets used to modify the deposit fixture.
const AMOUNT_BYTE_OFF: usize = 2 * 4;
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
const MAX_FEE_BYTE_OFF: usize = 43 * 4;
const NONCE_BYTE_OFF: usize = 51 * 4;
// The payload uses the deployed domain and faucet ID; field offsets come from the shared codec.

fn vector(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

fn base_vector() -> &'static DiVector {
    vector(BASE_VECTOR)
}

fn base_fields() -> &'static DiFields {
    base_vector()
        .fields
        .as_ref()
        .expect("the accept vector carries fields")
}

/// The `hook_data_len` field of a canonical vector (0 for [`BASE_VECTOR`], >0 for [`HOOKDATA_VECTOR`]).
pub fn hook_data_len(vector_id: &str) -> u32 {
    vector(vector_id)
        .fields
        .as_ref()
        .expect("the accept vector carries fields")
        .hook_data_len
}

/// Domain configuration for the mint fixture.
pub fn lnv2_domain_params() -> DomainParams {
    DomainParams {
        domain: MINT_DOMAIN,
        source_domain: 3,
        xreserve_contract: ForeignChainAddress::new(core::array::from_fn(|i| 0x10 + i as u8)),
        // Legacy vector-token identifier bytes — no longer the fresh faucet's identifier (that is
        // the own-id fixpoint, derived at init). Kept so DomainParams stays fully populated.
        identifier_bytes: parse_hex32(&base_fields().remote_token_hex),
    }
}

/// A big-endian 32-byte encoding of `value` (uint256 with the value in the low 8 bytes).
fn uint256_be(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Builds a mint DepositIntent payload from [`BASE_VECTOR`] (empty hookData). See
/// [`mint_payload_from`].
pub fn mint_payload(
    recipient: AccountId,
    amount_raw: u64,
    max_fee_raw: u64,
    nonce_salt: u8,
) -> Vec<u8> {
    mint_payload_from(BASE_VECTOR, recipient, amount_raw, max_fee_raw, nonce_salt)
}

/// Builds a mint DepositIntent payload from the canonical vector `vector_id`: splices the raw
/// uint256 `amount_raw` and `max_fee_raw`, points `remoteRecipient` at `recipient` (so the emitted
/// P2ID note targets a real wallet), and XOR-perturbs one nonce byte by `nonce_salt` (distinct salts
/// ⇒ distinct nonces, avoiding the replay gate across probes). The amount/maxFee/recipient/nonce all
/// live in the 60-felt header, so the splice is identical for the empty-hookData ([`BASE_VECTOR`])
/// and hookData-bearing ([`HOOKDATA_VECTOR`]) vectors; the hookData tail (if any) is carried verbatim
/// and covered by the attester's keccak.
pub fn mint_payload_from(
    vector_id: &str,
    recipient: AccountId,
    amount_raw: u64,
    max_fee_raw: u64,
    nonce_salt: u8,
) -> Vec<u8> {
    let mut payload = vector(vector_id).bytes();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(amount_raw));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(max_fee_raw));
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(recipient).to_bytes32());
    if nonce_salt != 0 {
        payload[NONCE_BYTE_OFF] ^= nonce_salt;
    }
    payload
}

/// A mint payload for a FRESH-deployed faucet: [`mint_payload_from`] spliced with the faucet's
/// OWN-ID `remoteToken` (`EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()`). The fresh faucet's identifier is the
/// note-derived own-id fixpoint (`XReserveIdentifierInitNote::identifier_for(faucet_id)` =
/// `bytes32_to_storage_map_key(EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32())`), so a mint's `remoteToken` MUST be
/// `EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()` for structural validation's identifier compare to pass — NOT the static
/// golden-vector `remoteToken` the vectors carry (the R2 identifier-binding fix). `remoteDomain`
/// already equals the build-seed [`MINT_DOMAIN`] on the fresh vectors, so only the token is spliced.
pub fn mint_payload_own_id(
    faucet_id: AccountId,
    vector_id: &str,
    recipient: AccountId,
    amount_raw: u64,
    max_fee_raw: u64,
    nonce_salt: u8,
) -> Vec<u8> {
    let mut payload = mint_payload_from(vector_id, recipient, amount_raw, max_fee_raw, nonce_salt);
    let remote_token_off = deposit_intent_field_offset(DepositIntentField::RemoteToken);
    payload[remote_token_off..remote_token_off + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32());
    payload
}

/// The two DepositIntent fields the mint gate (structural validation `deposit_intent_parser::validate`)
/// compares against the faucet's stored domain config: `remoteDomain` and `remoteToken`. This is the
/// config a mint payload must carry so structural validation's compares pass.
///
/// - Fresh-LOCAL full gate: the config is [`MintDomainConfig::for_deployed_faucet`]`(MINT_DOMAIN,
///   fresh_faucet_id)` — the build-seed `remoteDomain` ([`MINT_DOMAIN`]) paired with the OWN-ID
///   `remoteToken` (`EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()`), because the fresh faucet's identifier is the
///   own-id fixpoint the `identifier_init` note derives (NOT the golden-vector token — the R2
///   identifier-binding fix). The `remoteDomain` splice is a no-op on [`BASE_VECTOR`]; the `remoteToken`
///   splice is what binds the mint to the fresh identity.
/// - Existing-faucet (`--faucet-id`) re-check: the config is resolved from the DEPLOYED faucet —
///   `domain` read from its on-chain domain-config slot, `remote_token` recomputed as
///   `EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()` (the identifier A5's `identifier_init` set from
///   `EthEmbeddedAccountId::from_account_id(faucet.id()).to_bytes32()`). This is the A6 fix: the fixed vector's `remoteDomain` (7)
///   did not match a production faucet's stored `domain` (e.g. 10007), so structural validation rejected every mint.
///
/// There is deliberately NO `source_domain` field: the DepositIntent has no `sourceDomain` field and
/// the mint proc never reads one (the faucet's `source_domain` config slot is off-chain withdrawal
/// identity, not a mint gate). The mint gate compares ONLY `remoteDomain` + `remoteToken`.
///
/// `pub(crate)` (type, fields, and constructors): every consumer is intra-crate (the driver, the
/// runner, and the offline tests), so the harness-only config is not part of the library's public API
/// and its field layout stays free to evolve (private-fields-with-accessors intent, scoped to the
/// crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MintDomainConfig {
    /// The faucet's configured `domain` — spliced into `remoteDomain` (felt 10, big-endian u32).
    pub(crate) domain: u32,
    /// The faucet's identifier bytes32 — spliced into `remoteToken` (felt 11..18); the mint gate
    /// compares `bytes32_to_storage_map_key(remoteToken)` against the stored identifier key.
    pub(crate) remote_token: [u8; 32],
}

impl MintDomainConfig {
    /// A config carrying the [`BASE_VECTOR`]'s OWN `remoteDomain` ([`MINT_DOMAIN`]) and `remoteToken`:
    /// splicing it is a no-op on the [`BASE_VECTOR`] payload. Retained ONLY for the offline
    /// splice-correctness test (splicing a config equal to what the vector already carries must be
    /// byte-for-byte identical). It is NOT the fresh-local deploy config — that is
    /// [`MintDomainConfig::for_deployed_faucet`] (own-id `remoteToken`), since the fresh faucet's
    /// identifier is the own-id fixpoint, not the vector token.
    #[cfg(test)]
    pub(crate) fn local_vector() -> Self {
        Self {
            domain: MINT_DOMAIN,
            remote_token: parse_hex32(&base_fields().remote_token_hex),
        }
    }

    /// The config of a DEPLOYED faucet on the `--faucet-id` path: the operator-read on-chain `domain`
    /// paired with `remote_token = EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()` — the identifier A5's
    /// `identifier_init` stored (recomputable from `faucet_id` alone, no guessing).
    pub(crate) fn for_deployed_faucet(domain: u32, faucet_id: AccountId) -> Self {
        Self {
            domain,
            remote_token: EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32(),
        }
    }
}

/// Builds a mint DepositIntent that carries `config`'s `remoteDomain` + `remoteToken` (the two structural validation
/// gated fields) in addition to the amount/maxFee/recipient/nonce splice of [`mint_payload_from`].
/// The existing-faucet (`--faucet-id`) mint builder: the payload must match the DEPLOYED faucet's
/// stored domain config, or structural validation rejects it (`WRONG_DOMAIN` / `WRONG_IDENTIFIER`) before any later
/// gate — the root cause of the A6 300s path-N timeout. The attestation is re-signed over this
/// modified payload by the caller's `attestation_for` (keccak covers the whole preimage).
pub(crate) fn mint_payload_for(
    config: &MintDomainConfig,
    recipient: AccountId,
    amount_raw: u64,
    max_fee_raw: u64,
    nonce_salt: u8,
) -> Vec<u8> {
    let mut payload =
        mint_payload_from(BASE_VECTOR, recipient, amount_raw, max_fee_raw, nonce_salt);
    // Read field offsets from the shared deposit-intent codec.
    let remote_domain_off = deposit_intent_field_offset(DepositIntentField::RemoteDomain);
    let remote_token_off = deposit_intent_field_offset(DepositIntentField::RemoteToken);
    payload[remote_domain_off..remote_domain_off + 4].copy_from_slice(&config.domain.to_be_bytes());
    payload[remote_token_off..remote_token_off + 32].copy_from_slice(&config.remote_token);
    payload
}

/// Selects the mint-payload builder for the run mode: the existing-faucet path splices `config`'s
/// domain/identifier ([`mint_payload_for`]); the fresh-LOCAL path (`None`) leaves the [`BASE_VECTOR`]
/// header untouched ([`mint_payload`]). One seam so every mint call site chooses the right builder
/// from the driver's resolved config without duplicating the match.
pub(crate) fn mint_payload_opt(
    config: Option<&MintDomainConfig>,
    recipient: AccountId,
    amount_raw: u64,
    max_fee_raw: u64,
    nonce_salt: u8,
) -> Vec<u8> {
    match config {
        Some(c) => mint_payload_for(c, recipient, amount_raw, max_fee_raw, nonce_salt),
        None => mint_payload_from(BASE_VECTOR, recipient, amount_raw, max_fee_raw, nonce_salt),
    }
}

/// The `usedNonces[nonce]` storage-map key for a payload's nonce field (`bytes32_to_storage_map_key(nonce)`) —
/// the SAME key the mint's replay protection/mint effects derive and set, so the driver can read the marker back after a
/// committed mint or prove a rejected negative left it empty.
pub fn nonce_key(payload: &[u8]) -> Word {
    let nonce: [u8; 32] = payload[NONCE_BYTE_OFF..NONCE_BYTE_OFF + 32]
        .try_into()
        .expect("32 nonce bytes");
    bytes32_to_storage_map_key(&nonce).into()
}

/// The reduced (on-chain) asset amount for a raw uint256 amount (÷ 10^SCALE_EXP). Under the P0
/// scale-0 identity ([`SCALE_EXP`] == 0, `SCALE` == 1) this is the identity: the minted units equal
/// the raw deposit amount.
pub fn reduced(amount_raw: u64) -> u64 {
    amount_raw / SCALE
}

/// The raw uint256 amount that reduces to exactly `units` on-chain. Under the P0 scale-0 identity
/// ([`SCALE_EXP`] == 0, `SCALE` == 1) this is the identity: `raw_for_units(u) == u`.
pub fn raw_for_units(units: u64) -> u64 {
    units * SCALE
}

/// Builds a mint note signed by the local attester. `nonce_salt` distinguishes deposits.
#[allow(clippy::too_many_arguments)]
pub fn mint_note<R: FeltRng>(
    sender: AccountId,
    faucet: AccountId,
    attester: &AttesterKey,
    recipient: AccountId,
    amount_raw: u64,
    max_fee_raw: u64,
    nonce_salt: u8,
    rng: &mut R,
) -> Result<Note> {
    let payload = mint_payload(recipient, amount_raw, max_fee_raw, nonce_salt);
    let attestation = attester.attestation_for(&payload);
    XUsdcMintNote::create(sender, faucet, &payload, &attestation, rng)
        .context("building the XUsdcMintNote probe")
}

/// Packs a fee amount into eight limbs for the legacy fee-rejection probe.
pub fn fee_limbs_for(fee_raw: u64) -> [Felt; 8] {
    // Splice `fee_raw` into the base vector's amount field (leaving its own valid recipient), pack,
    // and read the amount-field limbs back — the reducer treats those limbs identically to the
    // advice feeAmount, so they reduce to `fee_raw / 10^SCALE_EXP`.
    let mut payload = base_vector().bytes();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(fee_raw));
    let packed =
        deposit_intent_to_packed_felts(&payload).expect("a well-formed accept payload packs");
    let felt_off = AMOUNT_BYTE_OFF / 4;
    core::array::from_fn(|i| packed[felt_off + i])
}

/// Builds an `XUsdcMintNote`-shaped mint note with a CUSTOM scheme-5 attestation attachment: the
/// same STOCK-`MintNote` transport shape the production [`XUsdcMintNote::create`] emits (the stock
/// standards MINT script via [`XUsdcMintNote::script`], the `FungiblePublic` storage embedding the
/// ATTESTED output — P2ID recipe to the payload's `remoteRecipient` with the nonce-key serial, the
/// scale-0-reduced [`FungibleAsset`], the recipient account-target tag — plus the scheme-4
/// DepositIntent attachment and the scheme-2 `NetworkAccountTarget` routing bind) but with the
/// attestation attachment's `[feeAmount(8), pubkey(16 affine), signature(17), pad(3)]` words
/// assembled from the caller-supplied `fee_limbs` + `attestation`. This is the harness's
/// ADVERSARIAL note builder — it exists solely to stage Row-E negatives the production factory
/// cannot (a non-zero feeAmount the F2 gate must trap); it never re-implements any faucet gate.
pub fn mint_note_with_fee<R: FeltRng>(
    sender: AccountId,
    faucet: AccountId,
    payload: &[u8],
    attestation: &DepositAttestation,
    fee_limbs: [Felt; 8],
    rng: &mut R,
) -> Result<Note> {
    // The ATTESTED storage ingredients, derived from the payload exactly as the production factory
    // does (and as the on-chain policy re-derives them), so the note passes every ASSERT-MATCH
    // binding leg and the probe traps at exactly the F2 fee gate.
    let header = parse_deposit_intent_header(payload)
        .map_err(|e| anyhow::anyhow!("deposit intent payload rejected by the 04 codec: {e}"))?;
    let recipient_id = EthEmbeddedAccountId::try_from_bytes32(header.remote_recipient)
        .map(EthEmbeddedAccountId::into_account_id)
        .map_err(|e| anyhow::anyhow!("remoteRecipient is not a valid account id: {e}"))?;
    let amount = header
        .reduced_amount(SCALE_EXP)
        .map_err(|e| anyhow::anyhow!("amount rejected by the 04 reducer: {e}"))?;
    let asset = FungibleAsset::new(faucet, u64::from(amount))
        .map_err(|e| anyhow::anyhow!("attested amount: {e}"))?;
    let serial = Word::from(bytes32_to_storage_map_key(&header.nonce));
    let recipient = P2idNoteStorage::new(recipient_id).into_recipient(serial);
    let tag = NoteTag::with_account_target(recipient_id);
    let storage = MintNoteStorage::new_fungible_public(recipient, asset, tag)
        .context("mint-note fungible-public storage")?;

    // The scheme-4 DepositIntent attachment: the u32-LE-packed payload felts, zero-padded to the
    // word boundary (identical to the production intent attachment).
    let mut intent_felts = deposit_intent_to_packed_felts(payload)
        .map_err(|e| anyhow::anyhow!("packing the deposit intent: {e}"))?;
    while !intent_felts.len().is_multiple_of(4) {
        intent_felts.push(Felt::from(0u32));
    }
    let intent_words: Vec<Word> = intent_felts
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| Word::new([c[0], c[1], c[2], c[3]]))
        .collect();
    let intent_attachment = NoteAttachment::with_words(
        NoteAttachmentScheme::new(XUSDC_MINT_INTENT_ATTACHMENT_SCHEME)
            .context("scheme-4 intent attachment scheme")?,
        intent_words,
    )
    .context("building the scheme-4 DepositIntent attachment")?;

    // Legacy attestation layout: fee(8), public key(16), signature(17), padding(3).
    let mut felts: Vec<Felt> = Vec::with_capacity(44);
    felts.extend(fee_limbs);
    felts.extend(attestation.pubkey().to_elements());
    felts.extend(attestation.signature().to_felts());
    felts.extend([Felt::from(0u32); 3]);
    let words: Vec<Word> = felts
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| Word::new([c[0], c[1], c[2], c[3]]))
        .collect();
    debug_assert_eq!(words.len(), XUSDC_MINT_ATTESTATION_NUM_WORDS);
    let attestation_attachment = NoteAttachment::with_words(
        NoteAttachmentScheme::new(XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME)
            .context("scheme-5 attestation attachment scheme")?,
        words,
    )
    .context("building the custom scheme-5 attestation attachment")?;

    let target = NetworkAccountTarget::new(faucet, NoteExecutionHint::Always)
        .map_err(|e| anyhow::anyhow!("faucet id is not a public network account: {e}"))?;
    let mint_note = MintNote::builder()
        .sender(sender)
        .mint_storage(storage)
        .serial_number(rng.draw_word())
        .attachment(intent_attachment)
        .attachment(attestation_attachment)
        .attachment(NoteAttachment::from(target))
        .build()
        .context("building the adversarial stock MintNote")?;
    Ok(Note::from(mint_note))
}

/// Builds a production `XReserveBurnNote` carrying `amount` units of the faucet's xUSDC (the note's
/// vault holds the asset; the faucet's `receive_and_burn` gate is what the C2/C4 probes exercise).
pub fn burn_note<R: FeltRng>(
    sender: AccountId,
    faucet: AccountId,
    amount: u64,
    _dest_salt: u8,
    rng: &mut R,
) -> Result<Note> {
    let items = XReserveBurnItems {
        amount: AssetAmount::new(amount).context("burn amount is a valid AssetAmount")?,
        dest_domain: 3,
        dest_recipient: ForeignChainAddress::new([0xAB; 32]),
    };
    XReserveBurnNote::create(sender, faucet, items, rng)
        .context("building the XReserveBurnNote probe")
}

/// Builds a burn probe routed to one faucet with an asset issued by another.
pub fn burn_note_wrong_asset<R: FeltRng>(
    sender: AccountId,
    target_faucet: AccountId,
    asset_faucet: AccountId,
    amount: u64,
    _dest_salt: u8,
    rng: &mut R,
) -> Result<Note> {
    use xusdc_encoding::note::xreserve_burn::FIXED_XUSDC_BURN_TAG;

    let items = XReserveBurnItems {
        amount: AssetAmount::new(amount)
            .context("wrong-asset burn amount is a valid AssetAmount")?,
        dest_domain: 3,
        dest_recipient: ForeignChainAddress::new([0xAB; 32]),
    };
    let asset = FungibleAsset::new(asset_faucet, amount)
        .map_err(|e| anyhow::anyhow!("building the wrong-asset fungible asset: {e}"))?;
    let storage = NoteStorage::new(Asset::from(asset).as_elements().to_vec())
        .context("wrong-asset burn storage")?;
    // Reuse the STOCK burn consume script (→ faucet::receive_and_burn → the burn security policy,
    // CMP-A10), exactly as the production factory does.
    let recipient = NoteRecipient::new(rng.draw_word(), XReserveBurnNote::script(), storage);
    // Public mandate + the fixed xUSDC burn tag; metadata.sender = the depositor.
    let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
        .with_tag(NoteTag::new(FIXED_XUSDC_BURN_TAG));
    // The vault asset is issued by the WRONG faucet — the whole point of this negative.
    let vault = NoteAssets::new(vec![asset.into()]).context("wrong-asset burn vault")?;
    // Route at the TARGET faucet (network account) — the note is still addressed at our faucet; only
    // the asset issuer differs.
    let target = NetworkAccountTarget::new(target_faucet, NoteExecutionHint::Always)
        .map_err(|e| anyhow::anyhow!("target faucet id is not a public network account: {e}"))?;
    let attachments = NoteAttachments::new(vec![
        NoteAttachment::from(target),
        NoteAttachment::from(&XUsdcBurnAttachment::new(items)),
    ])
        .context("wrong-asset burn attachments")?;
    Ok(Note::with_attachments(
        vault,
        metadata,
        recipient,
        attachments,
    ))
}
