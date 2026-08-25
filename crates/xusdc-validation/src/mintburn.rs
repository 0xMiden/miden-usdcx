//! Mint/burn note builders — the C-row PROBES.
//!
//! Rows C1/C3/C4 use real `XUsdcMintNote`s and C2/C4 use real `XReserveBurnNote`s as instruments
//! to prove an admin change took effect (a rotated-out attester can no longer mint, an over-cap mint
//! rejects, a paused faucet halts both, a raised minimum rejects a small burn). These are NOT the
//! mint/burn matrix rows (D/E/G/H — LNV-3/4); they are the smallest real notes that exercise the
//! gate each C row changes.
//!
//! The mint note carries a compressed Circle DepositIntent whose `remoteDomain` + `remoteToken`
//! must match the faucet's configured domain and its own id: the faucet writes both into the
//! message it rebuilds, so an intent naming different ones rebuilds a different digest and dies
//! on chain as an invalid signature. Amount/maxFee/recipient/nonce are spliced into a canonical
//! accept vector's payload (the `assembled_faucet_e2e` recipe); the attestation is signed by a
//! local test attester (`crate::actors::AttesterKey`), never Circle's key.

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachments, NoteRecipient, NoteStorage, NoteTag,
    NoteType, PartialNoteMetadata,
};
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::Word;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::note::xreserve_mint::{DepositAttestation, XUsdcMintNote};
use xusdc_encoding::vectors::{load, DiVector};
use xusdc_encoding::xreserve::encoding::{
    bytes32_to_storage_map_key, DepositIntent, DepositIntentField, ForeignChainAddress,
    XReserveBurnItems,
};

use crate::actors::AttesterKey;
use crate::config::DomainParams;

/// The canonical accept vector every LNV-2 mint payload is built from (empty hookData: the 60-felt
/// header, no hookData tail — the minimal valid mint). Its `remoteDomain` is 7 and its `remoteToken`
/// keys the faucet identifier.
pub const BASE_VECTOR: &str = "di-pos-empty-hookdata";

/// The canonical accept vector carrying a NON-empty hookData tail (`hook_data_len == 10`; a 250-byte
/// payload = the 240-byte header + 10 hookData bytes). Shares `remoteDomain` 7 and the SAME
/// `remoteToken` as [`BASE_VECTOR`], so ONE domain config validates BOTH the empty-hookData and the
/// hookData-bearing Row-D mints — the second variant (bounded hookData) the mint matrix requires.
pub const HOOKDATA_VECTOR: &str = "di-pos-hookdata";

/// The vector's `remoteDomain` (Q-DOM-1 OPEN; `TEST_DOMAIN` in the MockChain suite). The build
/// seed must carry this so the rebuilt message names the same domain the attester signed.
pub const MINT_DOMAIN: u32 = 7;

/// The reduction the shared-encoding decode applies to a deposit's uint256 `amount`: Circle sends a
/// 6-decimal deposit amount and Miden xUSDC is ALSO 6 decimals, so the reduction is the identity and
/// the on-chain minted asset amount EQUALS the raw uint256 deposit amount. The transport can express
/// no other scale — it carries the reduced `AssetAmount` and the faucet zero-extends it back into
/// the uint256 field when it rebuilds the signed message, which is lossless only at scale zero.
const SCALE: u64 = 1;

// DC-1 field byte offsets (felt offset × 4): the layout the shared-encoding codec packs. Mirrors the MockChain
// support constants (`AMOUNT_FELT_OFF` = 2, `REMOTE_RECIPIENT_FELT_OFF` = 19, `MAX_FEE_FELT_OFF` =
// 43, nonce at felt 51).
const AMOUNT_BYTE_OFF: usize = 2 * 4;
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
const MAX_FEE_BYTE_OFF: usize = 43 * 4;
const NONCE_BYTE_OFF: usize = 51 * 4;
// The two fields the faucet writes into the message it rebuilds — and so the two a mint payload has
// to name for the rebuilt digest to match — are `remoteDomain` (felt 10, a big-endian u32) and
// `remoteToken` (felt 11..18, a bytes32). Their wire offsets are NOT restated here: the DepositIntent
// layout owner is `xusdc-encoding`, so `mint_payload_for` reads them from
// `DepositIntentField::offset()` (the single source of truth, pinned by reference). There is
// deliberately NO `sourceDomain`: it is not a DepositIntent field and the mint path never reads one.

fn vector(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

#[cfg(test)]
fn base_vector() -> &'static DiVector {
    vector(BASE_VECTOR)
}

#[cfg(test)]
fn base_fields() -> &'static xusdc_encoding::vectors::DiFields {
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

/// The BUILD-SEEDED domain-config parameters LNV-2 deploys with: `domain` MATCHES the mint vector's
/// `remoteDomain` (so the rebuilt message names the same domain the attester signed),
/// `source_domain`/`xreserve_contract` are arbitrary distinct local test values (the mint path does
/// not read them — they are off-chain withdrawal identity). The faucet's identifier is not a param
/// at all: it is the faucet's own id, so a mint carries `remoteToken =
/// EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()` ([`mint_payload_own_id`] /
/// [`MintDomainConfig::for_deployed_faucet`]), never the vector token.
pub fn lnv2_domain_params() -> DomainParams {
    DomainParams {
        domain: MINT_DOMAIN,
        source_domain: 3,
        xreserve_contract: ForeignChainAddress::new(core::array::from_fn(|i| 0x10 + i as u8)),
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
/// OWN-ID `remoteToken` (`EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()`). The
/// faucet's identifier is its own account id, read from the kernel and written into the message it
/// rebuilds, so a mint's `remoteToken` MUST be that id for the rebuilt message to name this faucet —
/// NOT the static golden-vector `remoteToken` the vectors carry. `remoteDomain` already equals the
/// build-seed [`MINT_DOMAIN`] on the fresh vectors, so only the token is spliced.
pub fn mint_payload_own_id(
    faucet_id: AccountId,
    vector_id: &str,
    recipient: AccountId,
    amount_raw: u64,
    max_fee_raw: u64,
    nonce_salt: u8,
) -> Vec<u8> {
    let mut payload = mint_payload_from(vector_id, recipient, amount_raw, max_fee_raw, nonce_salt);
    let remote_token_off = DepositIntentField::RemoteToken.offset();
    payload[remote_token_off..remote_token_off + 32]
        .copy_from_slice(&EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32());
    payload
}

/// The two DepositIntent fields that bind a mint to its faucet — `remoteDomain` and `remoteToken` —
/// as the faucet itself would write them. This is the config a mint payload must carry for the
/// rebuilt message to match what the attester signed.
///
/// - Fresh-LOCAL full gate: the config is [`MintDomainConfig::for_deployed_faucet`]`(MINT_DOMAIN,
///   fresh_faucet_id)` — the build-seed `remoteDomain` ([`MINT_DOMAIN`]) paired with the OWN-ID
///   `remoteToken` (`EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()`), because the
///   faucet writes its own id there (NOT the golden-vector token). The `remoteDomain` splice is a
///   no-op on [`BASE_VECTOR`]; the `remoteToken` splice is what binds the mint to the fresh identity.
/// - Existing-faucet (`--faucet-id`) re-check: the config is resolved from the DEPLOYED faucet —
///   `domain` read from its on-chain domain-config slot, `remote_token` recomputed as
///   `EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()` (the id the faucet writes, recomputed from
///   `EthEmbeddedAccountId::from_account_id(faucet.id()).to_bytes32()`). This is the A6 fix: the fixed vector's `remoteDomain` (7)
///   did not match a production faucet's stored `domain` (e.g. 10007), so the rebuilt digest never matched and every mint was rejected.
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
            remote_token: xusdc_encoding::vectors::parse_hex32(&base_fields().remote_token_hex),
        }
    }

    /// The config of a DEPLOYED faucet on the `--faucet-id` path: the operator-read on-chain `domain`
    /// paired with `remote_token = EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()` — the identifier A5's
    /// own id, recomputable from `faucet_id` alone, no guessing.
    pub(crate) fn for_deployed_faucet(domain: u32, faucet_id: AccountId) -> Self {
        Self {
            domain,
            remote_token: EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32(),
        }
    }
}

/// Builds a mint DepositIntent that carries `config`'s `remoteDomain` + `remoteToken` (the two
/// gated fields) in addition to the amount/maxFee/recipient/nonce splice of [`mint_payload_from`].
/// The existing-faucet (`--faucet-id`) mint builder: the payload must match the DEPLOYED faucet's
/// configured domain and own id, or the rebuilt digest never matches and the mint dies as an invalid signature before any later
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
    // The two gated fields' wire offsets come from the DepositIntent layout owner (xusdc-encoding),
    // never a local restatement of DC-1: remoteDomain (felt 10, a 4-byte big-endian u32) and
    // remoteToken (felt 11..18, a 32-byte bytes32).
    let remote_domain_off = DepositIntentField::RemoteDomain.offset();
    let remote_token_off = DepositIntentField::RemoteToken.offset();
    payload[remote_domain_off..remote_domain_off + 4].copy_from_slice(&config.domain.to_be_bytes());
    payload[remote_token_off..remote_token_off + 32].copy_from_slice(&config.remote_token);
    payload
}

/// Selects the mint-payload builder: a resolved config splices its domain/identifier
/// ([`mint_payload_for`]), and `None` leaves the [`BASE_VECTOR`] header untouched ([`mint_payload`]).
/// One seam so every mint call site chooses the right builder from the driver's config without
/// duplicating the match. Both sanity run modes resolve a config, so `None` is the seam's identity
/// case: the offline tests use it to prove that splicing a config the vector already carries is
/// byte-for-byte a no-op.
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

// The `maxFee` field is a uint256 whose value occupies only its low bytes: the field width comes
// from the layout owner (the distance to the next field), and the value width from the AssetAmount
// felt the mint note carries. Everything above them is pad.
const MAX_FEE_FIELD_BYTES: usize =
    DepositIntentField::Nonce.offset() - DepositIntentField::MaxFee.offset();
const MAX_FEE_PAD_BYTES: usize = MAX_FEE_FIELD_BYTES - core::mem::size_of::<u64>();

/// A copy of `payload` whose `maxFee` pad limbs carry bytes instead of zeros — a fee ceiling the
/// faucet can never rebuild.
///
/// A mint note carries the ceiling as a single reduced `AssetAmount`, and the faucet writes it
/// right-aligned into a field it zeroes first, so those high limbs are zero in every message the
/// faucet is able to produce. An attestation taken over these bytes therefore commits to a ceiling
/// no mint can present: nothing in the transport can carry the difference, and the signature check
/// is the only gate that sees it. Used by the Row-E tamper family to bind that gate to the fee
/// ceiling specifically.
pub fn max_fee_pad_dirtied(payload: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    let off = DepositIntentField::MaxFee.offset();
    out[off..off + MAX_FEE_PAD_BYTES].fill(0xFF);
    out
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

/// The reduced (on-chain) asset amount for a raw uint256 amount. Under the scale-0 identity
/// ([`SCALE`] == 1) the minted units equal the raw deposit amount.
pub fn reduced(amount_raw: u64) -> u64 {
    amount_raw / SCALE
}

/// The raw uint256 amount that reduces to exactly `units` on-chain. Under the scale-0 identity
/// ([`SCALE`] == 1) this is the identity: `raw_for_units(u) == u`.
pub fn raw_for_units(units: u64) -> u64 {
    units * SCALE
}

/// Assembles the production mint note from a signed DepositIntent payload: decodes the payload with
/// the shared codec, then hands it to the [`XUsdcMintNote`] factory with the `target` faucet and the
/// `remote_domain` that faucet has configured.
///
/// Both of those are values the faucet writes into the message it rebuilds from its own state, so
/// the factory refuses a payload naming different ones rather than emitting a note that can only die
/// on chain as an invalid signature.
pub fn mint_note_from_payload<R: FeltRng>(
    sender: AccountId,
    target: AccountId,
    remote_domain: u32,
    payload: &[u8],
    attestation: &DepositAttestation,
    rng: &mut R,
) -> Result<Note> {
    let deposit_intent = DepositIntent::read_from_bytes(payload)
        .map_err(|e| anyhow::anyhow!("deposit intent payload rejected by the shared codec: {e}"))?;
    let note = XUsdcMintNote::builder()
        .sender(sender)
        .target(target)
        .remote_domain(remote_domain)
        .deposit_intent(deposit_intent)
        .attestation(attestation.clone())
        .generate_serial_number(rng)
        .build()
        .context("building the XUsdcMintNote probe")?;
    Ok(Note::from(note))
}

/// Builds a production `XUsdcMintNote` against `faucet`: `sender` the producer/relayer, `attester`
/// the local key that signs `keccak256(payload)`, and a payload minting `reduced(amount_raw)` units
/// to `recipient`. `max_fee_raw` must reduce to <= the reduced amount (R-MINT-10). `nonce_salt`
/// distinguishes otherwise-identical mints.
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
    let payload = mint_payload_own_id(
        faucet,
        BASE_VECTOR,
        recipient,
        amount_raw,
        max_fee_raw,
        nonce_salt,
    );
    let attestation = attester.attestation_for(&payload);
    mint_note_from_payload(sender, faucet, MINT_DOMAIN, &payload, &attestation, rng)
}

/// Builds a production `XReserveBurnNote` carrying `amount` units of the faucet's xUSDC (the note's
/// vault holds the asset; the faucet's `receive_and_burn` gate is what the C2/C4 probes exercise).
pub fn burn_note<R: FeltRng>(
    sender: AccountId,
    faucet: AccountId,
    amount: u64,
    dest_salt: u8,
    rng: &mut R,
) -> Result<Note> {
    let items = XReserveBurnItems {
        amount: AssetAmount::new(amount).context("burn amount is a valid AssetAmount")?,
        dest_domain: 3,
        dest_recipient: ForeignChainAddress::new([0xAB; 32]),
        salt: [dest_salt; 32],
    };
    XReserveBurnNote::create(sender, faucet, items, rng)
        .context("building the XReserveBurnNote probe")
}

/// Builds an `XReserveBurnNote`-shaped note whose VAULT ASSET is issued by `asset_faucet` (a
/// DIFFERENT faucet) while the note is still routed at `target_faucet` — the Row-I wrong-asset
/// negative. It is the production burn transport (the reused stock `BurnNote` consume script, the
/// fixed xUSDC burn tag, the stock 8-felt asset storage, the DC-7 withdrawal payload in its
/// scheme-tagged attachment, and the scheme-2 `NetworkAccountTarget` routing bind at
/// `target_faucet`) with ONLY the vault asset's issuer swapped to `asset_faucet`, so the faucet's
/// `receive_and_burn` → `faucet::burn` → `fungible_asset::validate_origin` trap fires
/// (`ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN`: a faucet can only burn its OWN token). It never
/// re-implements a faucet gate — it is the harness's adversarial burn builder, staging a negative
/// the production factory (which single-sources the asset issuer from `target_faucet`) cannot.
pub fn burn_note_wrong_asset<R: FeltRng>(
    sender: AccountId,
    target_faucet: AccountId,
    asset_faucet: AccountId,
    amount: u64,
    dest_salt: u8,
    rng: &mut R,
) -> Result<Note> {
    use xusdc_encoding::note::xreserve_burn::{XUsdcBurnAttachment, FIXED_XUSDC_BURN_TAG};

    let items = XReserveBurnItems {
        amount: AssetAmount::new(amount)
            .context("wrong-asset burn amount is a valid AssetAmount")?,
        dest_domain: 3,
        dest_recipient: ForeignChainAddress::new([0xAB; 32]),
        salt: [dest_salt; 32],
    };
    // The vault asset is issued by the WRONG faucet — the whole point of this negative.
    let asset = FungibleAsset::new(asset_faucet, amount)
        .map_err(|e| anyhow::anyhow!("building the wrong-asset fungible asset: {e}"))?;
    // NoteStorage carries the STOCK 8-felt asset layout the stock consume script asserts against,
    // exactly as the production factory places it.
    let storage = NoteStorage::new(Asset::from(asset).as_elements().to_vec())
        .context("wrong-asset burn storage")?;
    // Reuse the STOCK burn consume script (→ faucet::receive_and_burn → the burn security policy,
    // CMP-A10), exactly as the production factory does.
    let recipient = NoteRecipient::new(rng.draw_word(), XReserveBurnNote::script(), storage);
    // Public mandate + the fixed xUSDC burn tag; metadata.sender = the depositor.
    let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
        .with_tag(NoteTag::new(FIXED_XUSDC_BURN_TAG));
    let vault = NoteAssets::new(vec![asset.into()]).context("wrong-asset burn vault")?;
    // Route at the TARGET faucet (network account) — the note is still addressed at our faucet; only
    // the asset issuer differs.
    let target = NetworkAccountTarget::new(target_faucet, NoteExecutionHint::Always)
        .map_err(|e| anyhow::anyhow!("target faucet id is not a public network account: {e}"))?;
    // Two attachments, as the production burn note carries: the routing bind and the DC-7
    // withdrawal payload the off-chain attester decodes.
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
