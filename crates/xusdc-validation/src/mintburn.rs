//! Mint/burn note builders — the C-row PROBES.
//!
//! Rows C1/C3/C4 use real `XReserveMintNote`s and C2/C4 use real `XReserveBurnNote`s as instruments
//! to prove an admin change took effect (a rotated-out attester can no longer mint, an over-cap mint
//! rejects, a paused faucet halts both, a raised minimum rejects a small burn). These are NOT the
//! mint/burn matrix rows (D/E/G/H — LNV-3/4); they are the smallest real notes that exercise the
//! gate each C row changes.
//!
//! The mint note carries a Circle DepositIntent whose `remoteDomain` + `remoteToken` must match the
//! faucet's domain config, so LNV-2's `domain_init` is seeded from the SAME canonical accept vector
//! the payload is built from ([`lnv2_domain_params`]). Amount/maxFee/recipient/nonce are spliced
//! into the vector payload (the `assembled_faucet_e2e` recipe); the attestation is signed by a local
//! test attester (`crate::actors::AttesterKey`), never Circle's key.

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteRecipient,
    NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::{Felt, Word};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::note::xreserve_mint::{
    MintAttestation, XReserveMintNote, XRESERVE_MINT_ATTACHMENT_NUM_WORDS,
    XRESERVE_MINT_ATTACHMENT_SCHEME,
};
use xusdc_encoding::vectors::{load, parse_hex32, DiFields, DiVector};
use xusdc_encoding::xreserve::encoding::{
    account_id_to_bytes32, affine_pubkey_felts, bytes32_to_storage_map_key,
    deposit_intent_field_offset, deposit_intent_to_packed_felts, signature_felts,
    DepositIntentField, XReserveBurnItems,
};

use crate::actors::AttesterKey;
use crate::config::DomainParams;

/// The canonical accept vector every LNV-2 mint payload is built from (empty hookData: the 60-felt
/// header, no hookData tail — the minimal valid mint). Its `remoteDomain` is 7 and its `remoteToken`
/// keys the faucet identifier.
pub const BASE_VECTOR: &str = "di-pos-empty-hookdata";

/// The canonical accept vector carrying a NON-empty hookData tail (`hook_data_len == 10`; a 250-byte
/// payload = the 240-byte header + 10 hookData bytes). Shares `remoteDomain` 7 and the SAME
/// `remoteToken` as [`BASE_VECTOR`], so ONE `domain_init` validates BOTH the empty-hookData and the
/// hookData-bearing Row-D mints — the second variant (bounded hookData) the mint matrix requires.
pub const HOOKDATA_VECTOR: &str = "di-pos-hookdata";

/// The vector's `remoteDomain` (Q-DOM-1 OPEN; `TEST_DOMAIN` in the MockChain suite). `domain_init`
/// must write this so the D5a domain compare passes.
pub const MINT_DOMAIN: u32 = 7;

/// The scale exponent the D5b reducer applies. `masm-rust-constant-parity` mirror of the shipped
/// `xreserve_mint_note_entry.masm`'s `DEPOSIT_SCALE_EXP` — set to **0** by the P0 fix (commit
/// 75ece89): Circle sends a 6-decimal deposit amount and Miden xUSDC is ALSO 6 decimals, so the
/// EVM-minus-Miden decimal delta is 0. The reducer therefore computes `floor(x / 10^0) = x`: the
/// on-chain minted asset amount EQUALS the raw uint256 deposit amount (scale-0 identity, NO 10^6
/// division). Must stay equal to the MASM constant, or the harness would build mints expecting the
/// wrong on-chain amount.
pub const SCALE_EXP: u32 = 0;
const SCALE: u64 = 1; // 10^SCALE_EXP

// DC-1 field byte offsets (felt offset × 4): the layout the shared-encoding codec packs. Mirrors the MockChain
// support constants (`AMOUNT_FELT_OFF` = 2, `REMOTE_RECIPIENT_FELT_OFF` = 19, `MAX_FEE_FELT_OFF` =
// 43, nonce at felt 51).
const AMOUNT_BYTE_OFF: usize = 2 * 4;
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
const MAX_FEE_BYTE_OFF: usize = 43 * 4;
const NONCE_BYTE_OFF: usize = 51 * 4;
// The two fields the mint gate (D5a `deposit_intent_parser::assert_deposit_intent`) compares against
// the faucet's stored domain config are `remoteDomain` (felt 10, a big-endian u32) and `remoteToken`
// (felt 11..18, a bytes32). Their wire offsets are NOT restated here: the DepositIntent layout owner
// is `xusdc-encoding`, so `mint_payload_for` reads them from `deposit_intent_field_offset(...)` (the
// single source of truth, pinned by reference). There is deliberately NO `sourceDomain`: it is not a
// DepositIntent field and the mint proc never reads it — the gate compares ONLY those two fields.

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

/// The `domain_init` domain-config parameters LNV-2 deploys with: `domain`/`identifier` MATCH the mint
/// vector (so mints validate), `source_domain`/`xreserve_contract` are arbitrary distinct local
/// test values (the mint path does not read them — they are off-chain withdrawal identity).
pub fn lnv2_domain_params() -> DomainParams {
    DomainParams {
        domain: MINT_DOMAIN,
        source_domain: 3,
        xreserve_contract: core::array::from_fn(|i| 0x10 + i as u8),
        // The identifier bytes32 = the vector's remoteToken; DomainParams::identifier_word() hashes
        // it to the same key the D5a identifier compare reads.
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
        .copy_from_slice(&account_id_to_bytes32(recipient));
    if nonce_salt != 0 {
        payload[NONCE_BYTE_OFF] ^= nonce_salt;
    }
    payload
}

/// The two DepositIntent fields the mint gate (D5a `deposit_intent_parser::assert_deposit_intent`)
/// compares against the faucet's stored domain config: `remoteDomain` and `remoteToken`. This is the
/// config a mint payload must carry so D5a's compares pass.
///
/// - Fresh-LOCAL full gate: the config equals the [`BASE_VECTOR`]'s own `remoteDomain` ([`MINT_DOMAIN`])
///   and `remoteToken` ([`MintDomainConfig::local_vector`]) — because the fresh faucet's `domain_init`
///   is seeded from that same vector ([`lnv2_domain_params`]). Splicing THIS reproduces the untouched
///   [`BASE_VECTOR`] payload byte-for-byte, so the fresh-local vectors are unchanged.
/// - Existing-faucet (`--faucet-id`) re-check: the config is resolved from the DEPLOYED faucet —
///   `domain` read from its on-chain domain-config slot, `remote_token` recomputed as
///   `account_id_to_bytes32(faucet_id)` (the identifier A5's `domain_init` set from
///   `account_id_to_bytes32(faucet.id())`). This is the A6 fix: the fixed vector's `remoteDomain` (7)
///   did not match a production faucet's stored `domain` (e.g. 10007), so D5a rejected every mint.
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
    /// compares `bytes32_to_key(remoteToken)` against the stored identifier key.
    pub(crate) remote_token: [u8; 32],
}

impl MintDomainConfig {
    /// The config the fresh-LOCAL deploy commits: the [`BASE_VECTOR`]'s own `remoteDomain`
    /// ([`MINT_DOMAIN`]) and `remoteToken`. Splicing this is a no-op on the [`BASE_VECTOR`] payload,
    /// which is exactly the byte-for-byte invariant the offline suite asserts — so this exists ONLY
    /// for that test (production's fresh-local path passes `None`, never this config).
    #[cfg(test)]
    pub(crate) fn local_vector() -> Self {
        Self {
            domain: MINT_DOMAIN,
            remote_token: parse_hex32(&base_fields().remote_token_hex),
        }
    }

    /// The config of a DEPLOYED faucet on the `--faucet-id` path: the operator-read on-chain `domain`
    /// paired with `remote_token = account_id_to_bytes32(faucet_id)` — the identifier A5's
    /// `domain_init` stored (recomputable from `faucet_id` alone, no guessing).
    pub(crate) fn for_deployed_faucet(domain: u32, faucet_id: AccountId) -> Self {
        Self {
            domain,
            remote_token: account_id_to_bytes32(faucet_id),
        }
    }
}

/// Builds a mint DepositIntent that carries `config`'s `remoteDomain` + `remoteToken` (the two D5a
/// gated fields) in addition to the amount/maxFee/recipient/nonce splice of [`mint_payload_from`].
/// The existing-faucet (`--faucet-id`) mint builder: the payload must match the DEPLOYED faucet's
/// stored domain config, or D5a rejects it (`WRONG_DOMAIN` / `WRONG_IDENTIFIER`) before any later
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

/// The `usedNonces[nonce]` storage-map key for a payload's nonce field (`bytes32_to_key(nonce)`) —
/// the SAME key the mint's D5c/D5e derive and set, so the driver can read the marker back after a
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

/// Builds a production `XReserveMintNote`: `sender` the producer/relayer, `faucet` the target,
/// `attester` the local key that signs `keccak256(payload)`, and a payload minting `reduced(amount_raw)`
/// units to `recipient`. `max_fee_raw` must reduce to ≤ the reduced amount (R-MINT-10); `feeAmount`
/// stays MVP-zero. `nonce_salt` distinguishes otherwise-identical mints.
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
    XReserveMintNote::create(sender, faucet, &payload, &attestation, rng)
        .context("building the XReserveMintNote probe")
}

/// The 8 u32-LE `feeAmount` attachment limbs encoding a raw uint256 `fee_raw` — extracted from the
/// `amount` field position of a freshly-packed DepositIntent, so the on-chain `uint256_to_asset_amount`
/// reducer (shared by the `amount` field and the advice `feeAmount`) reduces them to EXACTLY
/// `fee_raw / 10^SCALE_EXP`. Deriving the limbs from the trusted amount-field packing avoids
/// re-deriving the wire-byte→limb layout by hand — the F2 negative needs a reduced fee ≥ 1, i.e.
/// `fee_raw ≥ SCALE`. The production attestation attachment hardcodes these eight limbs to zero
/// (DEV-8 MVP); only a harness-crafted note can carry a non-zero fee.
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

/// Builds an `XReserveMintNote` with a CUSTOM scheme-1 attestation attachment: the same transport
/// shape the production [`XReserveMintNote::create`] emits (custom mint script, DepositIntent
/// storage, scheme-2 `NetworkAccountTarget` routing bind) but with the attestation attachment's
/// `[feeAmount(8), pubkey(16 affine), signature(17), pad(3)]` words assembled from the
/// caller-supplied `fee_limbs` + `attestation`. This is the harness's ADVERSARIAL note builder — it
/// exists solely to stage Row-E negatives the production factory cannot (a non-zero feeAmount, a
/// payload the attestation did not sign); it never re-implements any faucet gate. Mirrors the
/// F5-suite `mint_note_with_attachments` helper (public-API note assembly, unchanged script root).
pub fn mint_note_with_fee<R: FeltRng>(
    sender: AccountId,
    faucet: AccountId,
    payload: &[u8],
    attestation: &MintAttestation,
    fee_limbs: [Felt; 8],
    rng: &mut R,
) -> Result<Note> {
    // The scheme-1 attestation content: [feeAmount(8), pubkey(16 affine), signature(17), pad(3)] =
    // 44 felts = 11 words — the exact order `mint` pops from the advice stack. Identical to the
    // production `attestation_attachment` (v16: the 33-byte compressed wire pubkey is decompressed
    // to its 16 affine-coordinate felts, vm#3342 / MIGRATION-V16-ALPHA2.md S16), save the
    // caller-chosen fee limbs (production hardcodes eight zeros).
    let mut felts: Vec<Felt> = Vec::with_capacity(44);
    felts.extend(fee_limbs);
    felts.extend(
        affine_pubkey_felts(attestation.pubkey())
            .map_err(|e| anyhow::anyhow!("attestation pubkey rejected by the 04 codec: {e}"))?,
    );
    felts.extend(signature_felts(attestation.signature()));
    felts.extend([Felt::from(0u32); 3]);
    let words: Vec<Word> = felts
        .chunks_exact(4)
        .map(|c| Word::new([c[0], c[1], c[2], c[3]]))
        .collect();
    debug_assert_eq!(words.len(), XRESERVE_MINT_ATTACHMENT_NUM_WORDS);
    let attestation_attachment = NoteAttachment::with_words(
        NoteAttachmentScheme::new(XRESERVE_MINT_ATTACHMENT_SCHEME)
            .context("scheme-1 attachment scheme")?,
        words,
    )
    .context("building the custom scheme-1 attestation attachment")?;

    let items = deposit_intent_to_packed_felts(payload)
        .map_err(|e| anyhow::anyhow!("packing the deposit intent: {e}"))?;
    let storage = NoteStorage::new(items).context("mint-note storage")?;
    let recipient_note = NoteRecipient::new(rng.draw_word(), XReserveMintNote::script(), storage);
    let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
        .with_tag(NoteTag::with_account_target(faucet));
    let target = NetworkAccountTarget::new(faucet, NoteExecutionHint::Always)
        .map_err(|e| anyhow::anyhow!("faucet id is not a public network account: {e}"))?;
    let attachments =
        NoteAttachments::new(vec![attestation_attachment, NoteAttachment::from(target)])
            .context("mint-note attachments")?;
    Ok(Note::with_attachments(
        NoteAssets::new(vec![]).context("empty mint-note vault")?,
        metadata,
        recipient_note,
        attachments,
    ))
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
        dest_recipient: [0xAB; 32],
        salt: [dest_salt; 32],
    };
    XReserveBurnNote::create(sender, faucet, items, rng)
        .context("building the XReserveBurnNote probe")
}

/// Builds an `XReserveBurnNote`-shaped note whose VAULT ASSET is issued by `asset_faucet` (a
/// DIFFERENT faucet) while the note is still routed at `target_faucet` — the Row-I wrong-asset
/// negative. It is the production burn transport (the reused stock `BurnNote` consume script, the
/// fixed xUSDC burn tag, the DC-7 storage items via the shared-encoding codec, the scheme-2 `NetworkAccountTarget`
/// routing bind at `target_faucet`) with ONLY the vault asset's issuer swapped to `asset_faucet`, so
/// the faucet's `receive_and_burn` → `faucet::burn` → `fungible_asset::validate_origin` trap fires
/// (`ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN`: a faucet can only burn its OWN token). It never
/// re-implements a faucet gate — it is the harness's adversarial burn builder, the twin of
/// [`mint_note_with_fee`], staging a negative the production factory (which single-sources the asset
/// issuer from `target_faucet`) cannot.
pub fn burn_note_wrong_asset<R: FeltRng>(
    sender: AccountId,
    target_faucet: AccountId,
    asset_faucet: AccountId,
    amount: u64,
    dest_salt: u8,
    rng: &mut R,
) -> Result<Note> {
    use miden_protocol::asset::FungibleAsset;
    use xusdc_encoding::note::xreserve_burn::FIXED_XUSDC_BURN_TAG;
    use xusdc_encoding::xreserve::encoding::encode_burn_note_items;

    let items = XReserveBurnItems {
        amount: AssetAmount::new(amount)
            .context("wrong-asset burn amount is a valid AssetAmount")?,
        dest_domain: 3,
        dest_recipient: [0xAB; 32],
        salt: [dest_salt; 32],
    };
    // DC-7 payload → NoteStorage.items via the shared-encoding codec (consumed by reference; no re-impl).
    let storage =
        NoteStorage::new(encode_burn_note_items(&items)).context("wrong-asset burn storage")?;
    // Reuse the STOCK burn consume script (→ faucet::receive_and_burn → the burn security policy,
    // CMP-A10), exactly as the production factory does.
    let recipient = NoteRecipient::new(rng.draw_word(), XReserveBurnNote::script(), storage);
    // Public mandate + the fixed xUSDC burn tag; metadata.sender = the depositor.
    let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
        .with_tag(NoteTag::new(FIXED_XUSDC_BURN_TAG));
    // The vault asset is issued by the WRONG faucet — the whole point of this negative.
    let asset = FungibleAsset::new(asset_faucet, amount)
        .map_err(|e| anyhow::anyhow!("building the wrong-asset fungible asset: {e}"))?;
    let vault = NoteAssets::new(vec![asset.into()]).context("wrong-asset burn vault")?;
    // Route at the TARGET faucet (network account) — the note is still addressed at our faucet; only
    // the asset issuer differs.
    let target = NetworkAccountTarget::new(target_faucet, NoteExecutionHint::Always)
        .map_err(|e| anyhow::anyhow!("target faucet id is not a public network account: {e}"))?;
    let attachments = NoteAttachments::new(vec![NoteAttachment::from(target)])
        .context("wrong-asset burn attachments")?;
    Ok(Note::with_attachments(
        vault,
        metadata,
        recipient,
        attachments,
    ))
}
