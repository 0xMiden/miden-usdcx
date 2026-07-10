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
use miden_protocol::note::Note;
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::note::xreserve_mint::XReserveMintNote;
use xusdc_encoding::vectors::{load, parse_hex32, DiFields, DiVector};
use xusdc_encoding::xreserve::encoding::{account_id_to_bytes32, XReserveBurnItems};

use crate::actors::AttesterKey;
use crate::config::DomainParams;

/// The canonical accept vector every LNV-2 mint payload is built from (empty hookData: the 60-felt
/// header, no hookData tail — the minimal valid mint). Its `remoteDomain` is 7 and its `remoteToken`
/// keys the faucet identifier.
pub const BASE_VECTOR: &str = "di-pos-empty-hookdata";

/// The vector's `remoteDomain` (Q-DOM-1 OPEN; `TEST_DOMAIN` in the MockChain suite). `domain_init`
/// must write this so the D5a domain compare passes.
pub const MINT_DOMAIN: u32 = 7;

/// The scale exponent the D5b reducer applies (= the faucet's 6 decimals): a raw uint256 amount is
/// divided by 10^6 to the on-chain asset amount.
pub const SCALE_EXP: u32 = 6;
const SCALE: u64 = 1_000_000; // 10^SCALE_EXP

// DC-1 field byte offsets (felt offset × 4): the layout the 04 codec packs. Mirrors the MockChain
// support constants (`AMOUNT_FELT_OFF` = 2, `REMOTE_RECIPIENT_FELT_OFF` = 19, `MAX_FEE_FELT_OFF` =
// 43, nonce at felt 51).
const AMOUNT_BYTE_OFF: usize = 2 * 4;
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
const MAX_FEE_BYTE_OFF: usize = 43 * 4;
const NONCE_BYTE_OFF: usize = 51 * 4;

fn base_vector() -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == BASE_VECTOR)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {BASE_VECTOR}"))
}

fn base_fields() -> &'static DiFields {
    base_vector().fields.as_ref().expect("the accept vector carries fields")
}

/// The §5.9 `domain_init` parameters LNV-2 deploys with: `domain`/`identifier` MATCH the mint
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

/// Builds a mint DepositIntent payload from the base vector: splices the raw uint256 `amount_raw`
/// and `max_fee_raw`, points `remoteRecipient` at `recipient` (so the emitted P2ID note targets a
/// real wallet), and XOR-perturbs one nonce byte by `nonce_salt` (distinct salts ⇒ distinct nonces,
/// avoiding the replay gate across probes).
pub fn mint_payload(recipient: AccountId, amount_raw: u64, max_fee_raw: u64, nonce_salt: u8) -> Vec<u8> {
    let mut payload = base_vector().bytes();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(amount_raw));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(max_fee_raw));
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&account_id_to_bytes32(recipient));
    if nonce_salt != 0 {
        payload[NONCE_BYTE_OFF] ^= nonce_salt;
    }
    payload
}

/// The reduced (on-chain) asset amount for a raw uint256 amount (÷ 10^SCALE_EXP).
pub fn reduced(amount_raw: u64) -> u64 {
    amount_raw / SCALE
}

/// The raw uint256 amount that reduces to exactly `units` on-chain.
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
    XReserveBurnNote::create(sender, faucet, items, rng).context("building the XReserveBurnNote probe")
}
