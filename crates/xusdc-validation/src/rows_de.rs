//! The LNV-3 rows-D/E driver: one deterministic arc against a fresh local node, producing the
//! [`RowsDeObservations`] the rows-D/E assertion suite judges.
//!
//! Execution model (LNV-1 posture, LNV-2-confirmed, reused verbatim):
//! - **Row D happy-path mints commit via path N (the ntx-builder).** Each `XReserveMintNote` is
//!   emitted from the owner/relayer wallet (a regular-account tx the user RPC accepts) carrying the
//!   routing attachment; the running ntx-builder auto-executes the faucet's consumption. The driver
//!   polls `GetAccount` until the committed `token_supply` rose, reads `usedNonces[nonce]` back,
//!   discovers the emitted P2ID recipient note, and drives the RECIPIENT wallet's consume of it (a
//!   second, strictly-later block — the two-block flow the matrix requires).
//! - **Row E negatives run CLIENT-SIDE (`execute_transaction`, no submission).** Each malformed mint
//!   is executed locally against the committed on-chain state: a trap is the reject proof, and
//!   because nothing is submitted the committed `token_supply` / nonce registry cannot move — which
//!   the driver reads back before/after to prove zero state change.
//!
//! The arc: deploy (domain_init) → allowlist attester A (path N) → Row D variant 1 (empty-hookData,
//! committed + recipient-consumed) → Row D variant 2 (hookData-bearing, committed + recipient-consumed)
//! → Row E negatives (replay, forged signature, non-allowlisted attester, non-zero fee, tampered
//! payload) each a client-side reject + read-back.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use miden_client::rpc::domain::account::AccountStorageRequirements;
use miden_client::rpc::NodeRpcClient;
use miden_client::store::TransactionFilter;
use miden_client::transaction::{
    ForeignAccount, TransactionId, TransactionRequestBuilder, TransactionStatus,
};
use miden_protocol::account::{Account, AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::asset::Asset;
use miden_protocol::note::{Note, NoteTag};
use miden_protocol::transaction::InputNote;
use miden_protocol::Word;
use miden_standards::note::P2idNote;
use xusdc_encoding::account::xreserve::USED_NONCES_SLOT_LABEL;
use xusdc_encoding::note::xreserve_admin::{XReserveDomainInitNote, XReserveSetAttesterNote};
use xusdc_encoding::note::xreserve_mint::XReserveMintNote;

use crate::actors::{create_actors, Actors};
use crate::client::{build_client, os_seed, HarnessClient};
use crate::config::RunConfig;
use crate::deploy::build_faucet_account;
use crate::mintburn::{
    self, fee_limbs_for, hook_data_len, mint_note_with_fee, mint_payload_from, nonce_key,
    raw_for_units, BASE_VECTOR, HOOKDATA_VECTOR,
};
use crate::observations_cf::{Verdict, Word4};
use crate::observations_de::{MintHappy, MintNegative, RowsDeObservations};
use crate::stack::NodeStack;

// FIXTURE VALUES (all reduced / on-chain units; every mint stays within the default 1e12 cap).
// ================================================================================================

/// The empty-hookData Row-D mint amount (units). Also the replay negative's nonce source.
const D_EMPTY_UNITS: u64 = 100;
/// The hookData-bearing Row-D mint amount (units).
const D_HOOK_UNITS: u64 = 150;
/// The Row-E negatives' (rejected) mint amount (units) — small, within cap, ≥ maxFee.
const E_UNITS: u64 = 40;
/// The maxFee every mint carries (units); reduces to 1 ≤ every amount, so R-MINT-10 holds.
const MAX_FEE_UNITS: u64 = 1;
/// The non-zero feeAmount the F2 negative injects (units, reduced ≥ 1 ⇒ the guard fires).
const FEE_UNITS: u64 = 5;

/// Nonce salts (distinct ⇒ distinct nonces). The empty-hookData Row-D salt is reused by the replay
/// negative (same nonce ⇒ D5c replay), so it is fixed here.
const SALT_D_EMPTY: u8 = 0x01;
const SALT_D_HOOK: u8 = 0x02;
const SALT_E_FORGED: u8 = 0x11;
const SALT_E_BAD_ATTESTER: u8 = 0x12;
const SALT_E_FEE: u8 = 0x13;
const SALT_E_TAMPERED: u8 = 0x14;

/// Bounded wait for the ntx-builder to commit a path-N faucet consumption (mint) or for a submitted
/// (recipient) transaction to commit.
const PATHN_TIMEOUT: Duration = Duration::from_secs(240);
const TX_COMMIT_TIMEOUT: Duration = Duration::from_secs(180);
/// Bounded wait for the client to sync a committed public P2ID note.
const NOTE_SYNC_TIMEOUT: Duration = Duration::from_secs(120);

// READ-BACK HELPERS (NODE `GetAccount` state → observation values).
// ================================================================================================

fn word4(w: Word) -> Word4 {
    [
        w[0].as_canonical_u64(),
        w[1].as_canonical_u64(),
        w[2].as_canonical_u64(),
        w[3].as_canonical_u64(),
    ]
}

fn value_slot(account: &Account, label: &str) -> Result<Word> {
    let name = StorageSlotName::new(label).with_context(|| format!("slot label '{label}'"))?;
    account
        .storage()
        .get_item(&name)
        .with_context(|| format!("reading value slot '{label}'"))
}

fn token_supply(account: &Account) -> Result<u64> {
    // token_config = [token_supply, max_supply, decimals, symbol].
    Ok(
        value_slot(account, "miden::standards::faucets::fungible::token_config")?[0]
            .as_canonical_u64(),
    )
}

fn used_nonce_marker(account: &Account, key: Word) -> Result<Word4> {
    let name = StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?;
    account
        .storage()
        .get_map_item(&name, StorageMapKey::new(key))
        .map(word4)
        .map_err(|e| anyhow::anyhow!("reading usedNonces[{key:?}]: {e}"))
}

/// A wallet's total balance of the faucet's fungible asset (vault iteration — the custody read-back).
fn wallet_balance(account: &Account, faucet_id: AccountId) -> u64 {
    account
        .vault()
        .assets()
        .filter_map(|asset| match asset {
            Asset::Fungible(f) if f.faucet_id() == faucet_id => Some(u64::from(f.amount())),
            _ => None,
        })
        .sum()
}

/// The recipient account-target tag the emitted P2ID note carries (prefix HIGH u32 masked
/// `0xfffc0000` — `NoteTag::with_account_target`).
fn expected_p2id_tag(recipient: AccountId) -> u32 {
    NoteTag::with_account_target(recipient).as_u32()
}

// THE DRIVER
// ================================================================================================

struct Driver {
    hc: HarnessClient,
    actors: Actors,
    faucet_id: AccountId,
}

impl Driver {
    /// The NODE's current view of `account_id` (`GetAccount`); `Ok(None)` if the node does not yet
    /// recognize it (a keyed wallet materializes only with its first transaction).
    async fn try_fetch(&mut self, account_id: AccountId) -> Result<Option<Account>> {
        self.hc
            .client
            .sync_state()
            .await
            .context("syncing before a node read")?;
        self.hc
            .rpc
            .get_account_details(account_id)
            .await
            .map_err(|e| anyhow::anyhow!("GetAccount({account_id}): {e}"))
    }

    /// The faucet account (must be recognized).
    async fn fetch_faucet(&mut self) -> Result<Account> {
        let id = self.faucet_id;
        self.try_fetch(id)
            .await?
            .with_context(|| format!("the node does not recognize the faucet {id}"))
    }

    /// A wallet's committed faucet-asset balance from the client's synced store (0 before the wallet
    /// has materialized on-chain). The raw `GetAccount` RPC rejects an account the node has never
    /// seen ("invalid request parameters") rather than returning empty, so the recipient's
    /// pre-consume balance is read from the client's own view — kept truthful by `sync_state`, which
    /// pulls the committed on-chain delta for every tracked account.
    async fn balance_of(&mut self, account_id: AccountId) -> Result<u64> {
        let faucet_id = self.faucet_id;
        self.hc
            .client
            .sync_state()
            .await
            .context("syncing before a balance read")?;
        Ok(self
            .hc
            .client
            .get_account(account_id)
            .await
            .map_err(|e| anyhow::anyhow!("client get_account({account_id}): {e}"))?
            .map(|a| wallet_balance(&a, faucet_id))
            .unwrap_or(0))
    }

    async fn wait_commit(&mut self, tx_id: TransactionId) -> Result<u32> {
        let deadline = Instant::now() + TX_COMMIT_TIMEOUT;
        loop {
            self.hc
                .client
                .sync_state()
                .await
                .context("syncing while waiting for a tx")?;
            let record = self
                .hc
                .client
                .get_transactions(TransactionFilter::Ids(vec![tx_id]))
                .await
                .context("querying tx status")?
                .pop()
                .with_context(|| format!("tx {tx_id} not tracked"))?;
            match record.status {
                TransactionStatus::Committed { block_number, .. } => {
                    return Ok(block_number.as_u32())
                }
                TransactionStatus::Discarded(cause) => bail!("tx {tx_id} DISCARDED: {cause:?}"),
                TransactionStatus::Pending => {
                    if Instant::now() > deadline {
                        bail!("tx {tx_id} did not commit within {TX_COMMIT_TIMEOUT:?}");
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    /// Emits a note from `sender` (a regular-account tx the user RPC accepts) and waits for the emit
    /// to commit. Returns the emit block.
    async fn emit(&mut self, sender: AccountId, note: Note) -> Result<u32> {
        let req = TransactionRequestBuilder::new()
            .own_output_notes(vec![note])
            .build()
            .context("building an emit request")?;
        let tx = self
            .hc
            .client
            .submit_new_transaction(sender, req)
            .await
            .context("submitting an emit transaction")?;
        self.wait_commit(tx).await
    }

    /// Commits a positive op via path N: emit the routed allowlisted note, then poll `GetAccount`
    /// until `ready` observes the committed effect. Returns the committed faucet account.
    async fn commit_via_ntx<F>(
        &mut self,
        sender: AccountId,
        note: Note,
        op: &str,
        ready: F,
    ) -> Result<Account>
    where
        F: Fn(&Account) -> bool,
    {
        self.emit(sender, note)
            .await
            .with_context(|| format!("emitting the {op} note"))?;
        let deadline = Instant::now() + PATHN_TIMEOUT;
        loop {
            let account = self.fetch_faucet().await?;
            if ready(&account) {
                return Ok(account);
            }
            if Instant::now() > deadline {
                bail!(
                    "path-N commit of '{op}' timed out after {PATHN_TIMEOUT:?} — the ntx-builder did \
                     not commit the faucet's consumption of the routed allowlisted note"
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Client-side execute of the faucet consuming `note` (no submission). Ok = ACCEPTED, a trap =
    /// REJECTED with the captured error.
    async fn probe_consume(&mut self, note: Note) -> Result<Verdict> {
        self.hc
            .client
            .sync_state()
            .await
            .context("syncing before a probe")?;
        let req = TransactionRequestBuilder::new()
            .input_notes(vec![(note, None)])
            .build()
            .context("building a probe consume request")?;
        Ok(
            match self
                .hc
                .client
                .execute_transaction(self.faucet_id, req)
                .await
            {
                Ok(_) => Verdict::Accepted,
                Err(e) => Verdict::Rejected(format!("{e:?}")),
            },
        )
    }

    /// Waits (syncing) until the recipient has a consumable committed note carrying exactly
    /// `amount_units` of this faucet's asset, and returns the discovered `(Note, inclusion_block)`.
    /// Matching on the AMOUNT (distinct per Row-D variant) — never on the serial — keeps the
    /// subsequent serial == nonce-key check honest (the discovery does not assume it).
    async fn wait_for_recipient_note(
        &mut self,
        recipient: AccountId,
        amount_units: u64,
    ) -> Result<(Note, u32)> {
        let faucet_id = self.faucet_id;
        let deadline = Instant::now() + NOTE_SYNC_TIMEOUT;
        loop {
            self.hc
                .client
                .sync_state()
                .await
                .context("syncing for the recipient P2ID note")?;
            let consumable = self
                .hc
                .client
                .get_consumable_notes(Some(recipient))
                .await
                .context("querying the recipient's consumable notes")?;
            for (record, _) in &consumable {
                let carries_amount =
                    record.details().assets().iter_fungible().any(|a| {
                        a.faucet_id() == faucet_id && u64::from(a.amount()) == amount_units
                    });
                if !carries_amount {
                    continue;
                }
                let block = record
                    .inclusion_proof()
                    .map(|p| p.location().block_num().as_u32())
                    .context("the discovered recipient note lacks an inclusion proof")?;
                let input: InputNote = record
                    .clone()
                    .try_into()
                    .context("converting the note record to an InputNote")?;
                return Ok((input.note().clone(), block));
            }
            if Instant::now() > deadline {
                bail!(
                    "the recipient {recipient} did not receive its committed P2ID mint note carrying \
                     {amount_units} units within {NOTE_SYNC_TIMEOUT:?}"
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// The recipient wallet consumes `note` (a regular-account tx the user RPC accepts). Returns the
    /// consume block. xUSDC is POLICED (F4-reversal): the receive callback dyncalls the faucet's
    /// `basic_blocklist::check_policy`, so the faucet MUST be declared as a foreign account.
    async fn recipient_consume(&mut self, recipient: AccountId, note: Note) -> Result<u32> {
        let req = TransactionRequestBuilder::new()
            .foreign_accounts([ForeignAccount::public(
                self.faucet_id,
                AccountStorageRequirements::default(),
            )
            .context("declaring the faucet as a foreign account for the policed consume")?])
            .build_consume_notes(vec![note])
            .context("building the recipient consume request")?;
        let tx = self
            .hc
            .client
            .submit_new_transaction(recipient, req)
            .await
            .context("submitting the recipient consume")?;
        self.wait_commit(tx).await
    }

    fn owner(&self) -> AccountId {
        self.actors.owner.id()
    }
    fn recipient(&self) -> AccountId {
        self.actors.recipient.id()
    }

    /// Builds a valid `XReserveMintNote` attested by attester `A` to the recipient.
    fn valid_mint(&mut self, vector_id: &str, units: u64, salt: u8) -> Result<(Note, Vec<u8>)> {
        let f = self.faucet_id;
        let sender = self.owner();
        let recipient = self.recipient();
        let payload = mint_payload_from(
            vector_id,
            recipient,
            raw_for_units(units),
            raw_for_units(MAX_FEE_UNITS),
            salt,
        );
        let attestation = self.actors.attester.attestation_for(&payload);
        let note =
            XReserveMintNote::create(sender, f, &payload, &attestation, self.hc.client.rng())
                .context("building a valid XReserveMintNote")?;
        Ok((note, payload))
    }
}

/// Runs one Row-D happy-path variant: commit the mint via path N, read `token_supply` +
/// `usedNonces` back, discover the emitted P2ID note, and drive the recipient's consume of it.
async fn run_mint_happy(
    d: &mut Driver,
    label: &str,
    vector_id: &str,
    units: u64,
    salt: u8,
) -> Result<MintHappy> {
    let owner = d.owner();
    let recipient = d.recipient();

    let supply_before = token_supply(&d.fetch_faucet().await?)?;
    let recipient_balance_before = d.balance_of(recipient).await?;

    let (note, payload) = d.valid_mint(vector_id, units, salt)?;
    let key = nonce_key(&payload); // the mint sets SERIAL_NUM = bytes32_to_key(nonce)

    // Commit the mint via path N (the ntx-builder consumes the routed allowlisted note).
    let committed = d
        .commit_via_ntx(owner, note, &format!("mint ({label})"), |a| {
            token_supply(a)
                .map(|s| s >= supply_before + units)
                .unwrap_or(false)
        })
        .await
        .with_context(|| format!("committing the {label} mint via path N"))?;
    let supply_after = token_supply(&committed)?;
    let nonce_marker_after = used_nonce_marker(&committed, key)?;

    // Discover the emitted P2ID recipient note by its AMOUNT (public, tagged to the recipient).
    let (p2id_note, note_commit_block) = d.wait_for_recipient_note(recipient, units).await?;
    let note_is_p2id = p2id_note.recipient().script().root() == P2idNote::script_root();
    let note_tag = p2id_note.metadata().tag().as_u32();
    let fungible: Vec<_> = p2id_note.assets().iter_fungible().collect();
    let (note_asset_amount, note_asset_is_faucet) = match fungible.first() {
        Some(a) => (u64::from(a.amount()), a.faucet_id() == d.faucet_id),
        None => (0, false),
    };

    // The recipient consumes it — a strictly-later block (needs the note's inclusion proof).
    let recipient_consume_block = d.recipient_consume(recipient, p2id_note.clone()).await?;
    let recipient_balance_after = d.balance_of(recipient).await?;

    Ok(MintHappy {
        label: label.to_string(),
        hook_data_len: hook_data_len(vector_id),
        amount_units: units,
        supply_before,
        supply_after,
        nonce_marker_after,
        note_serial: word4(p2id_note.recipient().serial_num()),
        expected_serial: word4(key),
        note_is_p2id,
        note_tag,
        expected_tag: expected_p2id_tag(recipient),
        note_asset_amount,
        note_asset_is_faucet,
        recipient_balance_before,
        recipient_balance_after,
        note_commit_block,
        recipient_consume_block,
    })
}

/// Runs all five Row-E negatives client-side, each a reject + committed-state read-back.
async fn run_negatives(d: &mut Driver, replay_payload: &[u8]) -> Result<Vec<MintNegative>> {
    let mut out = Vec::new();

    // E1 — REPLAY: re-consume a mint carrying the empty-hookData variant's ALREADY-COMMITTED nonce.
    {
        let f = d.faucet_id;
        let sender = d.owner();
        let attestation = d.actors.attester.attestation_for(replay_payload);
        let note =
            XReserveMintNote::create(sender, f, replay_payload, &attestation, d.hc.client.rng())
                .context("building the replay mint note")?;
        let key = nonce_key(replay_payload);
        out.push(
            negative(
                d,
                "replayed-nonce",
                crate::assertions_de::ERR_XRESERVE_NONCE_REPLAY,
                note,
                key,
                true,
            )
            .await?,
        );
    }

    // E2 — FORGED SIGNATURE: A's real pubkey, a WELL-FORMED signature over the WRONG digest.
    {
        let f = d.faucet_id;
        let sender = d.owner();
        let recipient = d.recipient();
        let payload = mint_payload_from(
            BASE_VECTOR,
            recipient,
            raw_for_units(E_UNITS),
            raw_for_units(MAX_FEE_UNITS),
            SALT_E_FORGED,
        );
        // A well-formed ECDSA signature over a digest that is NOT keccak256(payload).
        let attestation = d.actors.attester.attestation_over_digest([0xAB; 32]);
        let note = XReserveMintNote::create(sender, f, &payload, &attestation, d.hc.client.rng())
            .context("building the forged-signature mint note")?;
        let key = nonce_key(&payload);
        out.push(
            negative(
                d,
                "forged-signature",
                crate::assertions_de::ERR_XRESERVE_SIG_INVALID,
                note,
                key,
                false,
            )
            .await?,
        );
    }

    // E3 — NON-ALLOWLISTED ATTESTER: attester B (never allowlisted) signs, self-consistently.
    {
        let f = d.faucet_id;
        let sender = d.owner();
        let recipient = d.recipient();
        let payload = mint_payload_from(
            BASE_VECTOR,
            recipient,
            raw_for_units(E_UNITS),
            raw_for_units(MAX_FEE_UNITS),
            SALT_E_BAD_ATTESTER,
        );
        let attestation = d.actors.attester_b.attestation_for(&payload);
        let note = XReserveMintNote::create(sender, f, &payload, &attestation, d.hc.client.rng())
            .context("building the non-allowlisted-attester mint note")?;
        let key = nonce_key(&payload);
        out.push(
            negative(
                d,
                "non-allowlisted-attester",
                crate::assertions_de::ERR_XRESERVE_BAD_PK_COMMITMENT,
                note,
                key,
                false,
            )
            .await?,
        );
    }

    // E4 — NON-ZERO feeAmount: a valid A attestation, but the attachment carries a non-zero fee (F2).
    {
        let f = d.faucet_id;
        let sender = d.owner();
        let recipient = d.recipient();
        let payload = mint_payload_from(
            BASE_VECTOR,
            recipient,
            raw_for_units(E_UNITS),
            raw_for_units(MAX_FEE_UNITS),
            SALT_E_FEE,
        );
        let attestation = d.actors.attester.attestation_for(&payload);
        let fee_limbs = fee_limbs_for(raw_for_units(FEE_UNITS));
        let note = mint_note_with_fee(
            sender,
            f,
            &payload,
            &attestation,
            fee_limbs,
            d.hc.client.rng(),
        )
        .context("building the non-zero-fee mint note")?;
        let key = nonce_key(&payload);
        out.push(
            negative(
                d,
                "nonzero-fee",
                crate::assertions_de::ERR_XRESERVE_FEE_NONZERO,
                note,
                key,
                false,
            )
            .await?,
        );
    }

    // E5 — TAMPERED PAYLOAD: A signs one payload; the note carries a different (inflated) one.
    {
        let f = d.faucet_id;
        let sender = d.owner();
        let recipient = d.recipient();
        let signed_payload = mint_payload_from(
            BASE_VECTOR,
            recipient,
            raw_for_units(E_UNITS),
            raw_for_units(MAX_FEE_UNITS),
            SALT_E_TAMPERED,
        );
        let attestation = d.actors.attester.attestation_for(&signed_payload);
        // The note carries the SAME nonce (salt) but an INFLATED amount the attestation never signed.
        let note_payload = mint_payload_from(
            BASE_VECTOR,
            recipient,
            raw_for_units(E_UNITS * 2),
            raw_for_units(MAX_FEE_UNITS),
            SALT_E_TAMPERED,
        );
        let note =
            XReserveMintNote::create(sender, f, &note_payload, &attestation, d.hc.client.rng())
                .context("building the tampered-payload mint note")?;
        let key = nonce_key(&note_payload);
        out.push(
            negative(
                d,
                "tampered-payload",
                crate::assertions_de::ERR_XRESERVE_SIG_INVALID,
                note,
                key,
                false,
            )
            .await?,
        );
    }

    Ok(out)
}

/// Executes one negative client-side and records the reject + committed-state read-backs.
async fn negative(
    d: &mut Driver,
    label: &str,
    expected_error: &str,
    note: Note,
    key: Word,
    expects_nonce_set: bool,
) -> Result<MintNegative> {
    let supply_before = token_supply(&d.fetch_faucet().await?)?;
    let verdict = d.probe_consume(note).await?;
    let committed = d.fetch_faucet().await?;
    let supply_after = token_supply(&committed)?;
    // For the fresh-nonce negatives this MUST read empty; the read is captured either way so the
    // assertion (not the driver) decides.
    let nonce_marker_after = used_nonce_marker(&committed, key)?;
    Ok(MintNegative {
        label: label.to_string(),
        expected_error: expected_error.to_string(),
        verdict,
        supply_before,
        supply_after,
        nonce_marker_after,
        expects_nonce_set,
    })
}

/// Runs the full LNV-3 rows-D/E arc on its own fresh stack. See the module docs for the
/// execution model + arc order.
pub async fn run_rows_de(cfg: &RunConfig) -> Result<RowsDeObservations> {
    // 1. Fresh stack.
    let mut stack = NodeStack::bootstrap_and_start(&cfg.stack)
        .context("bootstrapping + starting the local node stack")?;
    if cfg.keep_stack {
        stack.keep_on_drop();
    }

    let obs = run_rows_de_on(cfg, "main").await?;

    // Teardown (Drop also covers the error paths above).
    if !cfg.keep_stack {
        stack.stop().context("stopping the node stack")?;
    }
    Ok(obs)
}

/// Runs the rows-D/E arc against an ALREADY-RUNNING stack (the LNV-5 consolidated run boots ONE
/// stack and drives every slice on it in matrix order). `client_label` namespaces this slice's
/// client store, keystore, and actor secrets under `<run_root>/client-<label>/` so composed
/// slices cannot collide. No stack lifecycle happens here.
pub async fn run_rows_de_on(cfg: &RunConfig, client_label: &str) -> Result<RowsDeObservations> {
    let main_commit = git_head_commit();

    // 2. Client + actors + the production faucet account (domain_init matching the mint vector).
    let mut hc = build_client(&cfg.stack, client_label).await?;
    hc.client.sync_state().await.context("initial sync")?;
    let actor_root = cfg.stack.run_root.join(format!("client-{client_label}"));
    let actors = create_actors(&mut hc, &actor_root).await?;
    let owner_id = actors.owner.id();
    let domain = mintburn::lnv2_domain_params();
    let faucet = build_faucet_account(
        owner_id,
        actors.pauser.id(),
        actors.manager.id(),
        actors.blk_manager.id(),
        cfg.max_supply,
        os_seed(),
    )?;
    let faucet_id = faucet.id();

    // 3. Deploy: the faucet's first tx consumes the owner's domain_init (first-deploy exemption).
    let note1 = XReserveDomainInitNote::create(
        owner_id,
        faucet_id,
        domain.domain,
        domain.source_domain,
        &domain.xreserve_contract,
        domain.identifier_word(),
        hc.client.rng(),
    )
    .context("building the domain_init note")?;
    let emit1 = TransactionRequestBuilder::new()
        .own_output_notes(vec![note1.clone()])
        .build()
        .context("building the domain_init emit")?;
    let emit1_tx = hc
        .client
        .submit_new_transaction(owner_id, emit1)
        .await
        .context("emit domain_init")?;
    let mut d = Driver {
        hc,
        actors,
        faucet_id,
    };
    d.wait_commit(emit1_tx)
        .await
        .context("waiting for the domain_init emit")?;
    d.hc.client
        .add_account(&faucet, false)
        .await
        .context("registering the faucet with the client")?;
    let deploy = TransactionRequestBuilder::new()
        .input_notes(vec![(note1.clone(), None)])
        .build()
        .context("building the deploy request")?;
    let deploy_tx =
        d.hc.client
            .submit_new_transaction(faucet_id, deploy)
            .await
            .context("deploy tx")?;
    d.wait_commit(deploy_tx)
        .await
        .context("waiting for the deploy")?;

    // Track the recipient's account-target tag so the client discovers the emitted public P2ID notes.
    let recipient_id = d.recipient();
    d.hc.client
        .add_note_tag(NoteTag::with_account_target(recipient_id))
        .await
        .context("tracking the recipient note tag")?;

    // 4. Allowlist attester A (path N) — the mints attest with A.
    let a_commitment = d.actors.attester.commitment_word();
    let set_a = {
        let f = d.faucet_id;
        XReserveSetAttesterNote::create(owner_id, f, a_commitment, 1, d.hc.client.rng())
            .context("building set_attester(A)")?
    };
    d.commit_via_ntx(owner_id, set_a, "set_attester(A, enabled=1)", |a| {
        attester_enabled(a, a_commitment)
    })
    .await
    .context("allowlisting attester A via path N")?;

    // 5. Row D — the two happy-path variants (each committed via path N + recipient-consumed).
    let (_, replay_payload) = d.valid_mint(BASE_VECTOR, D_EMPTY_UNITS, SALT_D_EMPTY)?;
    let d_empty = run_mint_happy(
        &mut d,
        "empty-hookData",
        BASE_VECTOR,
        D_EMPTY_UNITS,
        SALT_D_EMPTY,
    )
    .await?;
    let d_hook = run_mint_happy(
        &mut d,
        "hookData-bearing",
        HOOKDATA_VECTOR,
        D_HOOK_UNITS,
        SALT_D_HOOK,
    )
    .await?;

    // 6. Row E — the negatives (client-side rejects + zero-state-change read-backs). The replay
    //    reuses the empty-hookData variant's (now-committed) nonce.
    let e = run_negatives(&mut d, &replay_payload).await?;

    Ok(RowsDeObservations {
        main_commit,
        faucet_id: faucet_id.to_string(),
        recipient_id: recipient_id.to_string(),
        d: vec![d_empty, d_hook],
        e,
    })
}

/// Whether `commitment`'s `xReserveAttesters` marker is the enabled word [1,0,0,0].
fn attester_enabled(account: &Account, commitment: Word) -> bool {
    use xusdc_encoding::account::xreserve::XRESERVE_ATTESTERS_SLOT_LABEL;
    StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
        .ok()
        .and_then(|name| {
            account
                .storage()
                .get_map_item(&name, StorageMapKey::new(commitment))
                .ok()
        })
        .map(|w| word4(w) == crate::observations_cf::MARKER_SET)
        .unwrap_or(false)
}

/// The repo HEAD commit (ledger metadata; best-effort).
fn git_head_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
