//! The sanity driver + node-truth storage readers.
//!
//! [`SanityDriver`] wraps the [`HarnessClient`] with the small set of node interactions the checks
//! need: emit a routed note and wait for the ntx-builder to auto-commit its faucet consumption
//! (path N), client-side execute a doomed consumption to capture its exact trap (the negatives),
//! read committed account state, and discover a recipient's P2ID. The storage readers pull the
//! faucet's committed slots (`token_supply`, `max_supply`, `min_burn_size`, `is_paused`, the
//! `usedNonces` / `xReserveAttesters` maps) straight from a `GetAccount` result.

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
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId, NoteTag};
use miden_protocol::transaction::InputNote;
use miden_protocol::Word;

use xusdc_encoding::account::xreserve::{
    DOMAIN_CONFIG_SLOT_LABEL, IDENTIFIER_CONFIG_SLOT_LABEL, MIN_BURN_SIZE_SLOT_LABEL,
    USED_NONCES_SLOT_LABEL, XRESERVE_ATTESTERS_SLOT_LABEL,
};

use crate::client::HarnessClient;
use crate::mintburn::MintDomainConfig;
use crate::observations_cf::Verdict;

/// Bounded wait for a submitted (regular-account) tx to commit.
const TX_COMMIT_TIMEOUT: Duration = Duration::from_secs(240);
/// Bounded wait for the ntx-builder to auto-commit a routed faucet consumption (path N).
const PATHN_TIMEOUT: Duration = Duration::from_secs(300);
/// Bounded wait for a recipient's committed P2ID note to appear.
const NOTE_SYNC_TIMEOUT: Duration = Duration::from_secs(240);

const TOKEN_CONFIG_SLOT_LABEL: &str = "miden::standards::faucets::fungible::token_config";
const IS_PAUSED_SLOT_LABEL: &str = "miden::standards::access::pausable::is_paused";
/// The Ownable2Step owner slot; the value word is
/// `[owner_suffix, owner_prefix, nominated_suffix, nominated_prefix]`.
const OWNER_CONFIG_SLOT_LABEL: &str = "miden::standards::access::ownable2step::owner_config";

// STORAGE READERS (node-truth account state)
// ================================================================================================

pub(crate) fn word4(w: Word) -> [u64; 4] {
    [
        w[0].as_canonical_u64(),
        w[1].as_canonical_u64(),
        w[2].as_canonical_u64(),
        w[3].as_canonical_u64(),
    ]
}

pub(crate) fn is_zero_word(w: Word) -> bool {
    word4(w) == [0, 0, 0, 0]
}

fn value_slot(account: &Account, label: &str) -> Result<Word> {
    let name = StorageSlotName::new(label).with_context(|| format!("slot label '{label}'"))?;
    account
        .storage()
        .get_item(&name)
        .with_context(|| format!("reading value slot '{label}'"))
}

/// `token_config = [token_supply, max_supply, decimals, symbol]`.
pub(crate) fn token_supply(account: &Account) -> Result<u64> {
    Ok(value_slot(account, TOKEN_CONFIG_SLOT_LABEL)?[0].as_canonical_u64())
}

pub(crate) fn max_supply(account: &Account) -> Result<u64> {
    Ok(value_slot(account, TOKEN_CONFIG_SLOT_LABEL)?[1].as_canonical_u64())
}

pub(crate) fn min_burn(account: &Account) -> Result<u64> {
    Ok(value_slot(account, MIN_BURN_SIZE_SLOT_LABEL)?[0].as_canonical_u64())
}

/// The faucet's configured `domain` (element 0 of the domain-config slot) — the value the D5a mint
/// gate compares a mint's `remoteDomain` against. Read from the DEPLOYED faucet so the `--faucet-id`
/// mint carries the RIGHT domain (a domain id is a u32, so an out-of-u32 slot value is an error).
pub(crate) fn domain_config(account: &Account) -> Result<u32> {
    let raw = value_slot(account, DOMAIN_CONFIG_SLOT_LABEL)?[0].as_canonical_u64();
    u32::try_from(raw).map_err(|_| {
        anyhow::anyhow!("faucet domain-config slot holds {raw}, which does not fit a u32 domain id")
    })
}

/// The faucet's configured identifier key (the D5a `remoteToken` compare target): the stored
/// `bytes32_to_key(identifier_bytes)` Word. Used to VERIFY a resolved mint config's `remote_token`
/// hashes to what the deployed faucet actually stored, before any mint is emitted.
pub(crate) fn identifier_config(account: &Account) -> Result<Word> {
    value_slot(account, IDENTIFIER_CONFIG_SLOT_LABEL)
}

/// `true` iff the faucet's `is_paused` slot is set (non-zero element 0).
pub(crate) fn is_paused(account: &Account) -> Result<bool> {
    Ok(value_slot(account, IS_PAUSED_SLOT_LABEL)?[0].as_canonical_u64() != 0)
}

pub(crate) fn used_nonce_marker(account: &Account, key: Word) -> Result<Word> {
    let name = StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?;
    account
        .storage()
        .get_map_item(&name, StorageMapKey::new(key))
        .map_err(|e| anyhow::anyhow!("reading usedNonces[{key:?}]: {e}"))
}

pub(crate) fn attester_marker(account: &Account, commitment: Word) -> Result<Word> {
    let name = StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
        .context("xReserveAttesters slot label")?;
    account
        .storage()
        .get_map_item(&name, StorageMapKey::new(commitment))
        .map_err(|e| anyhow::anyhow!("reading xReserveAttesters[{commitment:?}]: {e}"))
}

/// The committed Ownable2Step ownership: `(current_owner, nominated_owner)`. `nominated_owner` is
/// `None` when no 2-step transfer is pending (the nominee half of the word is all-zero). This is the
/// GROUND TRUTH used by the finally-phase restore — never a client-side boolean that a failed/unseen
/// accept could leave stale.
pub(crate) fn owner_config(account: &Account) -> Result<(AccountId, Option<AccountId>)> {
    let w = value_slot(account, OWNER_CONFIG_SLOT_LABEL)?;
    let owner = AccountId::try_from_elements(w[0], w[1])
        .map_err(|e| anyhow::anyhow!("decoding owner_config current owner: {e}"))?;
    let e = word4(w);
    let nominated = if e[2] == 0 && e[3] == 0 {
        None
    } else {
        Some(
            AccountId::try_from_elements(w[2], w[3])
                .map_err(|e| anyhow::anyhow!("decoding owner_config nominated owner: {e}"))?,
        )
    };
    Ok((owner, nominated))
}

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

/// Declares the faucet as a foreign account IFF `note` carries the faucet's (policed) xUSDC asset —
/// the F4-reversal client-side coupling: a policed send/consume by a non-faucet account dyncalls the
/// faucet's `basic_blocklist::check_policy`, so the faucet must be a foreign account. Admin notes
/// (mint/domain/pause) carry no faucet asset and need none.
fn policed_faucet_foreign(note: &Note, faucet_id: AccountId) -> Result<Vec<ForeignAccount>> {
    let policed = note
        .assets()
        .iter()
        .any(|a| matches!(a, Asset::Fungible(f) if f.faucet_id() == faucet_id));
    if policed {
        Ok(vec![ForeignAccount::public(
            faucet_id,
            AccountStorageRequirements::default(),
        )
        .context(
            "declaring the faucet as a foreign account for the policed transfer",
        )?])
    } else {
        Ok(vec![])
    }
}

// THE DRIVER
// ================================================================================================

pub(crate) struct SanityDriver {
    pub(crate) hc: HarnessClient,
    pub(crate) faucet_id: AccountId,
    /// The domain config every mint payload must carry so the D5a gate accepts it. `None` on the
    /// fresh-LOCAL full gate (mints use the [`crate::mintburn::BASE_VECTOR`] header unchanged);
    /// `Some` on the existing-faucet (`--faucet-id`) re-check — resolved once from the DEPLOYED
    /// faucet's on-chain `domain` + `account_id_to_bytes32(faucet_id)`, then applied to EVERY mint
    /// (positives, negatives, and burn-funding), since all target the same faucet.
    pub(crate) mint_config: Option<MintDomainConfig>,
}

impl SanityDriver {
    pub(crate) async fn sync(&mut self) -> Result<()> {
        self.hc
            .client
            .sync_state()
            .await
            .context("syncing client state")?;
        Ok(())
    }

    /// The NODE's committed view of the faucet (`GetAccount`).
    pub(crate) async fn fetch_faucet(&mut self) -> Result<Account> {
        self.sync().await?;
        let id = self.faucet_id;
        self.hc
            .rpc
            .get_account_details(id)
            .await
            .map_err(|e| anyhow::anyhow!("GetAccount({id}): {e}"))?
            .with_context(|| format!("the node does not recognize the faucet {id}"))
    }

    pub(crate) async fn wait_commit(&mut self, tx_id: TransactionId) -> Result<u32> {
        let deadline = Instant::now() + TX_COMMIT_TIMEOUT;
        loop {
            self.sync().await?;
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

    /// Emits `note` from `sender` (a regular-account tx the user RPC accepts). Returns the emit block.
    pub(crate) async fn emit(&mut self, sender: AccountId, note: Note) -> Result<u32> {
        let foreign = policed_faucet_foreign(&note, self.faucet_id)?;
        let req = TransactionRequestBuilder::new()
            .foreign_accounts(foreign)
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

    /// Path N: emit the routed allowlisted note, then poll `GetAccount` until `ready` observes the
    /// ntx-builder-committed effect. Returns the committed faucet account.
    pub(crate) async fn commit_via_ntx<F>(
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

    /// Path N with a nullifier-based completion check: emit `note`, then poll until the faucet has
    /// consumed it (its nullifier is recorded on-chain). For admin ops whose effect is not a readable
    /// storage slot (ownership transfer/accept). Returns the note's consume block.
    pub(crate) async fn commit_via_ntx_consumed(
        &mut self,
        sender: AccountId,
        note: Note,
        op: &str,
    ) -> Result<u32> {
        self.emit(sender, note.clone())
            .await
            .with_context(|| format!("emitting the {op} note"))?;
        let deadline = Instant::now() + PATHN_TIMEOUT;
        loop {
            if let Some(block) = self.note_spent_block(&note).await? {
                return Ok(block);
            }
            if Instant::now() > deadline {
                bail!(
                    "path-N consumption of '{op}' timed out after {PATHN_TIMEOUT:?} — the ntx-builder \
                     did not consume the routed allowlisted note"
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Node-truth exact-tag discovery: does the node's `SyncNotes` (filtered to `tag`) return the
    /// committed `note_id`? This is the attester's real B3 discovery RPC — proving the burn note is
    /// findable on-chain by its fixed tag, not just decodable from an in-memory copy.
    pub(crate) async fn syncnotes_discovers(&mut self, tag: u32, note_id: NoteId) -> Result<bool> {
        self.sync().await?;
        let to = self
            .hc
            .client
            .get_sync_height()
            .await
            .context("reading the chain tip for SyncNotes")?;
        let tags = std::collections::BTreeSet::from([NoteTag::new(tag)]);
        let blocks = self
            .hc
            .rpc
            .sync_notes(BlockNumber::from(0u32), to, &tags)
            .await
            .map_err(|e| anyhow::anyhow!("SyncNotes(tag={tag:#010x}): {e}"))?;
        Ok(blocks.iter().any(|b| b.notes.contains_key(&note_id)))
    }

    /// Node-truth: the block `note`'s nullifier was spent in (`None` if not yet spent).
    pub(crate) async fn note_spent_block(&mut self, note: &Note) -> Result<Option<u32>> {
        self.sync().await?;
        let nullifier = note.nullifier();
        let heights = self
            .hc
            .rpc
            .get_nullifier_commit_heights(
                std::collections::BTreeSet::from([nullifier]),
                BlockNumber::from(0u32),
            )
            .await
            .map_err(|e| anyhow::anyhow!("querying nullifier commit heights: {e}"))?;
        Ok(heights
            .get(&nullifier)
            .copied()
            .flatten()
            .map(|b| b.as_u32()))
    }

    /// Client-side execute of the faucet consuming `note` (NO submission). Ok = ACCEPTED, a trap =
    /// REJECTED with the captured error. The mechanism every negative uses to capture the exact gate.
    pub(crate) async fn probe_consume(&mut self, note: Note) -> Result<Verdict> {
        self.sync().await?;
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

    /// Waits (syncing) until `target` has a consumable committed note carrying exactly `amount_units`
    /// of the faucet's asset. Matching on the AMOUNT keeps the subsequent balance check honest.
    pub(crate) async fn wait_for_target_note(
        &mut self,
        target: AccountId,
        amount_units: u64,
    ) -> Result<Note> {
        let faucet_id = self.faucet_id;
        let deadline = Instant::now() + NOTE_SYNC_TIMEOUT;
        loop {
            self.sync().await?;
            let consumable = self
                .hc
                .client
                .get_consumable_notes(Some(target))
                .await
                .context("querying the target's consumable notes")?;
            for (record, _) in &consumable {
                let carries =
                    record.details().assets().iter_fungible().any(|a| {
                        a.faucet_id() == faucet_id && u64::from(a.amount()) == amount_units
                    });
                if !carries {
                    continue;
                }
                let input: InputNote = record
                    .clone()
                    .try_into()
                    .context("converting the note record to an InputNote")?;
                return Ok(input.note().clone());
            }
            if Instant::now() > deadline {
                bail!(
                    "the target {target} did not receive its committed P2ID note carrying \
                     {amount_units} units within {NOTE_SYNC_TIMEOUT:?}"
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// `target` consumes `note` (a regular-account tx the user RPC accepts). Returns the consume block.
    /// The consumed note carries policed xUSDC (F4-reversal), so the faucet is declared foreign.
    pub(crate) async fn target_consume(&mut self, target: AccountId, note: Note) -> Result<u32> {
        let foreign = policed_faucet_foreign(&note, self.faucet_id)?;
        let req = TransactionRequestBuilder::new()
            .foreign_accounts(foreign)
            .build_consume_notes(vec![note])
            .context("building the target consume request")?;
        let tx = self
            .hc
            .client
            .submit_new_transaction(target, req)
            .await
            .context("submitting the target consume")?;
        self.wait_commit(tx).await
    }

    /// A wallet's committed faucet-asset balance from the client's synced store (0 before it
    /// materializes; the raw `GetAccount` RPC rejects an unseen account).
    pub(crate) async fn balance_of(&mut self, account_id: AccountId) -> Result<u64> {
        let faucet_id = self.faucet_id;
        self.sync().await?;
        Ok(self
            .hc
            .client
            .get_account(account_id)
            .await
            .map_err(|e| anyhow::anyhow!("client get_account({account_id}): {e}"))?
            .map(|a| wallet_balance(&a, faucet_id))
            .unwrap_or(0))
    }
}
