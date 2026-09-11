//! Adapts node reads to [`BurnEvidenceReads`] for [`assemble_evidence`].
//! Fetches the note and inclusion proof, spend observation, and transaction linkage asynchronously
//! before exposing them through the synchronous adapter.

use anyhow::{Context, Result};
use miden_client::rpc::domain::note::FetchedNote;
use miden_client::rpc::NodeRpcClient;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId, Nullifier};

use withdrawal_listener_attester::evidence::{
    assemble_evidence, BurnEvidenceReads, EvidenceReadError, NoteRecord, NullifierRecord,
    PublicNoteDetails, TransactionRecord as EvTx,
};

use crate::client::HarnessClient;

/// The three node reads, pre-fetched for one burn note, served synchronously to the attester's
/// [`assemble_evidence`]. The port ignores its args (the reads were resolved for exactly this
/// note/faucet); `assemble_evidence`'s own note-id / nullifier / two-block consistency checks are
/// what validate the packet.
struct Prefetched {
    note: NoteRecord,
    nullifier: NullifierRecord,
    txs: Vec<EvTx>,
}

impl BurnEvidenceReads for Prefetched {
    fn note_by_id(&self, _note_id: NoteId) -> Result<NoteRecord, EvidenceReadError> {
        Ok(self.note.clone())
    }
    fn faucet_transactions(&self, _faucet_id: AccountId) -> Result<Vec<EvTx>, EvidenceReadError> {
        Ok(self.txs.clone())
    }
    fn nullifier_status(&self, _n: Nullifier) -> Result<NullifierRecord, EvidenceReadError> {
        Ok(self.nullifier.clone())
    }
}

/// Fetches the `GetNotesById` record for the committed public burn note.
async fn fetch_note_record(hc: &HarnessClient, note_id: NoteId) -> Result<NoteRecord> {
    let fetched = hc
        .rpc
        .get_notes_by_id(&[note_id])
        .await
        .map_err(|e| anyhow::anyhow!("GetNotesById({note_id}): {e}"))?;
    for f in fetched {
        match f {
            FetchedNote::Public(note, proof) if note.id() == note_id => {
                return Ok(NoteRecord {
                    note_id,
                    details: Some(PublicNoteDetails {
                        nullifier: note.nullifier(),
                        inclusion_proof: proof,
                    }),
                });
            }
            // A private note carries no details — the burn would be unobservable (§10.11).
            FetchedNote::Private(id, ..) if id == note_id => {
                return Ok(NoteRecord {
                    note_id,
                    details: None,
                });
            }
            _ => {}
        }
    }
    anyhow::bail!("the node did not return the committed burn note {note_id} via GetNotesById")
}

/// Builds the `SyncTransactions(faucet_id)` records (each with its input-note nullifiers — the
/// `burnTxId` linkage) over `[0, tip]`.
async fn fetch_faucet_txs(hc: &HarnessClient, faucet_id: AccountId) -> Result<Vec<EvTx>> {
    let tip = hc
        .client
        .get_sync_height()
        .await
        .context("reading the chain tip for SyncTransactions")?;
    let records = hc
        .rpc
        .sync_transactions(BlockNumber::from(0u32), tip, vec![faucet_id])
        .await
        .map_err(|e| anyhow::anyhow!("SyncTransactions({faucet_id}): {e}"))?;
    Ok(records
        .into_iter()
        .map(|rec| {
            let h = &rec.transaction_header;
            EvTx {
                transaction_id: h.id(),
                account_id: h.account_id(),
                block_num: rec.block_num,
                input_note_nullifiers: h.input_notes().iter().map(|c| c.nullifier()).collect(),
                output_note_proofs: rec
                    .output_notes
                    .iter()
                    .map(|cn| (*cn.note_id(), cn.inclusion_proof().clone()))
                    .collect(),
            }
        })
        .collect())
}

/// Runs [`assemble_evidence`] against the committed burn and reports missing or inconsistent reads.
pub(crate) async fn assert_burn_evidence(
    hc: &HarnessClient,
    burn: &Note,
    faucet_id: AccountId,
) -> Result<String, String> {
    let note_id = burn.id();
    let note = fetch_note_record(hc, note_id)
        .await
        .map_err(|e| format!("GetNotesById read failed: {e:#}"))?;
    let nullifier_val = burn.nullifier();
    let heights = hc
        .rpc
        .get_nullifier_commit_heights(
            std::collections::BTreeSet::from([nullifier_val]),
            BlockNumber::from(0u32),
        )
        .await
        .map_err(|e| format!("SyncNullifiers read failed: {e}"))?;
    let nullifier = NullifierRecord {
        nullifier: nullifier_val,
        spent_in_block: heights.get(&nullifier_val).copied().flatten(),
    };
    let txs = fetch_faucet_txs(hc, faucet_id)
        .await
        .map_err(|e| format!("SyncTransactions read failed: {e:#}"))?;

    let port = Prefetched {
        note,
        nullifier,
        txs,
    };
    let pkg = assemble_evidence(&port, note_id, faucet_id)
        .map_err(|e| format!("assemble_evidence refused to build a DC-8 packet: {e:?}"))?;

    Ok(format!(
        "DC-8 packet assembled: note_id={}, nullifier={}, block_num={}, burnTxId={}",
        pkg.note_id_hex(),
        pkg.nullifier_hex(),
        pkg.block_num(),
        pkg.burn_tx_id(),
    ))
}
