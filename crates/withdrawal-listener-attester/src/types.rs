//! The two domain types §10.3 names that are not Circle wire shapes: the decoded burn payload and
//! the burn-evidence package.

use xusdc_encoding::xreserve::encoding::XReserveBurnItems;

/// The burn note's public payload — `(amount, destDomain, destRecipient, salt)`, decoded from
/// `NoteStorage.items` (`DC-7`).
///
/// This is an **alias**, not a second struct. §10.3's `BurnPayload` is field-for-field unit-04's
/// [`XReserveBurnItems`], which is the type that already owns the burn-item codec
/// (`encode_burn_note_items` / `decode_burn_note_items`, `BURN_NOTE_ITEMS_FELTS = 18`). Re-declaring
/// it here would create two structs that have to be kept in sync by hand — which is precisely how a
/// wire format drifts, and this one decides how much USDC a user gets back. Consumers pin the shared
/// shape by reference (single-owner rule); the alias exists only so the spec's name resolves.
///
/// The decode itself (`note_decode.rs`) lands with the Miden-facing slice — it needs a note, and
/// notes need a client.
pub type BurnPayload = XReserveBurnItems;

/// How strongly a piece of burn evidence is proven — reproduced from the evidence table (§10.7),
/// where the labels are not decoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofStrength {
    /// Proven by a cryptographic path the partner can check itself — the note's inclusion proof
    /// against the block's note root.
    Cryptographic,

    /// Observed from a node, and trusted because that node said so. There is **no
    /// `GetTransactionById`** on Miden (R-8), so tx-linkage cannot be resolved by hash alone; and
    /// `SyncNullifiers` carries no inclusion proof, so a spend observation is a report, not a proof.
    ///
    /// Labelling either of these `Cryptographic` would overstate to Circle what Miden proves. The
    /// optional full-block path (§10.7) is what upgrades tx-linkage — and it is itself `OPTIONAL` +
    /// `REQUIRES IMPLEMENTATION VALIDATION` (`IMPL-FULLBLOCK-PATH`).
    NodeTrusted,
}

/// The burn-evidence package (`DC-8`): the 4-tuple the partner hands Circle so it can independently
/// verify the burn, each element carrying its documented proof strength.
///
/// Whether a Miden transaction identifier is even an acceptable `burnTxId`, and whether Circle will
/// accept additional Miden evidence behind it, is `DEV-7` — **OPEN**, `REQUIRES CIRCLE CONFIRMATION`.
/// This type carries the evidence; it does not claim Circle has agreed to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePackage {
    burn_tx_id: String,
    note_id: [u8; 32],
    nullifier: [u8; 32],
    block_num: u32,
}

impl EvidencePackage {
    pub fn new(burn_tx_id: String, note_id: [u8; 32], nullifier: [u8; 32], block_num: u32) -> Self {
        Self {
            burn_tx_id,
            note_id,
            nullifier,
            block_num,
        }
    }

    /// The Miden burn transaction id — the `burnTxId` a `POST /v1/withdraw` batch carries.
    pub fn burn_tx_id(&self) -> &str {
        &self.burn_tx_id
    }

    pub fn note_id(&self) -> [u8; 32] {
        self.note_id
    }

    pub fn nullifier(&self) -> [u8; 32] {
        self.nullifier
    }

    pub fn block_num(&self) -> u32 {
        self.block_num
    }

    /// The note id as the `0x`-hex the Circle wire carries. Rendered here rather than at each call
    /// site, so the 32-byte fields cannot be hex-encoded two different ways.
    pub fn note_id_hex(&self) -> String {
        to_hex(&self.note_id)
    }

    pub fn nullifier_hex(&self) -> String {
        to_hex(&self.nullifier)
    }

    /// CRYPTOGRAPHIC — the `GetNotesById` inclusion path proves membership in the block's note root
    /// (R-2).
    pub fn note_id_strength(&self) -> ProofStrength {
        ProofStrength::Cryptographic
    }

    /// CRYPTOGRAPHIC — via that same note inclusion proof.
    pub fn block_num_strength(&self) -> ProofStrength {
        ProofStrength::Cryptographic
    }

    /// NODE-TRUSTED — tx-linkage (R-9/R-10), unless the optional full-block path runs.
    pub fn burn_tx_id_strength(&self) -> ProofStrength {
        ProofStrength::NodeTrusted
    }

    /// NODE-TRUSTED — the spend observation (R-5; `SyncNullifiers` carries no inclusion proof).
    pub fn nullifier_strength(&self) -> ProofStrength {
        ProofStrength::NodeTrusted
    }
}

fn to_hex(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}
