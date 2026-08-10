//! The two domain types that are this service's own rather than Circle wire shapes: the decoded
//! burn payload and the burn-evidence package.

use xusdc_encoding::xreserve::encoding::XReserveBurnItems;

/// The burn note's public payload — `(amount, destDomain, destRecipient, salt)`, decoded from
/// `NoteStorage.items`.
///
/// This is an **alias**, not a second struct. Circle's documented `BurnPayload` is field-for-field
/// the shared encoding crate's [`XReserveBurnItems`], which is the type that already owns the
/// burn-item codec (`XReserveBurnItems::encode` / `::decode`, `BURN_NOTE_ITEMS_FELTS = 18`). Re-declaring it here would create two structs that have to be kept in sync by hand — which
/// is precisely how a wire format drifts, and this one decides how much USDC a user gets back.
/// Consumers pin the shared shape by reference (single-owner rule); the alias exists only so the
/// spec's name resolves.
///
/// The decode itself is
/// [`note_decode::decode_burn_payload`](crate::note_decode::decode_burn_payload), which is that
/// same codec called by reference. What still waits on a client is only the DISCOVERY of the note
/// whose felts it decodes (the exact-tag scan and the retrieval — PARKED to the `miden-client`
/// slice).
pub type BurnPayload = XReserveBurnItems;

/// How strongly a piece of burn evidence is proven — reproduced from the evidence table,
/// where the labels are not decoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofStrength {
    /// Proven by a cryptographic path the partner can check itself — the note's inclusion proof
    /// against the block's note root.
    Cryptographic,

    /// Observed from a node, and trusted because that node said so. There is **no
    /// `GetTransactionById`** on Miden, so tx-linkage cannot be resolved by hash alone; and
    /// `SyncNullifiers` carries no inclusion proof, so a spend observation is a report, not a
    /// proof.
    ///
    /// Labelling either of these `Cryptographic` would overstate to Circle what Miden proves. The
    /// optional full-block path is what upgrades tx-linkage — and it is itself `OPTIONAL` +
    /// `REQUIRES IMPLEMENTATION VALIDATION`.
    NodeTrusted,
}

impl ProofStrength {
    /// The weaker of two strengths — a claim resting on several pieces of evidence is only as
    /// strong as the weakest of them.
    fn weaker_of(self, other: Self) -> Self {
        if self == Self::NodeTrusted || other == Self::NodeTrusted {
            Self::NodeTrusted
        } else {
            Self::Cryptographic
        }
    }
}

/// **What** a piece of burn evidence proves — orthogonal to [`ProofStrength`], which says only how
/// strongly it is proved.
///
/// The two are separate types because reporting strength alone would let the strongest label sit
/// beside the weakest claim: a creation proof is cryptographic and says nothing about consumption.
/// The [`evidence`](crate::evidence) module docs carry why that distinction decides whether USDC is
/// released against an unspent note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvenFact {
    /// The note existed and was CREATED in the named block — what the `GetNotesById` inclusion
    /// proof gives, and the whole of what it gives.
    NoteCreatedInBlock,

    /// A node REPORTS that a transaction of the faucet's consumed the note (`SyncTransactions`).
    /// No inclusion proof accompanies it, and there is no `GetTransactionById` to check it against.
    NoteConsumedByTransaction,

    /// A node REPORTS the note's nullifier spent (`SyncNullifiers`). No inclusion proof, and
    /// there is no `CheckNullifiers` RPC either.
    NullifierSpent,
}

impl ProvenFact {
    /// Whether this fact is a **consumption claim** — a claim that the burn actually happened — as
    /// opposed to a fact about the note's creation.
    ///
    /// Every consumption claim Miden can make today is a node report, so this predicate is what
    /// lets the package assert mechanically that no element is both CRYPTOGRAPHIC and a burn
    /// claim.
    pub fn is_consumption_claim(&self) -> bool {
        match self {
            Self::NoteCreatedInBlock => false,
            Self::NoteConsumedByTransaction | Self::NullifierSpent => true,
        }
    }
}

/// One element of an [`EvidencePackage`], with what it proves and how strongly.
///
/// The package exposes its elements as a list as well as one accessor per field, so a rule about
/// "every element" can be written — and checked — as a rule about every element, rather than as
/// four assertions someone has to remember to extend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EvidenceElement {
    /// The element's name as the evidence package writes it.
    pub name: &'static str,
    /// How strongly it is proved.
    pub strength: ProofStrength,
    /// What it proves.
    pub proves: ProvenFact,
}

/// The burn-evidence package: the 4-tuple the partner hands Circle so it can independently
/// verify the burn, each element carrying its documented proof strength.
///
/// # What this package does NOT say
///
/// It does not say the burn is confirmed, and there is deliberately no accessor that would. Its
/// cryptographic elements prove the note's CREATION, while every element that speaks to the burn
/// having happened is NODE-TRUSTED ([`Self::consumption_trust`]) — retrievable is not the same as
/// cryptographically proved. Nor does a package mean the withdrawal succeeded: only Circle's own
/// terminal `finalized` says that
/// ([`WithdrawalStatusKind::is_terminal`](crate::circle::schema::WithdrawalStatusKind::is_terminal)).
///
/// A package exists only where the evidence was complete and self-consistent. Assembling one from
/// ambiguous reads is refused rather than rounded up, with
/// [`EvidenceError::ReconciliationRequired`](crate::evidence::EvidenceError::ReconciliationRequired).
///
/// Whether a Miden transaction identifier is even an acceptable `burnTxId`, and whether Circle will
/// accept additional Miden evidence behind it, is **OPEN** — `REQUIRES CIRCLE CONFIRMATION`.
/// This type carries the evidence; it does not claim Circle has agreed to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePackage {
    burn_tx_id: String,
    note_id: [u8; 32],
    nullifier: [u8; 32],
    block_num: u32,
}

impl EvidencePackage {
    /// **`pub(crate)`: a package is minted by
    /// [`assemble_evidence`](crate::evidence::assemble_evidence) and by nothing else.** It is the
    /// difference between a token that MEANS the evidence was read and checked, and a token that
    /// merely LOOKS like one.
    ///
    /// Every guarantee this type's documentation makes lives in the assembler, not in these four
    /// fields: that the note was public and committed, that a spend was actually observed, that a
    /// faucet transaction actually consumed it, that the node did not contradict itself. A public
    /// constructor would let a caller skip all of that and produce a value indistinguishable from
    /// an assembled one — same type, same labels, four fields the caller typed — and Circle would
    /// release native USDC against them. Sealed, the type means what it says: outside this crate,
    /// holding one is proof the checks ran, and the only way to obtain one is to pass a
    /// [`BurnEvidenceReads`](crate::evidence::BurnEvidenceReads) port that answers consistently.
    ///
    /// The honest limit: in-crate code can still call this, so the one-caller rule is held by a
    /// structural-absence test rather than by the compiler.
    pub(crate) fn new(
        burn_tx_id: String,
        note_id: [u8; 32],
        nullifier: [u8; 32],
        block_num: u32,
    ) -> Self {
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

    /// CRYPTOGRAPHIC — the `GetNotesById` inclusion path proves the note's membership in the
    /// block's note root, which is proof it was CREATED there ([`Self::note_id_proves`]) and no
    /// evidence at all of a burn.
    pub fn note_id_strength(&self) -> ProofStrength {
        ProofStrength::Cryptographic
    }

    /// CRYPTOGRAPHIC — via that same note inclusion proof, and the block it names is the one the
    /// note was CREATED in.
    pub fn block_num_strength(&self) -> ProofStrength {
        ProofStrength::Cryptographic
    }

    /// NODE-TRUSTED — tx-linkage, unless the optional full-block path runs.
    pub fn burn_tx_id_strength(&self) -> ProofStrength {
        ProofStrength::NodeTrusted
    }

    /// NODE-TRUSTED — the spend observation (`SyncNullifiers` carries no inclusion proof).
    pub fn nullifier_strength(&self) -> ProofStrength {
        ProofStrength::NodeTrusted
    }

    /// The note's creation — NOT its consumption.
    pub fn note_id_proves(&self) -> ProvenFact {
        ProvenFact::NoteCreatedInBlock
    }

    /// The block the note was CREATED in.
    pub fn block_num_proves(&self) -> ProvenFact {
        ProvenFact::NoteCreatedInBlock
    }

    /// That a faucet transaction consumed the note — as reported by a node.
    pub fn burn_tx_id_proves(&self) -> ProvenFact {
        ProvenFact::NoteConsumedByTransaction
    }

    /// That the nullifier was spent — as observed by a node.
    pub fn nullifier_proves(&self) -> ProvenFact {
        ProvenFact::NullifierSpent
    }

    /// Every element of the package, in its documented order, each with its strength and the fact
    /// it proves.
    pub fn elements(&self) -> [EvidenceElement; 4] {
        [
            EvidenceElement {
                name: "burnTxId",
                strength: self.burn_tx_id_strength(),
                proves: self.burn_tx_id_proves(),
            },
            EvidenceElement {
                name: "note_id",
                strength: self.note_id_strength(),
                proves: self.note_id_proves(),
            },
            EvidenceElement {
                name: "nullifier",
                strength: self.nullifier_strength(),
                proves: self.nullifier_proves(),
            },
            EvidenceElement {
                name: "block_num",
                strength: self.block_num_strength(),
                proves: self.block_num_proves(),
            },
        ]
    }

    /// How strongly this package proves **that the burn happened at all** — the weakest of its
    /// consumption claims, and therefore NODE-TRUSTED today.
    ///
    /// This is the number that matters to Circle, and it is the one a reader is most likely to get
    /// wrong by eye: the package's *strongest* label is CRYPTOGRAPHIC, and that label belongs to
    /// the note's creation. The burn claim rests entirely on the two node reports behind it, so it
    /// is derived from their labels rather than written down as a constant — the day the optional
    /// full-block path (still open) upgrades the tx-linkage, this answer moves
    /// with it instead of being a promise someone forgot to revisit.
    pub fn consumption_trust(&self) -> ProofStrength {
        self.elements()
            .iter()
            .filter(|element| element.proves.is_consumption_claim())
            .map(|element| element.strength)
            .reduce(ProofStrength::weaker_of)
            .expect("DC-8 always carries consumption evidence — a burnTxId and a nullifier")
    }
}

fn to_hex(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}
