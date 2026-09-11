//! The two domain types that are this service's own rather than Circle wire shapes: the decoded
//! burn payload and the burn-evidence package.

use xusdc_encoding::xreserve::encoding::XReserveBurnItems;

/// Withdrawal payload decoded using the shared [`XReserveBurnItems`] codec.
pub type BurnPayload = XReserveBurnItems;

/// Evidence verification strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofStrength {
    /// Verified by the note-inclusion proof against the block note root.
    Cryptographic,

    /// Reported by a node without a cryptographic proof of the claim.
    NodeTrusted,
}

impl ProofStrength {
    fn weaker_of(self, other: Self) -> Self {
        if self == Self::NodeTrusted || other == Self::NodeTrusted {
            Self::NodeTrusted
        } else {
            Self::Cryptographic
        }
    }
}

/// The claim supported by evidence, separate from its [`ProofStrength`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvenFact {
    /// The note was created in the inclusion proof's block.
    NoteCreatedInBlock,

    /// A node reports that a faucet transaction consumed the note.
    NoteConsumedByTransaction,

    /// A node reports that the nullifier was spent.
    NullifierSpent,
}

impl ProvenFact {
    /// Whether the claim concerns note consumption.
    pub fn is_consumption_claim(&self) -> bool {
        match self {
            Self::NoteCreatedInBlock => false,
            Self::NoteConsumedByTransaction | Self::NullifierSpent => true,
        }
    }
}

/// An evidence claim and its verification strength.
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

/// Complete, consistent evidence returned by [`assemble_evidence`](crate::evidence::assemble_evidence).
/// Creation has an inclusion proof; consumption relies on node reports
/// ([`Self::consumption_trust`]). The package does not establish withdrawal completion.
/// Circle's acceptance of Miden transaction IDs and additional evidence remains OPEN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePackage {
    burn_tx_id: String,
    note_id: [u8; 32],
    nullifier: [u8; 32],
    block_num: u32,
}

impl EvidencePackage {
    /// Constructs checked evidence for [`assemble_evidence`](crate::evidence::assemble_evidence).
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

    /// Returns the note ID as a 0x-prefixed hex string.
    pub fn note_id_hex(&self) -> String {
        to_hex(&self.note_id)
    }

    pub fn nullifier_hex(&self) -> String {
        to_hex(&self.nullifier)
    }

    /// Strength of the note-creation claim.
    pub fn note_id_strength(&self) -> ProofStrength {
        ProofStrength::Cryptographic
    }

    /// Strength of the creation-block claim.
    pub fn block_num_strength(&self) -> ProofStrength {
        ProofStrength::Cryptographic
    }

    /// Strength of the transaction-consumption claim.
    pub fn burn_tx_id_strength(&self) -> ProofStrength {
        ProofStrength::NodeTrusted
    }

    /// Strength of the nullifier-spend claim.
    pub fn nullifier_strength(&self) -> ProofStrength {
        ProofStrength::NodeTrusted
    }

    /// Identifies the note-creation claim.
    pub fn note_id_proves(&self) -> ProvenFact {
        ProvenFact::NoteCreatedInBlock
    }

    /// Identifies the creation-block claim.
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

    /// Returns the weakest verification strength among the consumption claims.
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
