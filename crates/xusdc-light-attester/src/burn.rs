//! Structurally consumable xUSDC burn evidence discovered on Miden.

use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, NoteTag, Nullifier};
use miden_protocol::transaction::{PublicOutputNote, TransactionId};
use miden_standards::note::NetworkAccountTarget;
use xusdc_encoding::note::xreserve_burn::{
    XReserveBurnNote, XUsdcBurnAttachment, FIXED_XUSDC_BURN_TAG,
    XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME, XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS,
};
use xusdc_encoding::xreserve::encoding::XReserveBurnItems;
use xusdc_encoding::xreserve::MIDEN_DOMAIN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidBurnCandidate;

/// A public note whose structure allows the configured faucet to consume it as an xUSDC burn.
///
/// The fixed tag and Circle payload are deliberately not checked here. They do not participate in
/// on-chain consumption, so a note that violates either may still destroy xUSDC and must remain
/// discoverable for the later durable-refusal gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BurnCandidate {
    note: PublicOutputNote,
    creation_block: BlockNumber,
}

impl BurnCandidate {
    pub(crate) fn try_new(
        note: PublicOutputNote,
        creation_block: BlockNumber,
        faucet_account_id: AccountId,
    ) -> Result<Self, InvalidBurnCandidate> {
        let burn = note.as_note();
        if burn.script().root() != XReserveBurnNote::script_root() {
            return Err(InvalidBurnCandidate);
        }

        let attachments = burn.attachments();
        if attachments.num_attachments() != 2 {
            return Err(InvalidBurnCandidate);
        }
        let routing = attachments
            .find(NetworkAccountTarget::ATTACHMENT_SCHEME)
            .ok_or(InvalidBurnCandidate)?;
        let withdrawal = attachments
            .iter()
            .find(|attachment| {
                attachment.attachment_scheme().as_u16()
                    == XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME
            })
            .ok_or(InvalidBurnCandidate)?;
        let target = NetworkAccountTarget::try_from(routing).map_err(|_| InvalidBurnCandidate)?;
        if target.target_id() != faucet_account_id
            || usize::from(withdrawal.num_words()) != XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS
        {
            return Err(InvalidBurnCandidate);
        }

        let [Asset::Fungible(asset)] = burn.assets().as_slice() else {
            return Err(InvalidBurnCandidate);
        };
        if asset.faucet_id() != faucet_account_id
            || burn.storage().items() != Asset::Fungible(*asset).as_elements()
        {
            return Err(InvalidBurnCandidate);
        }

        Ok(Self {
            note,
            creation_block,
        })
    }

    pub(crate) fn note(&self) -> &PublicOutputNote {
        &self.note
    }

    pub(crate) fn creation_block(&self) -> BlockNumber {
        self.creation_block
    }

    pub(crate) fn note_id(&self) -> NoteId {
        self.note.id()
    }

    pub(crate) fn nullifier(&self) -> Nullifier {
        self.note.as_note().nullifier()
    }

    pub(crate) fn into_discovered(
        self,
        consumption_block: BlockNumber,
        burn_tx_id: TransactionId,
    ) -> DiscoveredBurn {
        DiscoveredBurn {
            note: self.note,
            creation_block: self.creation_block,
            consumption_block,
            burn_tx_id,
        }
    }
}

/// A structurally consumable candidate and its authenticated faucet-consumption evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiscoveredBurn {
    note: PublicOutputNote,
    creation_block: BlockNumber,
    consumption_block: BlockNumber,
    burn_tx_id: TransactionId,
}

impl DiscoveredBurn {
    pub(crate) fn try_new(
        note: PublicOutputNote,
        creation_block: BlockNumber,
        consumption_block: BlockNumber,
        burn_tx_id: TransactionId,
        faucet_account_id: AccountId,
    ) -> Result<Self, InvalidBurnCandidate> {
        BurnCandidate::try_new(note, creation_block, faucet_account_id)
            .map(|candidate| candidate.into_discovered(consumption_block, burn_tx_id))
    }

    pub(crate) fn note(&self) -> &PublicOutputNote {
        &self.note
    }

    pub(crate) fn creation_block(&self) -> BlockNumber {
        self.creation_block
    }

    pub(crate) fn consumption_block(&self) -> BlockNumber {
        self.consumption_block
    }

    pub(crate) fn burn_tx_id(&self) -> TransactionId {
        self.burn_tx_id
    }

    pub(crate) fn note_id(&self) -> NoteId {
        self.note.id()
    }

    pub(crate) fn nullifier(&self) -> Nullifier {
        self.note.as_note().nullifier()
    }
}

/// A durable reason why a consumed, structurally valid burn cannot become a withdrawal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BurnRefusal {
    WrongTag,
    InvalidWithdrawal,
}

impl BurnRefusal {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::WrongTag => "wrong_tag",
            Self::InvalidWithdrawal => "invalid_withdrawal",
        }
    }
}

/// A consumed burn whose Circle withdrawal fields decoded successfully.
///
/// This local validation is not permission to sign.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct ValidatedBurn {
    pub(crate) burn: DiscoveredBurn,
    pub(crate) items: XReserveBurnItems,
    pub(crate) amount: u64,
}

impl TryFrom<DiscoveredBurn> for ValidatedBurn {
    type Error = BurnRefusal;

    fn try_from(burn: DiscoveredBurn) -> Result<Self, Self::Error> {
        validate_burn(burn)
    }
}

pub(crate) fn validate_burn(burn: DiscoveredBurn) -> Result<ValidatedBurn, BurnRefusal> {
    let note = burn.note().as_note();
    if note.metadata().tag() != NoteTag::new(FIXED_XUSDC_BURN_TAG) {
        return Err(BurnRefusal::WrongTag);
    }

    let withdrawal = note
        .attachments()
        .iter()
        .find(|attachment| {
            attachment.attachment_scheme().as_u16() == XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME
        })
        .ok_or(BurnRefusal::InvalidWithdrawal)?;
    let items = XUsdcBurnAttachment::try_from(withdrawal)
        .map_err(|_| BurnRefusal::InvalidWithdrawal)?
        .items()
        .clone();
    if items.dest_domain == MIDEN_DOMAIN {
        return Err(BurnRefusal::InvalidWithdrawal);
    }
    let [Asset::Fungible(asset)] = note.assets().as_slice() else {
        return Err(BurnRefusal::InvalidWithdrawal);
    };
    let amount = u64::from(asset.amount());

    Ok(ValidatedBurn {
        burn,
        items,
        amount,
    })
}
