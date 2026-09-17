//! Local checks on a saved burn's withdrawal request.

use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::note::{NoteScriptRoot, NoteTag};
use miden_standards::note::NetworkAccountTarget;
use xusdc_encoding::note::xreserve_burn::{
    FIXED_XUSDC_BURN_TAG, XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME,
    XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS,
};
use xusdc_encoding::xreserve::encoding::{XReserveBurnItems, BURN_NOTE_ITEMS_FELTS};

use crate::store::DiscoveredBurn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BurnRefusal {
    WrongScript,
    WrongTag,
    WrongAttachments,
    InvalidRouting,
    WrongTarget,
    WrongAsset,
    StoredAssetMismatch,
    InvalidWithdrawal,
    AmountMismatch,
}

impl BurnRefusal {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::WrongScript => "wrong_script",
            Self::WrongTag => "wrong_tag",
            Self::WrongAttachments => "wrong_attachments",
            Self::InvalidRouting => "invalid_routing",
            Self::WrongTarget => "wrong_target",
            Self::WrongAsset => "wrong_asset",
            Self::StoredAssetMismatch => "stored_asset_mismatch",
            Self::InvalidWithdrawal => "invalid_withdrawal",
            Self::AmountMismatch => "amount_mismatch",
        }
    }
}

/// Local content checks passed; this is not permission to sign.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct ValidatedBurn {
    pub(crate) burn: DiscoveredBurn,
    pub(crate) items: XReserveBurnItems,
    pub(crate) amount: u64,
}

pub(crate) fn validate_burn(
    burn: DiscoveredBurn,
    faucet_account_id: AccountId,
    expected_script_root: NoteScriptRoot,
) -> Result<ValidatedBurn, BurnRefusal> {
    let note = burn.note.as_note();
    if note.script().root() != expected_script_root {
        return Err(BurnRefusal::WrongScript);
    }
    if note.metadata().tag() != NoteTag::new(FIXED_XUSDC_BURN_TAG) {
        return Err(BurnRefusal::WrongTag);
    }

    let attachments = note.attachments();
    if attachments.num_attachments() != 2 {
        return Err(BurnRefusal::WrongAttachments);
    }
    // Two different required schemes plus the exact count also excludes duplicates.
    let routing = attachments
        .find(NetworkAccountTarget::ATTACHMENT_SCHEME)
        .ok_or(BurnRefusal::WrongAttachments)?;
    let withdrawal = attachments
        .iter()
        .find(|attachment| {
            attachment.attachment_scheme().as_u16() == XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_SCHEME
        })
        .ok_or(BurnRefusal::WrongAttachments)?;
    let target =
        NetworkAccountTarget::try_from(routing).map_err(|_| BurnRefusal::InvalidRouting)?;
    if target.target_id() != faucet_account_id {
        return Err(BurnRefusal::WrongTarget);
    }

    let [Asset::Fungible(asset)] = note.assets().as_slice() else {
        return Err(BurnRefusal::WrongAsset);
    };
    if asset.faucet_id() != faucet_account_id {
        return Err(BurnRefusal::WrongAsset);
    }
    if note.storage().items() != Asset::Fungible(*asset).as_elements() {
        return Err(BurnRefusal::StoredAssetMismatch);
    }

    if usize::from(withdrawal.num_words()) != XRESERVE_BURN_WITHDRAWAL_ATTACHMENT_WORDS {
        return Err(BurnRefusal::InvalidWithdrawal);
    }
    // Only the payload is decoded; unused word padding is deliberately ignored.
    let payload = withdrawal
        .as_elements()
        .get(..BURN_NOTE_ITEMS_FELTS)
        .ok_or(BurnRefusal::InvalidWithdrawal)?;
    let items = XReserveBurnItems::decode(payload).map_err(|_| BurnRefusal::InvalidWithdrawal)?;
    let amount = u64::from(asset.amount());
    Ok(ValidatedBurn {
        burn,
        items,
        amount,
    })
}
