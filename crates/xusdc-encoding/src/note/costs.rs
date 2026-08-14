//! Benchmarked consumption costs for notes whose execution on the xUSDC faucet differs from the
//! corresponding standard note.

use miden_protocol::note::NoteScriptRoot;
use miden_standards::note::costs::{NoteConsumptionCost, NoteCost};
use miden_standards::note::P2idNote;

use super::xreserve_admin::{XReserveSetAttesterNote, XReserveSetMinBurnSizeNote};
use super::xreserve_burn::XReserveBurnNote;
use super::xreserve_mint::XUsdcMintNote;

/// Cycles of consuming an xUSDC MINT note: empty hook data 43899, maximum hook data 67255.
pub const XUSDC_MINT_CONSUMPTION_CYCLES: u32 = 67255;

/// Cycles of consuming an xUSDC BURN note.
pub const XUSDC_BURN_CONSUMPTION_CYCLES: u32 = 31540;

/// Cycles of consuming an xUSDC set-attester note: enable 29716, disable 29579.
pub const XRESERVE_SET_ATTESTER_CONSUMPTION_CYCLES: u32 = 29716;

/// Cycles of consuming an xUSDC set-minimum-burn-size note.
pub const XRESERVE_SET_MIN_BURN_SIZE_CONSUMPTION_CYCLES: u32 = 28073;

impl NoteConsumptionCost for XUsdcMintNote {
    fn consumption_cycles() -> u32 {
        XUSDC_MINT_CONSUMPTION_CYCLES
    }

    fn created_notes() -> Vec<NoteScriptRoot> {
        vec![P2idNote::script_root()]
    }
}

impl NoteConsumptionCost for XReserveBurnNote {
    fn consumption_cycles() -> u32 {
        XUSDC_BURN_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for XReserveSetAttesterNote {
    fn consumption_cycles() -> u32 {
        XRESERVE_SET_ATTESTER_CONSUMPTION_CYCLES
    }
}

impl NoteConsumptionCost for XReserveSetMinBurnSizeNote {
    fn consumption_cycles() -> u32 {
        XRESERVE_SET_MIN_BURN_SIZE_CONSUMPTION_CYCLES
    }
}

/// Returns the xUSDC-specific cost for `root`, or `None` when the standard cost applies.
pub(crate) fn note_cost(root: NoteScriptRoot) -> Option<NoteCost> {
    if root == XUsdcMintNote::script_root() {
        Some(NoteCost::of::<XUsdcMintNote>())
    } else if root == XReserveBurnNote::script_root() {
        Some(NoteCost::of::<XReserveBurnNote>())
    } else if root == XReserveSetAttesterNote::script_root() {
        Some(NoteCost::of::<XReserveSetAttesterNote>())
    } else if root == XReserveSetMinBurnSizeNote::script_root() {
        Some(NoteCost::of::<XReserveSetMinBurnSizeNote>())
    } else {
        None
    }
}
