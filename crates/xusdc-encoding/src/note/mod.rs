//! Faucet-owned note constructors: the public burn-event note `XReserveBurnNote`
//! — the Circle-facing withdrawal evidence note — the production mint-note
//! factory `XUsdcMintNote` — the STOCK standards `MintNote` carrying the
//! signed-DepositIntent transport as attachments, consumed by the faucet under its attestation
//! mint policy — and the `xreserve_admin` family of admin-note factories driving the faucet's
//! role-gated admin procs.
//!
//! All of them are producers only — nothing here consumes a note. Payloads are written with the
//! shared codecs in `crate::xreserve::encoding`, so the bytes a note carries are defined in exactly
//! one place.

use miden_protocol::account::AccountId;
use miden_protocol::errors::NoteError;
use miden_protocol::note::NoteAttachment;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};

pub mod xreserve_admin;
pub mod xreserve_burn;
pub mod xreserve_mint;

/// The scheme-2 `NetworkAccountTarget` routing bind to the faucet network account, shared by every
/// faucet-targeted note this module produces. Routing-only: the network transaction infrastructure
/// reads it to route the note; no note script or policy derives an effect from it. Requires a
/// PUBLIC faucet id.
pub(crate) fn network_routing_attachment(
    faucet_id: AccountId,
) -> Result<NoteAttachment, NoteError> {
    let target =
        NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always).map_err(|err| {
            NoteError::other_with_source("faucet id is not a public network account", err)
        })?;
    Ok(NoteAttachment::from(target))
}
