//! Faucet-owned note constructors: the public burn-event note `XReserveBurnNote`
//! (CMP-B2, DC-7) — the Circle-facing withdrawal evidence note — and the production mint-note
//! factory `XUsdcMintNote` (CMP-B1) — the STOCK standards `MintNote` carrying the
//! signed-DepositIntent transport as attachments, consumed by the faucet under its attestation
//! mint policy.
//!
//! These are FAUCET-owned producers; the `NoteStorage.items` payload is encoded via the
//! shared-encoding codec (`crate::xreserve::encoding`), consumed by reference.

pub mod xreserve_admin;
pub mod xreserve_burn;
pub mod xreserve_mint;
