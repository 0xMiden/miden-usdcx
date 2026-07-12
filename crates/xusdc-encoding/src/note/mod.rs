//! Faucet-owned note constructors: the public burn-event note `XReserveBurnNote`
//! (CMP-B2, DC-7) — the Circle-facing withdrawal evidence note — and the production mint note
//! `XReserveMintNote` (CMP-B1) — the signed-DepositIntent transport the faucet consumes to
//! drive the attested mint.
//!
//! These are FAUCET-owned producers; the `NoteStorage.items` payload is encoded via the
//! shared-encoding codec (`crate::xreserve::encoding`), consumed by reference.

pub mod xreserve_admin;
pub mod xreserve_burn;
pub mod xreserve_mint;
