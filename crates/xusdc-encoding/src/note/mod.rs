//! Faucet-owned note constructors (Component 1): the public burn-event note `XReserveBurnNote`
//! (CMP-B2, DC-7) — the Circle-facing withdrawal evidence note — and the production mint note
//! `XReserveMintNote` (CMP-B1, D4) — the signed-DepositIntent transport the faucet consumes to
//! drive the attested mint.
//!
//! These are FAUCET-owned producers; the `NoteStorage.items` payload is encoded via the
//! 04-owned codec (`crate::xreserve::encoding`), consumed by reference.

pub mod xreserve_burn;
pub mod xreserve_mint;
