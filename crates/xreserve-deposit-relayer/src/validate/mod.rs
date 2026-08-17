//! Circle-facing off-chain validation — the fail-fast checks that run before the seam: the
//! attestation envelope ([`envelope`] — `messageHash == keccak256(payload)` by RAW keccak, plus the
//! 65-byte `r‖s‖v` shape check) and the optional domain/token compare ([`domain_token`]).
//!
//! The DepositIntent decode itself has no module here: callers take the shared crate's
//! `DepositIntent::try_from` directly and map its rejection with
//! [`RelayerError::from_deposit_intent`](crate::error::RelayerError::from_deposit_intent), which is
//! where that path's reasoning lives.
//!
//! Every check here is a LIVENESS filter, never an authority: each one stops the relayer from
//! spending a Miden transaction on an envelope the chain would certainly reject. The authoritative
//! parse, the ECDSA verification, and the attester-allowlist gate are all on-chain.

pub mod domain_token;
pub mod envelope;

pub use domain_token::check_domain_token_against_info;
pub use envelope::{validate_attestation_envelope, verify_message_hash};
