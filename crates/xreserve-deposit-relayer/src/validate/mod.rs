//! Circle-facing off-chain validation (the fail-fast checks before the seam; §3, §8.1): the
//! DepositIntent structural decoder ([`deposit_intent`], the mirror of D5a) and the attestation
//! envelope ([`envelope`] — `messageHash == keccak256(payload)` by RAW keccak, DC-2, plus the
//! 65-byte `r‖s‖v` shape check).
//!
//! Every check here is a LIVENESS filter, never an authority: each one stops the relayer from
//! spending a Miden transaction on an envelope the chain would certainly reject. The authoritative
//! parse, the ECDSA verification, and the attester-allowlist gate are all on-chain (§1.2).

pub mod deposit_intent;
pub mod domain_token;
pub mod envelope;

pub use deposit_intent::{decode_and_validate_deposit_intent, DepositIntent};
pub use domain_token::check_domain_token_against_info;
pub use envelope::{validate_attestation_envelope, verify_message_hash, verify_message_hash_bytes};
