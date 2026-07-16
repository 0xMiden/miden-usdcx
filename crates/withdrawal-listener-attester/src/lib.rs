//! `withdrawal-listener-attester` — the Phase-4 off-chain burn-listener / attester (`CMP-C2`/`CMP-C3`).
//!
//! This is the service on the withdrawal side of xUSDC: it watches Miden for public
//! `XReserveBurnNote`s, asks Circle to prepare the corresponding burn intents, has the partner's
//! attesters sign them off-chain, and submits them with the burn evidence so Circle releases native
//! USDC on the source chain. **It releases real money** — which is why the Circle wire shapes are
//! frozen against the OpenAPI (`tests/fixtures/README.md`) rather than against these types, and why
//! `validate.rs`'s B5 field-by-field compare (`INV-CIRCLE-CANONICAL-WITHDRAWAL`) gates the signing
//! step rather than following it.
//!
//! # What this slice ships
//!
//! The Circle-facing half, end to end: the static [`config`], the [`circle::schema`] wire types (the
//! §10.3 shapes, matched field-for-field to the OpenAPI), the schema-exact mock fixtures, the
//! [`circle::auth`] posture, the [`circle::transport`] seam **with its production bounded-streaming
//! transport**, the [`circle::client::CircleClient`], and the three Circle HTTP drivers
//! ([`withdrawal_api::prepare`], [`withdrawal_api::withdraw`], [`withdrawal_api::poll_status`]). No
//! Miden read is made — the drivers are exercised against the in-process mock (§12), and the live
//! Circle legs stay `REQUIRES CIRCLE CONFIRMATION`.
//!
//! # What it deliberately does not ship
//!
//! * **Miden reads** (the exact-tag `SyncNotes` scan, `GetNotesById` retrieval, the evidence reads) —
//!   they need `miden-client`, which has **no v0.16 release**, so they are parked to a later slice.
//!   The dependency is absent from the manifest entirely, not feature-gated. What a discovered note
//!   *says* is already decodable without any of that, and [`note_decode`] does it: the `DC-7`
//!   payload (through unit-04's codec) and the `metadata.sender` read. Its tests are therefore
//!   NON-GATING — the GATING `T-LA-01`/`T-LA-04` local-node runs are parked with the discovery leg.
//! * **The `409` conflict-recovery and the `5xx` bounded-retry / rate-governor policies** (W7).
//!
//! # What this slice ADDS (W6)
//!
//! The three Circle HTTP drivers in [`withdrawal_api`], on the [`circle::client::CircleClient`]:
//! [`withdrawal_api::prepare`] (`POST /v1/prepare-withdrawal`), [`withdrawal_api::withdraw`]
//! (`POST /v1/withdraw`, the **array** response, one status per batch), and
//! [`withdrawal_api::poll_status`] (`GET /v1/withdrawal/{id}`, poll-to-terminal; a validated
//! [`circle::wire::Uuid`] id, and the response bound to it). Plus the fund-safety pre-submit
//! signer-allowlist gate ([`withdrawal_api::authorize_submission`] → [`withdrawal_api::AuthorizedWithdrawal`]),
//! which requires every recovered `burnSignatures` signer to be a configured registered attester
//! before any submission, and the production response-size ceiling enforced while streaming
//! ([`circle::transport::collect_bounded`]).
//!
//! # What this slice ADDS (W5)
//!
//! The PURE request builders, [`withdrawal_api`]: [`withdrawal_api::build_prepare_request`] (the
//! `DC-9` `PrepareWithdrawalRequest` the partner authors — `remoteDepositor` from the burn note's
//! `metadata.sender` through unit-04's `DC-6` codec, `sourceDepositor` structurally absent,
//! `INV-REMOTEDEPOSITOR-VS-SOURCEDEPOSITOR`) and [`withdrawal_api::build_withdraw_request`] (the
//! `POST /v1/withdraw` `{ batches: [..] }` wrapper, `1..=5`). Both build ONLY the API JSON — never
//! the binary `TransferSpec`/`BurnIntent`, which Circle encodes server-side. The Circle HTTP drivers
//! that carry these (`prepare` / `withdraw` / status poll) are W6.
//!
//! # What this slice ADDS (W4)
//!
//! The PURE validation gate, [`validate`]: the ordered **B3** discovery checklist
//! ([`validate::validate_discovery`]) and the **B5** field-by-field gate
//! ([`validate::validate_returned`]) that compares Circle's returned `burnIntents[].spec` against
//! the burn payload for EVERY batch and, on a full match, mints the [`validate::ValidatedWithdrawal`]
//! proof-of-validation token. The withdrawal flow's signer, [`validate::sign_validated`], consumes
//! that token — so a mismatch cannot reach signing (B5 gates B6, `INV-CIRCLE-CANONICAL-WITHDRAWAL`),
//! and "sign a response that failed validation" is untypeable, not merely unreached.
//!
//! # What this slice ADDS (W3)
//!
//! The PURE signing core, [`attester`]: [`attester::sign`] (a single `k256` ECDSA over Circle's
//! opaque `messageHashToSign`, emitting the Ethereum-shaped `r‖s‖v` with `v = 27`/`28` the
//! source-chain `ECDSA.recover` requires — `INV-OFFCHAIN-BURN-SIGNING`, `DC-11`, `Q-CRY-2` OPEN) and
//! [`attester::assemble_quorum`] (the exactly-threshold, every-signature-verifies-to-its-claimed-signer,
//! ascending-address, no-duplicate `burnSignatures` bundle, `DC-11`). `k256` (and `sha3`, for signer
//! address recovery) are LIBRARY dependencies here, unlike in the deposit relayer where they are
//! dev-only: the relayer never verifies a signature off-chain, whereas this service's off-chain
//! signature IS the product. A single signature is a non-gating local primitive that is NEVER
//! submitted to Circle on its own; the real keys the interface will drive (KMS/HSM, ≥2 attesters) are
//! human/ops-owned (W11) and no real key material lives here.
//!
//! # The invariants this slice's types carry
//!
//! * **`INV-REMOTEDEPOSITOR-VS-SOURCEDEPOSITOR`** — [`circle::schema::PrepareBurnIntentInput`] has no
//!   `sourceDepositor` field, and the returned [`circle::schema::TransferSpec`] does. The partner
//!   sends the Miden burner as `remoteDepositor`; Circle assigns `sourceDepositor` server-side.
//! * **`INV-CIRCLE-CANONICAL-WITHDRAWAL`** — the wire types decode what Circle *said*; nothing here
//!   validates or authorizes. Decoded is not validated.
//! * **`INV-PUBLIC-BURN-OBSERVABILITY` / anti-`ASG-3`** — [`config::ListenerConfig::burn_tag`] is one
//!   FULL 32-bit tag, matched by exact equality; `SyncNotes` does not prefix-scan.
//! * **`DC-7` / `DC-6` single-owner** — [`types::BurnPayload`] IS unit-04's `XReserveBurnItems`, and
//!   the `AccountId↔bytes32` encoding behind `remoteDepositor` is unit-04's codec. Both consumed by
//!   reference; neither re-implemented.
//!
//! # Circle-owned questions this slice touches — all still OPEN
//!
//! `Q-API-AUTH` (no auth scheme is documented; the client parameterizes an out-of-band key and
//! invents no header — [`circle::auth`]), `Q-DOM-1`/`Q-DOM-2`/`Q-DOM-3` (Miden's domain id, and the
//! `sourceDepositor` Circle assigns), `Q-CRY-2` (`messageHashToSign` is treated as opaque-and-sign),
//! and `DEV-7` (whether a Miden tx id is an acceptable `burnTxId`). None of them is answered here;
//! each is parameterized and left open.

pub mod attester;
pub mod circle;
pub mod config;
pub mod error;
pub mod note_decode;
pub mod types;
pub mod validate;
pub mod withdrawal_api;

pub use error::{
    DecodeError, DiscoveryReject, ListenerError, QuorumError, SignError, SignatureError,
    SubmitGateError, ValidationMismatch,
};
