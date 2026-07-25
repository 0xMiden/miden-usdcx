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
//! transport**, the [`circle::client::CircleClient`], and the three Circle endpoints
//! ([`withdrawal_api::prepare`], [`submit::submit_withdraw`], [`withdrawal_api::poll_status`]). No
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
//!
//! # What this slice ADDS (W9) — the orchestration, and the order that is the product
//!
//! [`listener::run_once`]: the **B3→B10 flow**, composing every unit above into the sequence that
//! releases a user's money. It re-implements none of them; what it owns is the ORDER, and the order
//! is enforced by types rather than by the order of its own lines:
//!
//! * **B5 gates B6, structurally.** [`validate::validate_returned`] mints the
//!   [`ValidatedWithdrawal`](crate::validate::ValidatedWithdrawal), and [`listener::QuorumSigner`] —
//!   the orchestration's only signing entry — takes one. On a mismatch no token exists, so the signer
//!   is not merely un-called: it is uncallable (`INV-CIRCLE-CANONICAL-WITHDRAWAL`).
//! * **The submitted batch carries Circle's ON-CHAIN quorum shape.** W6's submit gate checks signer
//!   MEMBERSHIP, and membership is not shape: two signatures from one registered attester pass it and
//!   fail Circle's exactly-2 / strictly-ascending / no-duplicate verifier. So
//!   [`attester::assemble_quorum`] now mints an [`attester::QuorumBundle`] — the shape as a TYPE —
//!   and [`withdrawal_api::build_withdraw_batch`] is the only assembly path, and it demands one.
//! * **The payload and the depositor come from ONE note.**
//!   [`withdrawal_api::build_prepare_request`] takes a
//!   [`DiscoveredBurn`](crate::validate::DiscoveredBurn), not a payload and a sender: shipping burn
//!   A's amount under burn B's depositor is a mistake nothing downstream could catch, so it is
//!   untypeable rather than avoided.
//! * **One burn ↔ one payload ↔ one batch** ([`listener::ONE_BATCH_PER_BURN`]) — a prepare response
//!   with any other batch count is refused BEFORE the signer.
//! * **Fail-closed at every stage**, and the ledger's durable claim still decides the submission, so
//!   a re-discovered burn makes zero calls.
//!
//! The Miden reads stay PORTS ([`listener::DiscoveredNote`], [`evidence::BurnEvidenceReads`]): they
//! are **W10, PARKED** on a `miden-client` with no v0.16 release, and nothing here fakes one — so
//! this slice's suites are NON-GATING, and W10's real-node leg is the gating one.
//!
//! # What this slice ADDS (W8) — the burn evidence, and the honesty of its labels
//!
//! [`evidence::assemble_evidence`]: the `DC-8` package (`burnTxId`, `note_id`, `nullifier`,
//! `block_num`), each element carrying BOTH how strongly it is proved ([`types::ProofStrength`]) and
//! WHAT it proves ([`types::ProvenFact`]). The second half is the fund-safety point, and it is
//! `DEV-7`, the HIGHEST-RISK deviation, still **OPEN**:
//!
//! * **A `GetNotesById` inclusion proof is cryptographic, and it proves the note was CREATED.** It is
//!   silent on consumption. "This note exists" is not "this burn happened", so no element is ever both
//!   CRYPTOGRAPHIC and a consumption claim, and [`types::EvidencePackage::consumption_trust`] — how
//!   well the BURN is proved — is NODE-TRUSTED, always, today. The tx-linkage (`SyncTransactions`) and
//!   the spend observation (`SyncNullifiers`) carry no inclusion proof; they are labelled to Circle as
//!   node-trusted, which is the substance of `DEV-7` (`INV-BURN-EVIDENCE-TRUST`).
//! * **No `burnTxId`-only path, structurally.** `GetTransactionById` does not exist on Miden (R-8), so
//!   [`evidence::BurnEvidenceReads`] has no by-hash method and the assembler's only entry key is a
//!   `NoteId` (anti-`ASG-4`). `U1` (`OPTIONAL-UPSTREAM`) stays OPEN.
//! * **A package cannot be manufactured.** [`types::EvidencePackage`]'s constructor is `pub(crate)`
//!   and [`evidence::assemble_evidence`] is its only caller, so holding one outside this crate is
//!   proof the checks ran rather than proof someone typed four plausible values. Every fail-closed
//!   rule below lives in the assembler; a public constructor would be a door around all of them.
//! * **Fail-closed.** Missing, ambiguous, or self-contradicting evidence yields
//!   [`evidence::EvidenceError::ReconciliationRequired`] — W7's vocabulary, deliberately reused — and
//!   never a package. Only Circle's terminal `finalized` settles a withdrawal.
//! * **No invented transport.** `note_id`/`nullifier`/`block_num` go nowhere on the wire: `burnTxId`
//!   is the only evidence field `POST /v1/withdraw` documents, and whether Circle would accept more is
//!   `DEV-7`'s to answer, not this crate's to assume.
//!
//! The reads behind [`evidence::BurnEvidenceReads`] are a crate-local port with a unit adapter — the
//! real v16-client leg is **W10**, parked, and this slice's tests are therefore NON-GATING. The
//! optional full-block upgrade ([`evidence::full_block_upgrade`], `IMPL-FULLBLOCK-PATH`) is P2: it
//! returns its typed deferral error rather than a panicking placeholder.
//!
//! # What this slice ADDS (W7) — the money path's error handling
//!
//! [`submit::submit_withdraw`], the production `POST /v1/withdraw` entry point, and the two policies
//! and one ledger it runs on:
//!
//! * **The `409` conflict-recovery contract (§10.10).** A `409` ("burnTxId already tied to an active
//!   withdrawal") is a **duplicate conflict requiring recovery/reconciliation, NOT success**, and is
//!   NEVER answered by re-sending. With `conflict.withdrawalId` → recover by POLLING
//!   `GET /v1/withdrawal/{withdrawalId}`; with only `conflict.burnTxId` → stop and mark reconciliation
//!   required; echoing a DIFFERENT `burnTxId` → a defect. [`submit::SubmitOutcome`] is closed and has
//!   no path from a `409` to its success variant, so the rule is structural rather than remembered.
//! * **Per-burn cross-invocation idempotency** ([`idempotency::SubmitLedger`]) — a durable SQLite
//!   claim, keyed on the `burnTxId`, mirroring the deposit relayer's seam. It is what makes "the same
//!   burn, re-discovered or re-submitted after a restart, is submitted at most once" true of the
//!   process rather than of one call. Unlike the relayer's, it is a SAFETY property, not a liveness
//!   backstop: there is no on-chain assert behind it.
//! * **Bounded retry + the documented rate ceilings** ([`circle::retry`], [`circle::rate`]) — a `5xx`
//!   retried within a bound and then SURFACED; a deterministic `400` attempted exactly once; a
//!   **status-less transport failure attempted exactly once too** (a timeout carries no evidence that
//!   Circle did not act, so re-POSTing a withdrawal on one is a blind resubmission — §10.10 names `5xx`
//!   and only `5xx` as retryable); 5 QPS/IP and 35 QPS global, a permit taken before every attempt.
//!   No `Retry-After`/`429` is documented, so none is invented.
//!
//! Everything ambiguous — an exhausted budget, an unreadable `201`, a conflict naming no withdrawal —
//! fails CLOSED: the burn is blocked for an operator rather than retried into a possible second
//! release. Only a terminal `finalized` settles a burn as done.
//!
//! # What this slice ADDS (W6)
//!
//! The three Circle HTTP drivers in [`withdrawal_api`], on the [`circle::client::CircleClient`]:
//! [`withdrawal_api::prepare`] (`POST /v1/prepare-withdrawal`), the `POST /v1/withdraw` submission
//! (the **array** response, one status per batch — W7 folded it into [`submit::submit_withdraw`], which
//! additionally takes the durable idempotency claim, and deleted the raw driver that could POST
//! without one), and
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
pub mod evidence;
pub mod idempotency;
pub mod listener;
pub mod note_decode;
pub mod submit;
pub mod types;
pub mod validate;
pub mod withdrawal_api;

pub use error::{
    DecodeError, DiscoveryReject, ListenerError, QuorumError, SignError, SignatureError,
    SubmitGateError, ValidationMismatch,
};
pub use evidence::{EvidenceError, EvidenceReadError};
pub use idempotency::LedgerError;
pub use submit::SubmitError;
