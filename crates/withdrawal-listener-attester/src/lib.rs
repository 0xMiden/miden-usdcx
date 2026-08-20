//! `withdrawal-listener-attester` — the off-chain burn listener / attester.
//!
//! This is the service on the withdrawal side of xUSDC: it watches Miden for public
//! `XReserveBurnNote`s, asks Circle to prepare the corresponding burn intents, has the partner's
//! attesters sign them off-chain, and submits them with the burn evidence so Circle releases native
//! USDC on the source chain. **It releases real money** — which is why the Circle wire shapes are
//! frozen against the OpenAPI (`tests/fixtures/README.md`) rather than against these types, and why
//! the field-by-field compare in `validate.rs` gates the signing step rather than following it.
//!
//! # The steps of a withdrawal, and the names this crate calls them by
//!
//! A withdrawal runs as a fixed sequence, and every event this service emits is tagged with the
//! step it belongs to. The names are short because operators read them in logs; they mean:
//!
//! * **B3 — discovery.** A burn note is found and validated: exact tag, publicly observable,
//!   consumed by the xUSDC burn script, payload decodable, sender readable, and carrying exactly
//!   the xUSDC its payload claims. Nothing leaves the process until this passes.
//! * **B4 — prepare request.** The validated burn is turned into Circle's prepare-withdrawal
//!   request, payload and depositor taken from that one note.
//! * **B5 — prepare and validate the response.** Circle returns a burn spec; it is compared to the
//!   burn note field by field. This is THE gate: a mismatch ends the run with nothing signed.
//! * **B6 — sign.** The attesters sign the validated batch and a two-signature quorum is assembled.
//! * **B7 — evidence and submit.** The burn evidence is assembled, the withdrawal batch built, the
//!   submission authorized against the fund-safety rules, and the request sent.
//! * **B10 — status.** Circle's withdrawal status is polled to completion.
//!
//! # What this crate ships
//!
//! The Circle-facing half, end to end: the static [`config`], the [`circle::schema`] wire types
//! (matched field-for-field to the OpenAPI), the schema-exact mock fixtures, the
//! [`circle::auth`] posture, the [`circle::transport`] seam **with its production bounded-streaming
//! transport**, the [`circle::client::CircleClient`], and the three Circle endpoints
//! ([`withdrawal_api::prepare`], [`submit::submit_withdraw`], [`withdrawal_api::poll_status`]). No
//! Miden read is made — the drivers are exercised against the in-process mock, and the live
//! Circle legs stay `REQUIRES CIRCLE CONFIRMATION`.
//!
//! # What it deliberately does not ship
//!
//! * **Miden reads** (the exact-tag `SyncNotes` scan, `GetNotesById` retrieval, the evidence reads)
//!   they need `miden-client`, which has **no v0.16 release**, so they are parked to a later slice.
//!   The dependency is absent from the manifest entirely, not feature-gated. What a discovered note
//!   *says* is already decodable without any of that, and [`note_decode`] does it: the burn-note
//!   payload (through the shared encoding crate's codec) and the `metadata.sender` read. Its tests
//!   are therefore NON-GATING; the gating local-node runs are parked with the discovery leg.
//!
//! # The orchestration — the order is the product
//!
//! [`listener::run_once`] walks B3 through B10, composing every unit above into the sequence that
//! releases a user's money. It re-implements none of them; what it owns is the ORDER, and the order
//! is enforced by types rather than by the order of its own lines:
//!
//! * **B5 gates B6, structurally.** [`validate::validate_returned`] mints the
//!   [`ValidatedWithdrawal`](crate::validate::ValidatedWithdrawal), and [`listener::QuorumSigner`]
//!   the orchestration's only signing entry — takes one. On a mismatch no token exists, so the
//!   signer is not merely un-called: it is uncallable.
//! * **The submitted batch carries Circle's ON-CHAIN quorum shape.** the submit gate checks signer
//!   MEMBERSHIP, and membership is not shape: two signatures from one registered attester pass it
//!   and fail Circle's exactly-2 / strictly-ascending / no-duplicate verifier. So
//!   [`attester::assemble_quorum`] now mints an [`attester::QuorumBundle`] — the shape as a TYPE
//!   and [`withdrawal_api::build_withdraw_batch`] is the only assembly path, and it demands one.
//! * **The payload and the depositor come from ONE note.**
//!   [`withdrawal_api::build_prepare_request`] takes a
//!   [`DiscoveredBurn`](crate::validate::DiscoveredBurn), not a payload and a sender: shipping burn
//!   A's amount under burn B's depositor is a mistake nothing downstream could catch, so it is
//!   untypeable rather than avoided.
//! * **One burn ↔ one payload ↔ one batch** ([`listener::ONE_BATCH_PER_BURN`]) — a prepare response
//!   with any other batch count is refused BEFORE the signer.
//! * **Fail-closed at every stage**, and the ledger's durable claim still decides the submission,
//!   so a re-discovered burn makes zero calls.
//!
//! The Miden reads stay PORTS ([`listener::DiscoveredNote`], [`evidence::BurnEvidenceReads`]): they
//! are PARKED on a `miden-client` with no v0.16 release, and nothing here fakes one — so
//! this slice's suites are NON-GATING, and the real-node leg, when it lands, is the gating one.
//!
//! # The burn evidence — the burn evidence, and the honesty of its labels
//!
//! [`evidence::assemble_evidence`]: the burn-evidence package (`burnTxId`, `note_id`, `nullifier`,
//! `block_num`), each element carrying BOTH how strongly it is proved ([`types::ProofStrength`])
//! and WHAT it proves ([`types::ProvenFact`]). The second half is the fund-safety point, and it is
//! the HIGHEST-RISK Circle-owned deviation, still **OPEN**:
//!
//! * **A `GetNotesById` inclusion proof is cryptographic, and it proves the note was CREATED.** It
//!   is silent on consumption. "This note exists" is not "this burn happened", so no element is
//!   ever both CRYPTOGRAPHIC and a consumption claim, and
//!   [`types::EvidencePackage::consumption_trust`] — how well the BURN is proved — is NODE-TRUSTED,
//!   always, today. The tx-linkage (`SyncTransactions`) and the spend observation
//!   (`SyncNullifiers`) carry no inclusion proof; they are labelled to Circle as node-trusted,
//!   which is the substance of the open burn-evidence question.
//! * **No `burnTxId`-only path, structurally.** `GetTransactionById` does not exist on Miden,
//!   so [`evidence::BurnEvidenceReads`] has no by-hash method and the assembler's only entry key is
//!   a `NoteId` (never a transaction id). The optional upstream by-hash lookup stays OPEN.
//! * **A package cannot be manufactured.** [`types::EvidencePackage`]'s constructor is `pub(crate)`
//!   and [`evidence::assemble_evidence`] is its only caller, so holding one outside this crate is
//!   proof the checks ran rather than proof someone typed four plausible values. Every fail-closed
//!   rule below lives in the assembler; a public constructor would be a door around all of them.
//! * **Fail-closed.** Missing, ambiguous, or self-contradicting evidence yields
//!   [`evidence::EvidenceError::ReconciliationRequired`] — the same vocabulary the idempotency
//!   store uses for an ambiguous claim, deliberately reused — and
//!   never a package. Only Circle's terminal `finalized` settles a withdrawal.
//! * **No invented transport.** `note_id`/`nullifier`/`block_num` go nowhere on the wire:
//!   `burnTxId` is the only evidence field `POST /v1/withdraw` documents, and whether Circle would
//!   accept more is Circle's to answer, not this crate's to assume.
//!
//! The reads behind [`evidence::BurnEvidenceReads`] are a crate-local port with a unit adapter —
//! the real node-backed leg is parked, so these tests are NON-GATING. The optional full-block
//! upgrade ([`evidence::full_block_upgrade`]) returns a typed deferral error rather than a
//! panicking placeholder.
//!
//! # Idempotency — the money path's error handling
//!
//! [`submit::submit_withdraw`], the production `POST /v1/withdraw` entry point, and the two
//! policies and one ledger it runs on:
//!
//! * **The `409` conflict-recovery contract.** A `409` ("burnTxId already tied to an active
//!   withdrawal") is a **duplicate conflict requiring recovery/reconciliation, NOT success**, and
//!   is NEVER answered by re-sending. With `conflict.withdrawalId` → recover by POLLING `GET
//!   /v1/withdrawal/{withdrawalId}`; with only `conflict.burnTxId` → stop and mark reconciliation
//!   required; echoing a DIFFERENT `burnTxId` → a defect. [`submit::SubmitOutcome`] is closed and
//!   has no path from a `409` to its success variant, so the rule is structural rather than
//!   remembered.
//! * **Per-burn cross-invocation idempotency** ([`idempotency::SubmitLedger`]) — a durable SQLite
//!   claim, keyed on the `burnTxId`, mirroring the deposit relayer's seam. It is what makes "the
//!   same burn, re-discovered or re-submitted after a restart, is submitted at most once" true of
//!   the process rather than of one call. Unlike the relayer's, it is a SAFETY property, not a
//!   liveness backstop: there is no on-chain assert behind it.
//! * **Bounded retry + the documented rate ceilings** ([`circle::retry`], [`circle::rate`]) — a
//!   `5xx` retried within a bound and then SURFACED; a deterministic `400` attempted exactly once;
//!   a **status-less transport failure attempted exactly once too** (a timeout carries no evidence
//!   that Circle did not act, so re-POSTing a withdrawal on one is a blind resubmission — Circle's
//!   documentation names `5xx` and only `5xx` as retryable); 5 QPS/IP and 35 QPS global, a permit
//!   taken before every attempt. No `Retry-After`/`429` is documented, so none is invented.
//!
//! Everything ambiguous — an exhausted budget, an unreadable `201`, a conflict naming no withdrawal
//! fails CLOSED: the burn is blocked for an operator rather than retried into a possible second
//! release. Only a terminal `finalized` settles a burn as done.
//!
//! # The Circle HTTP drivers
//!
//! The three drivers in [`withdrawal_api`], on the [`circle::client::CircleClient`]:
//! [`withdrawal_api::prepare`] (`POST /v1/prepare-withdrawal`), the `POST /v1/withdraw` submission
//! (the **array** response, one status per batch — submitting goes through
//! [`submit::submit_withdraw`], which additionally takes the durable idempotency claim, so there is
//! no path that can POST without one), and [`withdrawal_api::poll_status`] (`GET
//! /v1/withdrawal/{id}`, poll-to-terminal; a validated [`circle::wire::Uuid`] id, and the response
//! bound to it). Plus the fund-safety pre-submit signer-allowlist gate
//! ([`withdrawal_api::authorize_submission`] → [`withdrawal_api::AuthorizedWithdrawal`]), which
//! requires every recovered `burnSignatures` signer to be a configured registered attester before
//! any submission, and the production response-size ceiling enforced while streaming
//! ([`circle::transport::collect_bounded`]).
//!
//! # The request builders
//!
//! Pure, no I/O, [`withdrawal_api`]: [`withdrawal_api::build_prepare_request`] (the
//! `PrepareWithdrawalRequest` the partner authors — `remoteDepositor` from the burn note's
//! `metadata.sender` through the shared encoding crate's `AccountId↔bytes32` codec,
//! `sourceDepositor` structurally absent) and [`withdrawal_api::build_withdraw_request`] (the `POST
//! /v1/withdraw` `{ batches: [..] }` wrapper, `1..=5`). Both build ONLY the API JSON — never the
//! binary `TransferSpec`/`BurnIntent`, which Circle encodes server-side. The Circle HTTP drivers
//! that carry these (`prepare` / `withdraw` / status poll) are described above.
//!
//! # The validation gate
//!
//! Pure, no I/O: [`validate`] holds the discovery checklist ([`validate::validate_discovery`]) and
//! the field-by-field gate ([`validate::validate_returned`]), which compares Circle's returned
//! `burnIntents[].spec` against the burn payload for EVERY batch and, on a full match, mints the
//! [`validate::ValidatedWithdrawal`] token. The signer, [`validate::sign_validated`], consumes that
//! token — so a mismatch cannot reach signing, and "sign a response that failed validation" is
//! untypeable rather than merely unreached.
//!
//! # The signing core
//!
//! Pure, no I/O, [`attester`]: [`attester::sign`] (a single `k256` ECDSA over Circle's opaque
//! `messageHashToSign`, emitting the Ethereum-shaped `r‖s‖v` with `v = 27`/`28` the source-chain
//! `ECDSA.recover` requires — the digest's exact derivation stays OPEN with Circle) and
//! [`attester::assemble_quorum`] (the exactly-threshold,
//! every-signature-verifies-to-its-claimed-signer, ascending-address, no-duplicate `burnSignatures`
//! bundle). `k256` (and `sha3`, for signer address recovery) are LIBRARY dependencies here, unlike
//! in the deposit relayer where they are dev-only: the relayer never verifies a signature
//! off-chain, whereas this service's off-chain signature IS the product. A single signature is a
//! non-gating local primitive that is NEVER submitted to Circle on its own; the real keys the
//! interface will drive (KMS/HSM, ≥2 attesters) are human/ops-owned and no real key material lives
//! here.
//!
//! # The invariants this slice's types carry
//!
//! * **`remoteDepositor` is never `sourceDepositor`** — [`circle::schema::PrepareBurnIntentInput`]
//!   has no `sourceDepositor` field, and the returned [`circle::schema::TransferSpec`] does. The
//!   partner sends the Miden burner as `remoteDepositor`; Circle assigns `sourceDepositor`
//!   server-side.
//! * **Decoded is not validated** — the wire types decode what Circle *said*; nothing here
//!   validates or authorizes.
//! * **The burn note is Public with one fixed tag** (an exact match, never a prefix) —
//!   [`config::ListenerConfig::burn_tag`] is one FULL 32-bit tag, matched by exact equality;
//!   `SyncNotes` does not prefix-scan.
//! * **A tag is not a burn, and a payload is not an amount** — B3 additionally pins the note's
//!   script root to the shared encoding crate's `XReserveBurnNote::script_root()` (the tag is a
//!   routing hint anyone can write) and requires the note's VAULT to hold exactly the xUSDC its
//!   withdrawal payload claims (the chain burns the vault; Circle releases the payload). Both
//!   refuse BEFORE any Circle call.
//! * **Single-owner codecs** — [`types::BurnPayload`] IS the shared encoding crate's
//!   `XReserveBurnItems`, and the `AccountId↔bytes32` encoding behind `remoteDepositor` is the
//!   shared encoding crate's codec. Both consumed by reference; neither re-implemented.
//!
//! # Circle-owned questions this slice touches — all still OPEN
//!
//! the credential scheme (no auth scheme is documented; the client parameterizes an out-of-band key
//! and
//! invents no header — [`circle::auth`]), Miden's domain id and the forwarding scope, the
//! `sourceDepositor` Circle assigns, the `messageHashToSign` derivation (treated as
//! opaque-and-sign), and whether a Miden tx id is an acceptable `burnTxId`. None of them is
//! answered here; each is parameterized and left open.

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
