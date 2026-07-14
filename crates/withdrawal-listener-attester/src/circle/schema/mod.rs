//! The Circle withdrawal wire schema — serde types matching the OpenAPI EXACTLY
//! (`CIRCLE-API-SURFACE.md` § "OpenAPI JSON schemas"; `CIRCLE-DATA-SCHEMAS.md` §10).
//!
//! Split by direction of travel, one family per module (G3):
//!
//! * [`prepare`] — what the partner **sends** to `POST /v1/prepare-withdrawal`.
//! * [`intents`] — what Circle **returns** from it: the burn intents, their `TransferSpec`s, the
//!   `encoded` blob and the digest to sign.
//! * [`withdraw`] — the `POST /v1/withdraw` submission and the withdrawal status it (and `GET
//!   /v1/withdrawal/{id}`) return.
//!
//! Everything is re-exported here, so `circle::schema::WithdrawBatch` still resolves; the split is
//! about where a reader looks, not about renaming the wire.
//!
//! # The three shape decisions that are load-bearing
//!
//! This service releases real USDC, and none of these is a matter of taste:
//!
//! * **The top-level `batches[]` wrapper is real.** [`PrepareWithdrawalRequest`],
//!   [`PrepareWithdrawalResponse`] and [`WithdrawRequest`] are each `{ batches: [...] }` — never a
//!   bare batch. Flattening one is the classic simplification, and it produces a body Circle rejects.
//! * **`POST /v1/withdraw` returns an ARRAY**, one [`WithdrawalStatus`] per submitted batch — hence
//!   [`WithdrawSubmissionResponse`] is a `Vec` alias, not a wrapper struct. `GET
//!   /v1/withdrawal/{id}` returns the same object, singly.
//! * **`sourceDepositor` is ABSENT from [`PrepareBurnIntentInput`]** and PRESENT on the returned
//!   [`TransferSpec`]. The partner sends `remoteDepositor` (the Miden burner, from the burn note's
//!   `metadata.sender`); Circle fills `sourceDepositor` server-side (`Q-DOM-3`). Swapping them would
//!   name the wrong debtor (`INV-REMOTEDEPOSITOR-VS-SOURCEDEPOSITOR`, §10.8).
//!
//! # The schema is enforced, not merely described
//!
//! Every constrained field is a validating newtype from [`super::wire`], and every cross-field rule
//! the OpenAPI states — the value XOR, `remoteDomain >= 1` and `!= finalDestinationDomain`, batches
//! `1..=5`, burn intents `1..=10`, signatures `>= 2` — is checked in ONE place per type and reached
//! from BOTH construction paths: the builder calls it, and `#[serde(try_from = …)]` routes
//! deserialization through it. A body that violates the schema cannot become one of these types,
//! inbound or outbound. (§10.11: "malformed Circle response → reject, not signed.")
//!
//! Three kinds of leniency are refused specifically, because serde offers all three by default:
//!
//! * **Required means required.** No `#[serde(default)]` on a required field — a body that omits
//!   `token` is refused, not completed for.
//! * **Absent ≠ present-and-null.** Optional properties are non-nullable when present, so they
//!   deserialize through [`super::wire::present_non_null`]: omitting `salt` means "no salt"; sending
//!   `"salt": null` is refused rather than silently read as absence.
//! * **Unknown fields, on the REQUEST side only.** The request types `deny_unknown_fields` — this
//!   crate authors them, so an unknown key is a caller's mistake, and serde's default (dropping it)
//!   would ship a request missing the field the caller thought they set. The RESPONSE types do not:
//!   Circle may add a field, and refusing to decode a withdrawal because it grew one would strand
//!   real money.
//!
//! What is NOT constrained is what the OpenAPI does not document: `encoded`, `messageHashToSign`, and
//! the request-side `burnTxId` are typed `string` with no pattern, so they stay `String`. Inventing a
//! regex is the same defect as inventing a field.
//!
//! **Decoded ≠ validated.** These types carry what Circle *said*, in a well-formed shape. The
//! field-by-field compare against the burn-note payload — `amount`, `destinationDomain`,
//! `destinationRecipient` — is the B5 gate (`INV-CIRCLE-CANONICAL-WITHDRAWAL`, §10.4) and lands with
//! `validate.rs`; nothing here authorizes a signature. A schema-valid response can still be a lie.

pub mod intents;
pub mod prepare;
pub mod withdraw;

pub use intents::{
    BurnIntent, PrepareWithdrawalResponse, PreparedBatch, StructuredHookData, TransferSpec,
};
pub use prepare::{ForwardingOptions, PrepareBurnIntentInput, PrepareWithdrawalRequest};
pub use withdraw::{
    WithdrawBatch, WithdrawRequest, WithdrawSubmissionResponse, WithdrawalStatus,
    WithdrawalStatusKind,
};
