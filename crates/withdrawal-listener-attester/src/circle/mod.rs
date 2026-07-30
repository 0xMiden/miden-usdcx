//! The Circle-facing half: the constrained wire scalars, the schema built on them, the auth
//! posture, the transport seam, and the two policies every request runs under — the documented
//! [`rate`] ceilings and the bounded [`retry`] backoff.
//!
//! The drivers themselves — `POST /v1/prepare-withdrawal`, `POST /v1/withdraw`, `GET
//! /v1/withdrawal/{id}` — live in [`withdrawal_api`](crate::withdrawal_api), built on
//! [`transport`]; the submission path that carries the `409` conflict-recovery is
//! [`submit`](crate::submit). No Circle endpoint is ever contacted live: every Circle leg is
//! `REQUIRES CIRCLE CONFIRMATION`, and the surfaces are exercised against the schema-exact
//! in-process mock (the mock policy: "Circle API may be mocked; Miden behavior must not be faked
//! for final acceptance").

pub mod auth;
pub mod client;
pub mod rate;
pub mod retry;
pub mod schema;
pub mod transport;
pub mod wire;

pub use client::{CircleClient, PollPolicy};
pub use rate::RateGovernor;
pub use retry::RetryPolicy;
pub use transport::{HttpTransport, RawResponse, ReqwestTransport};
