//! The Circle-facing half: the constrained wire scalars, the schema built on them, the auth posture,
//! and the transport seam.
//!
//! The drivers themselves — `POST /v1/prepare-withdrawal` (`CMP-D5`), `POST /v1/withdraw`
//! (`CMP-D6`), `GET /v1/withdrawal/{id}` (`CMP-D7`) — land with W6, built on [`transport`]. This
//! slice contacts no Circle endpoint: every live Circle leg is `REQUIRES CIRCLE CONFIRMATION`, and
//! the surfaces are exercised against the schema-exact mock fixtures (§12 mock policy — "Circle API
//! may be mocked; Miden behavior must not be faked for final acceptance").

pub mod auth;
pub mod client;
pub mod schema;
pub mod transport;
pub mod wire;

pub use client::{CircleClient, PollPolicy};
pub use transport::{HttpTransport, RawResponse, ReqwestTransport};
