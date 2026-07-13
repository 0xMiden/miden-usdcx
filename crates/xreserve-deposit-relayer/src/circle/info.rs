//! `GET /v1/info` (`CMP-D1`) — Circle's discovery endpoint: the source domains, the remote domains,
//! and the token identifiers Circle advertises for each.
//!
//! **The no-`domain`-param shape is the default, and that is a recorded decision.** The NDA wrote
//! `/v1/info?domain={domain}`; the public API and the OpenAPI expose `/v1/info` with NO query
//! parameter. Per source-of-truth policy the conflict is RECORDED, not silently resolved — it is
//! `Q-INFO-PARAM`, `REQUIRES CIRCLE CONFIRMATION`. The relayer implements the more recent, public
//! shape and sends no `domain` param; if Circle confirms the NDA form, this is the one place that
//! changes.
//!
//! What the relayer does with it: discovers the Miden domain id (`Q-DOM-1`, OPEN) and the xUSDC
//! token identifier (`DEV-10`, OPEN) instead of hardcoding values Circle has not assigned. Both feed
//! only the OPTIONAL liveness fast-fail (§8.1 check 5) — the authoritative `remoteDomain`/
//! `remoteToken` compare is on-chain at D5a.

use crate::circle::attestation_fetch::decode;
use crate::circle::client::CircleClient;
use crate::circle::schema::InfoResponse;
use crate::error::RelayerError;

const ENDPOINT_INFO: &str = "GET /v1/info";

/// Fetches `GET /v1/info` — the PUBLIC shape: **no `domain` query parameter** (`Q-INFO-PARAM`).
///
/// # Errors
/// * [`RelayerError::Http`] — a non-2xx that survived the retry policy (the endpoint documents 200
///   and 500; a 500 is transient and is retried under the rate ceilings).
/// * [`RelayerError::Transport`] — the request never produced a status.
/// * [`RelayerError::Decode`] — the body is not the documented shape.
pub async fn fetch_info(client: &CircleClient) -> Result<InfoResponse, RelayerError> {
    let response = client.get(ENDPOINT_INFO, "/v1/info", &[]).await?;

    decode(client, ENDPOINT_INFO, &response.body)
}
