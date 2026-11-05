use crate::{
    config::{Config, Source},
    message::{select, unhex, Message},
    rpc::{bounded, client},
};
use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct Iris {
    client: reqwest::Client,
    base: url::Url,
}
pub(crate) enum Reply {
    Pending,
    Limited(u64),
    Messages(Vec<Message>),
}
impl Iris {
    pub fn new(base: url::Url) -> Result<Self> {
        Ok(Self {
            client: client()?,
            base,
        })
    }
    pub async fn get(&self, config: &Config, source: &Source, transaction: &str) -> Result<Reply> {
        let mut url = self.base.join(&format!("v2/messages/{}", source.domain))?;
        url.query_pairs_mut()
            .append_pair("transactionHash", transaction);
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("upstream unavailable")?;
        if response.status() == 429 {
            let delay = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| {
                    v.parse::<u64>().ok().or_else(|| {
                        httpdate::parse_http_date(v).ok().map(|at| {
                            at.duration_since(SystemTime::now())
                                .unwrap_or_default()
                                .as_secs()
                        })
                    })
                })
                .unwrap_or(60)
                .clamp(1, 3600);
            return Ok(Reply::Limited(delay));
        }
        if response.status() == 404 {
            return Ok(Reply::Pending);
        }
        ensure!(response.status().is_success(), "upstream unavailable");
        Ok(Reply::Messages(decode(
            &bounded(response, 2 * 1024 * 1024).await?,
            config,
            source,
            transaction,
        )?))
    }
}
pub(crate) fn decode(
    raw: &[u8],
    config: &Config,
    source: &Source,
    transaction: &str,
) -> Result<Vec<Message>> {
    let value: Value = serde_json::from_slice(raw)?;
    // The checked Circle envelope supplies transaction association. Source events
    // supply the relevant occurrence count, not an independent event-to-nonce proof.
    ensure!(
        source.transaction(
            value["sourceTxHash"]
                .as_str()
                .context("missing Circle transaction envelope")?
        )? == source.transaction(transaction)?,
        "Circle transaction envelope mismatch"
    );
    let records = value["messages"]
        .as_array()
        .context("missing Circle messages")?;
    ensure!(records.len() <= 1000, "too many Circle messages");
    // Validate the whole reply before admitting any record; a bad tail cannot
    // leave a partially accepted prefix in the journal.
    let mut out = vec![];
    for record in records {
        match record["status"].as_str().context("missing Circle status")? {
            "pending" | "pending_confirmations" => continue,
            "complete" => {}
            _ => anyhow::bail!("unsupported Circle status"),
        }
        ensure!(record["cctpVersion"] == 2, "unsupported Circle version");
        let bytes = unhex(
            record["message"]
                .as_str()
                .context("missing Circle message")?,
            65536,
        )?;
        let attestation = unhex(
            record["attestation"]
                .as_str()
                .context("missing Circle attestation")?,
            65536,
        )?;
        ensure!(
            !attestation.is_empty() && attestation.len().is_multiple_of(65),
            "invalid Circle attestation length"
        );
        if let Some(nonce) = select(&bytes, config, source, true)? {
            out.push(Message {
                nonce,
                domain: source.domain,
                transaction: transaction.to_owned(),
                bytes,
                attestation,
            });
        }
    }
    Ok(out)
}
pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
