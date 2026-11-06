use anyhow::{ensure, Context, Result};
use reqwest::{Client, Url};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Clone)]
pub(crate) struct Rpc {
    client: Client,
    url: Url,
}
impl Rpc {
    pub fn new(url: Url) -> Result<Self> {
        Ok(Self {
            client: client()?,
            url,
        })
    }
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let response = self
            .client
            .post(self.url.clone())
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .context("upstream unavailable")?;
        ensure!(response.status().is_success(), "RPC HTTP failure");
        let bytes = bounded(response, 16 * 1024 * 1024).await?;
        let value: Value = serde_json::from_slice(&bytes).context("invalid RPC JSON")?;
        ensure!(
            value.get("error").is_none_or(Value::is_null),
            "RPC method failed"
        );
        ensure!(
            value.get("id") == Some(&json!(1)),
            "RPC response id mismatch"
        );
        value.get("result").cloned().context("missing RPC result")
    }
}
pub(crate) fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building bounded HTTP client")
}
pub(crate) async fn bounded(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    ensure!(
        response.content_length().is_none_or(|n| n <= max as u64),
        "upstream body exceeds limit"
    );
    let mut out = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("reading bounded upstream body")?
    {
        ensure!(
            out.len().checked_add(chunk.len()).is_some_and(|n| n <= max),
            "upstream body exceeds limit"
        );
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
pub(crate) fn hex_u64(value: &Value) -> Result<u64> {
    let s = value.as_str().context("missing RPC integer")?;
    ensure!(s.starts_with("0x") && s.len() <= 18, "invalid RPC integer");
    u64::from_str_radix(&s[2..], 16).context("RPC integer overflow")
}
pub(crate) fn hex_u128(value: &Value) -> Result<u128> {
    let s = value.as_str().context("missing RPC integer")?;
    ensure!(s.starts_with("0x") && s.len() <= 34, "invalid RPC integer");
    u128::from_str_radix(&s[2..], 16).context("RPC integer overflow")
}
pub(crate) fn height(n: u64) -> String {
    format!("0x{n:x}")
}
