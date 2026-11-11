use super::Page;
use crate::{
    abi::Transmitter,
    config::{Config, Network, Source},
    message::{select, unhex, Candidate, Position},
    rpc::{height, hex_u64, Rpc},
};
use alloy_primitives::{keccak256, Address, B256};
use alloy_sol_types::SolEvent;
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) async fn block(rpc: &Rpc, tag: &str) -> Result<Value> {
    let value = rpc
        .call("eth_getBlockByNumber", json!([tag, false]))
        .await?;
    value["hash"]
        .as_str()
        .context("block hash unavailable")?
        .parse::<B256>()?;
    hex_u64(&value["number"])?;
    Ok(value)
}
pub(crate) async fn scan(
    config: &Config,
    source: &Source,
    rpc: &Rpc,
    cursor: &Value,
) -> Result<Option<Page>> {
    let Network::Evm {
        chain_id,
        transmitter,
        start_block,
        start_hash,
        ..
    } = source.network
    else {
        anyhow::bail!("wrong EVM reader")
    };
    ensure!(
        hex_u64(&rpc.call("eth_chainId", json!([])).await?)? == chain_id,
        "source chain changed"
    );
    let finalized = hex_u64(&block(rpc, "finalized").await?["number"])?;
    let next = if cursor.is_null() {
        let b = block(rpc, &height(start_block)).await?;
        ensure!(
            b["hash"]
                .as_str()
                .context("start hash missing")?
                .parse::<B256>()?
                == start_hash,
            "source start hash changed"
        );
        start_block
    } else {
        let end = cursor["end"].as_u64().context("invalid EVM cursor")?;
        ensure!(
            block(rpc, &height(end)).await?["hash"] == cursor["hash"],
            "finalized source anchor changed"
        );
        end.checked_add(1).context("source cursor overflow")?
    };
    if next > finalized {
        return Ok(None);
    }
    let mut end = next.saturating_add(255).min(finalized);
    let logs = loop {
        match rpc.call("eth_getLogs",json!([{"address":transmitter,"fromBlock":height(next),"toBlock":height(end),"topics":[Transmitter::MessageSent::SIGNATURE_HASH]}])).await {
            Ok(value) => break value,
            Err(_) if end > next => end = next + (end-next)/2,
            Err(error) => return Err(error),
        }
    };
    let page = block(rpc, &height(end)).await?;
    Ok(Some(Page {
        cursor: json!({"end":end,"hash":page["hash"]}),
        transactions: decode(config, source, &logs, next, end)?,
    }))
}
pub(crate) fn decode(
    config: &Config,
    source: &Source,
    logs: &Value,
    start: u64,
    end: u64,
) -> Result<Vec<Candidate>> {
    let Network::Evm { transmitter, .. } = source.network else {
        anyhow::bail!("wrong EVM reader")
    };
    let logs = logs.as_array().context("invalid EVM log page")?;
    ensure!(logs.len() <= 1000, "EVM log page too large");
    let mut transactions = BTreeMap::<String, Candidate>::new();
    let mut seen = BTreeMap::new();
    for log in logs {
        ensure!(
            log["removed"].as_bool() == Some(false),
            "removed or incomplete finalized log"
        );
        ensure!(
            log["address"]
                .as_str()
                .context("log address missing")?
                .parse::<Address>()?
                == transmitter,
            "wrong log emitter"
        );
        let block = hex_u64(&log["blockNumber"])?;
        ensure!(block >= start && block <= end, "log outside requested page");
        let hash = log["blockHash"]
            .as_str()
            .context("log block missing")?
            .parse::<B256>()?;
        let transaction = source.transaction(
            log["transactionHash"]
                .as_str()
                .context("log transaction missing")?,
        )?;
        let ordinal = hex_u64(&log["logIndex"])?;
        let topics = log["topics"]
            .as_array()
            .context("log topics missing")?
            .iter()
            .map(|v| {
                v.as_str()
                    .context("invalid log topic")?
                    .parse::<B256>()
                    .map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            topics == [Transmitter::MessageSent::SIGNATURE_HASH],
            "wrong log event"
        );
        let data = unhex(log["data"].as_str().context("log data missing")?, 65536)?;
        let digest = keccak256(&data);
        if let Some(prior) = seen.insert((hash, ordinal), (transaction.clone(), digest)) {
            ensure!(
                prior == (transaction.clone(), digest),
                "conflicting log position"
            );
            continue;
        }
        let message = Transmitter::MessageSent::decode_raw_log(topics, &data)?.message;
        let selected = select(&message, config, source, false);
        if matches!(selected, Ok(None)) {
            continue;
        }
        let candidate = transactions
            .entry(transaction.clone())
            .or_insert(Candidate {
                transaction,
                positions: vec![],
                manual: false,
            });
        candidate.manual |= selected.is_err();
        candidate.positions.push(Position { ordinal, digest });
    }
    Ok(transactions.into_values().collect())
}
