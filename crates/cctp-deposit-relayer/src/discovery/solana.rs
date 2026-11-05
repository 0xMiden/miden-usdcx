use super::Page;
use crate::{
    config::{base58, Config, Network, Source},
    message::{
        padded, Candidate, Position, APPLICATION_HOOK_LENGTH, APPLICATION_HOOK_VERSION,
        STANDARD_FINALITY,
    },
    rpc::Rpc,
};
use alloy_primitives::keccak256;
use anyhow::{ensure, Context, Result};
use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use std::{collections::BTreeSet, time::Duration};

const SCAN_BUDGET: Duration = Duration::from_secs(5);
const ANCHOR_EVENT_CPI_TAG: [u8; 8] = [0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d];
const ANCHOR_TAG_BYTES: usize = 8;
const EVENT_HEADER_BYTES: usize = 2 * ANCHOR_TAG_BYTES;
// Borsh uses 32-byte pubkeys, little-endian u64/u32 fields and a u32 Vec length.
const BURN_HEADER_BYTES: usize = 188;
const HOOK_LENGTH_OFFSET: usize = BURN_HEADER_BYTES - 4;
const MAX_EVENT_BYTES: usize = 65536;
const INNER_ORDINAL_BITS: u32 = 32;

#[derive(Deserialize, Serialize)]
struct Cursor {
    head: Option<String>,
    pass: Option<Pass>,
}
#[derive(Deserialize, Serialize)]
struct Pass {
    // The previous completed head, or the configured inclusive initial boundary.
    old_head: String,
    // Freeze the newest signature until every entry back to old_head is examined.
    pass_top: String,
    // Only fully examined signatures may become the next exclusive RPC cursor.
    resume_before: String,
}
#[derive(BorshDeserialize)]
struct Burn {
    burn_token: [u8; 32],
    _amount: u64,
    _depositor: [u8; 32],
    mint_recipient: [u8; 32],
    destination_domain: u32,
    destination_token_messenger: [u8; 32],
    destination_caller: [u8; 32],
    _max_fee: u64,
    min_finality_threshold: u32,
    hook_data: Vec<u8>,
}
pub(crate) async fn scan(
    config: &Config,
    source: &Source,
    rpc: &Rpc,
    cursor: &Value,
) -> Result<Option<Page>> {
    let started = tokio::time::Instant::now();
    let Network::Solana {
        messenger,
        start_signature,
        start_slot,
        ..
    } = &source.network
    else {
        anyhow::bail!("wrong runtime adapter")
    };
    let Network::Solana { genesis_hash, .. } = &source.network else {
        unreachable!()
    };
    ensure!(
        rpc.call("getGenesisHash", json!([])).await?.as_str() == Some(genesis_hash),
        "source genesis changed"
    );
    let cursor = if cursor.is_null() {
        Cursor {
            head: None,
            pass: None,
        }
    } else {
        serde_json::from_value::<Cursor>(cursor.clone()).context("invalid Solana checkpoint")?
    };
    if cursor.head.is_none() && cursor.pass.is_none() {
        let first = rpc
            .call("getFirstAvailableBlock", json!([]))
            .await?
            .as_u64()
            .context("history coverage unavailable")?;
        ensure!(first <= *start_slot, "source start history pruned");
    }
    let before = cursor.pass.as_ref().map(|p| p.resume_before.clone());
    let mut options = json!({"commitment":"finalized","limit":25});
    if let Some(before) = before {
        options["before"] = json!(before);
    }
    let page = rpc
        .call("getSignaturesForAddress", json!([messenger, options]))
        .await?;
    let page = page.as_array().context("invalid Solana signature page")?;
    ensure!(
        !page.is_empty() && page.len() <= 25,
        "Solana boundary unavailable"
    );
    let top = page[0]["signature"]
        .as_str()
        .context("signature missing")?
        .to_owned();
    base58::<64>(&top)?;
    let old = cursor
        .pass
        .as_ref()
        .map(|p| p.old_head.clone())
        .or(cursor.head.clone())
        .unwrap_or_else(|| start_signature.clone());
    let frozen = cursor
        .pass
        .as_ref()
        .map(|p| p.pass_top.clone())
        .unwrap_or(top);
    // Initial history includes the configured start signature. Later passes exclude
    // the prior completed head, which was already committed in the previous pass.
    let first_pass = cursor.head.is_none();
    let mut seen = BTreeSet::new();
    let mut transactions = Vec::new();
    let mut found = false;
    let mut last = None;
    for entry in page {
        let signature = entry["signature"].as_str().context("signature missing")?;
        base58::<64>(signature)?;
        ensure!(seen.insert(signature), "duplicate signature within page");
        let slot = entry["slot"].as_u64().context("signature slot missing")?;
        ensure!(
            entry["confirmationStatus"] == "finalized",
            "source signature unconfirmed"
        );
        if signature == old {
            found = true;
            if !first_pass {
                break;
            }
        }
        ensure!(
            slot >= *start_slot,
            "old Solana boundary missing before start slot"
        );
        if entry
            .get("err")
            .context("signature error metadata missing")?
            .is_null()
        {
            let transaction = rpc.call(
                "getTransaction",
                json!([signature, {"commitment":"finalized", "encoding":"jsonParsed", "maxSupportedTransactionVersion":1}]),
            ).await?;
            ensure!(
                transaction["slot"] == json!(slot),
                "signature and transaction slots differ"
            );
            let candidate = decode(config, source, signature, &transaction)?;
            if !candidate.positions.is_empty() {
                transactions.push(candidate);
            }
        }
        last = Some(signature.to_owned());
        // Advance only after the complete transaction has been examined. An in-flight
        // RPC keeps its ten-second transport bound; run() can also cancel on shutdown.
        if found || started.elapsed() >= SCAN_BUDGET {
            break;
        }
    }
    let next = if found {
        Cursor {
            head: Some(frozen),
            pass: None,
        }
    } else {
        Cursor {
            head: cursor.head,
            pass: Some(Pass {
                old_head: old,
                pass_top: frozen,
                resume_before: last.context("Solana page made no progress")?,
            }),
        }
    };
    Ok(Some(Page {
        cursor: serde_json::to_value(next)?,
        transactions,
    }))
}
pub(crate) fn decode(
    config: &Config,
    source: &Source,
    signature: &str,
    value: &Value,
) -> Result<Candidate> {
    let Network::Solana {
        messenger,
        usdc,
        start_slot,
        ..
    } = &source.network
    else {
        anyhow::bail!("wrong Solana reader")
    };
    base58::<64>(signature)?;
    let slot = value["slot"]
        .as_u64()
        .context("source transaction unavailable")?;
    ensure!(slot >= *start_slot, "transaction precedes source boundary");
    ensure!(
        value["transaction"]["signatures"]
            .as_array()
            .context("missing signatures")?
            .first()
            .and_then(Value::as_str)
            == Some(signature),
        "source signature mismatch"
    );
    ensure!(
        value["version"] == "legacy" || value["version"] == 0 || value["version"] == 1,
        "unsupported Solana version"
    );
    let meta = value["meta"]
        .as_object()
        .context("source metadata unavailable")?;
    ensure!(
        meta.get("err")
            .context("missing transaction status")?
            .is_null(),
        "failed source transaction"
    );
    let outer = value["transaction"]["message"]["instructions"]
        .as_array()
        .context("missing outer instructions")?;
    let parents = meta
        .get("innerInstructions")
        .and_then(Value::as_array)
        .context("missing inner instructions")?;
    ensure!(
        outer.len() <= 10000 && parents.len() <= outer.len(),
        "too many instruction groups"
    );
    let program = messenger.parse::<Pubkey>()?;
    let (authority, _) = Pubkey::try_find_program_address(&[b"__event_authority"], &program)
        .context("event PDA unavailable")?;
    let authority = authority.to_string();
    let discriminator = Sha256::digest(b"event:DepositForBurn");
    let mut candidate = Candidate {
        transaction: signature.to_owned(),
        positions: vec![],
        manual: false,
    };
    let mut seen = BTreeSet::new();
    for parent in parents {
        let index = parent["index"].as_u64().context("missing inner parent")?;
        ensure!(
            index < outer.len() as u64 && seen.insert(index),
            "invalid inner parent"
        );
        let instructions = parent["instructions"]
            .as_array()
            .context("missing inner instructions")?;
        ensure!(instructions.len() <= 10000, "too many inner instructions");
        for (ordinal, ix) in instructions.iter().enumerate() {
            let emitter = ix["programId"]
                .as_str()
                .context("missing parsed program id")?;
            base58::<32>(emitter)?;
            if emitter != messenger {
                continue;
            }
            let accounts = ix["accounts"]
                .as_array()
                .context("missing custom instruction accounts")?;
            if accounts.len() != 1 || accounts[0].as_str() != Some(&authority) {
                continue;
            }
            let encoded = ix["data"].as_str().context("missing event data")?;
            ensure!(encoded.len() <= 90000, "event data exceeds bound");
            let bytes = bs58::decode(encoded).into_vec()?;
            ensure!(
                bytes.len() >= EVENT_HEADER_BYTES
                    && bytes.len() <= MAX_EVENT_BYTES
                    && bytes[..ANCHOR_TAG_BYTES] == ANCHOR_EVENT_CPI_TAG,
                "invalid Anchor event tag"
            );
            if bytes[ANCHOR_TAG_BYTES..EVENT_HEADER_BYTES] != discriminator[..ANCHOR_TAG_BYTES] {
                continue;
            }
            let body = &bytes[EVENT_HEADER_BYTES..];
            ensure!(body.len() >= BURN_HEADER_BYTES, "truncated burn event");
            let length = u32::from_le_bytes(body[HOOK_LENGTH_OFFSET..BURN_HEADER_BYTES].try_into()?)
                as usize;
            ensure!(
                length <= MAX_EVENT_BYTES - BURN_HEADER_BYTES
                    && body.len() == BURN_HEADER_BYTES + length,
                "invalid Borsh hook length"
            );
            let burn = Burn::try_from_slice(body).context("invalid burn Borsh")?;
            let helper = padded(config.helper).0;
            let hook_version =
                alloy_primitives::U256::from(APPLICATION_HOOK_VERSION).to_be_bytes::<32>();
            if burn.burn_token != base58::<32>(usdc)?
                || burn.destination_domain != config.arc_domain
                || burn.mint_recipient != helper
                || burn.destination_caller != helper
            {
                continue;
            }
            candidate.manual |= burn.destination_token_messenger != padded(config.messenger).0
                || burn.min_finality_threshold != STANDARD_FINALITY
                || burn.hook_data.len() != APPLICATION_HOOK_LENGTH
                || burn.hook_data.get(..32) != Some(&hook_version[..]);
            // Preserve the outer instruction index and the full inner ordinal,
            // including unrelated inner instructions, as one stable occurrence ID.
            candidate.positions.push(Position {
                ordinal: (index << INNER_ORDINAL_BITS) | ordinal as u64,
                digest: keccak256(&bytes),
            });
        }
    }
    Ok(candidate)
}
