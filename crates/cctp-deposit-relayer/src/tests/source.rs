use super::*;
use alloy_sol_types::SolEvent;
pub(super) fn log(c: &Config, m: &Message, index: u64) -> Value {
    let e = abi::Transmitter::MessageSent {
        message: m.bytes.clone().into(),
    }
    .encode_log_data();
    let Network::Evm { transmitter, .. } = c.sources[0].network else {
        unreachable!()
    };
    json!({"address":transmitter,"topics":e.topics(),"data":format!("0x{}",hex::encode(e.data)),"removed":false,"transactionHash":m.transaction,"blockHash":block_hash(11),"blockNumber":"0xb","logIndex":rpc::height(index)})
}
#[test]
fn evm_message_sent_only_multiple_identical_burn_positions_and_spoof_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir, &TestSigner::new());
    let m = message(&c, 0, &B256::repeat_byte(1).to_string());
    let first = log(&c, &m, 3);
    let second = log(&c, &m, 7);
    let logs = json!([first.clone(), second, first.clone()]);
    let decoded = discovery::evm::decode(&c, &c.sources[0], &logs, 10, 20).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(
        decoded[0]
            .positions
            .iter()
            .map(|p| p.ordinal)
            .collect::<Vec<_>>(),
        vec![3, 7]
    );
    let mut removed = first.clone();
    removed["removed"] = json!(true);
    assert!(discovery::evm::decode(&c, &c.sources[0], &json!([removed]), 10, 20).is_err());
    let mut spoof = first;
    spoof["address"] = json!(Address::repeat_byte(7));
    assert!(discovery::evm::decode(&c, &c.sources[0], &json!([spoof]), 10, 20).is_err());
    let mut unsupported = m.clone();
    unsupported.bytes.push(0);
    assert!(
        discovery::evm::decode(
            &c,
            &c.sources[0],
            &json!([log(&c, &unsupported, 9)]),
            10,
            20
        )
        .unwrap()[0]
            .manual
    );
}
fn solana_config() -> (tempfile::TempDir, Config, Value) {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(&dir, &TestSigner::new());
    let route: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/solana-route-public.json"
    ))
    .unwrap();
    let d = &route["deployment"];
    let src = &d["source"];
    c.helper = d["helper"]["address"].as_str().unwrap().parse().unwrap();
    c.messenger = d["arc"]["tokenMessenger"]["address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let capture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/solana-standard-helper-jsonParsed.json"
    ))
    .unwrap();
    let packet = capture["result"].clone();
    c.sources = vec![Source {
        domain: 5,
        rpc: c.arc_rpc.clone(),
        network: Network::Solana {
            genesis_hash: src["genesisHash"].as_str().unwrap().into(),
            messenger: src["tokenMessengerProgram"].as_str().unwrap().into(),
            usdc: src["mint"].as_str().unwrap().into(),
            start_signature: packet["transaction"]["signatures"][0]
                .as_str()
                .unwrap()
                .into(),
            start_slot: 1,
        },
    }];
    (dir, c, packet)
}
#[test]
fn genuine_jsonparsed_legacy_v0_v1_and_authentic_cpi_grammar_negatives() {
    let (_dir, c, tx) = solana_config();
    let sig = tx["transaction"]["signatures"][0].as_str().unwrap();
    let decoded = discovery::solana::decode(&c, &c.sources[0], sig, &tx).unwrap();
    assert_eq!(decoded.positions.len(), 1);
    assert_eq!(decoded.positions[0].ordinal, 3);
    assert!(!decoded.manual);
    for bytes in [
        include_str!("../../tests/fixtures/solana-v0-fast-burn-jsonParsed.json"),
        include_str!("../../tests/fixtures/solana-v1-receive-jsonParsed.json"),
    ] {
        let value: Value = serde_json::from_str(bytes).unwrap();
        let packet = &value["result"];
        let sig = packet["transaction"]["signatures"][0].as_str().unwrap();
        discovery::solana::decode(&c, &c.sources[0], sig, packet).unwrap();
    }
    for mutation in 0..7 {
        let mut q = tx.clone();
        let ix = &mut q["meta"]["innerInstructions"][0]["instructions"][3];
        match mutation {
            0 => ix["programId"] = json!(bs58::encode([9; 32]).into_string()),
            1 => ix["accounts"] = json!([bs58::encode([9; 32]).into_string()]),
            2 => {
                let mut raw = bs58::decode(ix["data"].as_str().unwrap())
                    .into_vec()
                    .unwrap();
                raw[0] ^= 1;
                ix["data"] = json!(bs58::encode(raw).into_string());
            }
            3 => {
                let mut raw = bs58::decode(ix["data"].as_str().unwrap())
                    .into_vec()
                    .unwrap();
                raw.push(0);
                ix["data"] = json!(bs58::encode(raw).into_string());
            }
            4 => q["meta"]["innerInstructions"] = Value::Null,
            5 => q["version"] = json!(2),
            _ => q["meta"]["err"] = json!({"InstructionError":[0,"InvalidArgument"]}),
        };
        let result = discovery::solana::decode(&c, &c.sources[0], sig, &q);
        if mutation < 2 {
            assert!(result.unwrap().positions.is_empty());
        } else {
            assert!(result.is_err(), "mutation {mutation}");
        }
    }
}

#[tokio::test]
async fn evm_scanner_shrinks_ranges_and_rejects_changed_finalized_anchor() {
    let (_dir, c, _key, state, task) = server().await;
    state.lock().unwrap().fail_wide_logs = true;
    let rpc = rpc::Rpc::new(c.arc_rpc.clone()).unwrap();
    let page = discovery::evm::scan(&c, &c.sources[0], &rpc, &Value::Null)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(page.cursor["end"], 10);
    assert_eq!(state.lock().unwrap().log_ranges.last(), Some(&(10, 10)));
    let mut store = Store::open(&c, true).unwrap();
    store.page(&c, 0, &page).unwrap();
    let mut bad = page.cursor;
    bad["hash"] = json!(B256::repeat_byte(55));
    assert!(discovery::evm::scan(&c, &c.sources[0], &rpc, &bad)
        .await
        .is_err());
    assert_eq!(
        store.cursor(0).unwrap().unwrap()["hash"],
        json!(block_hash(10))
    );
    task.abort();
}
#[tokio::test]
async fn solana_real_reader_frozen_pass_same_slot_reopen_and_pruned_gap() {
    use axum::{routing::post, Router};
    use std::collections::VecDeque;
    let (dir, mut c, packet) = solana_config();
    let signature = packet["transaction"]["signatures"][0]
        .as_str()
        .unwrap()
        .to_owned();
    let boundary = bs58::encode([7; 64]).into_string();
    let newest = bs58::encode([8; 64]).into_string();
    let slot = packet["slot"].as_u64().unwrap();
    if let Network::Solana {
        start_signature, ..
    } = &mut c.sources[0].network
    {
        *start_signature = boundary.clone();
    }
    let entry = |sig: &str| json!({"signature":sig,"slot":slot,"err":null,"confirmationStatus":"finalized"});
    let pages = Arc::new(Mutex::new(VecDeque::from([
        json!([entry(&signature)]),
        json!([entry(&boundary)]),
        json!([entry(&newest), entry(&signature)]),
        json!([]),
    ])));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    c.sources[0].rpc = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let genesis = match &c.sources[0].network {
        Network::Solana { genesis_hash, .. } => genesis_hash.clone(),
        _ => unreachable!(),
    };
    let app = Router::new().route(
        "/",
        post(move |axum::Json(body): axum::Json<Value>| {
            let pages = pages.clone();
            let packet = packet.clone();
            let genesis = genesis.clone();
            async move {
                let result = match body["method"].as_str().unwrap() {
                    "getGenesisHash" => json!(genesis),
                    "getFirstAvailableBlock" => json!(0),
                    "getSignaturesForAddress" => pages.lock().unwrap().pop_front().unwrap(),
                    "getTransaction" => {
                        assert_eq!(body["params"][1]["encoding"], "jsonParsed");
                        assert_eq!(body["params"][1]["maxSupportedTransactionVersion"], 1);
                        let mut p = packet;
                        p["transaction"]["signatures"][0] = body["params"][0].clone();
                        p
                    }
                    method => panic!("unexpected {method}"),
                };
                axum::Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
            }
        }),
    );
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let rpc = rpc::Rpc::new(c.sources[0].rpc.clone()).unwrap();
    let mut store = Store::open(&c, true).unwrap();
    let first = discovery::solana::scan(&c, &c.sources[0], &rpc, &Value::Null)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.cursor["pass"]["pass_top"], signature);
    store.page(&c, 5, &first).unwrap();
    drop(store);
    let mut store = Store::open(&c, false).unwrap();
    let second =
        discovery::solana::scan(&c, &c.sources[0], &rpc, &store.cursor(5).unwrap().unwrap())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(second.cursor["head"], signature);
    store.page(&c, 5, &second).unwrap();
    let third =
        discovery::solana::scan(&c, &c.sources[0], &rpc, &store.cursor(5).unwrap().unwrap())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(third.cursor["head"], newest);
    assert_eq!(third.transactions.len(), 1);
    store.page(&c, 5, &third).unwrap();
    let before = store.cursor(5).unwrap().unwrap();
    assert!(discovery::solana::scan(&c, &c.sources[0], &rpc, &before)
        .await
        .is_err());
    assert_eq!(store.cursor(5).unwrap().unwrap(), before);
    drop(dir);
    task.abort();
}

#[test]
fn complete_large_solana_hook_is_retained_manual_and_full_ordinal_is_preserved() {
    let (_dir, c, mut packet) = solana_config();
    let signature = packet["transaction"]["signatures"][0]
        .as_str()
        .unwrap()
        .to_owned();
    let ix = &mut packet["meta"]["innerInstructions"][0]["instructions"][3];
    let mut bytes = bs58::decode(ix["data"].as_str().unwrap())
        .into_vec()
        .unwrap();
    bytes[200..204].copy_from_slice(&513u32.to_le_bytes());
    bytes.resize(16 + 188 + 513, 0);
    ix["data"] = json!(bs58::encode(bytes).into_string());
    let candidate = discovery::solana::decode(&c, &c.sources[0], &signature, &packet).unwrap();
    assert!(candidate.manual);
    assert_eq!(candidate.positions.len(), 1);
    let mut store = Store::open(&c, true).unwrap();
    store
        .page(
            &c,
            5,
            &discovery::Page {
                cursor: json!({"head":signature}),
                transactions: vec![candidate],
            },
        )
        .unwrap();
    assert_eq!(
        store
            .db
            .query_row("SELECT state FROM source_txs", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "manual"
    );
    assert!(store.ready(0).unwrap().is_none());
    let (_, c, mut packet) = solana_config();
    let unrelated = packet["meta"]["innerInstructions"][0]["instructions"][0].clone();
    packet["meta"]["innerInstructions"][0]["instructions"]
        .as_array_mut()
        .unwrap()
        .insert(0, unrelated);
    let sig = packet["transaction"]["signatures"][0].as_str().unwrap();
    assert_eq!(
        discovery::solana::decode(&c, &c.sources[0], sig, &packet)
            .unwrap()
            .positions[0]
            .ordinal,
        4
    );
}
