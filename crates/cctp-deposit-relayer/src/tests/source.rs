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

#[derive(Default)]
struct SlowHistory {
    signatures: Vec<String>,
    unavailable: Option<String>,
    transactions: Vec<String>,
}
async fn slow_history(
    c: &mut Config,
    packet: Value,
    history: Arc<Mutex<SlowHistory>>,
) -> tokio::task::JoinHandle<()> {
    use axum::{routing::post, Router};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    c.sources[0].rpc = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let Network::Solana { genesis_hash, .. } = &c.sources[0].network else {
        unreachable!()
    };
    let genesis = genesis_hash.clone();
    let slot = packet["slot"].as_u64().unwrap();
    let app = Router::new().route("/", post(move |axum::Json(body): axum::Json<Value>| {
        let packet = packet.clone();
        let genesis = genesis.clone();
        let history = history.clone();
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let mut history = history.lock().unwrap();
            let result = match body["method"].as_str().unwrap() {
                "getGenesisHash" => json!(genesis),
                "getFirstAvailableBlock" => json!(0),
                "getSignaturesForAddress" => {
                    let before = body["params"][1]["before"].as_str();
                    let start = before.map(|sig| history.signatures.iter().position(|s| s == sig).unwrap() + 1).unwrap_or(0);
                    json!(history.signatures.iter().skip(start).take(25).map(|sig| json!({"signature":sig,"slot":slot,"err":null,"confirmationStatus":"finalized"})).collect::<Vec<_>>())
                },
                "getTransaction" => {
                    let sig = body["params"][0].as_str().unwrap().to_owned();
                    history.transactions.push(sig.clone());
                    if history.unavailable.as_ref() == Some(&sig) { Value::Null } else {
                        let mut packet = packet;
                        packet["transaction"]["signatures"][0] = json!(sig);
                        packet
                    }
                },
                method => panic!("unexpected {method}"),
            };
            axum::Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
        }
    }));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    })
}

#[tokio::test]
async fn actual_worker_slow_solana_prefix_restart_frozen_head_and_fairness() {
    let (_dir, mut c, signer, arc_state, arc_task) = server().await;
    let (_sol_dir, sol, packet) = solana_config();
    c.helper = sol.helper;
    c.messenger = sol.messenger;
    c.sources.insert(0, sol.sources[0].clone());
    let signatures = (1..=25)
        .map(|n| bs58::encode([n; 64]).into_string())
        .collect::<Vec<_>>();
    let boundary = signatures.last().unwrap().clone();
    let frozen = signatures[0].clone();
    if let Network::Solana {
        start_signature, ..
    } = &mut c.sources[0].network
    {
        *start_signature = boundary;
    }
    let history = Arc::new(Mutex::new(SlowHistory {
        signatures: signatures.clone(),
        ..Default::default()
    }));
    let sol_task = slow_history(&mut c, packet, history.clone()).await;
    arc_state.lock().unwrap().config = c.clone();
    arc_state.lock().unwrap().pending_nonce = 1;
    let mut store = Store::open(&c, true).unwrap();
    // Existing EVM work owns sender nonce N, with another ready message and a due Circle job.
    let mut evm_config = c.clone();
    evm_config.sources.swap(0, 1);
    let pending_hash = B256::repeat_byte(90).to_string();
    let messages = admit(&mut store, &evm_config, &pending_hash, 2);
    let due_hash = B256::repeat_byte(91).to_string();
    store.page(&c, 0, &page(&c, &due_hash, 1)).unwrap();
    store
        .db
        .execute("UPDATE sources SET cursor='null' WHERE domain=0", [])
        .unwrap();
    let arc = sender(&c).await;
    let pending = arc
        .prepare(&c, &messages[0], 0, &signer, circle::now())
        .await
        .unwrap();
    arc.submit(&c, &mut store, &pending).await.unwrap();
    let mut worker = worker::Worker::new(c.clone(), store, Box::new(signer.clone()))
        .await
        .unwrap();
    worker.cycle().await.unwrap();
    let count = |store: &Store| {
        store
            .db
            .query_row("SELECT count(*) FROM source_txs WHERE domain=5", [], |r| {
                r.get::<_, usize>(0)
            })
            .unwrap()
    };
    let prefix = count(&worker.store);
    eprintln!("SLOW_WORKER_PREFIX_BODY prefix={prefix} total=25");
    assert!(
        prefix > 0 && prefix < 25,
        "actual Worker must durably commit a strict nonempty examined prefix"
    );
    let cursor = worker.store.cursor(5).unwrap().unwrap();
    assert_eq!(cursor["pass"]["pass_top"], frozen);
    assert_eq!(cursor["pass"]["resume_before"], signatures[prefix - 1]);
    assert!(worker.store.pending().unwrap().is_some());
    assert!(arc_state.lock().unwrap().iris_calls.contains(&due_hash));
    assert!(arc_state
        .lock()
        .unwrap()
        .calls
        .iter()
        .any(|m| m == "eth_getTransactionReceipt"));
    let newcomer = bs58::encode([26; 64]).into_string();
    history
        .lock()
        .unwrap()
        .signatures
        .insert(0, newcomer.clone());
    drop(worker);
    let store = Store::open(&c, false).unwrap();
    assert_eq!(store.cursor(5).unwrap().unwrap(), cursor);
    let mut worker = worker::Worker::new(c.clone(), store, Box::new(signer))
        .await
        .unwrap();
    for _ in 0..10 {
        worker.cycle().await.unwrap();
        let cursor = worker.store.cursor(5).unwrap().unwrap();
        if cursor["head"] == frozen && cursor["pass"].is_null() {
            break;
        }
        assert_eq!(cursor["pass"]["pass_top"], frozen);
        assert!(!history.lock().unwrap().transactions.contains(&newcomer));
    }
    assert_eq!(worker.store.cursor(5).unwrap().unwrap()["head"], frozen);
    assert_eq!(
        count(&worker.store),
        25,
        "initial boundary is inclusive, including same-slot entries"
    );
    assert!(
        !arc_state.lock().unwrap().log_ranges.is_empty(),
        "other source scheduled during the slow frozen pass"
    );
    // Wait only for the fixed source schedule; the following pass must exclude the old head.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    for _ in 0..2 {
        worker.cycle().await.unwrap();
    }
    assert_eq!(worker.store.cursor(5).unwrap().unwrap()["head"], newcomer);
    assert_eq!(count(&worker.store), 26);
    let reads = &history.lock().unwrap().transactions;
    for sig in &signatures {
        assert_eq!(reads.iter().filter(|s| *s == sig).count(), 1);
    }
    assert_eq!(reads.iter().filter(|s| *s == &newcomer).count(), 1);
    let state = arc_state.lock().unwrap();
    assert!(
        state.sends.iter().all(|raw| raw == &pending.raw),
        "no signed N+1 while N remains unresolved"
    );
    assert!(state.observed.iter().all(|visible| *visible));
    eprintln!("SLOW_WORKER_COVERAGE_BODY candidates=26 same_slot=true inclusive=true exclusive=true fairness=true");
    sol_task.abort();
    arc_task.abort();
}

#[tokio::test]
async fn unavailable_solana_transaction_does_not_checkpoint_past_unfinished_entry() {
    let (_dir, mut c, signer, arc_state, arc_task) = server().await;
    let (_sol_dir, sol, packet) = solana_config();
    c.helper = sol.helper;
    c.messenger = sol.messenger;
    c.sources = sol.sources;
    let signatures = (1..=3)
        .map(|n| bs58::encode([n; 64]).into_string())
        .collect::<Vec<_>>();
    if let Network::Solana {
        start_signature, ..
    } = &mut c.sources[0].network
    {
        *start_signature = signatures[2].clone();
    }
    let history = Arc::new(Mutex::new(SlowHistory {
        signatures: signatures.clone(),
        unavailable: Some(signatures[1].clone()),
        ..Default::default()
    }));
    let sol_task = slow_history(&mut c, packet, history.clone()).await;
    arc_state.lock().unwrap().config = c.clone();
    let store = Store::open(&c, true).unwrap();
    let mut worker = worker::Worker::new(c, store, Box::new(signer))
        .await
        .unwrap();
    worker.cycle().await.unwrap();
    let cursor: String = worker
        .store
        .db
        .query_row("SELECT cursor FROM sources WHERE domain=5", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(cursor, "null");
    assert!(!history
        .lock()
        .unwrap()
        .transactions
        .contains(&signatures[2]));
    sol_task.abort();
    arc_task.abort();
}
