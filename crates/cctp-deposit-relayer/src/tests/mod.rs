use super::*;
use alloy_primitives::{keccak256, Address, Signature, B256, U256};
use alloy_sol_types::SolCall;
use config::{Config, Kms, Network, Source};
use message::{padded, Candidate, Message, Position};
use serde_json::{json, Value};
use std::{
    io::Read,
    sync::{Arc, Mutex},
};
use store::{Job, Store};
use usdcx_kms_signer::{Signer, SignerFuture, SigningPublicKey};

#[derive(Clone)]
struct TestSigner(k256::ecdsa::SigningKey);
impl TestSigner {
    fn new() -> Self {
        let mut key = [0; 32];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut key)
            .unwrap();
        Self::from_bytes(key)
    }
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(k256::ecdsa::SigningKey::from_bytes(&bytes.into()).unwrap())
    }
    fn address(&self) -> Address {
        Address::from_private_key(&self.0)
    }
}
impl Signer for TestSigner {
    fn public_key(&self) -> SignerFuture<'_, SigningPublicKey> {
        Box::pin(async move {
            SigningPublicKey::from_compressed(
                self.0
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            )
        })
    }
    fn sign_digest(&self, digest: B256) -> SignerFuture<'_, Signature> {
        Box::pin(async move {
            let (sig, id) = self.0.sign_prehash_recoverable(digest.as_slice()).unwrap();
            assert!(!id.is_x_reduced());
            Ok(Signature::from_signature_and_parity(sig, id.is_y_odd()))
        })
    }
}
fn config(dir: &tempfile::TempDir, signer: &TestSigner) -> Config {
    Config {
        journal: dir.path().join("relay.sqlite"),
        arc_rpc: "http://127.0.0.1:1".parse().unwrap(),
        circle_url: "http://127.0.0.1:1/".parse().unwrap(),
        chain_id: 31337,
        arc_domain: 26,
        helper: Address::repeat_byte(0x21),
        helper_code_hash: keccak256([0x60, 0]),
        messenger: Address::repeat_byte(0x23),
        signer: signer.address(),
        kms: Some(Kms {
            region: "ephemeral-loopback".into(),
            key_arn: "unused-injected-signer".into(),
        }),
        local_env: None,
        max_gas: 500000,
        max_fee_per_gas: 30_000_000_000,
        priority_fee_per_gas: 1_000_000_000,
        pending_timeout_secs: 3600,
        queue_capacity: 100,
        sources: vec![Source {
            domain: 0,
            rpc: "http://127.0.0.1:1".parse().unwrap(),
            network: Network::Evm {
                chain_id: 31337,
                messenger: Address::repeat_byte(0x11),
                transmitter: Address::repeat_byte(0x12),
                usdc: Address::repeat_byte(0x13),
                start_block: 10,
                start_hash: block_hash(10),
            },
        }],
    }
}
fn block_hash(n: u64) -> B256 {
    U256::from(n).to_be_bytes::<32>().into()
}
fn message(c: &Config, n: u8, transaction: &str) -> Message {
    let source = &c.sources[0];
    let (messenger, token) = source.route().unwrap();
    let mut b = vec![0; 440];
    for (pos, num) in [
        (0, 1u32),
        (4, source.domain),
        (8, 26),
        (140, 2000),
        (144, 2000),
        (148, 1),
    ] {
        b[pos..pos + 4].copy_from_slice(&num.to_be_bytes());
    }
    let nonce = B256::repeat_byte(n);
    for (pos, word) in [
        (12, nonce),
        (44, messenger),
        (76, padded(c.messenger)),
        (108, padded(c.helper)),
        (152, token),
        (184, padded(c.helper)),
        (216, block_hash(1_000_000)),
        (376, block_hash(1)),
        (
            408,
            "0x000000000000000000000000000000008110548cc41852010140bd1325ff0800"
                .parse()
                .unwrap(),
        ),
    ] {
        b[pos..pos + 32].copy_from_slice(word.as_slice());
    }
    Message {
        nonce,
        domain: source.domain,
        transaction: transaction.into(),
        bytes: b,
        attestation: vec![0x11; 65],
    }
}
fn page(c: &Config, transaction: &str, count: usize) -> discovery::Page {
    let _ = c;
    discovery::Page {
        cursor: json!({"end":20,"hash":block_hash(20)}),
        transactions: vec![Candidate {
            transaction: transaction.into(),
            positions: (0..count)
                .map(|i| Position {
                    ordinal: i as u64,
                    digest: B256::repeat_byte(i as u8),
                })
                .collect(),
            manual: false,
        }],
    }
}
fn admit(store: &mut Store, c: &Config, transaction: &str, count: usize) -> Vec<Message> {
    store
        .page(c, c.sources[0].domain, &page(c, transaction, count))
        .unwrap();
    let messages = (1..=count)
        .map(|i| message(c, i as u8, transaction))
        .collect::<Vec<_>>();
    store
        .admit(
            &Job {
                domain: c.sources[0].domain,
                transaction: transaction.into(),
            },
            &messages,
            0,
        )
        .unwrap();
    messages
}
struct Mock {
    config: Config,
    receipt: Value,
    finalized: u64,
    final_nonce: u64,
    pending_nonce: u64,
    used: bool,
    sends: Vec<Vec<u8>>,
    observed: Vec<bool>,
    fail_send: bool,
    simulation_fail: bool,
    low_balance: bool,
    nonce_failure: bool,
    logs: Value,
    marker: Option<std::path::PathBuf>,
    calls: Vec<String>,
    iris_calls: Vec<String>,
    iris_status: u16,
    fail_wide_logs: bool,
    log_ranges: Vec<(u64, u64)>,
}
async fn server() -> (
    tempfile::TempDir,
    Config,
    TestSigner,
    Arc<Mutex<Mock>>,
    tokio::task::JoinHandle<()>,
) {
    use axum::{
        routing::{get, post},
        Router,
    };
    let dir = tempfile::tempdir().unwrap();
    let signer = TestSigner::new();
    let mut c = config(&dir, &signer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    c.arc_rpc = url.parse().unwrap();
    c.circle_url = c.arc_rpc.clone();
    c.sources[0].rpc = c.arc_rpc.clone();
    let state = Arc::new(Mutex::new(Mock {
        config: c.clone(),
        receipt: Value::Null,
        finalized: 20,
        final_nonce: 0,
        pending_nonce: 0,
        used: false,
        sends: vec![],
        observed: vec![],
        fail_send: false,
        simulation_fail: false,
        low_balance: false,
        nonce_failure: false,
        logs: json!([]),
        marker: None,
        calls: vec![],
        iris_calls: vec![],
        iris_status: 200,
        fail_wide_logs: false,
        log_ranges: vec![],
    }));
    let app = Router::new()
        .route("/", post(rpc_handler))
        .route("/v2/messages/{domain}", get(iris_handler))
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (dir, c, signer, state, task)
}
async fn rpc_handler(
    axum::extract::State(state): axum::extract::State<Arc<Mutex<Mock>>>,
    axum::Json(body): axum::Json<Value>,
) -> axum::Json<Value> {
    let mut s = state.lock().unwrap();
    let method = body["method"].as_str().unwrap();
    s.calls.push(method.into());
    let result = match method {
        "eth_chainId" => json!(rpc::height(s.config.chain_id)),
        "eth_getCode" => json!("0x6000"),
        "eth_getBlockByNumber" => {
            let n = if body["params"][0] == "finalized" {
                s.finalized
            } else {
                rpc::hex_u64(&body["params"][0]).unwrap()
            };
            json!({"number":rpc::height(n),"hash":block_hash(n)})
        }
        "eth_getLogs" => {
            let from = rpc::hex_u64(&body["params"][0]["fromBlock"]).unwrap();
            let to = rpc::hex_u64(&body["params"][0]["toBlock"]).unwrap();
            s.log_ranges.push((from, to));
            if s.fail_wide_logs && from < to {
                return axum::Json(
                    json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"range too wide"}}),
                );
            }
            s.logs.clone()
        }
        "eth_getTransactionCount" if s.nonce_failure => {
            return axum::Json(
                json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"PRIVATE_PROVIDER_SENTINEL https://name:password@rpc.invalid/?token=SECRET"}}),
            )
        }
        "eth_getTransactionCount" => json!(rpc::height(if body["params"][1] == "finalized" {
            s.final_nonce
        } else {
            s.pending_nonce
        })),
        "eth_getTransactionReceipt" => s.receipt.clone(),
        "eth_gasPrice" => json!("0x3b9aca00"),
        "eth_estimateGas" => json!("0x10000"),
        "eth_getBalance" => json!(if s.low_balance {
            "0x0"
        } else {
            "0x1000000000000000000"
        }),
        "eth_call" => {
            let data = body["params"][0]["data"].as_str().unwrap();
            if data
                == format!(
                    "0x{}",
                    hex::encode(abi::Helper::messageTransmitterCall {}.abi_encode())
                )
            {
                json!(padded(Address::repeat_byte(0x22)))
            } else if data
                == format!(
                    "0x{}",
                    hex::encode(abi::Helper::tokenMessengerCall {}.abi_encode())
                )
            {
                json!(padded(s.config.messenger))
            } else if body["params"][0]["to"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap()
                == Address::repeat_byte(0x22)
            {
                json!(if s.used { block_hash(1) } else { B256::ZERO })
            } else if s.simulation_fail {
                return axum::Json(
                    json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"PRIVATE_SIMULATION_SENTINEL https://name:password@rpc.invalid/?token=SECRET"}}),
                );
            } else {
                json!("0x")
            }
        }
        "eth_sendRawTransaction" => {
            let raw = message::unhex(body["params"][0].as_str().unwrap(), 70000).unwrap();
            let hash = keccak256(&raw);
            let observed = rusqlite::Connection::open_with_flags(
                &s.config.journal,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .ok()
            .and_then(|db| {
                db.query_row(
                    "SELECT raw FROM pending WHERE hash=?",
                    [hash.to_string()],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .ok()
            })
            .is_some_and(|saved| saved == raw);
            s.observed.push(observed);
            s.sends.push(raw);
            if let Some(marker) = &s.marker {
                std::fs::write(marker, if observed { "committed" } else { "MISSING" }).unwrap();
            }
            if s.fail_send {
                return axum::Json(
                    json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"injected lost send reply"}}),
                );
            }
            json!(hash)
        }
        _ => panic!("unexpected RPC method {method}"),
    };
    axum::Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
}
async fn sender(c: &Config) -> arc::ArcSender {
    let mut a = arc::ArcSender::new(c).unwrap();
    a.verify(c).await.unwrap();
    a
}
fn receipt(c: &Config, p: &store::Pending, status: u64) -> Value {
    json!({"transactionHash":p.hash,"from":c.signer,"to":c.helper,"blockNumber":"0x14","blockHash":block_hash(20),"status":rpc::height(status)})
}
mod diagnostics;
mod journal;
mod local_evm;
mod local_signer;
mod process;
mod sender;
mod source;

async fn iris_handler(
    axum::extract::State(state): axum::extract::State<Arc<Mutex<Mock>>>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl axum::response::IntoResponse {
    let hash = query.get("transactionHash").unwrap();
    let mut s = state.lock().unwrap();
    s.iris_calls.push(hash.clone());
    (
        axum::http::StatusCode::from_u16(s.iris_status).unwrap(),
        [("retry-after", "60")],
        axum::Json(json!({"sourceTxHash":hash,"messages":[{"status":"pending"}]})),
    )
}
