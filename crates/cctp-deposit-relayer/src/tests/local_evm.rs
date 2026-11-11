use super::*;
async fn control(url: &str, action: &str, body: Value) -> Value {
    assert_eq!(url::Url::parse(url).unwrap().host_str(), Some("127.0.0.1"));
    reqwest::Client::new()
        .post(format!("{url}/{action}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn until(worker: &mut worker::Worker, count: u64) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        worker.cycle().await.unwrap();
        let done: u64 = worker
            .store
            .db
            .query_row(
                "SELECT count(*) FROM messages WHERE state='success'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        if done == count {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "actual helper flow timed out: done={done}, halt={}",
            worker.store.halted().unwrap()
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
#[tokio::test]
#[ignore = "requires fresh loopback genuine Circle/helper fixture runner"]
async fn genuine_helper_flow() {
    let path = std::env::var("CCTP_LOCAL_FIXTURE_PROFILE").unwrap();
    let c = Config::load(std::path::Path::new(&path)).unwrap();
    assert_eq!(c.chain_id, 5_042_002);
    assert!(c.kms.is_none() && c.local_env.is_some());
    // Exercise ordinary credential/address/helper/nonce initialization before
    // the real serial worker signs any genuine helper transaction.
    crate::run(
        std::path::Path::new(&path),
        true,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    let key = crate::local_signer::LocalEnvSigner::load(&c).unwrap();
    let controller = std::env::var("CCTP_LOCAL_FIXTURE_CONTROL").unwrap();
    let arc = sender(&c).await;
    assert_eq!(arc.nonces(&c).await.unwrap(), (0, 0));
    let store = Store::open(&c, false).unwrap();
    let mut worker = worker::Worker::new(c.clone(), store, Box::new(key))
        .await
        .unwrap();
    until(&mut worker, 1).await;
    let batch = control(&controller, "new-burn", json!({"batch":true})).await;
    assert_eq!(batch["messages"].as_array().unwrap().len(), 2);
    assert_ne!(
        batch["messages"][0]["eventNonce"],
        batch["messages"][1]["eventNonce"]
    );
    until(&mut worker, 3).await;
    let final_state = control(&controller, "state", json!({})).await;
    assert_eq!(final_state["gatewayTotal"], "3000000");
    assert_eq!(final_state["helperBalance"], "0");
    assert_eq!(final_state["helperAllowance"], "0");
    assert_eq!(final_state["preSendViolations"], 0);
    assert_eq!(final_state["preSendCalls"], 3);
    assert_eq!(final_state["fixedTargetValuePayloadChecks"], 3);
    let original = message::unhex(batch["messages"][0]["message"].as_str().unwrap(), 440).unwrap();
    let expected = B256::from_slice(&original[408..440]).to_string();
    let recipients = final_state["recipientEvents"].as_array().unwrap();
    assert_eq!(recipients.len(), 3);
    assert!(recipients
        .iter()
        .all(|recipient| recipient.as_str().unwrap().eq_ignore_ascii_case(&expected)));

    assert_eq!(worker.store.next_nonce().unwrap(), 3);
    assert!(worker.store.pending().unwrap().is_none());
    let count: u64 = worker
        .store
        .db
        .query_row("SELECT count(*) FROM source_txs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
    drop(worker);
    let shutdown = tokio_util::sync::CancellationToken::new();
    shutdown.cancel();
    crate::run(std::path::Path::new(&path), false, shutdown)
        .await
        .unwrap();
    let restarted = Store::open(&c, false).unwrap();
    assert_eq!(restarted.next_nonce().unwrap(), 3);
    assert!(restarted.pending().unwrap().is_none());
    let after_restart = control(&controller, "state", json!({})).await;
    assert_eq!(after_restart["preSendCalls"], 3);
    std::fs::write(std::env::var("CCTP_LOCAL_FIXTURE_RESULT").unwrap(),serde_json::to_vec_pretty(&json!({"bodyExecuted":true,"signerMode":"local_env","chainId":c.chain_id,"ordinaryInitialization":true,"restartNextNonce":3,"actualSourceTransactions":count,"actualBurnsAndDistinctNonces":3,"successfulHelperCalls":3,"checkedZeroValueFixedTargetPayloadCalls":3,"checkedHelperRecipientEvents":3,"independentCommittedRawObservations":3,"finalState":final_state})).unwrap()).unwrap();
    println!("GENUINE_SMALL_RELAY_HELPER_FLOW_EXECUTED");
}
