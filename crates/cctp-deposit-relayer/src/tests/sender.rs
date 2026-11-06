use super::*;
#[tokio::test]
async fn committed_raw_is_visible_at_actual_rpc_send_and_reopen() {
    let (_dir, c, key, state, task) = server().await;
    let mut store = Store::open(&c, true).unwrap();
    let m = admit(&mut store, &c, &B256::repeat_byte(1).to_string(), 1).remove(0);
    let arc = sender(&c).await;
    let p = arc.prepare(&c, &m, 0, &key, 0).await.unwrap();
    arc.submit(&c, &mut store, &p).await.unwrap();
    assert_eq!(state.lock().unwrap().observed, vec![true]);
    drop(store);
    let store = Store::open(&c, false).unwrap();
    assert_eq!(store.pending().unwrap().unwrap().raw, p.raw);
    drop(store);
    let db = rusqlite::Connection::open(&c.journal).unwrap();
    db.execute("UPDATE pending SET raw=x'00'", []).unwrap();
    drop(db);
    assert!(Store::open(&c, false).is_err());
    task.abort();
}
#[tokio::test]
async fn pending_and_settlement_sql_failures_do_not_send_or_release_nonce() {
    let (_dir, c, key, state, task) = server().await;
    let mut store = Store::open(&c, true).unwrap();
    let m = admit(&mut store, &c, &B256::repeat_byte(1).to_string(), 1).remove(0);
    let arc = sender(&c).await;
    let p = arc.prepare(&c, &m, 0, &key, 0).await.unwrap();
    store.db.execute_batch("CREATE TRIGGER no_pending BEFORE INSERT ON pending BEGIN SELECT RAISE(ABORT,'disk'); END;").unwrap();
    assert!(arc.submit(&c, &mut store, &p).await.is_err());
    assert!(state.lock().unwrap().sends.is_empty());
    assert!(store.pending().unwrap().is_none());
    store.db.execute_batch("DROP TRIGGER no_pending").unwrap();
    arc.submit(&c, &mut store, &p).await.unwrap();
    store.db.execute_batch("CREATE TRIGGER no_nonce BEFORE UPDATE OF next_nonce ON meta BEGIN SELECT RAISE(ABORT,'disk'); END;").unwrap();
    assert!(store.settle(&p, true).is_err());
    assert_eq!(store.next_nonce().unwrap(), 0);
    assert!(store.pending().unwrap().is_some());
    task.abort();
}
#[tokio::test]
async fn lost_reply_third_party_and_unknown_nonce_keep_exact_pending_across_restart() {
    let (_dir, c, key, state, task) = server().await;
    let mut store = Store::open(&c, true).unwrap();
    let m = admit(&mut store, &c, &B256::repeat_byte(1).to_string(), 1).remove(0);
    let arc = sender(&c).await;
    let p = arc.prepare(&c, &m, 0, &key, 0).await.unwrap();
    state.lock().unwrap().fail_send = true;
    assert!(arc.submit(&c, &mut store, &p).await.is_err());
    drop(store);
    let mut store = Store::open(&c, false).unwrap();
    {
        let mut s = state.lock().unwrap();
        s.used = true;
        s.pending_nonce = 1;
        s.fail_send = false;
    }
    arc.reconcile(&c, &mut store, &p, 1).await.unwrap();
    assert_eq!(store.next_nonce().unwrap(), 0);
    assert_eq!(store.pending().unwrap().unwrap().raw, p.raw);
    assert!(state.lock().unwrap().sends.iter().all(|raw| *raw == p.raw));
    state.lock().unwrap().final_nonce = 1;
    arc.reconcile(&c, &mut store, &p, 2).await.unwrap();
    assert!(store.halted().unwrap());
    assert!(store.pending().unwrap().is_some());
    drop(store);
    let store = Store::open(&c, false).unwrap();
    assert!(store.halted().unwrap());
    assert_eq!(store.next_nonce().unwrap(), 0);
    task.abort();
}
#[tokio::test]
async fn canonical_paid_revert_is_manual_forever() {
    let (_dir, c, key, state, task) = server().await;
    let mut store = Store::open(&c, true).unwrap();
    let m = admit(&mut store, &c, &B256::repeat_byte(1).to_string(), 1).remove(0);
    let arc = sender(&c).await;
    let p = arc.prepare(&c, &m, 0, &key, 0).await.unwrap();
    arc.submit(&c, &mut store, &p).await.unwrap();
    state.lock().unwrap().receipt = receipt(&c, &p, 0);
    arc.reconcile(&c, &mut store, &p, 1).await.unwrap();
    assert_eq!(store.next_nonce().unwrap(), 1);
    assert!(store.pending().unwrap().is_none());
    assert!(store.ready(10).unwrap().is_none());
    drop(store);
    let mut store = Store::open(&c, false).unwrap();
    store
        .db
        .execute("UPDATE source_txs SET state='pending'", [])
        .unwrap();
    store
        .admit(
            &Job {
                domain: m.domain,
                transaction: m.transaction.clone(),
            },
            std::slice::from_ref(&m),
            100,
        )
        .unwrap();
    assert!(store.ready(100).unwrap().is_none());
    assert_eq!(
        store
            .db
            .query_row("SELECT state FROM messages", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "reverted"
    );
    task.abort();
}
#[tokio::test]
async fn raw_fixed_request_mutations_and_simulation_rejected_before_sign_or_send() {
    let (_dir, c, key, state, task) = server().await;
    let mut store = Store::open(&c, true).unwrap();
    let m = admit(&mut store, &c, &B256::repeat_byte(1).to_string(), 1).remove(0);
    let arc = sender(&c).await;
    let p = arc.prepare(&c, &m, 0, &key, 0).await.unwrap();
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_eips::eip2718::Encodable2718;
    for change in 0..10 {
        let mut q = p.clone();
        let mut tx = TxEip1559 {
            chain_id: c.chain_id,
            nonce: 0,
            gas_limit: c.max_gas,
            max_fee_per_gas: 3_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: alloy_primitives::TxKind::Call(c.helper),
            value: U256::ZERO,
            input: abi::Helper::receiveAndDepositCall {
                message: m.bytes.clone().into(),
                attestation: m.attestation.clone().into(),
            }
            .abi_encode()
            .into(),
            access_list: Default::default(),
        };
        match change {
            0 => tx.to = alloy_primitives::TxKind::Call(Address::repeat_byte(9)),
            1 => tx.nonce = 1,
            2 => tx.chain_id += 1,
            3 => {
                let mut bytes = tx.input.to_vec();
                bytes[4] ^= 1;
                tx.input = bytes.into();
            }
            4 => tx.gas_limit = c.max_gas + 1,
            5 => tx.max_fee_per_gas = c.max_fee_per_gas + 1,
            6 => tx.value = U256::from(1),
            7 => q.eoa_nonce = 1,
            8 => q.message.bytes[439] ^= 1,
            _ => tx.max_priority_fee_per_gas = tx.max_fee_per_gas + 1,
        };
        let signature = key.sign_digest(tx.signature_hash()).await.unwrap();
        q.raw = tx.into_signed(signature).encoded_2718();
        q.hash = keccak256(&q.raw);
        assert!(arc::validate_saved(&c, &q, 0).is_err(), "mutation {change}");
    }
    state.lock().unwrap().simulation_fail = true;
    assert!(arc.prepare(&c, &m, 0, &key, 0).await.is_err());
    assert!(state.lock().unwrap().sends.is_empty());
    task.abort();
}

#[tokio::test]
async fn serial_worker_pending_nonce_blocks_new_signing_while_iris_remains_fair() {
    let (_dir, c, key, state, task) = server().await;
    let mut store = Store::open(&c, true).unwrap();
    let hash = B256::repeat_byte(1).to_string();
    let m = admit(&mut store, &c, &hash, 1).remove(0);
    let arc = sender(&c).await;
    let p = arc.prepare(&c, &m, 0, &key, circle::now()).await.unwrap();
    arc.submit(&c, &mut store, &p).await.unwrap();
    let second_hash = B256::repeat_byte(4).to_string();
    worker_ready_second(&mut store, &c, &second_hash);
    for n in 2..=3 {
        store
            .page(&c, 0, &page(&c, &B256::repeat_byte(n).to_string(), 1))
            .unwrap();
    }
    let mut worker = worker::Worker::new(c.clone(), store, Box::new(key))
        .await
        .unwrap();
    state.lock().unwrap().used = true;
    worker.cycle().await.unwrap();
    worker.cycle().await.unwrap();
    let observed = state.lock().unwrap().iris_calls.clone();
    assert_eq!(observed.len(), 2);
    assert_ne!(observed[0], observed[1]);
    assert_eq!(worker.store.next_nonce().unwrap(), 0);
    assert_eq!(
        worker
            .store
            .db
            .query_row(
                "SELECT state FROM messages WHERE nonce=?",
                [B256::repeat_byte(2).to_string()],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "queued"
    );

    assert_eq!(worker.store.pending().unwrap().unwrap().raw, p.raw);
    assert!(state.lock().unwrap().sends.iter().all(|raw| *raw == p.raw));
    state.lock().unwrap().iris_status = 429;
    worker
        .store
        .db
        .execute(
            "UPDATE source_txs SET next_poll=0 WHERE state='pending'",
            [],
        )
        .unwrap();
    worker.cycle().await.unwrap();
    let count = state.lock().unwrap().iris_calls.len();
    worker.cycle().await.unwrap();
    assert_eq!(state.lock().unwrap().iris_calls.len(), count);
    drop(worker);
    let store = Store::open(&c, false).unwrap();
    assert!(store.due(circle::now()).unwrap().is_none());
    task.abort();
}

fn worker_ready_second(store: &mut Store, c: &Config, hash: &str) {
    store.page(c, 0, &page(c, hash, 1)).unwrap();
    store
        .admit(
            &Job {
                domain: 0,
                transaction: hash.into(),
            },
            &[message(c, 2, hash)],
            0,
        )
        .unwrap();
}
#[tokio::test]
async fn contradictory_receipt_and_stale_pending_persist_manual_halt() {
    for conflict in [true, false] {
        let (_dir, c, key, state, task) = server().await;
        let mut store = Store::open(&c, true).unwrap();
        let m = admit(&mut store, &c, &B256::repeat_byte(1).to_string(), 1).remove(0);
        let arc = sender(&c).await;
        let p = arc.prepare(&c, &m, 0, &key, 0).await.unwrap();
        arc.submit(&c, &mut store, &p).await.unwrap();
        if conflict {
            let mut wrong = receipt(&c, &p, 1);
            wrong["blockHash"] = json!(B256::repeat_byte(99));
            state.lock().unwrap().receipt = wrong;
        }
        arc.reconcile(
            &c,
            &mut store,
            &p,
            if conflict {
                1
            } else {
                c.pending_timeout_secs as i64 + 1
            },
        )
        .await
        .unwrap();
        assert!(store.halted().unwrap());
        assert!(store.pending().unwrap().is_some());
        assert_eq!(store.next_nonce().unwrap(), 0);
        drop(store);
        assert!(Store::open(&c, false).unwrap().halted().unwrap());
        task.abort();
    }
}
#[tokio::test]
async fn fresh_journal_initialization_refuses_old_sender_before_kms_or_store_creation() {
    let (dir, c, _key, state, task) = server().await;
    let profile = dir.path().join("config.json");
    std::fs::write(&profile, serde_json::to_vec(&c).unwrap()).unwrap();
    state.lock().unwrap().final_nonce = 1;
    assert!(
        crate::run(&profile, true, tokio_util::sync::CancellationToken::new())
            .await
            .is_err()
    );
    assert!(!c.journal.exists());
    assert!(state.lock().unwrap().sends.is_empty());
    task.abort();
}
#[tokio::test]
async fn cancelled_serial_worker_exits_without_an_extra_send() {
    let (_dir, c, key, state, task) = server().await;
    let store = Store::open(&c, true).unwrap();
    let worker = worker::Worker::new(c, store, Box::new(key)).await.unwrap();
    let stop = tokio_util::sync::CancellationToken::new();
    stop.cancel();
    tokio::time::timeout(std::time::Duration::from_millis(200), worker.run(stop))
        .await
        .unwrap()
        .unwrap();
    assert!(state.lock().unwrap().sends.is_empty());
    task.abort();
}

#[tokio::test]
async fn full_source_page_rolls_back_but_actual_worker_still_polls_and_sends_admitted_work() {
    let (_dir, mut c, key, state, task) = server().await;
    c.queue_capacity = 3;
    let mut store = Store::open(&c, true).unwrap();
    admit(&mut store, &c, &B256::repeat_byte(1).to_string(), 1);
    let due = B256::repeat_byte(2).to_string();
    store.page(&c, 0, &page(&c, &due, 1)).unwrap();
    store
        .db
        .execute("UPDATE sources SET cursor='null'", [])
        .unwrap();
    let new = message(&c, 0, &B256::repeat_byte(3).to_string());
    state.lock().unwrap().logs = json!([
        super::source::log(&c, &new, 7),
        super::source::log(&c, &new, 8)
    ]);
    let mut worker = worker::Worker::new(c, store, Box::new(key)).await.unwrap();
    worker.cycle().await.unwrap();
    assert_eq!(worker.store.cursor(0).unwrap(), Some(Value::Null));
    assert_eq!(state.lock().unwrap().iris_calls, vec![due]);
    assert_eq!(state.lock().unwrap().sends.len(), 1);
    assert_eq!(
        worker
            .store
            .db
            .query_row("SELECT count(*) FROM source_txs", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
    task.abort();
}

#[tokio::test]
async fn signer_runtime_and_bounded_body_fail_before_any_send() {
    let (_dir, c, key, state, task) = server().await;
    let mut store = Store::open(&c, true).unwrap();
    let m = admit(&mut store, &c, &B256::repeat_byte(1).to_string(), 1).remove(0);
    let arc = sender(&c).await;
    assert!(arc.prepare(&c, &m, 0, &TestSigner::new(), 0).await.is_err());
    let response = reqwest::Client::new()
        .get(
            c.circle_url
                .join("v2/messages/0?transactionHash=0x01")
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert!(rpc::bounded(response, 4).await.is_err());
    let mut wrong = c.clone();
    wrong.helper_code_hash = B256::repeat_byte(99);
    assert!(arc::ArcSender::new(&wrong)
        .unwrap()
        .verify(&wrong)
        .await
        .is_err());
    assert!(worker::Worker::new(c, store, Box::new(TestSigner::new()))
        .await
        .is_err());
    assert!(state.lock().unwrap().sends.is_empty());
    let _ = key;
    task.abort();
}
