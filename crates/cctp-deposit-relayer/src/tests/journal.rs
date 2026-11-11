use super::*;
#[test]
fn journal_page_atomicity_reopen_identity_and_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let signer = TestSigner::new();
    let c = config(&dir, &signer);
    c.validate().unwrap();
    let round: Config = serde_json::from_value(serde_json::to_value(&c).unwrap()).unwrap();
    assert_eq!(round.identity().unwrap(), c.identity().unwrap());
    assert!(Store::open(&c, false).is_err());
    let mut store = Store::open(&c, true).unwrap();
    assert!(Store::open(&c, false).is_err());
    let hash = B256::repeat_byte(1).to_string();
    store.db.execute_batch("CREATE TRIGGER fail_page BEFORE INSERT ON source_txs BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(store.page(&c, 0, &page(&c, &hash, 1)).is_err());
    assert_eq!(store.cursor(0).unwrap(), Some(Value::Null));
    assert_eq!(
        store
            .db
            .query_row("SELECT count(*) FROM source_txs", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    store.db.execute_batch("DROP TRIGGER fail_page").unwrap();
    store.page(&c, 0, &page(&c, &hash, 1)).unwrap();
    drop(store);
    let store = Store::open(&c, false).unwrap();
    assert_eq!(store.cursor(0).unwrap().unwrap()["end"], 20);
    drop(store);
    let mut changed = c.clone();
    changed.sources.clear();
    assert!(Store::open(&changed, false).is_err());
    let mut tiny = c.clone();
    tiny.journal = dir.path().join("tiny.sqlite");
    tiny.queue_capacity = 1;
    let mut store = Store::open(&tiny, true).unwrap();
    assert!(!store.page(&tiny, 0, &page(&tiny, &hash, 2)).unwrap());
    assert_eq!(store.cursor(0).unwrap(), Some(Value::Null));
    drop(store);
    rusqlite::Connection::open(&tiny.journal)
        .unwrap()
        .execute_batch("PRAGMA user_version=2")
        .unwrap();
    assert!(Store::open(&tiny, false).is_err());
}
#[test]
fn circle_partial_reordered_identical_burns_and_whole_reply_conflicts() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir, &TestSigner::new());
    let mut store = Store::open(&c, true).unwrap();
    let hash = B256::repeat_byte(1).to_string();
    let job = Job {
        domain: 0,
        transaction: hash.clone(),
    };
    store.page(&c, 0, &page(&c, &hash, 2)).unwrap();
    let first = message(&c, 1, &hash);
    let second = message(&c, 2, &hash);
    store.admit(&job, std::slice::from_ref(&second), 0).unwrap();
    assert!(store.due(20).unwrap().is_some());
    store
        .admit(&job, &[second.clone(), first.clone()], 20)
        .unwrap();
    assert!(store.due(40).unwrap().is_none());
    assert_eq!(
        store
            .db
            .query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        2
    );
    let hash2 = B256::repeat_byte(2).to_string();
    let job2 = Job {
        domain: 0,
        transaction: hash2.clone(),
    };
    store.page(&c, 0, &page(&c, &hash2, 1)).unwrap();
    store
        .admit(&job2, &[message(&c, 3, &hash2), message(&c, 4, &hash2)], 40)
        .unwrap();
    assert_eq!(
        store
            .db
            .query_row(
                "SELECT count(*) FROM messages WHERE source_tx=?",
                [&hash2],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .db
            .query_row("SELECT state FROM source_txs WHERE hash=?", [&hash2], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "manual"
    );
    let hash3 = B256::repeat_byte(3).to_string();
    store.page(&c, 0, &page(&c, &hash3, 1)).unwrap();
    let mut conflict = first;
    conflict.transaction = hash3.clone();
    store
        .admit(
            &Job {
                domain: 0,
                transaction: hash3,
            },
            &[conflict],
            50,
        )
        .unwrap();
    assert!(store.ready(60).unwrap().is_none());
    drop(store);
    assert!(Store::open(&c, false).unwrap().ready(60).unwrap().is_none());
}
#[test]
fn circle_every_record_envelope_route_and_terminal_not_rearmed() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir, &TestSigner::new());
    let hash = B256::repeat_byte(1).to_string();
    let m = message(&c, 1, &hash);
    let record = json!({"status":"complete","cctpVersion":2,"message":format!("0x{}",hex::encode(&m.bytes)),"attestation":format!("0x{}",hex::encode(&m.attestation))});
    let mut reply = json!({"sourceTxHash":hash,"messages":[record.clone(),{"status":"pending"}]});
    assert_eq!(
        circle::decode(
            &serde_json::to_vec(&reply).unwrap(),
            &c,
            &c.sources[0],
            &hash
        )
        .unwrap()
        .len(),
        1
    );
    reply["messages"][1] =
        json!({"status":"complete","cctpVersion":2,"message":"0x","attestation":"0x11"});
    assert!(circle::decode(
        &serde_json::to_vec(&reply).unwrap(),
        &c,
        &c.sources[0],
        &hash
    )
    .is_err());
    reply["messages"] = json!([record]);
    reply["sourceTxHash"] = json!(B256::repeat_byte(9));
    assert!(circle::decode(
        &serde_json::to_vec(&reply).unwrap(),
        &c,
        &c.sources[0],
        &hash
    )
    .is_err());
    let mut store = Store::open(&c, true).unwrap();
    admit(&mut store, &c, &hash, 1);
    store.received(m.nonce).unwrap();
    assert!(store.ready(100).unwrap().is_none());
    drop(store);
    assert!(Store::open(&c, false)
        .unwrap()
        .ready(100)
        .unwrap()
        .is_none());
}

#[test]
fn retained_descriptor_cannot_extend_store_ownership_and_errors_release_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir, &TestSigner::new());
    let store = Store::open(&c, true).unwrap();
    // dup/try_clone shares the open-file description, as fork does before exec.
    let inherited = store.retained_owner_descriptor().unwrap();
    assert!(
        Store::open(&c, false).is_err(),
        "live owner must exclude another opener"
    );
    drop(store);
    let reopened =
        Store::open(&c, false).expect("retained descriptor must not outlive Store ownership");
    drop(inherited);
    assert!(
        Store::open(&c, false).is_err(),
        "closing an old descriptor must not unlock the new owner"
    );
    drop(reopened);
    let mut mismatch = c.clone();
    mismatch.max_gas += 1;
    let error = Store::open(&mismatch, false).err().unwrap();
    assert!(error.to_string().contains("identity mismatch"));
    let reopened = Store::open(&c, false).expect("failed open must release ownership");
    assert!(Store::open(&c, false).is_err());
    drop(reopened);
    assert!(Store::open(&c, false).is_ok());
    eprintln!(
        "LOCK_LIFETIME_BODY retained_fd=true live_owner_exclusive=true failed_open_released=true"
    );
}
