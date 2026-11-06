use super::*;
use std::collections::BTreeMap;
use tracing::{
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    Event, Metadata, Subscriber,
};

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<BTreeMap<String, String>>>>);
struct Fields(BTreeMap<String, String>);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
}
impl Subscriber for Events {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target().starts_with("cctp_deposit_relayer")
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}
impl Events {
    fn matching(&self, stage: &str, reason: &str) -> Vec<BTreeMap<String, String>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                e.get("stage").is_some_and(|v| v == stage)
                    && e.get("reason").is_some_and(|v| v == reason)
            })
            .cloned()
            .collect()
    }
    fn sanitized(&self) {
        let events = format!("{:?}", self.0.lock().unwrap());
        for secret in ["PRIVATE_", "password", "token=", "SECRET", "rpc.invalid"] {
            assert!(!events.contains(secret), "diagnostic leaked {secret}");
        }
    }
}
#[derive(Clone)]
struct FailingSigner {
    key: TestSigner,
    public_failure: bool,
}
impl Signer for FailingSigner {
    fn public_key(&self) -> SignerFuture<'_, SigningPublicKey> {
        if self.public_failure {
            Box::pin(async {
                Err(usdcx_kms_signer::SignerError::new(
                    "PRIVATE_AWS_SENTINEL password SECRET",
                ))
            })
        } else {
            self.key.public_key()
        }
    }
    fn sign_digest(&self, _: B256) -> SignerFuture<'_, Signature> {
        Box::pin(async {
            Err(usdcx_kms_signer::SignerError::new(
                "PRIVATE_AWS_SIGN_SENTINEL password SECRET",
            ))
        })
    }
}

#[tokio::test]
async fn startup_events_keep_controlled_reasons_without_private_error_chains() {
    let events = Events::default();
    let _capture = tracing::subscriber::set_default(events.clone());
    let (dir, c, signer, _state, task) = server().await;
    let profile = dir.path().join("config.json");
    std::fs::write(
        &profile,
        br#"{"PRIVATE_CONFIG_SENTINEL":"https://name:password@rpc.invalid/?token=SECRET"}"#,
    )
    .unwrap();
    let error = crate::run(&profile, false, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_err();
    crate::report_failure(&error);
    assert_eq!(
        events
            .matching("configuration", "configuration_invalid")
            .len(),
        1
    );
    std::fs::write(&profile, serde_json::to_vec(&c).unwrap()).unwrap();
    let store = Store::open(&c, true).unwrap();
    let error = crate::run(&profile, false, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_err();
    crate::report_failure(&error);
    assert_eq!(events.matching("journal_open", "journal_owned").len(), 1);
    drop(store);
    let mut changed = c.clone();
    changed.max_gas += 1;
    std::fs::write(&profile, serde_json::to_vec(&changed).unwrap()).unwrap();
    let error = crate::run(&profile, false, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_err();
    crate::report_failure(&error);
    assert_eq!(
        events
            .matching("journal_open", "journal_identity_mismatch")
            .len(),
        1
    );
    let mut bad = c.clone();
    bad.helper_code_hash = B256::repeat_byte(99);
    let store = Store::open(&c, false).unwrap();
    let error = worker::Worker::new(bad, store, Box::new(signer.clone()))
        .await
        .err()
        .unwrap();
    crate::report_failure(&error);
    assert_eq!(
        events.matching("startup", "helper_runtime_mismatch").len(),
        1
    );
    let store = Store::open(&c, false).unwrap();
    let error = worker::Worker::new(
        c.clone(),
        store,
        Box::new(FailingSigner {
            key: signer.clone(),
            public_failure: true,
        }),
    )
    .await
    .err()
    .unwrap();
    crate::report_failure(&error);
    assert_eq!(
        events
            .matching("signer_connect", "signer_unavailable")
            .len(),
        1
    );
    let mut bad = c.clone();
    bad.arc_rpc = "http://name:password@127.0.0.1:1/?token=SECRET"
        .parse()
        .unwrap();
    let store = Store::open(&c, false).unwrap();
    let error = worker::Worker::new(bad, store, Box::new(signer))
        .await
        .err()
        .unwrap();
    crate::report_failure(&error);
    assert_eq!(events.matching("startup", "provider_unavailable").len(), 1);
    let error = crate::diagnostics::at(
        anyhow::anyhow!("PRIVATE_AWS_AUTH_SENTINEL password SECRET"),
        "signer_connect",
        "authentication_or_key_unavailable",
    );
    crate::report_failure(&error);
    assert_eq!(
        events
            .matching("signer_connect", "authentication_or_key_unavailable")
            .len(),
        1
    );
    events.sanitized();
    task.abort();
}

#[tokio::test]
async fn actual_worker_preparation_and_nonce_events_identify_work_and_preserve_retry() {
    for reason in [
        "simulation_failed",
        "gas_cap_exceeded",
        "fee_cap_exceeded",
        "insufficient_gas_balance",
        "signing_failed",
        "provider_unavailable",
    ] {
        let events = Events::default();
        let _capture = tracing::subscriber::set_default(events.clone());
        let (_dir, mut c, signer, state, task) = server().await;
        match reason {
            "simulation_failed" => state.lock().unwrap().simulation_fail = true,
            "gas_cap_exceeded" => c.max_gas = 1,
            "fee_cap_exceeded" => c.max_fee_per_gas = 1,
            "insufficient_gas_balance" => state.lock().unwrap().low_balance = true,
            "provider_unavailable" => state.lock().unwrap().nonce_failure = true,
            _ => {}
        }
        state.lock().unwrap().config = c.clone();
        let mut store = Store::open(&c, true).unwrap();
        let hash = B256::repeat_byte(78).to_string();
        let message = admit(&mut store, &c, &hash, 1).remove(0);
        let signer: Box<dyn Signer> = if reason == "signing_failed" {
            Box::new(FailingSigner {
                key: signer,
                public_failure: false,
            })
        } else {
            Box::new(signer)
        };
        let mut worker = worker::Worker::new(c, store, signer).await.unwrap();
        worker.cycle().await.unwrap();
        let stage = if reason == "provider_unavailable" {
            "nonce_lookup"
        } else {
            "preparation"
        };
        let matching = events.matching(stage, reason);
        assert_eq!(matching.len(), 1, "{reason}");
        assert_eq!(matching[0]["source_tx"], hash);
        assert_eq!(matching[0]["cctp_nonce"], message.nonce.to_string());
        assert_eq!(matching[0]["domain"], "0");
        assert_eq!(matching[0]["eoa_nonce"], "0");
        assert!(worker.store.pending().unwrap().is_none());
        assert!(!worker.store.halted().unwrap());
        assert!(state.lock().unwrap().sends.is_empty());
        let status: String = worker
            .store
            .db
            .query_row("SELECT state FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "queued");
        events.sanitized();
        task.abort();
    }
}

#[tokio::test]
async fn durable_terminal_events_follow_commit_once_and_failed_sql_emits_no_transition() {
    let events = Events::default();
    let _capture = tracing::subscriber::set_default(events.clone());
    let (_dir, c, signer, state, task) = server().await;
    let mut store = Store::open(&c, true).unwrap();
    let hash = B256::repeat_byte(80).to_string();
    let mut unsupported = page(&c, &hash, 1);
    unsupported.transactions[0].manual = true;
    store.db.execute_batch("CREATE TRIGGER no_cursor BEFORE UPDATE ON sources BEGIN SELECT RAISE(ABORT,'PRIVATE_SQL_SENTINEL'); END;").unwrap();
    assert!(store.page(&c, 0, &unsupported).is_err());
    assert!(events
        .matching("source_manual", "unsupported helper event")
        .is_empty());
    store.db.execute_batch("DROP TRIGGER no_cursor").unwrap();
    store.page(&c, 0, &unsupported).unwrap();
    store
        .manual(
            &Job {
                domain: 0,
                transaction: hash.clone(),
            },
            "unsupported helper event",
        )
        .unwrap();
    assert_eq!(
        events
            .matching("source_manual", "unsupported helper event")
            .len(),
        1
    );
    let manual_hash = B256::repeat_byte(81).to_string();
    store.page(&c, 0, &page(&c, &manual_hash, 1)).unwrap();
    let job = Job {
        domain: 0,
        transaction: manual_hash.clone(),
    };
    store.manual(&job, "invalid Circle response").unwrap();
    store.manual(&job, "invalid Circle response").unwrap();
    assert_eq!(
        events
            .matching("source_manual", "invalid Circle response")
            .len(),
        1
    );
    let message = admit(&mut store, &c, &B256::repeat_byte(82).to_string(), 1).remove(0);
    let arc = sender(&c).await;
    let pending = arc.prepare(&c, &message, 0, &signer, 0).await.unwrap();
    arc.submit(&c, &mut store, &pending).await.unwrap();
    state.lock().unwrap().receipt = receipt(&c, &pending, 0);
    store.db.execute_batch("CREATE TRIGGER no_nonce BEFORE UPDATE OF next_nonce ON meta BEGIN SELECT RAISE(ABORT,'PRIVATE_SQL_SENTINEL'); END;").unwrap();
    assert!(arc.reconcile(&c, &mut store, &pending, 1).await.is_err());
    assert!(events.matching("settlement", "paid_revert").is_empty());
    assert!(store.pending().unwrap().is_some());
    store.db.execute_batch("DROP TRIGGER no_nonce").unwrap();
    arc.reconcile(&c, &mut store, &pending, 1).await.unwrap();
    assert!(store.settle(&pending, false).is_err());
    let paid = events.matching("settlement", "paid_revert");
    assert_eq!(paid.len(), 1);
    assert_eq!(paid[0]["arc_tx"], pending.hash.to_string());
    assert_eq!(paid[0]["source_tx"], message.transaction);
    assert_eq!(paid[0]["cctp_nonce"], message.nonce.to_string());
    assert_eq!(store.next_nonce().unwrap(), 1);
    assert!(store.ready(100).unwrap().is_none());
    store.source_halt(0, "invalid_source_history").unwrap();
    store.source_halt(0, "invalid_source_history").unwrap();
    assert_eq!(
        events
            .matching("source_halt", "invalid_source_history")
            .len(),
        1
    );
    store
        .halt("unknown sender nonce; manual recovery required")
        .unwrap();
    store
        .halt("unknown sender nonce; manual recovery required")
        .unwrap();
    assert_eq!(
        events
            .matching(
                "sender_halt",
                "unknown sender nonce; manual recovery required"
            )
            .len(),
        1
    );
    events.sanitized();
    task.abort();
}
