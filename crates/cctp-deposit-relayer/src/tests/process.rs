use super::*;
#[tokio::test]
#[ignore = "isolated child; invoked by actual process-kill parent"]
async fn child_entrypoint() {
    let path = std::env::var("CCTP_CHILD_CONFIG").unwrap();
    let c = Config::load(std::path::Path::new(&path)).unwrap();
    let key = TestSigner::from_bytes(
        hex::decode(std::env::var("CCTP_CHILD_KEY").unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let marker = std::path::PathBuf::from(std::env::var("CCTP_CHILD_MARKER").unwrap());
    let hold = std::env::var("CCTP_CHILD_MODE").unwrap() == "pre";
    let mut store = Store::open(&c, false).unwrap();
    let arc = sender(&c).await;
    let message = store.ready(circle::now()).unwrap().unwrap();
    if hold {
        store
            .db
            .create_scalar_function(
                "uncommitted_boundary",
                0,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                move |_| -> rusqlite::Result<i64> {
                    std::fs::write(&marker, "actual-pending-insert-uncommitted").unwrap();
                    loop {
                        std::thread::park();
                    }
                },
            )
            .unwrap();
        store.db.execute_batch("CREATE TEMP TRIGGER hold_uncommitted AFTER INSERT ON pending BEGIN SELECT uncommitted_boundary(); END;").unwrap();
    }
    let p = arc
        .prepare(
            &c,
            &message,
            store.next_nonce().unwrap(),
            &key,
            circle::now(),
        )
        .await
        .unwrap();
    arc.submit(&c, &mut store, &p).await.unwrap();
    println!("CHILD_ACTUAL_SUBMIT_COMMITTED");
    std::future::pending::<()>().await;
}
#[tokio::test]
async fn actual_child_kill_before_and_after_commit_reopens_exact_continuity() {
    for mode in ["pre", "post"] {
        let (dir, c, key, state, task) = server().await;
        let mut store = Store::open(&c, true).unwrap();
        admit(&mut store, &c, &B256::repeat_byte(1).to_string(), 1);
        drop(store);
        let profile = dir.path().join("config.json");
        std::fs::write(&profile, serde_json::to_vec(&c).unwrap()).unwrap();
        let marker = dir.path().join("boundary");
        if mode == "post" {
            state.lock().unwrap().marker = Some(marker.clone());
        }
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::process::child_entrypoint",
                "--ignored",
                "--nocapture",
            ])
            .env("CCTP_CHILD_CONFIG", profile)
            .env("CCTP_CHILD_KEY", hex::encode(key.0.to_bytes()))
            .env("CCTP_CHILD_MARKER", &marker)
            .env("CCTP_CHILD_MODE", mode)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !marker.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "child did not reach {mode} boundary; exit {:?}",
                child.try_wait().unwrap()
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        child.kill().await.unwrap();
        let _ = child.wait().await.unwrap();
        let mut reopened = Store::open(&c, false).unwrap();
        if mode == "pre" {
            assert!(reopened.pending().unwrap().is_none());
            assert!(state.lock().unwrap().sends.is_empty());
        } else {
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "committed");
            let p = reopened.pending().unwrap().unwrap();
            let arc = sender(&c).await;
            arc.reconcile(&c, &mut reopened, &p, circle::now())
                .await
                .unwrap();
            assert_eq!(reopened.pending().unwrap().unwrap().raw, p.raw);
            assert!(state.lock().unwrap().sends.iter().all(|raw| *raw == p.raw));
        }
        println!("ACTUAL_CHILD_KILL_{mode}_PASS");
        task.abort();
    }
}
