use std::cell::Cell;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::*;

#[tokio::test]
async fn shutdown_drains_both_services() {
    let shutdown = CancellationToken::new();
    let (stop, wait) = mpsc::channel();
    let relayer = tokio::task::spawn_blocking(move || {
        assert!(wait.recv().is_err());
        Ok(())
    });
    let finished = Cell::new(false);
    let attester = async {
        shutdown.cancelled().await;
        tokio::task::yield_now().await;
        finished.set(true);
        Ok(())
    };
    monitor(
        attester,
        async { relayer.await? },
        async { Ok(()) },
        shutdown.clone(),
        stop,
    )
    .await
    .unwrap();
    assert!(finished.get());
}

#[tokio::test]
async fn service_failure_stops_its_peer() {
    for attester_fails in [false, true] {
        let shutdown = CancellationToken::new();
        let (stop, wait) = mpsc::channel();
        let relayer = tokio::task::spawn_blocking(move || {
            if !attester_fails {
                bail!("relay failure");
            }
            assert!(wait.recv().is_err());
            Ok(())
        });
        let attester = guarded(async {
            if attester_fails {
                panic!("attester test panic");
            }
            shutdown.cancelled().await;
            Ok(())
        });
        let result = monitor(
            attester,
            async { relayer.await? },
            std::future::pending(),
            shutdown.clone(),
            stop,
        )
        .await;
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains(if attester_fails {
            "attester panicked"
        } else {
            "relay failure"
        }));
        assert!(shutdown.is_cancelled());
    }
}

#[test]
fn process_signal_stops_both_services() {
    const READY: &str = "XUSDC_BRIDGE_SIGNAL_TEST_READY";
    if let Some(path) = std::env::var_os(READY) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut signals = Signals::install().unwrap();
            let shutdown = CancellationToken::new();
            let (stop, wait) = mpsc::channel();
            let relayer = tokio::task::spawn_blocking(move || {
                assert!(wait.recv().is_err());
                Ok(())
            });
            let attester = async {
                shutdown.cancelled().await;
                Ok(())
            };
            std::fs::write(&path, "ready").unwrap();
            monitor(
                attester,
                async { relayer.await? },
                signals.recv(),
                shutdown.clone(),
                stop,
            )
            .await
            .unwrap();
            std::fs::write(path, "stopped").unwrap();
        });
        return;
    }
    for signal in ["-TERM", "-INT"] {
        let directory = tempfile::TempDir::new().unwrap();
        let ready = directory.path().join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "supervisor::tests::process_signal_stops_both_services",
                "--nocapture",
            ])
            .env(READY, &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        while !ready.exists() {
            if started.elapsed() > Duration::from_secs(5) || child.try_wait().unwrap().is_some() {
                let _ = child.kill();
                panic!(
                    "signal test child failed before readiness: {:?}",
                    child.wait_with_output().unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(Command::new("kill")
            .args([signal, &child.id().to_string()])
            .status()
            .unwrap()
            .success());
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > Duration::from_secs(5) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("process did not stop after {signal}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(child.wait_with_output().unwrap().status.success());
        assert_eq!(std::fs::read_to_string(&ready).unwrap(), "stopped");
    }
}
