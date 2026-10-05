use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;

use super::*;

/// A relayer stand-in that runs until its stop channel closes.
fn relayer_until_stopped() -> (mpsc::Sender<()>, impl Future<Output = Result<()>>) {
    let (stop, wait) = mpsc::channel::<()>();
    let relayer = tokio::task::spawn_blocking(move || {
        assert!(wait.recv().is_err());
        Ok(())
    });
    (stop, async { relayer.await? })
}

#[tokio::test]
async fn shutdown_stops_both_services() {
    let shutdown = CancellationToken::new();
    let (stop, relayer) = relayer_until_stopped();
    let attester = async {
        shutdown.cancelled().await;
        Ok(())
    };
    shutdown.cancel();
    supervise(attester, relayer, stop, shutdown.clone())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_failed_relayer_stops_the_attester() {
    let shutdown = CancellationToken::new();
    let (stop, _wait) = mpsc::channel();
    let attester = async {
        shutdown.cancelled().await;
        Ok(())
    };
    let relayer = async { bail!("relayer test failure") };
    let error = supervise(attester, relayer, stop, shutdown.clone())
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("relayer test failure"));
}

#[tokio::test]
async fn a_service_that_stops_early_is_an_error_and_stops_its_peer() {
    let shutdown = CancellationToken::new();
    let (stop, relayer) = relayer_until_stopped();
    let error = supervise(async { Ok(()) }, relayer, stop, shutdown.clone())
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("attester stopped unexpectedly"));
}

#[test]
fn an_attester_panic_lets_the_relayer_finish_before_the_process_ends() {
    let relayer_finished = Arc::new(AtomicBool::new(false));
    let finished = relayer_finished.clone();
    let bridge = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (stop, wait) = mpsc::channel::<()>();
            let relayer = tokio::task::spawn_blocking(move || {
                assert!(wait.recv().is_err());
                // Stands in for the page the relayer finishes after shutdown is requested.
                std::thread::sleep(Duration::from_millis(200));
                finished.store(true, Ordering::SeqCst);
                Ok(())
            });
            let attester = async {
                tokio::task::yield_now().await;
                panic!("attester test panic")
            };
            supervise(
                attester,
                async { relayer.await? },
                stop,
                CancellationToken::new(),
            )
            .await
        })
    });
    assert!(bridge.join().is_err());
    assert!(relayer_finished.load(Ordering::SeqCst));
}

#[test]
fn process_signal_stops_both_services() {
    const READY: &str = "USDCX_BRIDGE_SIGNAL_TEST_READY";
    if let Some(path) = std::env::var_os(READY) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let shutdown = CancellationToken::new();
            cancel_on_signal(shutdown.clone()).unwrap();
            let (stop, relayer) = relayer_until_stopped();
            let attester = async {
                shutdown.cancelled().await;
                Ok(())
            };
            std::fs::write(&path, "ready").unwrap();
            supervise(attester, relayer, stop, shutdown.clone())
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
