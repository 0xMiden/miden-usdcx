use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;

use super::*;

/// A relayer stand-in that runs until shutdown is requested.
fn relayer_until_shutdown(shutdown: &CancellationToken) -> impl Future<Output = Result<()>> {
    let shutdown = shutdown.clone();
    let relayer = tokio::spawn(async move {
        shutdown.cancelled().await;
        Ok(())
    });
    async { relayer.await? }
}

/// Long enough that no test below reaches it unless it means to.
const TEST_TIMEOUT: Duration = Duration::from_secs(60);

/// An attester stand-in that runs until shutdown is requested.
fn attester_until_shutdown(shutdown: &CancellationToken) -> impl Future<Output = Result<()>> {
    let shutdown = shutdown.clone();
    async move {
        shutdown.cancelled().await;
        Ok(())
    }
}

#[tokio::test]
async fn shutdown_stops_both_services() {
    let shutdown = CancellationToken::new();
    let relayer = relayer_until_shutdown(&shutdown);
    let attester = attester_until_shutdown(&shutdown);
    shutdown.cancel();
    supervise(attester, relayer, shutdown, TEST_TIMEOUT)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_failed_relayer_stops_the_attester() {
    let shutdown = CancellationToken::new();
    let attester = attester_until_shutdown(&shutdown);
    let relayer = async { bail!("relayer test failure") };
    let error = supervise(attester, relayer, shutdown, TEST_TIMEOUT)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("relayer test failure"));
}

#[tokio::test]
async fn a_service_that_stops_early_is_an_error_and_stops_its_peer() {
    let shutdown = CancellationToken::new();
    let relayer = relayer_until_shutdown(&shutdown);
    let error = supervise(async { Ok(()) }, relayer, shutdown, TEST_TIMEOUT)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("attester stopped unexpectedly"));
}

#[tokio::test]
async fn an_attester_panic_is_an_error_after_the_relayer_finishes() {
    let relayer_finished = Arc::new(AtomicBool::new(false));
    let finished = relayer_finished.clone();
    let shutdown = CancellationToken::new();
    let relayer_shutdown = shutdown.clone();
    let relayer = tokio::spawn(async move {
        relayer_shutdown.cancelled().await;
        // Stands in for the page the relayer finishes after shutdown is requested.
        tokio::time::sleep(Duration::from_millis(200)).await;
        finished.store(true, Ordering::SeqCst);
        Ok(())
    });
    let attester = async {
        tokio::task::yield_now().await;
        panic!("attester test panic")
    };
    let error = supervise(attester, async { relayer.await? }, shutdown, TEST_TIMEOUT)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("attester test panic"));
    assert!(relayer_finished.load(Ordering::SeqCst));
}

#[test]
fn an_attester_panic_with_a_stuck_relayer_exits_the_process_after_the_timeout() {
    const CHILD: &str = "USDCX_BRIDGE_PANIC_TEST_CHILD";
    const TIMEOUT: Duration = Duration::from_millis(200);
    if std::env::var_os(CHILD).is_some() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = runtime.block_on(async {
            // Stands in for a relayer waiting on a transaction while the node produces no blocks.
            let relayer = std::future::pending();
            let attester = async {
                tokio::task::yield_now().await;
                panic!("attester test panic")
            };
            supervise(attester, relayer, CancellationToken::new(), TIMEOUT).await
        });
        // Only reached if the supervisor returned instead of terminating the process.
        std::process::exit(0);
    }
    let started = Instant::now();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "supervisor::tests::an_attester_panic_with_a_stuck_relayer_exits_the_process_after_the_timeout",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(10) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("process did not exit after an attester panic");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(1));
    assert!(started.elapsed() >= TIMEOUT);
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
            let relayer = relayer_until_shutdown(&shutdown);
            let attester = attester_until_shutdown(&shutdown);
            std::fs::write(&path, "ready").unwrap();
            supervise(attester, relayer, shutdown, TEST_TIMEOUT)
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
