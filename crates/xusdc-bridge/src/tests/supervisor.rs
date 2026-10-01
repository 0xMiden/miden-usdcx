use std::cell::Cell;
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::time::{Duration, Instant};

use rstest::rstest;

use super::*;

#[tokio::test]
async fn startup_gate_prevents_work_and_shutdown_joins_the_worker() {
    let mut shutdown = Shutdown::new(Duration::from_secs(5));
    let began = Arc::new(AtomicBool::new(false));
    let observed = began.clone();
    let mut worker = RelayerWorker::spawn(&mut shutdown, move || {
        Ok(move |stop: mpsc::Receiver<()>| {
            observed.store(true, Ordering::SeqCst);
            let _ = stop.recv();
            Ok(())
        })
    })
    .unwrap();
    (&mut worker.ready).await.unwrap();
    assert!(!began.load(Ordering::SeqCst));
    shutdown.begin_relayer().unwrap();
    shutdown.request();
    worker.join().await.unwrap();
    assert!(began.load(Ordering::SeqCst));
    shutdown.finish();
}

#[tokio::test]
async fn startup_failure_keeps_the_run_gate_closed() {
    let mut shutdown = Shutdown::new(Duration::from_secs(5));
    let mut worker = RelayerWorker::spawn(
        &mut shutdown,
        || -> Result<fn(mpsc::Receiver<()>) -> Result<()>> {
            bail!("relayer startup test failure")
        },
    )
    .unwrap();
    assert_eq!(
        (&mut worker.ready).await.unwrap_err().to_string(),
        "channel closed"
    );
    shutdown.request();
    assert_eq!(
        worker.join().await.unwrap_err().to_string(),
        "relayer startup test failure"
    );
    shutdown.finish();
}

#[tokio::test]
async fn cancellation_during_startup_drops_the_prepared_worker_without_running() {
    let mut shutdown = Shutdown::new(Duration::from_secs(5));
    let (continue_startup, wait) = mpsc::channel();
    let began = Arc::new(AtomicBool::new(false));
    let observed = began.clone();
    let worker = RelayerWorker::spawn(&mut shutdown, move || {
        wait.recv().unwrap();
        Ok(move |_stop| {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        })
    })
    .unwrap();
    shutdown.request();
    continue_startup.send(()).unwrap();
    worker.join().await.unwrap();
    assert!(!began.load(Ordering::SeqCst));
    shutdown.finish();
}

#[rstest]
#[case::failure(false, "relayer failed: relay test failure")]
#[case::panic(true, "relayer failed: relayer panicked")]
#[tokio::test]
async fn relayer_failure_drains_the_attester(#[case] panic: bool, #[case] expected: &str) {
    let mut shutdown = Shutdown::new(Duration::from_secs(5));
    let mut worker = RelayerWorker::spawn(&mut shutdown, move || {
        Ok(move |_stop| {
            assert!(!panic, "test relayer panic");
            bail!("relay test failure")
        })
    })
    .unwrap();
    (&mut worker.ready).await.unwrap();
    shutdown.begin_relayer().unwrap();
    let token = shutdown.token.clone();
    let finished = Cell::new(false);
    let attester = async {
        token.cancelled().await;
        tokio::task::yield_now().await;
        finished.set(true);
        Ok(())
    };
    let result = monitor(
        attester,
        worker.join(),
        std::future::pending(),
        &mut shutdown,
    )
    .await;
    assert_eq!(format!("{:#}", result.unwrap_err()), expected);
    assert!(finished.get());
    shutdown.finish();
}

#[rstest]
#[case::signal(false)]
#[case::worker_cancel(true)]
#[tokio::test]
async fn shutdown_retains_both_futures(#[case] worker_cancel: bool) {
    let mut shutdown = Shutdown::new(Duration::from_secs(5));
    let token = shutdown.token.clone();
    let attester_done = Cell::new(false);
    let relayer_done = Cell::new(false);
    let attester = async {
        if worker_cancel {
            token.cancel();
        }
        token.cancelled().await;
        tokio::task::yield_now().await;
        attester_done.set(true);
        Ok(())
    };
    let relayer = async {
        token.cancelled().await;
        relayer_done.set(true);
        Ok(())
    };
    let signal = async {
        if worker_cancel {
            std::future::pending::<()>().await;
        }
        Ok(())
    };
    monitor(attester, relayer, signal, &mut shutdown)
        .await
        .unwrap();
    assert!(attester_done.get() && relayer_done.get());
    shutdown.finish();
}

#[rstest]
#[case::return_ok(false, "attester stopped unexpectedly")]
#[case::panic(true, "attester failed: attester panicked")]
#[tokio::test]
async fn unexpected_attester_exit_stops_the_relayer(#[case] panic: bool, #[case] expected: &str) {
    let mut shutdown = Shutdown::new(Duration::from_secs(5));
    let token = shutdown.token.clone();
    let stopped = Cell::new(false);
    let relayer = async {
        token.cancelled().await;
        stopped.set(true);
        Ok(())
    };
    let attester = guarded("attester", async {
        assert!(!panic, "test attester panic");
        Ok(())
    });
    let result = monitor(attester, relayer, std::future::pending(), &mut shutdown).await;
    assert_eq!(format!("{:#}", result.unwrap_err()), expected);
    assert!(stopped.get());
    shutdown.finish();
}

#[test]
fn deadline_kills_the_process() {
    const CHILD: &str = "XUSDC_BRIDGE_DEADLINE_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let mut shutdown = Shutdown::new(Duration::from_millis(50));
        shutdown.request();
        let (_held, wait) = mpsc::channel::<()>();
        let _ = wait.recv();
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "supervisor::tests::deadline_kills_the_process",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if started.elapsed() > Duration::from_secs(5) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("shutdown deadline left the process running");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("bridge shutdown did not finish"));
}

#[test]
fn process_signals_stop_both_services() {
    const READY: &str = "XUSDC_BRIDGE_SIGNAL_TEST_READY";
    if let Some(path) = std::env::var_os(READY) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut signals = Signals::install().unwrap();
            let mut shutdown = Shutdown::new(Duration::from_secs(2));
            let mut worker = RelayerWorker::spawn(&mut shutdown, || {
                Ok(|stop: mpsc::Receiver<()>| {
                    let _ = stop.recv();
                    Ok(())
                })
            })
            .unwrap();
            (&mut worker.ready).await.unwrap();
            shutdown.begin_relayer().unwrap();
            let token = shutdown.token.clone();
            let attester = async {
                token.cancelled().await;
                tokio::task::yield_now().await;
                Ok(())
            };
            std::fs::write(&path, "ready").unwrap();
            monitor(attester, worker.join(), signals.recv(), &mut shutdown)
                .await
                .unwrap();
            shutdown.finish();
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
                "supervisor::tests::process_signals_stop_both_services",
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
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{signal}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_to_string(&ready).unwrap(), "stopped");
    }
}
