use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

pub(crate) struct Shutdown {
    pub(crate) token: CancellationToken,
    grace: Duration,
    deadline: Option<Sender<()>>,
    pub(crate) start_relayer: Option<Sender<()>>,
    pub(crate) stop_relayer: Option<Sender<()>>,
}

impl Shutdown {
    pub(crate) fn new(grace: Duration) -> Self {
        Self {
            token: CancellationToken::new(),
            grace,
            deadline: None,
            start_relayer: None,
            stop_relayer: None,
        }
    }

    pub(crate) fn begin_relayer(&mut self) -> Result<()> {
        self.start_relayer
            .take()
            .context("relayer start gate is closed")?
            .send(())
            .context("relayer stopped before its start gate opened")
    }

    pub(crate) fn request(&mut self) {
        if self.deadline.is_none() {
            let (finished, wait) = mpsc::channel();
            let grace = self.grace;
            // The deadline must still expire if the async runtime stops making progress.
            let watchdog = thread::Builder::new().name("bridge-shutdown".into()).spawn(move || {
                if wait.recv_timeout(grace).is_err() {
                    eprintln!("bridge shutdown did not finish within {grace:?}; terminating the process");
                    std::process::exit(1);
                }
            });
            if let Err(error) = watchdog {
                eprintln!("failed to start the shutdown deadline: {error}");
                std::process::exit(1);
            }
            self.deadline = Some(finished);
        }
        self.token.cancel();
        self.start_relayer.take();
        self.stop_relayer.take();
    }

    pub(crate) fn finish(mut self) {
        if let Some(finished) = self.deadline.take() {
            let _ = finished.send(());
        }
    }
}
