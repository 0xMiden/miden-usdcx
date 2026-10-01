use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};

use anyhow::{anyhow, Context, Result};
use tokio::sync::oneshot;

use crate::shutdown::Shutdown;

pub(crate) struct RelayerWorker {
    pub(crate) ready: oneshot::Receiver<()>,
    done: oneshot::Receiver<Result<()>>,
    thread: JoinHandle<()>,
}

impl RelayerWorker {
    pub(crate) fn spawn<F, R>(shutdown: &mut Shutdown, prepare: F) -> Result<Self>
    where
        F: FnOnce() -> Result<R> + Send + 'static,
        R: FnOnce(Receiver<()>) -> Result<()>,
    {
        let (ready, ready_rx) = oneshot::channel();
        let (done, done_rx) = oneshot::channel();
        let (begin, begin_rx) = mpsc::channel();
        let (stop, stop_rx) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("deposit-relayer".into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let run = prepare()?;
                    if ready.send(()).is_err() || begin_rx.recv().is_err() {
                        return Ok(());
                    }
                    run(stop_rx)
                }))
                .unwrap_or_else(|_| Err(anyhow!("relayer panicked")));
                let _ = done.send(result);
            })
            .context("failed to start relayer thread")?;
        shutdown.start_relayer = Some(begin);
        shutdown.stop_relayer = Some(stop);
        Ok(Self {
            ready: ready_rx,
            done: done_rx,
            thread,
        })
    }

    pub(crate) async fn join(self) -> Result<()> {
        let result = self.done.await.context("relayer result channel closed");
        self.thread
            .join()
            .map_err(|_| anyhow!("relayer thread panicked"))?;
        result?
    }
}
