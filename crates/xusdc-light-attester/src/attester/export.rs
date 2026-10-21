//! Store-owner checkpoints for the optional S3 worker. No checkpoint awaits network IO.

use std::time::Duration;

use tokio::time::Instant;
use tracing::warn;

use crate::export::{ExportConfig, Exporter};
use crate::store::Store;

const INTERVAL: Duration = Duration::from_secs(10);
const BATCH_SIZE: usize = 100;

pub(super) struct ExportRuntime {
    destination: String,
    exporter: Exporter,
    next_tick: Instant,
}

impl ExportRuntime {
    pub(super) fn start(config: ExportConfig) -> Self {
        let exporter = Exporter::start(config.clone());
        Self::with_exporter(config, exporter)
    }

    pub(super) fn with_exporter(config: ExportConfig, exporter: Exporter) -> Self {
        Self {
            destination: config.destination_key(),
            exporter,
            next_tick: Instant::now(),
        }
    }

    pub(super) fn next_tick(&self) -> Instant {
        self.next_tick
    }

    pub(super) fn checkpoint(&mut self, store: &mut Store) {
        if let Some(completion) = self.exporter.try_complete() {
            if let Some(completed) = completion.completed {
                if let Err(error) = store.ack_export(&self.destination, completion.after, completed)
                {
                    // The durable cursor is unchanged. Replaying this prefix is safe, and avoids
                    // losing the completion or advancing past an unconfirmed object.
                    warn!(error = %format!("{error:#}"), "failed to save S3 export progress; replaying");
                }
            }
            if let Some(error) = completion.error {
                warn!(error = %format!("{error:#}"), "S3 withdrawal lookup export failed; retrying");
            }
        }
        if Instant::now() < self.next_tick {
            return;
        }
        // Advance the timer even while a request is blocked, so the owner cannot spin.
        self.next_tick = Instant::now() + INTERVAL;
        match store.export_batch(&self.destination, BATCH_SIZE) {
            Ok(batch) if !batch.records.is_empty() => {
                self.exporter.try_send(batch);
            }
            Ok(_) => {}
            Err(error) => {
                warn!(error = %format!("{error:#}"), "failed to read S3 export batch; retrying");
            }
        }
    }

    pub(super) async fn shutdown(self) {
        self.exporter.shutdown().await;
    }
}
