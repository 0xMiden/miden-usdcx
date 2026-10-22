//! Store-owner checkpoints for the optional S3 worker. No checkpoint awaits network IO.

use std::time::Duration;

use tokio::time::Instant;
use tracing::info_span;
use usdcx_telemetry::{Failure, FailureClass::Actionable};

use crate::export::{ExportConfig, Exporter};
use crate::store::Store;

const INTERVAL: Duration = Duration::from_secs(10);
const BATCH_SIZE: usize = 100;

pub(crate) struct ExportRuntime {
    destination: String,
    exporter: Exporter,
    next_tick: Instant,
}

impl ExportRuntime {
    pub(super) fn start(config: ExportConfig) -> Self {
        let exporter = Exporter::start(config.clone());
        Self::with_exporter(config, exporter)
    }

    pub(crate) fn with_exporter(config: ExportConfig, exporter: Exporter) -> Self {
        Self {
            destination: config.destination_key(),
            exporter,
            next_tick: Instant::now(),
        }
    }

    pub(super) fn next_tick(&self) -> Instant {
        self.next_tick
    }

    pub(crate) fn checkpoint(&mut self, store: &mut Store) {
        if let Some(completion) = self.exporter.try_complete() {
            if let Some(last_uploaded_seq) = completion.last_uploaded_seq {
                if let Err(error) = store.ack_export(&self.destination, last_uploaded_seq) {
                    // Unchanged durable progress leaves these snapshots pending for replay.
                    report_failure(
                        Failure::new(Actionable("store"), error),
                        "failed to save S3 export progress; replaying",
                    );
                }
            }
            if let Some(error) = completion.error {
                report_failure(error, "S3 withdrawal lookup export failed");
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
                report_failure(
                    Failure::new(Actionable("store"), error),
                    "failed to read S3 export batch; retrying",
                );
            }
        }
    }

    pub(crate) async fn shutdown(self) {
        self.exporter.shutdown().await;
    }
}

fn report_failure(failure: Failure, message: &str) {
    info_span!(parent: None, "attester.export").in_scope(|| failure.report(message));
}
