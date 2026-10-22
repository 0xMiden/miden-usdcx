//! Optional, serialized publication of the withdrawal ID lookup to S3.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{retry::RetryConfig, timeout::TimeoutConfig, Region};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use usdcx_telemetry::FailureClass::{Actionable, Transient};
use usdcx_telemetry::{Classify, Failure, FailureContext};

use crate::store::{ExportBatch, ExportRecord};

const DEFAULT_PREFIX: &str = "withdrawals/";
const INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(10);
const PUT_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
// A canonical note ID uses 66 ASCII bytes and its extension uses another five.
const MAX_PREFIX_BYTES: usize = 1024 - 66 - 5;

/// A bucket and normalized object prefix identify one independently acknowledged destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExportConfig {
    bucket: String,
    prefix: String,
    region: Option<String>,
}

impl ExportConfig {
    pub(crate) fn new(
        bucket: String,
        prefix: Option<String>,
        region: Option<String>,
    ) -> Result<Self> {
        ensure!(
            (3..=63).contains(&bucket.len())
                && bucket.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'.')
                })
                && bucket.as_bytes()[0].is_ascii_alphanumeric()
                && bucket.as_bytes()[bucket.len() - 1].is_ascii_alphanumeric()
                && !bucket.contains("..")
                && bucket.parse::<Ipv4Addr>().is_err()
                && !["xn--", "sthree-", "amzn-s3-demo-"]
                    .iter()
                    .any(|reserved| bucket.starts_with(reserved))
                && ["-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"]
                    .iter()
                    .all(|reserved| !bucket.ends_with(reserved)),
            "export bucket must be a valid general purpose S3 bucket name"
        );

        let prefix = prefix.unwrap_or_else(|| DEFAULT_PREFIX.to_owned());
        ensure!(
            !prefix.chars().any(char::is_control)
                && !prefix.contains('\\')
                && !prefix.split('/').any(|part| matches!(part, "." | "..")),
            "export prefix must not contain control characters, backslashes or dot path segments"
        );
        let prefix = prefix.trim_matches('/');
        let prefix = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}/")
        };
        ensure!(
            prefix.len() <= MAX_PREFIX_BYTES,
            "export prefix is too long for the S3 object key"
        );
        if let Some(region) = &region {
            ensure!(
                !region.is_empty()
                    && region.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    }),
                "export region must be a nonempty AWS region name"
            );
        }
        Ok(Self {
            bucket,
            prefix,
            region,
        })
    }

    pub(crate) fn bucket(&self) -> &str {
        &self.bucket
    }

    pub(crate) fn prefix(&self) -> &str {
        &self.prefix
    }

    pub(crate) fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// Region changes keep the same cursor; bucket or prefix changes start a separate backfill.
    pub(crate) fn destination_key(&self) -> String {
        format!("s3://{}/{}", self.bucket, self.prefix)
    }
}

/// Only this ordered prefix of the batch is eligible for the store owner's acknowledgement.
#[derive(Debug)]
pub(crate) struct ExportCompletion {
    pub(crate) last_uploaded_seq: Option<i64>,
    pub(crate) error: Option<Failure>,
}

/// The store owner sends immutable snapshots and consumes completions without awaiting network IO.
pub(crate) struct Exporter {
    batches: mpsc::Sender<ExportBatch>,
    completions: mpsc::Receiver<ExportCompletion>,
    in_flight: bool,
    cancellation: CancellationToken,
    worker: Option<JoinHandle<()>>,
}

impl Exporter {
    pub(crate) fn start(config: ExportConfig) -> Self {
        Self::spawn(config, None)
    }

    #[cfg(test)]
    pub(crate) fn with_client(config: ExportConfig, client: Client) -> Self {
        Self::spawn(config, Some(client))
    }

    fn spawn(config: ExportConfig, client: Option<Client>) -> Self {
        let (batches, receiver) = mpsc::channel(1);
        let (sender, completions) = mpsc::channel(1);
        let cancellation = CancellationToken::new();
        let stopped = cancellation.clone();
        let worker = tokio::spawn(async move {
            tokio::select! {
                biased;
                () = stopped.cancelled() => {}
                () = run_worker(config, client, receiver, sender) => {}
            }
        });
        Self {
            batches,
            completions,
            in_flight: false,
            cancellation,
            worker: Some(worker),
        }
    }

    pub(crate) fn try_send(&mut self, batch: ExportBatch) -> bool {
        // Channel capacity alone would allow a second batch after the worker receives the first.
        // Keep ownership of the slot until the owner has consumed and handled its completion.
        if self.in_flight {
            return false;
        }
        if self.batches.try_send(batch).is_err() {
            return false;
        }
        self.in_flight = true;
        true
    }

    pub(crate) fn try_complete(&mut self) -> Option<ExportCompletion> {
        match self.completions.try_recv() {
            Ok(completion) => {
                self.in_flight = false;
                Some(completion)
            }
            Err(mpsc::error::TryRecvError::Disconnected) => std::mem::take(&mut self.in_flight)
                .then(|| ExportCompletion {
                    last_uploaded_seq: None,
                    error: Some(Failure::new(
                        Actionable("s3_export"),
                        anyhow!("S3 export worker stopped before reporting completion"),
                    )),
                }),
            Err(mpsc::error::TryRecvError::Empty) => None,
        }
    }

    /// Cancels pending AWS initialization or PUTs; unacknowledged rows remain durable for replay.
    pub(crate) async fn shutdown(mut self) {
        self.cancellation.cancel();
        if let Some(mut worker) = self.worker.take() {
            if tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut worker)
                .await
                .is_err()
            {
                worker.abort();
                let _ = worker.await;
            }
        }
    }
}

impl Drop for Exporter {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}

async fn run_worker(
    config: ExportConfig,
    mut client: Option<Client>,
    mut batches: mpsc::Receiver<ExportBatch>,
    completions: mpsc::Sender<ExportCompletion>,
) {
    while let Some(batch) = batches.recv().await {
        // Loading the default providers may do IO. It happens only here, after receiving work.
        let initialized = match &mut client {
            Some(client) => Ok(client),
            slot @ None => match load_client(&config).await {
                Ok(loaded) => Ok(slot.insert(loaded)),
                Err(error) => Err(error),
            },
        };
        let completion = match initialized {
            Ok(client) => put_batch(client, &config, batch).await,
            Err(error) => ExportCompletion {
                last_uploaded_seq: None,
                error: Some(error),
            },
        };
        if completions.send(completion).await.is_err() {
            break;
        }
    }
}

async fn load_client(config: &ExportConfig) -> Result<Client, Failure> {
    tokio::time::timeout(INITIALIZATION_TIMEOUT, async {
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .retry_config(RetryConfig::standard().with_max_attempts(3))
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(3))
                    .read_timeout(Duration::from_secs(5))
                    .operation_attempt_timeout(Duration::from_secs(5))
                    .operation_timeout(PUT_TIMEOUT)
                    .build(),
            );
        if let Some(region) = config.region() {
            loader = loader.region(Region::new(region.to_owned()));
        }
        let sdk = loader.load().await;
        sdk.region()
            .context("S3 export region is unresolved; set --export-region or configure the AWS region provider")
            .classify(Actionable("s3_export"))?;
        Ok(Client::new(&sdk))
    })
    .await
    .context("S3 export SDK initialization timed out")
    .classify(Transient("s3_export"))?
}

async fn put_batch(client: &Client, config: &ExportConfig, batch: ExportBatch) -> ExportCompletion {
    let mut completion = ExportCompletion {
        last_uploaded_seq: None,
        error: None,
    };
    for record in batch.records {
        if let Err(error) = put_record(client, config, &record).await {
            completion.error = Some(error);
            break;
        }
        completion.last_uploaded_seq = Some(record.revision);
    }
    completion
}

async fn put_record(
    client: &Client,
    config: &ExportConfig,
    record: &ExportRecord,
) -> Result<(), Failure> {
    #[derive(Serialize)]
    struct Lookup<'a> {
        withdrawal_id: Option<&'a str>,
    }
    let body = serde_json::to_vec(&Lookup {
        withdrawal_id: record.withdrawal_id.as_deref(),
    })
    .context("serialize S3 withdrawal ID lookup")
    .classify(Actionable("s3_export"))?;
    let key = format!("{}{}.json", config.prefix(), record.note_id.to_hex());
    tokio::time::timeout(
        PUT_TIMEOUT,
        client
            .put_object()
            .bucket(config.bucket())
            .key(key)
            .content_type("application/json")
            .cache_control("max-age=10")
            .body(ByteStream::from(body))
            .send(),
    )
    .await
    .context("S3 export PutObject timed out")
    .classify(Transient("s3_export"))?
    .classify_with(|error| {
        if error.as_service_error().and_then(|error| error.code()) == Some("AccessDenied") {
            Actionable("s3_export")
        } else {
            Transient("s3_export")
        }
    })
    .context("S3 export PutObject request failed")?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
