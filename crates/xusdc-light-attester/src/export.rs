//! Optional, serialized publication of the withdrawal ID lookup to S3.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{retry::RetryConfig, timeout::TimeoutConfig};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use usdcx_telemetry::FailureClass::{Actionable, Transient};
use usdcx_telemetry::{Classify, Failure, FailureContext};

use crate::store::ExportRecord;

const INITIALIZATION_TIMEOUT: Duration = Duration::from_secs(10);
const PUT_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
// Both lookup formats fit well within 1 KiB. Bound downloads even for a misconfigured prefix.
const MAX_LOOKUP_BYTES: usize = 1024;
// A canonical note ID uses 66 ASCII bytes and its extension uses another five.
const MAX_PREFIX_BYTES: usize = 1024 - 66 - 5;

/// A bucket and normalized object prefix identify one independently acknowledged destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExportConfig {
    bucket: String,
    prefix: String,
}

impl ExportConfig {
    pub(crate) fn from_url(url: &str) -> Result<Self> {
        let destination = url
            .strip_prefix("s3://")
            .context("export URL must start with s3://")?;
        if let Some(character) = destination
            .chars()
            .find(|character| matches!(character, '?' | '#' | '@' | ':'))
        {
            anyhow::bail!("export URL must not contain {character:?} after s3://");
        }

        let (bucket, prefix) = destination.split_once('/').unwrap_or((destination, ""));
        ensure!(!bucket.is_empty(), "export URL must contain a bucket name");
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
        Ok(Self {
            bucket: bucket.to_owned(),
            prefix,
        })
    }

    pub(crate) fn bucket(&self) -> &str {
        &self.bucket
    }

    pub(crate) fn prefix(&self) -> &str {
        &self.prefix
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
    batches: mpsc::Sender<Vec<ExportRecord>>,
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

    /// The slot stays reserved until the store owner takes the completion.
    pub(crate) fn has_in_flight_batch(&self) -> bool {
        self.in_flight
    }

    pub(crate) fn try_send(&mut self, batch: Vec<ExportRecord>) -> bool {
        if self.has_in_flight_batch() {
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
    mut batches: mpsc::Receiver<Vec<ExportRecord>>,
    completions: mpsc::Sender<ExportCompletion>,
) {
    while let Some(batch) = batches.recv().await {
        // Loading the default providers may do IO. It happens only here, after receiving work.
        let initialized = match &mut client {
            Some(client) => Ok(client),
            slot @ None => match load_client().await {
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

async fn load_client() -> Result<Client, Failure> {
    tokio::time::timeout(INITIALIZATION_TIMEOUT, async {
        let sdk = aws_config::defaults(BehaviorVersion::latest())
            .retry_config(RetryConfig::standard().with_max_attempts(3))
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(3))
                    .read_timeout(Duration::from_secs(5))
                    .operation_attempt_timeout(Duration::from_secs(5))
                    .operation_timeout(PUT_TIMEOUT)
                    .build(),
            )
            .load()
            .await;
        sdk.region()
            .context("S3 export region is unresolved. Set AWS_REGION or configure the AWS region provider")
            .classify(Actionable("s3_export"))?;
        Ok(Client::new(&sdk))
    })
    .await
    .context("S3 export SDK initialization timed out")
    .classify(Transient("s3_export"))?
}

async fn put_batch(
    client: &Client,
    config: &ExportConfig,
    batch: Vec<ExportRecord>,
) -> ExportCompletion {
    let mut completion = ExportCompletion {
        last_uploaded_seq: None,
        error: None,
    };
    for record in batch {
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
        revision: i64,
    }
    let body = serde_json::to_vec(&Lookup {
        withdrawal_id: record.withdrawal_id.as_deref(),
        revision: record.revision,
    })
    .context("serialize S3 withdrawal ID lookup")
    .classify(Actionable("s3_export"))?;
    let key = format!("{}{}.json", config.prefix(), record.note_id.to_hex());
    let put = || {
        client
            .put_object()
            .bucket(config.bucket())
            .key(&key)
            .content_type("application/json")
            .cache_control("max-age=10")
            .body(ByteStream::from(body.clone()))
    };

    tokio::time::timeout(PUT_TIMEOUT, async {
        match put().if_none_match("*").send().await {
            Ok(_) => return Ok(()),
            Err(error)
                if error
                    .raw_response()
                    .is_some_and(|r| r.status().as_u16() == 412) => {}
            Err(error) => {
                return Err(s3_failure(error).context("S3 export PutObject request failed"))
            }
        }

        let current = client
            .get_object()
            .bucket(config.bucket())
            .key(&key)
            .send()
            .await
            .map_err(s3_failure)
            .context("S3 export GetObject request failed")?;
        let mut bytes = Vec::new();
        current
            .body
            .into_async_read()
            .take((MAX_LOOKUP_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .context("read S3 lookup body")
            .classify(Transient("s3_export"))?;
        if stored_revision(&bytes).classify(Actionable("s3_export"))? >= record.revision {
            return Ok(());
        }
        let etag = current
            .e_tag
            .filter(|tag| tag.starts_with('"') && tag.ends_with('"'))
            .context("S3 lookup has no usable ETag")
            .classify(Actionable("s3_export"))?;
        // A competing update invalidates this ETag. Leave the record pending for the next batch.
        put()
            .if_match(etag)
            .send()
            .await
            .map_err(s3_failure)
            .context("S3 export conditional PutObject request failed")?;
        Ok(())
    })
    .await
    .context("S3 lookup publication timed out")
    .classify(Transient("s3_export"))?
}

fn stored_revision(bytes: &[u8]) -> Result<i64> {
    ensure!(
        bytes.len() <= MAX_LOOKUP_BYTES,
        "S3 lookup exceeds {MAX_LOOKUP_BYTES} bytes"
    );
    let lookup: serde_json::Value =
        serde_json::from_slice(bytes).context("parse S3 lookup JSON")?;
    ensure!(
        lookup
            .get("withdrawal_id")
            .is_some_and(|id| id.is_null() || id.is_string()),
        "S3 lookup has an invalid withdrawal_id"
    );
    match lookup.get("revision") {
        // Objects written before revisions contained only the withdrawal ID.
        None => Ok(0),
        Some(value) => value
            .as_i64()
            .filter(|revision| *revision > 0)
            .context("S3 lookup revision must be a positive integer"),
    }
}

fn s3_failure(error: impl ProvideErrorMetadata + Into<anyhow::Error>) -> Failure {
    let class = if error.code() == Some("AccessDenied") {
        Actionable("s3_export")
    } else {
        Transient("s3_export")
    };
    Failure::new(class, error)
}

#[cfg(test)]
pub(crate) mod tests;
