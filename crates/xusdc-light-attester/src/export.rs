//! Optional, serialized publication of the withdrawal ID lookup to S3.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{retry::RetryConfig, timeout::TimeoutConfig};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use serde::Serialize;
use tokio::sync::OnceCell;
use tokio::task::JoinSet;
use usdcx_telemetry::FailureClass::{Actionable, Transient};
use usdcx_telemetry::{Classify, Failure, FailureContext};

use crate::store::ExportRecord;

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

impl ExportCompletion {
    fn failed(error: Failure) -> Self {
        Self {
            last_uploaded_seq: None,
            error: Some(error),
        }
    }
}

/// One task uploads a batch while the attester continues processing withdrawals.
pub(crate) struct Exporter {
    config: ExportConfig,
    client: Arc<OnceCell<Client>>,
    task: JoinSet<ExportCompletion>,
}

impl Exporter {
    pub(crate) fn new(config: ExportConfig) -> Self {
        Self {
            config,
            client: Arc::new(OnceCell::new()),
            task: JoinSet::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_client(config: ExportConfig, client: Client) -> Self {
        Self {
            client: Arc::new(OnceCell::from(client)),
            ..Self::new(config)
        }
    }

    /// A finished batch still owns the slot until the attester collects its result.
    pub(crate) fn has_in_flight_batch(&self) -> bool {
        !self.task.is_empty()
    }

    pub(crate) fn try_send(&mut self, batch: Vec<ExportRecord>) -> bool {
        if self.has_in_flight_batch() {
            return false;
        }
        let config = self.config.clone();
        let client = self.client.clone();
        self.task.spawn(async move {
            match client.get_or_try_init(load_client).await {
                Ok(client) => put_batch(client, &config, batch).await,
                Err(error) => ExportCompletion::failed(error),
            }
        });
        true
    }

    pub(crate) fn try_complete(&mut self) -> Option<ExportCompletion> {
        let result = self.task.try_join_next()?;
        Some(result.unwrap_or_else(|error| {
            ExportCompletion::failed(Failure::new(
                Actionable("s3_export"),
                anyhow!(error).context("S3 export task stopped before reporting completion"),
            ))
        }))
    }

    pub(crate) async fn shutdown(mut self) {
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, self.task.shutdown()).await;
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
