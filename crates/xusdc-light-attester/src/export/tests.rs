use std::collections::VecDeque;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aws_sdk_s3::config::http::{HttpRequest, HttpResponse};
use aws_sdk_s3::config::{Credentials, IntoShared, Region};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::operation::put_object::PutObjectError;
use aws_smithy_runtime_api::client::http::{http_client_fn, HttpConnector, HttpConnectorFuture};
use miden_protocol::note::NoteId;
use serde_json::json;
use tokio::sync::Notify;

use super::*;

fn config() -> ExportConfig {
    ExportConfig::from_url("s3://withdrawal-lookups/withdrawals/").unwrap()
}

fn record(note: u8, revision: i64, id: Option<&str>) -> ExportRecord {
    ExportRecord {
        note_id: NoteId::try_from_hex(&format!("0x{}", hex::encode([note; 32]))).unwrap(),
        withdrawal_id: id.map(str::to_owned),
        revision,
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Reply {
    Success,
    Denied,
    Block(Arc<Notify>),
}

/// The real S3 serializer and signer run against this connector with explicit dummy credentials.
#[derive(Clone, Debug, Default)]
pub(crate) struct PreparedS3 {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
    active: Arc<AtomicUsize>,
}

impl PreparedS3 {
    pub(crate) fn answering(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(replies.into_iter().collect())),
            ..Self::default()
        }
    }

    pub(crate) fn client(&self) -> Client {
        let sink = self.clone();
        let sdk = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-north-1"))
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .http_client(http_client_fn(move |_, _| sink.clone().into_shared()))
            .build();
        Client::from_conf(sdk)
    }

    pub(crate) fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    pub(crate) fn active_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

fn success() -> HttpResponse {
    HttpResponse::new(200_u16.try_into().unwrap(), "".into())
}

struct ActiveRequest(Arc<AtomicUsize>);

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl HttpConnector for PreparedS3 {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        self.requests.lock().unwrap().push(request);
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("S3 got an unexpected request");
        match reply {
            Reply::Success => HttpConnectorFuture::ready(Ok(success())),
            Reply::Denied => HttpConnectorFuture::ready(Ok(HttpResponse::new(
                403_u16.try_into().unwrap(),
                "<Error><Code>AccessDenied</Code><Message>test denied</Message></Error>".into(),
            ))),
            Reply::Block(released) => {
                self.active.fetch_add(1, Ordering::SeqCst);
                let guard = ActiveRequest(self.active.clone());
                HttpConnectorFuture::new(async move {
                    let _guard = guard;
                    released.notified().await;
                    Ok(success())
                })
            }
        }
    }
}

/// Yielding instead of sleeping also lets paused-time tests observe each worker transition.
pub(crate) async fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("S3 worker did not reach the expected state");
}

async fn completion(exporter: &mut Exporter) -> ExportCompletion {
    let mut result = None;
    wait_until(|| {
        result = exporter.try_complete();
        result.is_some()
    })
    .await;
    result.unwrap()
}

#[test]
fn export_url_preserves_destination_prefix_and_root() {
    for (url, prefix) in [
        ("s3://bucket/withdrawals/", "withdrawals/"),
        ("s3://bucket", ""),
        ("s3://bucket/", ""),
        ("s3://bucket///", ""),
        ("s3://bucket//nested//", "nested/"),
        ("s3://bucket/%2Fraw//space here", "%2Fraw//space here/"),
    ] {
        let export = ExportConfig::from_url(url).unwrap();
        assert_eq!(export.bucket(), "bucket", "{url}");
        assert_eq!(export.prefix(), prefix, "{url}");
        assert_eq!(export.destination_key(), format!("s3://bucket/{prefix}"));
    }
}

#[test]
fn export_url_rejects_scheme_empty_bucket_and_reserved_characters() {
    for (url, expected_error) in [
        (
            "https://bucket/withdrawals/",
            "export URL must start with s3://",
        ),
        ("s3://", "export URL must contain a bucket name"),
        (
            "s3:///withdrawals/",
            "export URL must contain a bucket name",
        ),
        (
            "s3://bucket/withdrawals/?query",
            "export URL must not contain '?' after s3://",
        ),
        (
            "s3://bucket/withdrawals/#fragment",
            "export URL must not contain '#' after s3://",
        ),
        (
            "s3://user@bucket/withdrawals/",
            "export URL must not contain '@' after s3://",
        ),
        (
            "s3://bucket:9000/withdrawals/",
            "export URL must not contain ':' after s3://",
        ),
        (
            "s3://bucket/withdrawals/a:b",
            "export URL must not contain ':' after s3://",
        ),
    ] {
        let error = ExportConfig::from_url(url).expect_err(url);
        assert_eq!(error.to_string(), expected_error, "{url}");
    }
}

#[test]
fn export_url_validates_the_bucket_and_prefix() {
    for bucket in [
        "ab",
        "MyBucket",
        "-bucket",
        "bucket.",
        "bucket..name",
        "127.0.0.1",
        "xn--bucket",
        "sthree-bucket",
        "bucket-s3alias",
        "bucket--x-s3",
        &"b".repeat(64),
    ] {
        let error = ExportConfig::from_url(&format!("s3://{bucket}")).expect_err(bucket);
        assert_eq!(
            error.to_string(),
            "export bucket must be a valid general purpose S3 bucket name"
        );
    }
    for prefix in [
        "../private",
        "safe/./lookup",
        "safe\\lookup",
        "bad\n",
        "bad\0",
    ] {
        assert!(
            ExportConfig::from_url(&format!("s3://bucket/{prefix}")).is_err(),
            "{prefix:?}"
        );
    }
    assert!(
        ExportConfig::from_url(&format!("s3://bucket/{}", "x".repeat(MAX_PREFIX_BYTES))).is_err()
    );
    assert!(
        ExportConfig::from_url(&format!("s3://bucket/{}", "x".repeat(MAX_PREFIX_BYTES - 1)))
            .is_ok()
    );
}

#[tokio::test]
async fn sdk_puts_only_the_lookup_json_at_the_canonical_note_key_in_order() {
    let sink = PreparedS3::answering([Reply::Success, Reply::Success, Reply::Success]);
    let records = [
        record(1, 7, Some("first-id")),
        record(1, 9, None),
        record(1, 12, Some("replacement-id")),
    ];
    let result = put_batch(&sink.client(), &config(), records.to_vec()).await;
    assert_eq!(result.last_uploaded_seq, Some(12));
    assert!(result.error.is_none());
    let requests = sink.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    for (request, record) in requests.iter().zip(records) {
        assert_eq!(request.method(), "PUT");
        assert_eq!(
            request.uri(),
            format!(
                "https://withdrawal-lookups.s3.eu-north-1.amazonaws.com/withdrawals/{}.json?x-id=PutObject",
                record.note_id.to_hex()
            )
        );
        let headers = request.headers();
        assert_eq!(headers.get("content-type"), Some("application/json"));
        assert_eq!(headers.get("cache-control"), Some("max-age=10"));
        assert!(headers
            .get("authorization")
            .unwrap()
            .contains("Credential=test/"));
        for forbidden in ["x-amz-acl", "x-amz-tagging"] {
            assert!(!headers.contains_key(forbidden));
        }
        assert!(headers
            .iter_bytes()
            .all(|(name, _)| !name.starts_with("x-amz-meta-")));
        let body = request.body().bytes().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(body).unwrap(),
            json!({"withdrawal_id": record.withdrawal_id})
        );
    }
}

#[tokio::test]
async fn failure_preserves_the_sdk_source_and_acknowledges_only_the_successful_prefix() {
    for failed_index in [0, 1] {
        let mut replies = [Reply::Success, Reply::Success, Reply::Success];
        replies[failed_index] = Reply::Denied;
        let sink = PreparedS3::answering(replies);
        let result = put_batch(
            &sink.client(),
            &config(),
            vec![
                record(1, 5, Some("first")),
                record(2, 7, None),
                record(3, 8, Some("last")),
            ],
        )
        .await;
        assert_eq!(result.last_uploaded_seq, (failed_index == 1).then_some(5));
        let failure = result.error.unwrap();
        assert_eq!(failure.class, Actionable("s3_export"));
        let source = failure
            .error
            .downcast::<aws_sdk_s3::error::SdkError<PutObjectError>>()
            .unwrap();
        assert_eq!(
            source.as_service_error().unwrap().code(),
            Some("AccessDenied")
        );
        assert_eq!(sink.count(), failed_index + 1);
    }
}

#[tokio::test]
async fn one_batch_remains_in_flight_until_its_completion_is_consumed() {
    let released = Arc::new(Notify::new());
    let sink = PreparedS3::answering([Reply::Block(released.clone()), Reply::Success]);
    let mut exporter = Exporter::with_client(config(), sink.client());
    assert!(exporter.try_send(vec![record(1, 1, Some("first"))]));
    wait_until(|| sink.active.load(Ordering::SeqCst) == 1).await;
    assert!(!exporter.try_send(vec![record(2, 2, None)]));
    assert!(exporter.try_complete().is_none());
    released.notify_one();
    wait_until(|| sink.active_count() == 0).await;
    assert!(!exporter.try_send(vec![record(2, 2, None)]));
    let first = completion(&mut exporter).await;
    assert_eq!(first.last_uploaded_seq, Some(1));
    assert!(first.error.is_none());
    assert!(exporter.try_send(vec![record(2, 2, None)]));
    let second = completion(&mut exporter).await;
    assert_eq!(second.last_uploaded_seq, Some(2));
    exporter.shutdown().await;
    assert_eq!(sink.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_stopped_batch_reports_its_failure_and_can_be_retried() {
    let sink = PreparedS3::answering([Reply::Block(Arc::new(Notify::new())), Reply::Success]);
    let mut exporter = Exporter::with_client(config(), sink.client());
    assert!(exporter.try_send(vec![record(1, 1, None)]));
    wait_until(|| sink.active_count() == 1).await;
    exporter.task.abort_all();
    let result = completion(&mut exporter).await;
    assert_eq!(result.last_uploaded_seq, None);
    assert_eq!(result.error.unwrap().class, Actionable("s3_export"));
    assert!(exporter.try_complete().is_none());
    assert!(exporter.try_send(vec![record(1, 1, None)]));
    let retry = completion(&mut exporter).await;
    assert!(retry.error.is_none());
    assert_eq!(retry.last_uploaded_seq, Some(1));
    assert_eq!(sink.count(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_blocked_put_times_out_without_acknowledgement() {
    let sink = PreparedS3::answering([Reply::Block(Arc::new(Notify::new()))]);
    let mut exporter = Exporter::with_client(config(), sink.client());
    assert!(exporter.try_send(vec![record(1, 8, None)]));
    wait_until(|| sink.active.load(Ordering::SeqCst) == 1).await;
    tokio::time::advance(PUT_TIMEOUT).await;
    let result = completion(&mut exporter).await;
    assert_eq!(result.last_uploaded_seq, None);
    let failure = result.error.unwrap();
    assert_eq!(failure.class, Transient("s3_export"));
    assert!(failure
        .error
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some());
    assert_eq!(sink.active.load(Ordering::SeqCst), 0);
    exporter.shutdown().await;
}

#[tokio::test]
async fn shutdown_cancels_and_joins_a_blocked_put() {
    let sink = PreparedS3::answering([Reply::Block(Arc::new(Notify::new()))]);
    let mut exporter = Exporter::with_client(config(), sink.client());
    assert!(exporter.try_send(vec![record(1, 1, None)]));
    wait_until(|| sink.active.load(Ordering::SeqCst) == 1).await;
    tokio::time::timeout(SHUTDOWN_TIMEOUT, exporter.shutdown())
        .await
        .expect("shutdown waited for a blocked S3 request");
    assert_eq!(sink.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dropping_the_exporter_also_cancels_a_blocked_put() {
    let sink = PreparedS3::answering([Reply::Block(Arc::new(Notify::new()))]);
    let mut exporter = Exporter::with_client(config(), sink.client());
    assert!(exporter.try_send(vec![record(1, 1, None)]));
    wait_until(|| sink.active.load(Ordering::SeqCst) == 1).await;
    drop(exporter);
    wait_until(|| sink.active.load(Ordering::SeqCst) == 0).await;
}

const ISOLATED_S3_TEST: &str = "XUSDC_ATTESTER_ISOLATED_S3_TEST";

/// Provider tests run with local profile files containing only dummy credentials.
/// The parent process environment and real AWS configuration are never changed or read.
fn in_isolated_process(test_name: &str, profile_config: &str) -> bool {
    if std::env::var(ISOLATED_S3_TEST).as_deref() == Ok(test_name) {
        return true;
    }
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config");
    let credentials = directory.path().join("credentials");
    std::fs::write(&config, profile_config).unwrap();
    std::fs::write(
        &credentials,
        "[default]\naws_access_key_id = unused-default\naws_secret_access_key = unused-default-secret\n\
         [exporter-test]\naws_access_key_id = dummy-exporter-profile\naws_secret_access_key = dummy-exporter-secret\n",
    )
    .unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(test_name)
        .env_clear()
        .env(ISOLATED_S3_TEST, test_name)
        .env("AWS_CONFIG_FILE", config)
        .env("AWS_SHARED_CREDENTIALS_FILE", credentials)
        .env("AWS_PROFILE", "exporter-test")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .status()
        .unwrap();
    assert!(status.success());
    false
}

#[tokio::test]
async fn s3_uses_the_standard_aws_profile() {
    if !in_isolated_process(
        "export::tests::s3_uses_the_standard_aws_profile",
        "[profile exporter-test]\nregion = eu-west-1\n",
    ) {
        return;
    }
    let client = load_client().await.unwrap();
    assert_eq!(client.config().region().unwrap().as_ref(), "eu-west-1");
    // Preserve the production client's inherited identity resolver and replace only its transport.
    let sink = PreparedS3::answering([Reply::Success]);
    let transport = sink.clone();
    let captured_client = Client::from_conf(
        client
            .config()
            .to_builder()
            .http_client(http_client_fn(move |_, _| transport.clone().into_shared()))
            .build(),
    );
    put_record(
        &captured_client,
        &config(),
        &record(1, 1, Some("profile-id")),
    )
    .await
    .unwrap();
    {
        let requests = sink.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let authorization = requests[0].headers().get("authorization").unwrap();
        assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=dummy-exporter-profile/"));
        assert!(authorization.contains("/eu-west-1/s3/aws4_request"));
        assert!(authorization.contains("Signature="));
    }
    assert_eq!(client.config().retry_config().unwrap().max_attempts(), 3);
    assert_eq!(
        client
            .config()
            .timeout_config()
            .unwrap()
            .operation_timeout(),
        Some(PUT_TIMEOUT)
    );
}

#[tokio::test]
async fn unresolved_region_is_reported_as_a_retryable_batch_completion() {
    if !in_isolated_process(
        "export::tests::unresolved_region_is_reported_as_a_retryable_batch_completion",
        "",
    ) {
        return;
    }
    let mut exporter = Exporter::new(config());
    for _ in 0..2 {
        assert!(exporter.try_send(vec![record(1, 8, None)]));
        // The provider reads local files asynchronously, so use a clock bound for this transition.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(result) = exporter.try_complete() {
                    break result;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(result.last_uploaded_seq, None);
        let failure = result.error.unwrap();
        assert_eq!(failure.class, Actionable("s3_export"));
        assert!(failure
            .to_string()
            .contains("Set AWS_REGION or configure the AWS region provider"));
    }
    exporter.shutdown().await;
}
