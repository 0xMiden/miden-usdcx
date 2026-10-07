//! Tracing for the USDCx services: events go to stdout, and when an OTLP endpoint is configured the
//! services' spans are also exported over OpenTelemetry.
//!
//! The deposit relayer, the withdrawal attester and the bridge that runs both flatten
//! [`TelemetryArgs`] into their command line, then call [`init`] with it once, at the top of an
//! async `main` on the multi-thread runtime, and keep the returned [`Telemetry`] until they exit.
//!
//! Export is on when `--otel-exporter-otlp-endpoint` (or `--otel-exporter-otlp-traces-endpoint`)
//! is set and not blank; each option also reads the standard OpenTelemetry variable of the same
//! name. The exporter itself reads the other standard variables, such as
//! `OTEL_EXPORTER_OTLP_HEADERS` for the credentials and `OTEL_RESOURCE_ATTRIBUTES`. `RUST_LOG`
//! filters stdout only, so lowering the log level never removes the spans the alerts are built on.
//! `--export-filter` (`USDCX_EXPORT_FILTER`) filters the export instead, in the same syntax as
//! `RUST_LOG`. It replaces the default rather than adding to it, so it names the services' own
//! targets too: `warn,xusdc_attester=info,miden_client=debug` exports the attester's spans and adds
//! the node client's while debugging, and `info` exports every crate's.
//!
//! The guard only sends what is buffered when `main` returns, so each service stops on SIGTERM or
//! SIGINT through [`cancel_on_signal`] instead of being killed by it, and bounds that stop with
//! [`stop_within`].

mod shutdown;

pub use shutdown::{cancel_on_signal, stop_within, SHUTDOWN_TIMEOUT};

use std::fmt;
use std::sync::OnceLock;

use anyhow::{bail, ensure, Context};
use clap::Args;
use opentelemetry::trace::{Status, TracerProvider as _};
use opentelemetry_otlp::{WithExportConfig as _, WithTonicConfig as _};
use opentelemetry_sdk::resource::{
    EnvResourceDetector, ResourceDetector, TelemetryResourceDetector,
};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tokio::runtime::{Handle, RuntimeFlavor};
use tonic::transport::ClientTlsConfig;
use tracing::{error, Span};
use tracing_opentelemetry::{OpenTelemetryLayer, OpenTelemetrySpanExt as _};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

/// The stdout filter when `RUST_LOG` is unset or invalid.
const DEFAULT_STDOUT_FILTER: &str = "info";

/// What is exported when `--export-filter` is unset or blank: the services' own spans and events at
/// `info` and above, and only warnings from their dependencies. The node client and the HTTP stack
/// would otherwise add their internal spans to every cycle and page.
const DEFAULT_EXPORT_FILTER: &str =
    "warn,usdcx_bridge=info,xreserve_deposit_relayer=info,xusdc_attester=info";

/// The tracing options every service takes. A blank value counts as unset, so a deployment can
/// turn export off by leaving a templated variable empty.
#[derive(Debug, Clone, Default, Args)]
#[command(next_help_heading = "Tracing options")]
pub struct TelemetryArgs {
    /// Where to send the spans over OTLP gRPC, for example https://api.honeycomb.io:443. Export is
    /// off when this and --otel-exporter-otlp-traces-endpoint are both unset or blank.
    #[arg(long, env = "OTEL_EXPORTER_OTLP_ENDPOINT", global = true)]
    otel_exporter_otlp_endpoint: Option<String>,

    /// Where to send the spans; takes precedence over --otel-exporter-otlp-endpoint.
    #[arg(long, env = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", global = true)]
    otel_exporter_otlp_traces_endpoint: Option<String>,

    /// The exported `service.name`, in place of the service's own name.
    #[arg(long, env = "OTEL_SERVICE_NAME", global = true)]
    otel_service_name: Option<String>,

    /// Which spans and events are exported, in the syntax of RUST_LOG. Replaces the default of the
    /// services' own at info and above and only warnings from their dependencies.
    #[arg(long, env = "USDCX_EXPORT_FILTER", global = true)]
    export_filter: Option<String>,
}

impl TelemetryArgs {
    /// Where the spans go, or `None` when export is off.
    fn endpoint(&self) -> Option<&str> {
        non_blank(&self.otel_exporter_otlp_traces_endpoint)
            .or_else(|| non_blank(&self.otel_exporter_otlp_endpoint))
    }
}

/// The span pipeline, once [`init`] has turned export on. It is kept here rather than only in the
/// [`Telemetry`] guard so that [`flush`] can reach it from an exit that skips the guard.
static PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Keeps the export running. Dropping it sends the spans that are still buffered and stops the
/// export, so it is held until the service has finished.
#[must_use = "dropping the guard stops the export"]
pub struct Telemetry {
    _private: (),
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        if let Some(provider) = PROVIDER.get() {
            if let Err(error) = provider.shutdown() {
                error!(%error, "failed to export the remaining spans");
            }
        }
    }
}

/// Sends the spans that are still buffered, for an exit that skips the [`Telemetry`] guard, such
/// as [`std::process::exit`]. Does nothing when export is off.
pub fn flush() {
    if let Some(provider) = PROVIDER.get() {
        if let Err(error) = provider.force_flush() {
            error!(%error, "failed to export the remaining spans");
        }
    }
}

/// How loudly a failure is alerted on, exported as the span's `failure.class` under its name in
/// snake case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum FailureClass {
    /// Something the service authenticates did not check out, such as a diverged chain.
    Integrity,
    /// A failure that will not fix itself and needs an operator, such as a hold or a failed
    /// startup.
    Actionable,
    /// A failure that is retried by design and matters only when it persists, such as a request
    /// that timed out.
    Transient,
}

/// An error that knows how loudly it is alerted on, so a span can be marked failed from the error
/// alone.
pub trait Classified {
    /// The error's class, and `kind`, a short name for what happened.
    fn failure(&self) -> (FailureClass, &'static str);
}

/// Marks a span failed and records why. The caller still logs the failure at `error`, inside the
/// span, so it reaches stdout and the exported span carries the details.
pub trait FailureSpanExt {
    /// Records `class` as `failure.class` and `kind`, a short name for what happened, as
    /// `failure.kind`, and sets the span's status to an error.
    fn record_failure(&self, class: FailureClass, kind: &'static str);

    /// Records the failure `error` classifies itself as.
    fn record_error(&self, error: &impl Classified) {
        let (class, kind) = error.failure();
        self.record_failure(class, kind);
    }

    /// Records an [`Integrity`](FailureClass::Integrity) failure.
    fn record_integrity_failure(&self, kind: &'static str) {
        self.record_failure(FailureClass::Integrity, kind);
    }

    /// Records an [`Actionable`](FailureClass::Actionable) failure.
    fn record_actionable_failure(&self, kind: &'static str) {
        self.record_failure(FailureClass::Actionable, kind);
    }

    /// Records a [`Transient`](FailureClass::Transient) failure.
    fn record_transient_failure(&self, kind: &'static str) {
        self.record_failure(FailureClass::Transient, kind);
    }
}

impl FailureSpanExt for Span {
    fn record_failure(&self, class: FailureClass, kind: &'static str) {
        self.set_attribute("failure.class", <&'static str>::from(class));
        self.set_attribute("failure.kind", kind);
        self.set_status(Status::error(kind));
    }
}

/// An error, with the `failure.class` and `failure.kind` the span it stopped is marked with.
///
/// Errors that carry no class of their own, such as an [`anyhow::Error`], are classified where
/// they happen with [`Classify::classify`], because that is the only place the difference is
/// known: a request that timed out is retried by design, while a store that cannot be written
/// will not fix itself.
#[derive(Debug)]
pub struct Failure {
    pub class: FailureClass,
    pub kind: &'static str,
    pub error: anyhow::Error,
}

impl Failure {
    pub fn new(class: FailureClass, kind: &'static str, error: impl Into<anyhow::Error>) -> Self {
        Self {
            class,
            kind,
            error: error.into(),
        }
    }

    /// Wraps an error that classifies itself, under its own class and kind.
    pub fn classified(error: impl Classified + Into<anyhow::Error>) -> Self {
        let (class, kind) = error.failure();
        Self::new(class, kind, error)
    }

    /// Adds `context` to the error, keeping its class and kind.
    #[must_use]
    pub fn context(self, context: &'static str) -> Self {
        Self {
            error: self.error.context(context),
            ..self
        }
    }

    /// Marks the current span failed and logs the error inside it at `error`, with its whole
    /// chain of context.
    pub fn report(&self, message: &str) {
        Span::current().record_error(self);
        error!(error = %format_args!("{:#}", self.error), "{message}");
    }
}

impl Classified for Failure {
    fn failure(&self) -> (FailureClass, &'static str) {
        (self.class, self.kind)
    }
}

/// Renders the error alone, so `{:#}` still prints its whole chain of context.
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

/// Classifies the error of a [`Result`] where it is returned.
pub trait Classify<T> {
    fn classify(self, class: FailureClass, kind: &'static str) -> Result<T, Failure>;
}

impl<T, E: Into<anyhow::Error>> Classify<T> for Result<T, E> {
    fn classify(self, class: FailureClass, kind: &'static str) -> Result<T, Failure> {
        self.map_err(|error| Failure::new(class, kind, error))
    }
}

/// Installs the global subscriber: stdout always, and the OTLP export when `args` configures it.
/// `service_name` is the exported `service.name`, unless `--otel-service-name` overrides it.
///
/// # Errors
///
/// - Export is configured but this is not called on a multi-thread Tokio runtime. The exporter's
///   gRPC connection runs on the caller's runtime, and flushing blocks the calling thread until
///   the connection has sent the spans, which a current-thread runtime could never do.
/// - Export is configured but `--export-filter` is not a valid filter.
/// - Export is configured but the exporter cannot be built.
/// - A global subscriber is already installed, including by an earlier call.
pub fn init(service_name: &'static str, args: &TelemetryArgs) -> anyhow::Result<Telemetry> {
    if PROVIDER.get().is_some() {
        bail!("tracing is already initialised");
    }
    let export = if let Some(endpoint) = args.endpoint() {
        let filter = export_filter(non_blank(&args.export_filter))?;
        let resource = resource(service_name, non_blank(&args.otel_service_name));
        let provider = provider(resource, endpoint)?;
        let tracer = provider.tracer(service_name);
        if PROVIDER.set(provider).is_err() {
            bail!("tracing is already initialised");
        }
        Some(OpenTelemetryLayer::new(tracer).with_filter(filter))
    } else {
        None
    };
    let stdout = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(DEFAULT_STDOUT_FILTER)),
        );
    tracing_subscriber::registry()
        .with(stdout)
        .with(export)
        .try_init()
        .context("installing the tracing subscriber")?;
    Ok(Telemetry { _private: () })
}

/// The export filter from `directives`, or the default one when there are none. Unlike the stdout
/// filter, an invalid one is an error: falling back would quietly change which spans the alerts see.
fn export_filter(directives: Option<&str>) -> anyhow::Result<EnvFilter> {
    let Some(directives) = directives else {
        return Ok(EnvFilter::new(DEFAULT_EXPORT_FILTER));
    };
    EnvFilter::builder()
        .parse(directives)
        .with_context(|| format!("invalid --export-filter {directives:?}"))
}

/// Builds the span pipeline that exports to `endpoint`, with its gRPC connection on the caller's
/// runtime.
fn provider(resource: Resource, endpoint: &str) -> anyhow::Result<SdkTracerProvider> {
    let runtime = Handle::try_current().context("span export needs a Tokio runtime")?;
    ensure!(
        runtime.runtime_flavor() == RuntimeFlavor::MultiThread,
        "span export needs the multi-thread Tokio runtime"
    );
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        // Named here so the option decides where the spans go, not the exporter's own read of the
        // same variables, which takes a blank one as the endpoint.
        .with_endpoint(endpoint)
        .with_tls_config(ClientTlsConfig::new().with_enabled_roots())
        .build()
        .context("building the OTLP span exporter")?;
    Ok(SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build())
}

/// The service's name, then what `OTEL_RESOURCE_ATTRIBUTES` sets, then `name_override`; a later
/// source overrides an earlier one.
fn resource(service_name: &'static str, name_override: Option<&str>) -> Resource {
    let detectors: [Box<dyn ResourceDetector>; 2] = [
        Box::new(TelemetryResourceDetector),
        Box::new(EnvResourceDetector::new()),
    ];
    let mut resource = Resource::builder_empty()
        .with_service_name(service_name)
        .with_detectors(&detectors);
    if let Some(name) = name_override {
        resource = resource.with_service_name(name.to_owned());
    }
    resource.build()
}

fn non_blank(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use opentelemetry::trace::Status;
    use opentelemetry::{KeyValue, Value};
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        telemetry: TelemetryArgs,
    }

    fn endpoint(args: &[&str]) -> Option<String> {
        let cli = Cli::try_parse_from(["service"].iter().chain(args)).unwrap();
        cli.telemetry.endpoint().map(str::to_owned)
    }

    #[test]
    fn the_traces_endpoint_takes_precedence_and_a_blank_one_is_unset() {
        let both = [
            "--otel-exporter-otlp-endpoint=https://all.invalid",
            "--otel-exporter-otlp-traces-endpoint=https://traces.invalid",
        ];
        assert_eq!(endpoint(&both).as_deref(), Some("https://traces.invalid"));

        let blank_traces = [
            "--otel-exporter-otlp-endpoint=https://all.invalid",
            "--otel-exporter-otlp-traces-endpoint= ",
        ];
        assert_eq!(
            endpoint(&blank_traces).as_deref(),
            Some("https://all.invalid")
        );

        let blank = [
            "--otel-exporter-otlp-endpoint=",
            "--otel-exporter-otlp-traces-endpoint= ",
        ];
        assert_eq!(endpoint(&blank), None);
    }

    struct Diverged;

    impl Classified for Diverged {
        fn failure(&self) -> (FailureClass, &'static str) {
            (FailureClass::Integrity, "chain_diverged")
        }
    }

    #[test]
    fn a_recorded_failure_marks_the_exported_span() {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(OpenTelemetryLayer::new(provider.tracer("test")));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("attester.cycle");
            span.record_error(&Diverged);
        });

        let spans = exporter.get_finished_spans().unwrap();
        let [span] = spans.as_slice() else {
            panic!("expected one span, got {}", spans.len());
        };
        assert_eq!(span.status, Status::error("chain_diverged"));
        for (key, value) in [
            ("failure.class", "integrity"),
            ("failure.kind", "chain_diverged"),
        ] {
            assert!(
                span.attributes
                    .contains(&KeyValue::new(key, Value::from(value))),
                "missing {key}={value} in {:?}",
                span.attributes
            );
        }
    }

    #[test]
    fn a_reported_failure_keeps_its_class_and_context() {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(OpenTelemetryLayer::new(provider.tracer("test")));
        let failure = Err::<(), _>(anyhow::anyhow!("disk full"))
            .classify(FailureClass::Actionable, "store")
            .unwrap_err()
            .context("saving the cursor");
        assert_eq!(format!("{failure:#}"), "saving the cursor: disk full");
        tracing::subscriber::with_default(subscriber, || {
            tracing::info_span!("attester.cycle").in_scope(|| failure.report("cycle stopped"));
        });

        let spans = exporter.get_finished_spans().unwrap();
        let [span] = spans.as_slice() else {
            panic!("expected one span, got {}", spans.len());
        };
        assert_eq!(span.status, Status::error("store"));
        assert!(span
            .attributes
            .contains(&KeyValue::new("failure.class", Value::from("actionable"))));
    }

    /// The alerts match on these names, so a renamed variant must not change them.
    #[test]
    fn failure_classes_export_under_their_alerting_names() {
        for (class, name) in [
            (FailureClass::Integrity, "integrity"),
            (FailureClass::Actionable, "actionable"),
            (FailureClass::Transient, "transient"),
        ] {
            assert_eq!(<&'static str>::from(class), name);
        }
    }

    #[test]
    fn the_export_filter_defaults_to_the_services_own_spans() {
        let filter = export_filter(None).unwrap();
        assert_eq!(
            filter.to_string(),
            EnvFilter::new(DEFAULT_EXPORT_FILTER).to_string()
        );
    }

    #[test]
    fn the_export_filter_can_be_replaced() {
        let filter = export_filter(Some("info,miden_client=debug")).unwrap();
        assert_eq!(
            filter.to_string(),
            EnvFilter::new("info,miden_client=debug").to_string()
        );
    }

    #[test]
    fn an_invalid_export_filter_is_an_error() {
        let error = export_filter(Some("miden_client=loud")).unwrap_err();
        assert!(format!("{error:#}").contains("--export-filter"));
    }
}
