//! Tracing for the USDCx services: events go to stdout, and when an OTLP endpoint is configured the
//! services' spans are also exported over OpenTelemetry.
//!
//! The deposit relayer, the withdrawal attester and the bridge that runs both call [`init`] once,
//! at the top of an async `main` on the multi-thread runtime, and keep the returned [`Telemetry`]
//! until they exit.
//!
//! Export is on when `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) is set
//! and not blank. The exporter then reads the standard OpenTelemetry variables, such as
//! `OTEL_EXPORTER_OTLP_HEADERS` for the credentials, `OTEL_SERVICE_NAME` and
//! `OTEL_RESOURCE_ATTRIBUTES`. `RUST_LOG` filters stdout only, so lowering the log level never
//! removes the spans the alerts are built on. `USDCX_EXPORT_FILTER` filters the export instead, in
//! the same syntax as `RUST_LOG`. It replaces the default rather than adding to it, so it names the
//! services' own targets too: `warn,xusdc_attester=info,miden_client=debug` exports the attester's
//! spans and adds the node client's while debugging, and `info` exports every crate's.
//!
//! The guard only sends what is buffered when `main` returns, so each service stops on SIGTERM or
//! SIGINT through [`cancel_on_signal`] instead of being killed by it, and bounds that stop with
//! [`stop_within`].

mod shutdown;

pub use shutdown::{cancel_on_signal, stop_within, SHUTDOWN_TIMEOUT};

use std::sync::OnceLock;

use anyhow::{bail, ensure, Context};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{WithExportConfig as _, WithTonicConfig as _};
use opentelemetry_sdk::resource::{
    EnvResourceDetector, ResourceDetector, TelemetryResourceDetector,
};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tokio::runtime::{Handle, RuntimeFlavor};
use tonic::transport::ClientTlsConfig;
use tracing::error;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

/// The stdout filter when `RUST_LOG` is unset or invalid.
const DEFAULT_STDOUT_FILTER: &str = "info";

/// What is exported when `USDCX_EXPORT_FILTER` is unset or blank: the services' own spans and
/// events at `info` and above, and only warnings from their dependencies. The node client and the
/// HTTP stack would otherwise add their internal spans to every cycle and page.
const DEFAULT_EXPORT_FILTER: &str =
    "warn,usdcx_bridge=info,xreserve_deposit_relayer=info,xusdc_attester=info";

/// The environment variable that replaces [`DEFAULT_EXPORT_FILTER`], in the syntax of `RUST_LOG`.
const EXPORT_FILTER_VARIABLE: &str = "USDCX_EXPORT_FILTER";

/// The environment variables that turn export on. Either one names where the spans go, and the
/// first one that is set and not blank wins.
const ENDPOINT_VARIABLES: [&str; 2] = [
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
];

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

/// Installs the global subscriber: stdout always, and the OTLP export when it is configured.
/// `service_name` is the exported `service.name`, unless `OTEL_SERVICE_NAME` overrides it.
///
/// # Errors
///
/// - Export is configured but this is not called on a multi-thread Tokio runtime. The exporter's
///   gRPC connection runs on the caller's runtime, and flushing blocks the calling thread until
///   the connection has sent the spans, which a current-thread runtime could never do.
/// - Export is configured but `USDCX_EXPORT_FILTER` is not a valid filter.
/// - Export is configured but the exporter cannot be built.
/// - A global subscriber is already installed, including by an earlier call.
pub fn init(service_name: &'static str) -> anyhow::Result<Telemetry> {
    if PROVIDER.get().is_some() {
        bail!("tracing is already initialised");
    }
    let export = if let Some(endpoint) = endpoint() {
        let filter = export_filter(non_blank_variable(EXPORT_FILTER_VARIABLE))?;
        let provider = provider(service_name, endpoint)?;
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
fn export_filter(directives: Option<String>) -> anyhow::Result<EnvFilter> {
    let Some(directives) = directives else {
        return Ok(EnvFilter::new(DEFAULT_EXPORT_FILTER));
    };
    EnvFilter::builder()
        .parse(&directives)
        .with_context(|| format!("invalid {EXPORT_FILTER_VARIABLE} {directives:?}"))
}

/// Builds the span pipeline that exports to `endpoint`, with its gRPC connection on the caller's
/// runtime.
fn provider(service_name: &'static str, endpoint: String) -> anyhow::Result<SdkTracerProvider> {
    let runtime = Handle::try_current().context("span export needs a Tokio runtime")?;
    ensure!(
        runtime.runtime_flavor() == RuntimeFlavor::MultiThread,
        "span export needs the multi-thread Tokio runtime"
    );
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        // Named here because the exporter reads the same variables but takes a blank one as the
        // endpoint.
        .with_endpoint(endpoint)
        .with_tls_config(ClientTlsConfig::new().with_enabled_roots())
        .build()
        .context("building the OTLP span exporter")?;
    Ok(SdkTracerProvider::builder()
        .with_resource(resource(service_name))
        .with_batch_exporter(exporter)
        .build())
}

/// The service's name, then what `OTEL_RESOURCE_ATTRIBUTES` sets, then `OTEL_SERVICE_NAME`; a later
/// source overrides an earlier one.
fn resource(service_name: &'static str) -> Resource {
    let detectors: [Box<dyn ResourceDetector>; 2] = [
        Box::new(TelemetryResourceDetector),
        Box::new(EnvResourceDetector::new()),
    ];
    let mut resource = Resource::builder_empty()
        .with_service_name(service_name)
        .with_detectors(&detectors);
    if let Some(name) = non_blank_variable("OTEL_SERVICE_NAME") {
        resource = resource.with_service_name(name);
    }
    resource.build()
}

/// Where the spans go, or `None` when export is off.
fn endpoint() -> Option<String> {
    ENDPOINT_VARIABLES.into_iter().find_map(non_blank_variable)
}

fn non_blank_variable(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let filter = export_filter(Some("info,miden_client=debug".to_owned())).unwrap();
        assert_eq!(
            filter.to_string(),
            EnvFilter::new("info,miden_client=debug").to_string()
        );
    }

    #[test]
    fn an_invalid_export_filter_is_an_error() {
        let error = export_filter(Some("miden_client=loud".to_owned())).unwrap_err();
        assert!(format!("{error:#}").contains(EXPORT_FILTER_VARIABLE));
    }
}
