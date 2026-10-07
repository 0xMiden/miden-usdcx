//! Errors that say how loudly to alert on them.
//!
//! Every way a page can fail is classified where it happens, because that is the only place the
//! difference is known: a node request that timed out is retried by design, while a progress file
//! that cannot be written will not fix itself. The page span then carries the class and a short
//! kind, and the alerts route on them.

use std::fmt;

use tracing::{error, Span};
use usdcx_telemetry::{FailureClass, FailureSpanExt as _};

/// An error, with the `failure.class` and `failure.kind` the span it stopped is marked with.
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

    /// Marks the current span failed and logs the error inside it at `error`.
    pub(crate) fn report(&self, message: &str) {
        Span::current().record_failure(self.class, self.kind);
        error!(error = %format_args!("{:#}", self.error), "{message}");
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
