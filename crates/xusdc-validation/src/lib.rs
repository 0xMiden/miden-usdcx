//! Local-node validation harness, currently excluded from the workspace.
//! Drivers collect transaction results and node state; assertion modules check those observations.
//! The same assertions are exercised with synthetic fixtures in the offline tests.

pub mod actors;
pub mod assertions;
pub mod assertions_cf;
pub mod assertions_de;
pub mod assertions_gj;
pub mod assertions_kl;
pub mod client;
pub mod config;
pub mod deploy;
pub mod evidence;
pub mod evidence_cf;
pub mod evidence_de;
pub mod evidence_gj;
pub mod mintburn;
pub mod observations;
pub mod observations_cf;
pub mod observations_de;
pub mod observations_gj;
pub mod observations_kl;
pub mod record;
pub mod rows_ab;
pub mod rows_cf;
pub mod rows_de;
pub mod rows_gj;
pub mod rows_kl;
pub mod sanity;
pub mod stack;

pub use config::{DomainParams, RunConfig, StackConfig};
pub use observations::RowsAbObservations;
pub use observations_cf::RowsCfObservations;
pub use observations_de::RowsDeObservations;
pub use observations_gj::RowsGjObservations;
pub use observations_kl::FullMatrixObservations;
pub use rows_ab::run_rows_ab;
pub use rows_cf::run_rows_cf;
pub use rows_de::run_rows_de;
pub use rows_gj::run_rows_gj;
pub use rows_kl::run_full_matrix;
pub use sanity::{run_sanity, SanityConfig, SanityReport};
