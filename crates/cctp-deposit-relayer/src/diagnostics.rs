use anyhow::Error;
use std::fmt;

// Only these locally chosen labels cross the logging boundary. Upstream errors
// remain available for control flow, but their URLs, credentials and SDK chains do not.
#[derive(Debug)]
struct Failure {
    stage: &'static str,
    reason: &'static str,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.reason)
    }
}
impl std::error::Error for Failure {}

pub(crate) fn at(error: Error, stage: &'static str, fallback: &'static str) -> Error {
    let reason = reason(&error, fallback);
    error.context(Failure { stage, reason })
}
pub(crate) fn summary(error: &Error) -> (&'static str, &'static str) {
    error
        .downcast_ref::<Failure>()
        .map(|e| (e.stage, e.reason))
        .unwrap_or(("runtime", "journal_or_worker_failure"))
}
pub(crate) fn reason(error: &Error, fallback: &'static str) -> &'static str {
    for cause in error.chain() {
        let reason = match cause.to_string().as_str() {
            "journal already owned" => "journal_owned",
            "journal configuration identity mismatch" => "journal_identity_mismatch",
            "unrecognized journal schema" => "journal_schema_mismatch",
            "journal integrity failure" | "journal foreign key failure" => {
                "journal_integrity_failure"
            }
            "saved raw hash mismatch" | "saved signed bytes differ from fixed helper request" => {
                "saved_transaction_mismatch"
            }
            "Arc chain identity mismatch" => "arc_chain_mismatch",
            "helper runtime identity mismatch" => "helper_runtime_mismatch",
            "helper binding mismatch" => "helper_binding_mismatch",
            "initialization requires a genuinely fresh dedicated sender at nonce zero" => {
                "sender_nonce_not_zero"
            }
            "loaded signer mismatch" => "signer_identity_mismatch",
            "source genesis changed" | "source chain identity mismatch" => {
                "source_identity_mismatch"
            }
            "source start history pruned" => "source_history_pruned",
            "Solana boundary unavailable" | "old Solana boundary missing before start slot" => {
                "source_boundary_unavailable"
            }
            "source transaction unavailable" | "signature and transaction slots differ" => {
                "source_transaction_invalid"
            }
            "source signature unconfirmed" => "source_not_finalized",
            "exact helper simulation failed" => "simulation_failed",
            "helper gas estimation failed" => "gas_estimation_unavailable",
            "helper gas estimate exceeds cap" => "gas_cap_exceeded",
            "gas price lookup failed" => "gas_price_unavailable",
            "fee overflow" | "fee exceeds cap" => "fee_cap_exceeded",
            "balance lookup failed" => "balance_unavailable",
            "insufficient gas balance" => "insufficient_gas_balance",
            "KMS digest signing failed" => "signing_failed",
            "digest signer mismatch" => "signer_identity_mismatch",
            _ => continue,
        };
        return reason;
    }
    fallback
}
