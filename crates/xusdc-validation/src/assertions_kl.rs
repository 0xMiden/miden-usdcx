//! The rows-K/L assertion suite (JUDGE half; the derivations in [`crate::rows_kl`] OBSERVE).
//!
//! **Row K** passes only when the liveness verdict is recorded WITH complete, consistent
//! evidence — either way: a YES must carry at least one path-N MINT commit AND one path-N BURN
//! commit (the spec asks about both consumptions) plus node-side ntx-builder log markers; a NO
//! must carry the exact cause and the spec's "relayer executes client-side (path C)" posture
//! statement, and must not contradict observed mint/burn commits. Partial evidence (e.g. mint
//! committed but no burn) fails LOUDLY — row K surfaces it instead of silently downgrading the
//! verdict. Path N being dead is NOT a gate failure (a clean, recorded NO passes); an
//! incompletely-evidenced verdict is.
//!
//! **Row L** passes only when all four service logs were archived non-empty and the scan found
//! ZERO unexpected ERROR lines, ZERO panics, and ZERO untriaged warnings — with every triaged
//! line carrying its explanation. Weakening any of these to reach green would falsify the gate.

use anyhow::{bail, ensure, Result};

use crate::observations_kl::{RowKObservations, RowLObservations};
use crate::rows_kl::REQUIRED_SERVICE_LOGS;

/// Row K — ntx-builder liveness (path N): the verdict + evidence must be recorded either way.
pub fn assert_k(k: &RowKObservations) -> Result<()> {
    ensure!(
        !k.posture.trim().is_empty(),
        "row K: the deployment-posture statement must be recorded with the verdict"
    );
    for c in &k.commits {
        ensure!(
            !c.op.trim().is_empty() && !c.effect.trim().is_empty(),
            "row K: every path-N commit must carry its op + committed effect (got op='{}', effect='{}')",
            c.op,
            c.effect
        );
        ensure!(
            matches!(c.kind.as_str(), "mint" | "burn" | "admin"),
            "row K: unknown path-N commit kind '{}' (expected mint|burn|admin)",
            c.kind
        );
    }

    let mints = k.commits.iter().filter(|c| c.kind == "mint").count();
    let burns = k.commits.iter().filter(|c| c.kind == "burn").count();

    if k.auto_executes {
        ensure!(
            mints >= 1,
            "row K: a YES liveness verdict requires at least one observed path-N MINT commit \
             (the spec's question covers the mint consumption)"
        );
        ensure!(
            burns >= 1,
            "row K: a YES liveness verdict requires at least one observed path-N BURN commit \
             (the spec's question covers the burn consumption)"
        );
        ensure!(
            !k.ntx_log_evidence.is_empty(),
            "row K: a YES verdict requires node-side ntx-builder execution markers, not \
             client-side inference alone"
        );
        ensure!(
            k.no_cause.is_none(),
            "row K: a YES verdict must not carry a no-cause (inconsistent record)"
        );
    } else {
        match k.no_cause.as_deref() {
            Some(cause) if !cause.trim().is_empty() => {}
            _ => bail!(
                "row K: a NO verdict must record the exact cause (version/config), not a bare NO"
            ),
        }
        ensure!(
            k.posture.contains("client-side (path C)"),
            "row K: a NO verdict must record the deployment-posture statement 'relayer executes \
             client-side (path C)', got: {}",
            k.posture
        );
        ensure!(
            mints == 0 && burns == 0,
            "row K: a NO verdict contradicts the observed path-N evidence ({mints} mint / \
             {burns} burn commits) — partial liveness must be surfaced, not recorded as NO"
        );
    }
    Ok(())
}

/// Row L — clean logs: all four service logs archived non-empty; zero unexpected ERROR lines,
/// zero panics, zero untriaged warnings; every triaged line explained.
pub fn assert_l(l: &RowLObservations) -> Result<()> {
    for required in REQUIRED_SERVICE_LOGS {
        let entry = l.scanned.iter().find(|s| s.service == required);
        match entry {
            None => bail!(
                "row L: the required service log '{required}.log' was not archived — the run's \
                 log evidence is incomplete"
            ),
            Some(s) => ensure!(
                s.bytes > 0,
                "row L: the required service log '{required}.log' is empty — the service wrote \
                 no output, so the archive proves nothing"
            ),
        }
    }
    if let Some(first) = l.panics.first() {
        bail!(
            "row L: {} panic line(s) in the service logs — first ({}): {}",
            l.panics.len(),
            first.service,
            first.line
        );
    }
    if let Some(first) = l.unexpected_errors.first() {
        bail!(
            "row L: {} ERROR line(s) match no expected pattern — first ({}): {}",
            l.unexpected_errors.len(),
            first.service,
            first.line
        );
    }
    if let Some(first) = l.untriaged_warnings.first() {
        bail!(
            "row L: {} WARN line(s) are untriaged — every warning must be triaged + explained; \
             first ({}): {}",
            l.untriaged_warnings.len(),
            first.service,
            first.line
        );
    }
    for t in l.expected_errors.iter().chain(l.triaged_warnings.iter()) {
        ensure!(
            !t.explanation.trim().is_empty(),
            "row L: a triaged line must carry its explanation (pattern '{}', service '{}')",
            t.pattern,
            t.service
        );
    }
    Ok(())
}
