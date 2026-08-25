//! The generated **VALIDATION-RECORD-SANITY.md** renderer.

use super::{SanityReport, BURN_UNITS, MINT_NONROUND_UNITS, MINT_ROUND_UNITS};

/// Renders the record: the per-check matrix, the mandated amounts, the scale-0 identity proof, the
/// node-log gate, and the reproduction commands. Per the charter the GATE verdict defers to a human
/// — the record NEVER self-declares the gate.
///
/// The record is labeled by the run's ACTUAL mode — never mislabeled: a FRESH local deploy (the ONLY
/// mode that runs the destructive admin surface, against a faucet we own + throw away), a LOCAL
/// existing-faucet non-destructive re-check, or a DEVNET existing-faucet non-destructive re-check. An
/// already-deployed faucet is NEVER mutated (no admin), so its subset is the INTENDED, COMPLETE gate.
pub fn render_sanity_record(report: &SanityReport) -> String {
    let mut s = String::new();
    let failures = report.failures();
    // The run's ENVIRONMENT word — derived from the node (loopback vs remote), so a caller-supplied
    // faucet exercised on localhost is labeled LOCAL, never DEVNET.
    let env_word = if report.local_node { "LOCAL" } else { "DEVNET" };
    // A fresh deploy is loopback-only, so it is always LOCAL. The two existing-faucet modes differ only
    // by environment; neither runs the admin surface against the deployed faucet.
    let deploy_note = if report.deployed_fresh {
        "a FRESH production faucet deployed on the running LOCAL node — the FULL suite incl. the \
         destructive admin surface, against a faucet we own and throw away with the test node"
            .to_string()
    } else {
        format!(
            "a caller-supplied ALREADY-deployed faucet on {env_word} — the non-destructive \
             fund-correctness subset (the admin surface is NOT run against a deployed faucet)"
        )
    };

    s.push_str("# xUSDC Faucet — v16 E2E Sanity Validation Record\n\n");
    s.push_str(
        "The pre-deploy confidence gate: a cohesive run driving the xUSDC faucet's core on-chain \
         functionality against a real Miden node, with fund-correctness (the P0 scale-0 identity, \
         mint/burn amounts + destinations, replay, supply-cap, attestation gates) proven end-to-end, \
         plus DC-8 burn-evidence readiness and a clean-node-log gate. The DESTRUCTIVE admin surface \
         runs ONLY on a fresh LOCAL faucet we own — NEVER against a deployed faucet. \
         **Validator-not-fixer:** a failing check is a SURFACED finding that BLOCKS the deploy, \
         never a faucet hot-fix.\n\n",
    );
    // The attester's provenance. Only the LOCALLY-GENERATED branch can assert the key is not a Circle
    // key — the harness minted it. For an OPERATOR-SUPPLIED key this run cannot establish who owns it,
    // so it makes NO origin claim (provenance is the operator's responsibility).
    let attester_line = if report.attester_supplied {
        format!(
            "- Operator-supplied allowlisted attester commitment `{}` (the deployed faucet's \
             existing allowlisted key; this run does NOT assert its origin — provenance is the \
             operator's responsibility).",
            report.attester_commitment_hex,
        )
    } else {
        format!(
            "- Local test attester commitment `{}` (a throwaway key the harness generated + \
             allowlisted — NEVER a Circle key).",
            report.attester_commitment_hex,
        )
    };
    s.push_str(&format!(
        "- Node: **{}** — RPC `{}`.\n- Faucet under test: `{}` ({}).\n- Owner `{}`; mint recipient \
         `{}`; burn holder `{}`.\n{}\n\n",
        report.node_version,
        report.rpc_url,
        report.faucet_id,
        deploy_note,
        report.owner_id,
        report.recipient_id,
        report.holder_id,
        attester_line,
    ));

    s.push_str("## Mandated amounts + the scale-0 identity (P0 regression)\n\n");
    s.push_str(&format!(
        "The shipped faucet mints under `DEPOSIT_SCALE_EXP = 0` — the reducer does NO 10^6 division, \
         so minted units EQUAL the raw 6-decimal deposit amount. Proven with a round amount and a \
         NON-round amount so any residual rescale is caught:\n\n\
         | flow | deposit amount (6-dec smallest units) | expected minted units |\n|---|---|---|\n\
         | mint (round) | {MINT_ROUND_UNITS} (100 xUSDC) | {MINT_ROUND_UNITS} |\n\
         | mint (non-round) | {MINT_NONROUND_UNITS} | {MINT_NONROUND_UNITS} |\n\
         | burn | {BURN_UNITS} (50 xUSDC) | supply −{BURN_UNITS} |\n\n",
    ));

    let passed = report.checks.iter().filter(|c| c.pass).count();
    s.push_str(&format!(
        "## Result — {}/{} checks passed\n\n",
        passed,
        report.checks.len(),
    ));
    s.push_str("| id | area | assertion | verdict | evidence |\n|---|---|---|---|---|\n");
    for c in &report.checks {
        let verdict = if c.pass { "PASS" } else { "FAIL" };
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            c.id,
            c.area,
            c.what,
            verdict,
            c.detail.replace('|', "\\|"),
        ));
    }
    s.push('\n');

    if failures.is_empty() {
        s.push_str(
            "**GATE VERDICT: PENDING HUMAN ACCEPTANCE.** Every check passed its assertion on this \
             run. Per the charter the PASS is a HUMAN decision: a human reproduces from a fresh node, \
             inspects this record + the node logs, and declares the gate outcome (and only then does \
             the deploy proceed).\n\n",
        );
    } else {
        s.push_str(&format!(
            "**GATE VERDICT: GATE CANNOT PASS — {} check(s) FAILED.** Each failure is a surfaced \
             finding that BLOCKS the deploy (validator-not-fixer). Failing checks:\n\n",
            failures.len()
        ));
        for c in &failures {
            s.push_str(&format!(
                "- {} ({}): {} — {}\n",
                c.id, c.area, c.what, c.detail
            ));
        }
        s.push('\n');
    }

    s.push_str("## Coverage\n\n");
    s.push_str(
        "- Mint (deposit direction): scale-0 identity round + non-round, correct recipient, supply \
         rise, nonce marker.\n\
         - Burn (withdrawal direction): supply decrement, correct public `XReserveBurnNote` (tag \
         `0x4255_524E`, one `NetworkAccountTarget` → faucet, DC-7 payload), attester-consumable via \
         the withdrawal attester's own `validate_discovery` / `decode_burn_payload`, and DC-8 \
         evidence (`note_id`/`nullifier`/`block_num`/`burnTxId`) assembled by the attester's own \
         `assemble_evidence` over a LIVE `BurnEvidenceReads` adapter.\n\
         - Attestation + fund-safety negatives: wrong-attester, forged signature, replayed nonce, \
         over-cap — each rejected client-side, none moved supply.\n",
    );
    if report.deployed_fresh {
        s.push_str(
            "- Admin (FRESH local faucet ONLY): pause (mint+burn rejected) → unpause (mint AND burn \
             work), attester rotation (disabled attester's mint rejected + re-enabled), \
             `set_min_burn_size` (below-min rejected, at/above-min accepted), `set_max_supply` \
             (mutate + read back + tightened-cap ENFORCED on a mint + below-current-supply guard), \
             authority gating, and SAN-HANDOVER (the `ADMIN` rotation arc: hand the role to an \
             ephemeral successor, prove the successor can USE it and the predecessor is locked out, \
             hand it back and prove the lockout reverses — grant always before revoke, so `ADMIN` \
             never empties), then a best-effort restore. This DESTRUCTIVE surface runs ONLY here — \
             against a faucet we own and throw away.\n",
        );
    }
    s.push_str(
        "- Node logs (local runs): the run's four service logs scanned for unexpected \
         ERROR/panic/untriaged-WARN lines (the clean-log gate).\n\n",
    );
    if !report.deployed_fresh {
        s.push_str(&format!(
            "> **{env_word} existing-faucet non-destructive re-check:** this mode targets an \
             ALREADY-deployed faucet and re-proves ONLY the fund-correctness subset (scale-0 mints, \
             the attestation/replay/cap negatives, and the burn arc — structure + \
             attester-consumability + DC-8 evidence), using the operator-supplied allowlisted \
             attester. The DESTRUCTIVE admin surface (pause, `set_*`) is NEVER \
             run against a deployed faucet — by DESIGN, not skipped — so this IS the intended, \
             COMPLETE {env_word} gate (it exits 0 on pass). The admin surface is validated separately \
             on a FRESH local faucet we own.\n\n",
        ));
    }

    // THIS record's faithful reproduction — the ACTUAL run mode + command. Run in RELEASE (proving is
    // far faster than debug).
    let (this_mode, this_cmd) = if report.deployed_fresh {
        (
            "the FRESH-deploy LOCAL full gate (deploys the production faucet on the loopback node, \
             then drives the WHOLE matrix incl. the destructive admin surface)"
                .to_string(),
            format!(
                "# in the v16 client repo: ./scripts/start-test-node.sh --background   (RPC {rpc})\n\
                 cargo run --release --locked -p xusdc-validation --bin sanity_e2e -- --rpc-url {rpc}",
                rpc = report.rpc_url,
            ),
        )
    } else {
        (
            format!(
                "the {env_word} existing-faucet non-destructive re-check against {faucet} (scale-0 \
                 mints, negatives, the burn arc; the admin surface is NOT run against a deployed \
                 faucet)",
                faucet = report.faucet_id,
            ),
            format!(
                "# the allowlisted attester secret is read from a FILE / env, NEVER argv\n\
                 SANITY_ATTESTER_SECRET=$(cat allowlisted-attester.hex) \\\n\
                 cargo run --release --locked -p xusdc-validation --bin sanity_e2e -- \\\n\
                 --rpc-url {rpc} --faucet-id {faucet}",
                rpc = report.rpc_url,
                faucet = report.faucet_id,
            ),
        )
    };
    s.push_str("## Reproduction\n\n");
    s.push_str(&format!(
        "**This record** was produced by {this_mode} against `{}` (node {}). Reproduce it with:\n\n\
         ```bash\n{this_cmd}\n```\n\n",
        report.rpc_url, report.node_version,
    ));
    s.push_str(
        "For reference, the two modes (there is NO destructive-admin path against a deployed faucet):\n\n\
         - **LOCAL full gate** — a fresh deploy on the loopback node; the ONLY mode that runs the \
         destructive admin surface, against a throwaway faucet:\n\n\
         ```bash\n\
         # in the v16 client repo: ./scripts/start-test-node.sh --background   (RPC 127.0.0.1:57291)\n\
         cargo run --release --locked -p xusdc-validation --bin sanity_e2e -- --rpc-url http://127.0.0.1:57291\n\
         ```\n\n\
         - **DEVNET (or local existing-faucet) non-destructive re-check** — targets an ALREADY-deployed \
         faucet and NEVER mutates it; the allowlisted attester secret is read from a FILE / env, never \
         argv:\n\n\
         ```bash\n\
         SANITY_ATTESTER_SECRET=$(cat allowlisted-attester.hex) \\\n\
         cargo run --release --locked -p xusdc-validation --bin sanity_e2e -- \\\n\
             --rpc-url https://rpc.devnet.miden.io --faucet-id <DEPLOYED_FAUCET_ID>\n\
         ```\n",
    );
    s
}
