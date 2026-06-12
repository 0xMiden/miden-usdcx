#!/usr/bin/env bash
# Re-sync the read-only doc mirrors from their canonical sources in the
# agentic-template program tree. Run from the repo root.
set -euo pipefail
CI="/Users/philipp/Documents/Work/Miden-Coding/agentic-template/ai-tasks/circle-integration"
DATE="$(date +%F)"
declare -a PAIRS=(
  "07-implementation-readiness/CANONICAL-OWNERSHIP-MAP.md|docs/governing/CANONICAL-OWNERSHIP-MAP.md"
  "07-implementation-readiness/BUILDER-GATES.md|docs/governing/BUILDER-GATES.md"
  "07-implementation-readiness/V15-DEVNET-BASELINE.md|docs/governing/V15-DEVNET-BASELINE.md"
  "07-implementation-readiness/MASM-STRUCTURE-RESEARCH-REPORT.md|docs/governing/MASM-STRUCTURE-RESEARCH-REPORT.md"
  "08-masm-grounding-spike/GROUNDING-REPORT.md|docs/governing/GROUNDING-REPORT.md"
  "06-phase4-component-specs/04-shared-encoding/COMPONENT-SPEC.md|docs/spec/04-shared-encoding/COMPONENT-SPEC.md"
  "06-phase4-component-specs/04-shared-encoding/CLAIM-EVIDENCE-MATRIX.md|docs/spec/04-shared-encoding/CLAIM-EVIDENCE-MATRIX.md"
  "06-phase4-component-specs/04-shared-encoding/TEST-AND-VERIFICATION-HARNESS.md|docs/spec/04-shared-encoding/TEST-AND-VERIFICATION-HARNESS.md"
)
for pair in "${PAIRS[@]}"; do
  src="${CI}/${pair%%|*}"; dst="${pair##*|}"
  [ -f "$src" ] || { echo "MISSING canonical source: $src" >&2; exit 1; }
  {
    printf '> **MIRROR — READ-ONLY (mirrored %s).** Canonical source: `%s`. Do NOT edit this copy; if it diverges from the canonical source, the canonical source wins. Re-sync via `tools/sync-mirrors.sh`.\n\n' "$DATE" "$src"
    cat "$src"
  } > "$dst"
  echo "synced $dst"
done
