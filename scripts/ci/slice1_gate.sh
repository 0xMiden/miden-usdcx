#!/usr/bin/env bash
#
# slice1_gate.sh — THE slice-1 exit gate (TEMPORARY; deleted by slice 2).
#
# The raw test suite is RED BY DESIGN: one work item is deferred to slice 2 —
#   (F) the ECDSA signature-verify rebuild (the deleted upstream `verify_prehash` primitive is
#       stood in for by a fail-closed shim that denies every attestation with a DISTINCT error
#       identity, so every mint-path test fails on that identity).
# The burn-payload relocation landed in this slice, so its five tests are green and removed from the
# manifest; only the ECDSA path remains red. Judging on a raw `cargo test` exit code is therefore
# unreachable by construction. This wrapper is the pass/fail signal instead.
#
# It runs the raw suite and exits 0 IF AND ONLY IF:
#   1. the observed set of failing `<target>::<test>` identifiers equals the frozen manifest
#      (scripts/ci/slice1-expected-red.txt) EXACTLY — a NEW red fails the gate, and a manifest
#      entry that unexpectedly PASSES also fails the gate; and
#   2. every failing test fails for the single PERMITTED reason (the shim's distinct
#      unavailable-verifier identity), AND the reason the manifest pairs with each test is present
#      in that test's captured failure output.
#
# This is NOT an ignore-failures wrapper: it pins the expected-red set to an exact manifest and
# rejects any deviation in either direction.
set -o pipefail
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST="$ROOT/scripts/ci/slice1-expected-red.txt"

# The ONLY reasons a failing test may fail for in slice 1. Any failing test whose captured output
# contains none of these is a red for an UNEXPECTED reason and fails the gate.
PERMITTED=(
  "deposit attestation signature verification is temporarily unavailable"
)

# A stable byte collation for `sort` AND `comm` alike: without it the two can disagree on strings
# containing `::` / `_`, which would make the set-difference below unreliable.
export LC_ALL=C

RAW="$(mktemp)"
cleanup() { rm -f "$RAW"; }
trap cleanup EXIT

if [[ ! -f "$MANIFEST" ]]; then
  echo "slice1_gate: FAIL — manifest not found at $MANIFEST" >&2
  exit 2
fi

echo "slice1_gate: running the raw suite (red by design) ..." >&2
# --no-fail-fast so every target reports; the raw exit code is intentionally ignored (the suite is
# red by design). set -o pipefail keeps `tee` from masking a crash of cargo itself.
#
# COLOUR MUST BE OFF, and this is not cosmetic — every parser below depends on it.
# On a TTY-less local run cargo emits plain text, but on a CI runner it colours its own status
# lines while libtest leaves its output plain. A coloured "   Running …" line then begins with an
# ESC byte, so `^[[:space:]]+(Running |Doc-tests )` matches nothing, `launches` counts 0 against a
# non-zero `results`, and the gate aborts at the launch-count check WITHOUT EVER REACHING the
# manifest comparison. The compile-break sentinel fails the same way: CI renders
# `<ESC>[1m<ESC>[91merror<ESC>[0m: could not compile`, so the literal substring never matches and
# the sentinel is dead while looking alive.
#
# Belt and braces, because the failure is SILENT and looks like a passing gate locally:
#   1. suppress colour at the source, for cargo and for libtest;
#   2. strip any residual ANSI before anything is parsed, so a future tool that colours its output
#      cannot quietly re-break the parsers.
# If you ever "simplify" this line, run the gate in CI and confirm `launches` is non-zero.
( cd "$ROOT" && CARGO_TERM_COLOR=never cargo test --workspace --locked --release --no-fail-fast --color never ) 2>&1 \
  | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
  | tee "$RAW"
raw_status=${PIPESTATUS[0]}
# A cargo *invocation* failure (compile error, not a test failure) is status 101 with no test
# lines; distinguish it from an ordinary red suite below by requiring at least one "test result:".
if ! grep -q '^test result:' "$RAW"; then
  echo "slice1_gate: FAIL — the suite did not run to completion (build broke or cargo crashed, raw status $raw_status)" >&2
  exit 2
fi

# ── reject anything the "... FAILED" parser cannot see ──────────────────────────────────────────
# A test binary killed by a signal (SIGABRT/SIGSEGV/SIGKILL/OOM) or a target that fails to COMPILE
# emits no ordinary "test <name> ... FAILED" line, so its out-of-manifest failure would silently
# vanish and the gate would fail OPEN. cargo reports an ordinary test failure as
# "(exit status: 101)"; a signal death as "(signal: N, SIG…)"; a build break as
# "could not compile" / "error[E….]". None of those are permitted — only the enumerated ordinary
# test failures are.
if grep -qE '\(signal: [0-9]+|SIGABRT|SIGSEGV|SIGKILL|process abort|out of memory|error: could not compile|error\[E[0-9]{4}\]' "$RAW"; then
  echo "slice1_gate: FAIL — a process-level termination or build failure was detected (signal/abort/OOM/compile); the FAILED-line parser cannot see it:" >&2
  grep -nE '\(signal: [0-9]+|SIGABRT|SIGSEGV|SIGKILL|process abort|out of memory|error: could not compile|error\[E[0-9]{4}\]' "$RAW" | head -8 >&2
  exit 2
fi

# Every LAUNCHED test target must produce a terminal "test result:" line. A binary that aborts
# mid-run prints its "Running …" (or "Doc-tests …") launch line but no result, so launches > results
# means a target vanished without reporting — reject rather than trust the surviving lines.
launches=$(grep -cE '^[[:space:]]+(Running |Doc-tests )' "$RAW")
results=$(grep -c '^test result:' "$RAW")
if [[ "$launches" -ne "$results" ]]; then
  echo "slice1_gate: FAIL — $launches test targets launched but only $results reported a terminal 'test result:' (a binary aborted without reporting)." >&2
  exit 2
fi

# ── observed failing set: "<target>::<test>" ────────────────────────────────────────────────────
# Track the current target from each "Running … (…/deps/<target>-<hash>)" line, then tag every
# "test <name> ... FAILED" with it. Target names use '_' so the only '-' is before the hash.
observed_ids="$(
  awk '
    /Running / && /\(/ {
      line=$0
      sub(/.*\(/, "", line); sub(/\).*/, "", line)   # -> path inside parens
      sub(/.*\//, "", line)                            # -> basename (<target>-<hash>)
      sub(/-[0-9a-f]+$/, "", line)                     # -> <target>
      target=line
    }
    /^test .* \.\.\. FAILED$/ {
      name=$0
      sub(/^test /, "", name); sub(/ \.\.\. FAILED$/, "", name)
      print target "::" name
    }
  ' "$RAW" | sort -u
)"

# ── manifest set: first field before a TAB (comments/blank lines ignored) ────────────────────────
manifest_ids="$(
  grep -vE '^[[:space:]]*(#|$)' "$MANIFEST" | awk -F'\t' '{print $1}' | sort -u
)"

# stdout block for a bare test name (concatenated across binaries).
block_of() {
  awk -v t="$1" '
    $0 == "---- " t " stdout ----" { cap=1; next }
    /^---- .* stdout ----$/ { cap=0 }
    /^failures:$/ { cap=0 }
    cap { print }
  ' "$RAW"
}

fail=0

# 1) exact set equality
only_observed="$(comm -23 <(printf '%s\n' "$observed_ids" | sort) <(printf '%s\n' "$manifest_ids" | sort))"
only_manifest="$(comm -13 <(printf '%s\n' "$observed_ids" | sort) <(printf '%s\n' "$manifest_ids" | sort))"
if [[ -n "${only_observed// /}" ]]; then
  echo "slice1_gate: FAIL — NEW failing tests not in the manifest:" >&2
  printf '  + %s\n' $only_observed >&2
  fail=1
fi
if [[ -n "${only_manifest// /}" ]]; then
  echo "slice1_gate: FAIL — manifest entries that did NOT fail (unexpectedly passing):" >&2
  printf '  - %s\n' $only_manifest >&2
  fail=1
fi

# 2) every failing test fails for a permitted reason, matching its manifest-paired string.
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  bare="${id#*::}"
  paired="$(grep -vE '^[[:space:]]*(#|$)' "$MANIFEST" | awk -F'\t' -v k="$id" '$1==k{print $2; exit}')"
  blk="$(block_of "$bare")"
  # the paired reason must itself be one of the permitted enumerations
  permitted_ok=0
  for p in "${PERMITTED[@]}"; do
    [[ "$paired" == "$p" ]] && permitted_ok=1
  done
  if [[ "$permitted_ok" -ne 1 ]]; then
    echo "slice1_gate: FAIL — manifest reason for $id is not in the permitted list: '$paired'" >&2
    fail=1
    continue
  fi
  if ! grep -qF -- "$paired" <<<"$blk"; then
    echo "slice1_gate: FAIL — $id did not fail for its manifest reason ('$paired'); captured output:" >&2
    sed 's/^/      /' <<<"$blk" | head -20 >&2
    fail=1
  fi
done <<<"$observed_ids"

if [[ "$fail" -ne 0 ]]; then
  echo "slice1_gate: RESULT = NON-ZERO (the observed red set does not match the frozen manifest)" >&2
  exit 1
fi

echo "slice1_gate: RESULT = 0 — the observed red set equals the frozen manifest and every failure is permitted." >&2
exit 0
