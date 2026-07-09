# xusdc-validation

The Phase-4 §11.2 **local-node validation harness** (LNV track): deploys the PRODUCTION xUSDC
faucet to a fresh, isolated local Miden node and drives the validation matrix against real RPC.
Validation-only — it never modifies faucet code; a red assertion here is a surfaced finding.

- **Pins:** protocol v0.15.3 (git `681fc905…`), node binaries v0.15.1 (installed in
  `/usr/local/bin`), `miden-client =0.15.3`. Ledger + discovered mechanics + evidence:
  [`VALIDATION-RECORD.md`](VALIDATION-RECORD.md).
- **This slice (LNV-1):** harness foundation + matrix rows A (deploy + recognize) and
  B (`domain_init` init-once).

## One-command runs

```bash
# THE GATE RUN — rows A/B against a fresh local stack (bootstraps genesis, starts
# validator + ntx-builder + sequencer + tx prover, tears down after)
cargo run -p xusdc-validation --bin lnv1_rows_ab
# equivalent via the test suite (real-node E2E + the 9 synthetic assertion negatives)
cargo test -p xusdc-validation --locked -- --include-ignored

# the DEFAULT (sandbox-safe) suite: the 9 synthetic assertion negatives only — no node,
# no listener sockets. Green here carries NO real-node claim.
cargo test -p xusdc-validation --locked

# supervised manual stack (leaves it running; pids under the run root)
cargo run -p xusdc-validation --bin lnv_stack -- up  [label]
cargo run -p xusdc-validation --bin lnv_stack -- down <run-root>
```

The real-node E2E is `#[ignore]`d in the default suite — NOT because it is optional (it is the
gate), but because it must bind loopback listener sockets for the four node services, which
hermetic audit sandboxes deny (`bind: Operation not permitted`). Run it explicitly with
`-- --include-ignored` on a network-enabled box; its result is visible in the test summary
(`1 ignored` = it did NOT run). The §11.2 gate claim rides only on real runs (evidence +
archived logs under `local-node-data/`) plus the LNV-1 human supervision gate.

Requirements for the gate run: the four v0.15.1 node binaries on `PATH`, loopback ports
57291–57294 free. Run artifacts (node data, stores, keystores, logs, `evidence.json`) land under
the gitignored `local-node-data/lnv1/<label>/`. The E2E takes ~6 minutes: three Falcon-signed
transactions proven client-side (path C) plus bounded block waits.
