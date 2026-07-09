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
# rows A/B against a fresh local stack (bootstraps genesis, starts
# validator + ntx-builder + sequencer + tx prover, tears down after)
cargo run -p xusdc-validation --bin lnv1_rows_ab

# the same flow as a test, plus the 9 synthetic assertion negatives
cargo test -p xusdc-validation --locked

# supervised manual stack (leaves it running; pids under the run root)
cargo run -p xusdc-validation --bin lnv_stack -- up  [label]
cargo run -p xusdc-validation --bin lnv_stack -- down <run-root>
```

Requirements: the four v0.15.1 node binaries on `PATH`, loopback ports 57291–57294 free. Run
artifacts (node data, stores, keystores, logs, `evidence.json`) land under the gitignored
`local-node-data/lnv1/<label>/`.

The real-node E2E takes ~6 minutes: three Falcon-signed/derived transactions are proven
client-side (path C) plus bounded block waits.
