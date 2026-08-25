# xusdc-validation

The Phase-4 §11.2 **local-node validation harness** (LNV track): deploys the PRODUCTION xUSDC
faucet to a fresh, isolated local Miden node and drives the validation matrix against real RPC.
Validation-only — it never modifies faucet code; a red assertion here is a surfaced finding.

- **Pins:** use the workspace manifests and `Cargo.lock`.
- **LNV-1:** harness foundation + matrix row A (deploy + recognize + the build-seeded
  domain-config read-back). The deploy construction is also driven offline, in memory, through the
  same row-A shape assertions — the MASM is embedded at build time, so only the first transaction's
  nonce bump needs a node.
- **LNV-2:** matrix rows C (admin suite — `set_attester` + rotation, `set_min_burn_size`,
  `set_max_supply`, pause/unpause + F6, DOM_MANAGER role rotation, non-authorized-sender negatives)
  and F (the F5 auth boundary — non-allowlisted note + tx-script both rejected). Admin state changes
  commit via the ntx-builder (path N); accept/reject probes run client-side (kernel traps).
- **LNV-3:** matrix rows D (mint happy path — both hookData variants, committed via path N with the
  recipient consuming the emitted P2ID) and E (mint negatives — replay, forged signature,
  non-allowlisted attester, tampered payload, and a fee ceiling the attestation signed but the
  faucet cannot rebuild).
- **LNV-4:** matrix rows G (burn two-block — the Circle read-path proof: the production
  `XReserveBurnNote` committed, tag-discoverable, and durably `GetNotesById`-retrievable after the
  faucet consumes it), H (the **F7 same-block-erasure RIV** — a Circle/DEV-7 EVIDENCE packet against
  the production note, no acceptability decision), I (burn negatives — below-min, while-paused,
  wrong-asset) and J (conservation — `token_supply == Σminted − Σburned`).
- **LNV-5:** The consolidated §11.2 gate run — the whole matrix on one fresh node (the
  LNV-1..4 drivers composed in matrix order), plus rows K (**ntx-builder liveness / path N** —
  verdict + evidence either way) and L (**clean logs** — zero unexplained ERROR/panic lines,
  every warning triaged). The command generates its run artifacts locally.

The matrix is **A + C–L**, eleven rows. There is no row B: the faucet's identifier is its own
account id, derived on chain, so the init-once note and the slot it wrote are gone. The binding a
row-B negative used to prove is proven in row A instead, at the layer that now enforces it — the
Rust structural gate that refuses a deposit intent whose `remoteToken` names another faucet.

## One-command runs

```bash
# THE LNV-1 GATE RUN — row A against a fresh local stack (bootstraps genesis, starts
# validator + ntx-builder + sequencer + tx prover, tears down after)
cargo run -p xusdc-validation --bin lnv1_rows_ab
# THE LNV-2 GATE RUN — rows C/F (~30 min: ~16 ntx-builder-committed admin ops + client-side probes)
cargo run -p xusdc-validation --bin lnv2_rows_cf
# THE LNV-3 GATE RUN — rows D/E (mint lifecycle: path-N mints + recipient P2ID consumes, client-side negatives)
cargo run -p xusdc-validation --bin lnv3_rows_de
# THE LNV-4 GATE RUN — rows G/H/I/J (~15 min: burn two-block + F7 same-block RIV + burn negatives + conservation)
cargo run -p xusdc-validation --bin lnv4_rows_gj
# THE LNV-5 CONSOLIDATED §11.2 GATE RUN — the WHOLE matrix on ONE fresh node (~45–60 min)
cargo run -p xusdc-validation --bin lnv5_full_matrix
# equivalent via the test suite (all real-node E2Es + all synthetic assertion negatives)
cargo test -p xusdc-validation --locked -- --include-ignored

# the DEFAULT (sandbox-safe) suite: the synthetic assertion negatives + err_code tripwire only —
# no node, no listener sockets. Green here carries NO real-node claim.
cargo test -p xusdc-validation --locked

# supervised manual stack (leaves it running; pids under the run root)
cargo run -p xusdc-validation --bin lnv_stack -- up  [label]
cargo run -p xusdc-validation --bin lnv_stack -- down <run-root>
```

Six real-node E2Es — one per integration suite (`lnv1_rows_ab_against_real_local_node`,
`lnv2_rows_cf_against_real_local_node`, `lnv3_rows_de_against_real_local_node`,
`lnv4_rows_gj_against_real_local_node`, `lnv5_full_matrix_against_real_local_node`,
`sanity_e2e_live`) — are `#[ignore]`d in the default suite, NOT because they are optional (they are
the gate) but because they must bind loopback listener sockets for the four node services, which
hermetic audit sandboxes deny (`bind: Operation not permitted`). Run them explicitly with
`-- --include-ignored` on a network-enabled box; `6 ignored` in the test summary means they did NOT
run. Those six are the only ignored tests in the crate — a seventh would mean a check silently
stopped running. The §11.2 gate claim rides only on real runs (evidence + archived logs under
`local-node-data/`) plus the LNV-1 human supervision gate.

Alongside the LNV matrix the crate carries the leaner pre-deploy **sanity gate** (`src/sanity/`, the
`sanity_e2e` binary): mint / burn / negatives against a running node, plus — on a fresh LOCAL faucet
only — the destructive admin surface, which includes SAN-HANDOVER, the `ADMIN` rotation arc (the role
handed to an ephemeral successor and back, with the successor's capability and the predecessor's
lockout each proven by a real op, and the role never left without a member). Its pure logic, including
the finally-phase restore's planner, is unit-tested offline in the default suite.

The faucet's MASM is assembled at BUILD time by `crates/xusdc-encoding/build.rs` and embedded in the
shipped `XReserveFaucetExtension` component, so `src/deploy.rs` composes the faucet purely from
`XReserveStablecoinBuilder` — nothing here assembles MASM or reads a source tree.

Requirements for the gate run (operator-run): a v16 client repo checkout whose
`scripts/start-test-node.sh` brings the four node services up (`MIDEN_V16_NODE_DIR`; see
[`config::DEFAULT_V16_NODE_DIR`]), and loopback ports 57291 / 50101 / 50301 / 50051 free. Run
artifacts (node data, stores, keystores, logs, `evidence.json`) land under the gitignored
`local-node-data/lnv1/<label>/`. The E2E takes ~6 minutes: Falcon-signed transactions proven
client-side (path C) plus bounded block waits.

The faucet is built against the fee parameters of the chain it deploys to, read from the node's
latest block header — its auth component prices every allowlisted note against them, so a faucet
built with foreign fee parameters would carry a schedule the node disagrees with.
