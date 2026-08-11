# xusdc-validation

The Phase-4 §11.2 **local-node validation harness** (LNV track): deploys the PRODUCTION xUSDC
faucet to a fresh, isolated local Miden node and drives the validation matrix against real RPC.
Validation-only — it never modifies faucet code; a red assertion here is a surfaced finding.

- **Pins:** use the workspace manifests and `Cargo.lock`.
- **LNV-1:** harness foundation + matrix rows A (deploy + recognize) and B (`domain_init` init-once).
- **LNV-2:** matrix rows C (admin suite — `set_attester` + rotation, `set_min_burn_size`,
  `set_max_supply`, pause/unpause + F6, DOM_MANAGER role rotation, non-authorized-sender negatives)
  and F (the F5 auth boundary — non-allowlisted note + tx-script both rejected). Admin state changes
  commit via the ntx-builder (path N); accept/reject probes run client-side (kernel traps).
- **LNV-3:** matrix rows D (mint happy path — both hookData variants, committed via path N with the
  recipient consuming the emitted P2ID) and E (mint negatives — replay, forged signature,
  non-allowlisted attester, non-zero fee, tampered payload).
- **LNV-4:** matrix rows G (burn two-block — the Circle read-path proof: the production
  `XReserveBurnNote` committed, tag-discoverable, and durably `GetNotesById`-retrievable after the
  faucet consumes it), H (the **F7 same-block-erasure RIV** — a Circle/DEV-7 EVIDENCE packet against
  the production note, no acceptability decision), I (burn negatives — below-min, while-paused,
  wrong-asset) and J (conservation — `token_supply == Σminted − Σburned`).
- **LNV-5:** The consolidated §11.2 gate run — the whole A–L matrix on one fresh node (the
  LNV-1..4 drivers composed in matrix order), plus rows K (**ntx-builder liveness / path N** —
  verdict + evidence either way) and L (**clean logs** — zero unexplained ERROR/panic lines,
  every warning triaged). The command generates its run artifacts locally.

## One-command runs

```bash
# THE LNV-1 GATE RUN — rows A/B against a fresh local stack (bootstraps genesis, starts
# validator + ntx-builder + sequencer + tx prover, tears down after)
cargo run -p xusdc-validation --bin lnv1_rows_ab
# THE LNV-2 GATE RUN — rows C/F (~30 min: ~16 ntx-builder-committed admin ops + client-side probes)
cargo run -p xusdc-validation --bin lnv2_rows_cf
# THE LNV-3 GATE RUN — rows D/E (mint lifecycle: path-N mints + recipient P2ID consumes, client-side negatives)
cargo run -p xusdc-validation --bin lnv3_rows_de
# THE LNV-4 GATE RUN — rows G/H/I/J (~15 min: burn two-block + F7 same-block RIV + burn negatives + conservation)
cargo run -p xusdc-validation --bin lnv4_rows_gj
# THE LNV-5 CONSOLIDATED §11.2 GATE RUN — the WHOLE A–L matrix on ONE fresh node (~45–60 min)
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

The real-node E2E is `#[ignore]`d in the default suite — NOT because it is optional (it is the
gate), but because it must bind loopback listener sockets for the four node services, which
hermetic audit sandboxes deny (`bind: Operation not permitted`). Run it explicitly with
`-- --include-ignored` on a network-enabled box; its result is visible in the test summary
(`1 ignored` = it did NOT run). The §11.2 gate claim rides only on real runs (evidence +
archived logs under `local-node-data/`) plus the LNV-1 human supervision gate.

**Un-parking also has to catch this crate up to build-time MASM assembly.** `src/deploy.rs` still
assembles the faucet library at runtime from a source path (`xusdc_encoding::xreserve_asm_dir()`),
and neither that function nor the tree it pointed at exists any more: the MASM is assembled by
`crates/xusdc-encoding/build.rs` and embedded. Replace that whole path with the shipped component —
`XReserveComponent::assemble()`, or `xusdc_encoding::XReserveLibrary::default()` if the raw library
is what a row needs. The seven-slot shape `deploy.rs` declares is stale for the same vintage of
reasons; the shipped component carries six.

Requirements for the gate run (operator-run, **P1b-b**): the four node binaries on `PATH`, loopback
ports 57291–57294 free. The harness (`src/stack.rs`) as currently coded targets the **v0.15.1** node
binaries; running these rows against a **v16** node — and any node-CLI-flag updates that requires —
is the P1b-b step (this offline un-park, P1b-a, only restores the crate to the v16 workspace and the
green offline gate). Run artifacts (node data, stores, keystores, logs, `evidence.json`) land under
the gitignored `local-node-data/lnv1/<label>/`. The E2E takes ~6 minutes: three Falcon-signed
transactions proven client-side (path C) plus bounded block waits.
