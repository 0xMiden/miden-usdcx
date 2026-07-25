# LNV-2 VALIDATION RECORD — admin suite (rows C) + auth boundary (row F)

**Slice:** LNV-2 (Phase-4 §11.2 local-node validation track, second slice — extends the LNV-1
harness). **Scope:** rows **C** + **F** of the A–L local-node validation matrix (see
`crates/xusdc-validation/README.md`).
**Status:** rows **C1–C6** and **F** _PASS_ on a real, fresh, isolated local node (evidence §5).
**Gate discipline:** this record feeds the HARD HUMAN GATE. Nothing here self-declares the §11.2
gate — that is LNV-5. Validator-not-fixer: every reject below is a real on-chain trap the row exists
to prove; NO production faucet code was touched.

---

## 1. Launch gate + toolchain

Unchanged from LNV-1 (`VALIDATION-RECORD.md` §1–2): F5 is on `main` (production builder composes
`AuthNetworkAccount`; the frozen 13-root note allowlist at this record's commit — [SUPERSEDED
2026-07-14 → S21 flip: now 12 roots, the runtime `set_role_admin` note removed]; empty tx-script
allowlist; note-driven admin). Pins: protocol `681fc905…` (= v0.15.3), node binaries **v0.15.1** in `/usr/local/bin`,
`miden-client =0.15.3`, the `[patch.crates-io]` type-unification. LNV-2 adds NO new dependencies and
NO new MASM — it drives the SAME shipped faucet composition + admin notes by reference.

## 2. Execution model (the discovered mechanics this slice validated)

LNV-1 §3.2 found that v0.15.1 **rejects post-deploy user-RPC transactions against network accounts**
(only the first-deployment tx is exempt; otherwise the submitter must present the
`x-miden-network-tx-auth` header). LNV-2 needs MANY post-deploy faucet state changes, so it resolves
the two supported paths empirically:

### 2.1 Path C′ (client + token header) is NOT available via the stock client
`miden-client 0.15.3`'s `MetadataInterceptor` injects only `authorization: Bearer <token>`
(`rpc/tonic_client/api_client.rs`); the node's network-tx exemption checks a DIFFERENT header,
`x-miden-network-tx-auth` (`miden-node-rpc-0.15.1 server/api.rs:63,243-248` +
`submit_proven_tx.rs:120-130`). The stock client cannot present it, so **path C′ is closed at this
pin** — a deployment-posture input for the record, not a faucet defect.

### 2.2 Path N (the ntx-builder) commits positive faucet state changes — CONFIRMED
Every positive admin op is emitted as its routed, allowlisted admin note from its (kernel-forced)
sender wallet — a regular-account tx the user RPC accepts — and the running **ntx-builder
auto-executes + commits the faucet's consumption** (`submitted transaction landed; advanced
in-memory account by its delta` in `ntx-builder.log`). The harness polls `GetAccount` until the
committed effect appears. This is the first LNV confirmation that path N commits *successful* faucet
transactions (LNV-1 only observed it *failing* the init-once gate); the full row-K liveness verdict
stays LNV-5, but rows C1–C5 ride this path for their committed state changes.
- **Cadence:** the ntx-builder processes a given network account roughly every ~2 minutes, so the
  full ~16-commit rows-C arc takes ~30 minutes wall-clock on the real node. (Sequencer block
  interval is 3s; the ~2-min cadence is the ntx-builder's own account-scheduling interval — no CLI
  flag exposes it at v0.15.1.)

### 2.3 Accept/reject PROBES run client-side (no submission)
A mint/burn/P2ID/tx-script consumption is executed locally against the committed on-chain state
(`execute_transaction`, never submitted): executing `Ok` = ACCEPTED, a trap = REJECTED with the
captured error. This is the LNV-1 row-B kernel-trap technique — a reject needs no submission path,
and an accept proves validity against real chain state without mutating it (so the arc stays
deterministic: committed `token_supply` is fixed by a single path-N supply mint). **Confirmed:
client-side execute of an *unauthenticated* `XReserveMintNote` succeeds** — the executor
auto-injects the attachment advice from the note itself, so mint/burn probes need no emit and cause
no ntx-builder interference.

### 2.4 Reject error surfacing — message vs err_code (a real-node discovery)
A client-side trap in **xreserve-owned MASM** (the attestation / burn-policy / supply-cap gates)
carries the full `err_msg` text; a trap in **STOCK miden-standards MASM** (the owner / role / pause /
note-script-allowlist / tx-script-allowlist gates) carries `err_msg: None` and only the deterministic
`err_code`. The rows-C/F assertion therefore matches a reject on EITHER the message substring OR the
expected error's `err_code` — the code is derived from the same expected string via
`MasmError::code()` (== the assembler's `error_code_from_msg`), never a hardcoded magic number. The
`stock_gate_err_codes_match_the_real_node_observed_values` test pins that derivation to the codes
observed on the real node (a protocol-pin / string-drift tripwire).

## 3. The rows-C/F arc (single evolving chain, one deterministic run)

deploy (`domain_init`, domain 7 + identifier from the mint vector) → allowlist attester A (path N) →
one committed supply mint attested by A (establishes `token_supply` for the burn probes) → **C3**
`set_max_supply` (over-cap mint rejects, within-cap accepts) → **C2** `set_min_burn_size` raise
(below-min burn rejects) / lower (at-min burn passes) → **C1** rotation A→B (mint by A rejects "not
allowlisted", by B accepts) → **C4** DOM_PAUSER pause (mint AND burn reject "paused"; owner
`set_attester`/`set_min_burn_size` STILL commit while paused — F6) / unpause (mint accepts) → **C5**
DOM_MANAGER grants DOM_PAUSER to a new account (it can pause) then revokes it (it cannot — role gate)
→ **C6** every admin note from a non-authorized sender traps at the proc gate AND stays unconsumed
node-side → **row F** a stock P2ID note and a tx-script transaction against the faucet are both
rejected by `AuthNetworkAccount`.

## 4. Harness inventory (this slice's deliverable)

New in `crates/xusdc-validation` (extends the LNV-1 harness; reuses its stack / client / deploy /
actor keygen):
- `src/actors.rs` — extended: the attester now signs real mint attestations
  (`AttesterKey::attestation_for`), and a SECOND attester B + a C5 `new_pauser` wallet are generated.
- `src/mintburn.rs` — the C-row mint/burn PROBE builders (deposit-intent payload spliced from the
  canonical `di-pos-empty-hookdata` vector; the local attester signs it; `XReserveMintNote` /
  `XReserveBurnNote` by reference).
- `src/observations_cf.rs` — `RowsCfObservations` (every verdict + committed read-back; `Serialize`).
- `src/assertions_cf.rs` — the rows-C/F assertion suite (written test-first).
- `src/rows_cf.rs` — the rows-C/F driver (the arc above; path-N commits + client-side probes).
- `src/evidence_cf.rs` — `evidence-cf.json` writer (pins + full observations + per-row verdicts + log
  manifest).
- `src/bin/lnv2_rows_cf.rs` — the one-command gate run.
- `tests/rows_cf.rs` — the real-node E2E (`#[ignore]`d) + 28 synthetic assertion negatives + the
  err_code tripwire (the DEFAULT, sandbox-safe suite).

## 5. Rows C/F — evidence

Run: `local-node-data/lnv1/run-1783634350` (VPS, 2026-07-09; fresh genesis; full logs archived in
that gitignored run root; `evidence-cf.json` alongside). Faucet
`0xcbf04aad8f61cdd16b7524a68969d7` (PUBLIC). Every row PASSED via the one-command
`cargo run -p xusdc-validation --bin lnv2_rows_cf` (`LNV-2 rows C/F: ALL ROWS PASS`).

| Row | What it proves | Verdict |
|---|---|---|
| **C1** `set_attester` + rotation | A allowlisted `[1,0,0,0]`; rotation disables A `[0,0,0,0]` + enables B `[1,0,0,0]`; mint by A REJECTED (`deposit attester pubkey commitment is not allowlisted`), by B ACCEPTED | **PASS** |
| **C2** `set_min_burn_size` | raise→50 (read-back), below-min (5) burn REJECTED (`burn amount is below the minimum burn size`); lower→10 (read-back), at-min (10) burn ACCEPTED | **PASS** |
| **C3** `set_max_supply` | cap→300 (read-back); over-cap mint REJECTED (`mint amount exceeds the faucet supply cap`); within-cap mint ACCEPTED | **PASS** |
| **C4** pause/unpause (F6) | `is_paused`→`[1,0,0,0]`; mint AND burn REJECTED (`the contract is paused`, matched by err_code `13643929038179635348`); owner `set_attester` + `set_min_burn_size` STILL committed while paused (F6); unpause→`[0,0,0,0]`; mint ACCEPTED | **PASS** |
| **C5** role rotation (CMP-F5) | DOM_MANAGER grant → new pauser membership `[1,0,0,0]`, it CAN pause (`is_paused` `[1,0,0,0]`); revoke → membership `[0,0,0,0]`, revoked pause REJECTED (`note sender does not hold the required role`, err_code `2534091087325248367`) | **PASS** |
| **C6** negatives | `set_attester`/`set_max_supply` from a non-owner REJECTED (`note sender is not the owner`, err_code `7385238526269899403`) + note stays UNCONSUMED; `pause` from a non-DOM_PAUSER REJECTED (role gate) + UNCONSUMED | **PASS** |
| **F** auth boundary | stock P2ID note REJECTED by `AuthNetworkAccount` (`input note script root is not in the note script allowlist`, err_code `2177567524790281771`); tx-script transaction REJECTED (`transaction script root is not in the tx script allowlist`, err_code `18283006182033373596`) | **PASS** |

### Log triage (row-L discipline)
- `ntx-builder.log` — the path-N commits (`submitted transaction landed; advanced in-memory account
  by its delta`) plus **57 ERROR lines, all `err=all notes failed to be executed` against the faucet
  account**: the ntx-builder repeatedly attempting the C6 non-authorized notes (routed + allowlisted)
  over the run and failing the SAME proc gate the client-side probe traps on — independent node-side
  confirmation of C6 (the LNV-1 domain_init-#2 pattern, at the ~2-min retry cadence over ~30 min). 7
  `WARN`s are start-order block-subscription retries. NOT defects.
- `sequencer.log` — 3 ERRORs: 1 graceful-shutdown timeout on OUR teardown SIGTERM, and **2 tonic
  `` `async fn` resumed after completion `` worker-thread panics** (`tonic-0.14.6
  transport/server/mod.rs:891`) in the RPC transport mid-run. The sequencer SURVIVED both (196+
  blocks committed afterward) and the whole rows-C/F arc committed and passed after them — a
  node-internal, per-connection tonic transport panic isolated by the tokio runtime, NOT attributable
  to any faucet transaction's semantics.
- validator / tx-prover / all three bootstraps — zero ERROR/WARN.
- **No ERROR/panic attributable to a faucet transaction we intended to succeed.**

## 6. Reproduction

```bash
# THE rows-C/F gate run (fresh stack; ~30 min: ~16 ntx-builder-committed admin ops + client-side probes)
cargo run -p xusdc-validation --bin lnv2_rows_cf
# or via the test suite (the real-node E2E, #[ignore]d, + the synthetic negatives)
cargo test -p xusdc-validation --locked -- --include-ignored
# the DEFAULT (sandbox-safe) suite: synthetic assertion negatives + the err_code tripwire — no node
cargo test -p xusdc-validation --locked
```

The real-node E2E is `#[ignore]`d in the default suite (it binds loopback listener sockets, denied in
hermetic audit sandboxes). The §11.2 gate claim rides only on real runs + the human gate — a green
default suite proves the assertion layer only.

## 7. Open items carried forward (NOT resolved here)

- Circle-owned `DEV-*`/`Q-*` stay OPEN (all domain / amount / attester values here are LOCAL TEST
  values; the attester is locally generated, never Circle's key).
- Mint/burn matrix rows **D/E/G/H/I/J** and the ntx-builder liveness verdict **K** are LNV-3/4/5 —
  LNV-2's mints/burns are row-C PROBES (the smallest real notes that exercise each admin gate), not
  the mint/burn rows themselves.
- The §2.1 path-C′ closure + the §2.2 ~2-min ntx-builder cadence feed the deployment-posture
  statement the authoritative spec requires.
