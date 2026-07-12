# LNV-1 VALIDATION RECORD — harness foundation + matrix rows A/B

**Slice:** LNV-1 (Phase-4 §11.2 local-node validation track, first slice).
**Scope:** the A–L local-node validation matrix (see `crates/xusdc-validation/README.md`); this
slice runs rows **A** and **B**.
**Status:** rows A + B **PASS** on a real, fresh, isolated local node (evidence §5).
**Gate discipline:** this record feeds the LNV-1 HARD HUMAN GATE (first-run supervision + the
`miden-client` re-pin acceptance). Nothing here self-declares the §11.2 gate — that is LNV-5.

---

## 1. Launch-gate re-verification (F5 on `main`)

Verified on `main` @ **`aade6655f512b785534fefe24aca0ffee092f7ce`** (the branch point of
`feat/phase4-local-node-validation`):

| F5 prerequisite | Where verified | Result |
|---|---|---|
| Production builder composes `AuthNetworkAccount` | `crates/xusdc-encoding/src/account/xreserve/builder.rs` `auth_component()` — stock `AuthNetworkAccount::with_allowed_notes(...)` | ✅ |
| Frozen note-script allowlist (mint + burn + admin roots) | `allowed_note_scripts()` — the 13-root set (2 supply + 11 admin, incl. `domain_init`) | ✅ |
| Tx-script allowlist EMPTY | `auth_component()` never calls `.with_allowed_tx_scripts` (doc: "EMPTY tx-script allowlist … never `.with_allowed_tx_scripts`") | ✅ |
| Admin is note-driven | `asm/standards/notes/xreserve_*_note.masm` (11 admin note scripts) + `src/note/xreserve_admin.rs` factories | ✅ |

## 2. Toolchain + dependency ledger

| Pin | Value | Why |
|---|---|---|
| `main` commit | `aade6655f512b785534fefe24aca0ffee092f7ce` | branch point, post-F5 |
| protocol | git `681fc90584131560b87db8f7487685f4fa8420a8` = the **v0.15.3** release-tag commit | the repo-wide pin (V15-DEVNET-BASELINE) |
| assembler family | 0.23.3 (unchanged, lock-resolved) | v0.15.3-locked |
| node binaries | `miden-node` / `miden-validator` / `miden-ntx-builder` **0.15.1** + `miden-remote-prover` (v0.15.1 tag), installed in `/usr/local/bin` | the node pin; **its own Cargo.lock pins `miden-protocol 0.15.3`** — node↔protocol compat confirmed at the source level |
| **`miden-client` (NEW, the re-pin this gate records)** | **`=0.15.3` from crates.io** (+ `miden-client-sqlite-store =0.15.3`) | the newest v0.15-line client; its protocol-family requirements are exactly `^0.15.3` — no contradiction with the pinned protocol API (no STOP condition met) |
| rustc | 1.93.0 (box) == the client's `rust-version = 1.93` | |

**New workspace deps** (all in `crates/xusdc-validation/Cargo.toml`, none touching
`xusdc-encoding`):

- `miden-client =0.15.3` (features `std`, `tonic`) — RPC + store + tx pipeline (path C).
- `miden-client-sqlite-store =0.15.3` — the client's native store.
- `miden-protocol` / `miden-standards` / `miden-tx` @ the pinned git rev — direct harness use
  (account/note types, `TransactionKernel` assembler, `StandardsLib`, faucet + auth components).
- `tokio 1` (client is async), `anyhow`, `serde`/`serde_json` (evidence),
  `k256 0.13` + `sha3 0.10` + `rand 0.8` + `miden-crypto 0.25` (attester keygen — the same
  versions `xusdc-encoding` already uses for its attestation vectors; promoting these shared
  versions to `[workspace.dependencies]` is deliberately deferred to a cleanup slice).

**The type-unification patch** (workspace `Cargo.toml` `[patch.crates-io]`): `miden-client` from
crates.io requires the protocol family from crates.io; the repo pins the SAME v0.15.3 source by
git rev. Without intervention cargo would build TWO copies of every protocol crate with
non-unifiable types. The patch redirects the five registry requirements (`miden-protocol`,
`miden-standards`, `miden-tx`, `miden-tx-batch-prover`, `miden-agglayer`) onto the pinned git
rev — one copy of each crate in the whole graph, byte-identical source to the registry releases
(the rev IS the v0.15.3 tag). The lockfile delta is exactly this resolution plus the client's own
transitive deps.

## 3. Discovered real-node mechanics (Phase-1 findings — the spec divergences, surfaced)

### 3.1 v0.15.1 topology — the spec's "bundled start" does not exist (KNOWN, now validated)
The authoritative spec's node-start guidance (`miden-node bundled start …`) is topology-stale for
v0.15.1: there is NO `bundled` subcommand. The validated local stack (all loopback, all
harness-owned — `crates/xusdc-validation/src/stack.rs`):

```
miden-validator bootstrap --genesis-block-directory G --accounts-directory A --data-directory V
miden-node        bootstrap --data-directory N --file G/genesis.dat
miden-ntx-builder bootstrap --data-directory X --file G/genesis.dat
miden-remote-prover --kind transaction --port 57294
miden-validator   start --listen 127.0.0.1:57292 --data-directory V
miden-ntx-builder start --listen 127.0.0.1:57293 --rpc.url http://127.0.0.1:57291 \
    --rpc.auth-header-value <token> --tx-prover.url http://127.0.0.1:57294 --data-directory X
miden-node sequencer --data-directory N --rpc.listen 127.0.0.1:57291 \
    --validator.url http://127.0.0.1:57292 --ntx-builder.url http://127.0.0.1:57293 \
    --rpc.network-tx-auth-header-value <token>
```

- **Genesis is fully local + isolated** (`bootstrap --file`, never `--network devnet|testnet`) —
  satisfies the ratified Q1 constraint. `miden-validator bootstrap` signs with its documented
  **default dev validator key** (`0101…01`, per `--help`) — the procedure is deterministic with
  no key ceremony; a pinned custom key is NOT needed for gate reproducibility (the procedure, not
  the genesis bytes, is what Round-F reproduces).
- **Ports (fixed, recorded):** sequencer RPC `57291`, validator `57292`, ntx-builder `57293`,
  tx prover `57294` — all loopback.
- The ntx-builder REQUIRES `--tx-prover.url`; the harness runs `miden-remote-prover --kind
  transaction` so the stack's network-transaction pipeline is real (row K exercises it end-to-end
  in LNV-5).

### 3.2 NEW FINDING — v0.15.1 blocks post-deployment user-RPC transactions against network accounts
`miden-node v0.15.1` (`crates/rpc/src/server/api/submit_proven_tx.rs:120-130` +
`api.rs:220-249`): a user-submitted `SubmitProvenTransaction` whose target account the store
classifies as a **network account** (= carries the standardized allowlist slot) is REJECTED with
`"Network transactions may not be submitted by users yet"` — **unless**
(a) the transaction is the account's **first deployment** (`initial_state_commitment` empty), or
(b) the submitter presents the sequencer-configured `x-miden-network-tx-auth` metadata header.

**Impact on the spec's path-C assumption ("anyone can — no key"):** post-deploy, "anyone" can
still *execute + prove* the keyless faucet's transactions, but the pinned node's user RPC will
not *accept* them. The supported post-deploy submission paths at v0.15.1 are (N) the ntx-builder
(which itself must hold the shared token) or (C′) an authorized submitter presenting the token.
The harness therefore starts its own sequencer with a local token (§3.1) so the stack is fully
operational. This is a **deployment-posture input for the record** (the production relayer
cannot client-side-drive the faucet through a public RPC at this node version), not a faucet
defect. Rows A/B do not depend on the token (see §3.3).

### 3.3 Keyless-network-account deploy mechanics + `domain_init` as the first admin note
From pinned source (`miden-client 0.15.3` integration tests `network_transaction.rs`; protocol
`AuthNetworkAccount` MASM) and validated live:

- The account is composed with `AccountBuilder::new(seed) … .with_auth_component(auth)
  .build_with_schema_commitment()` → registered locally (`add_account`, seed embedded) →
  **materializes on-chain with its FIRST transaction** (the RPC first-deployment exemption).
- `AuthNetworkAccount` authorizes a transaction iff every consumed note's script root is
  allowlisted AND (tx script ∈ allowlist; with the frozen EMPTY tx allowlist: no tx script at
  all). It increments the nonce when state changed **or the account is new**.
- **Therefore the deploy transaction can and does consume the owner's `domain_init` note** — the
  first admin note rides the first (and only user-submittable) faucet transaction: deploy +
  domain-config init commit atomically, entirely client-side (path C, no token needed). This is
  the production deploy recipe at v0.15.1.
- The init-once negative (row B) is proven WITHOUT a submission path: the second `domain_init`'s
  consumption **fails in the transaction kernel itself** (`ERR_XRESERVE_DOMAIN_REINIT`) when
  executed against the real on-chain state — no valid proof of a second init can exist, so no
  such transaction is submittable by anyone, token or not. The running ntx-builder additionally
  attempted the note (it is allowlisted + routed) and failed the same gate (§5.3) — independent
  node-side confirmation.

## 4. Harness inventory (this slice's deliverable)

- `crates/xusdc-validation` — workspace member 2.
  - `src/stack.rs` — three-service + prover lifecycle (fresh genesis per run, structured log
    capture, teardown-on-drop, port-free verification).
  - `src/client.rs` — the pinned client assembly (gRPC 127.0.0.1:57291, SQLite store, filesystem
    keystore, local prover).
  - `src/actors.rs` — actor keygen: owner / DOM_PAUSER / DOM_MANAGER / recipient / holder
    (Falcon512 `AuthSingleSig` + `BasicWallet`, PUBLIC) + locally generated secp256k1 attester
    (secret only under the gitignored run root; commitment recorded).
  - `src/deploy.rs` — the production composition consumed by reference
    (`XReserveStablecoinBuilder` + frozen `auth_component()`), deploy-account build.
  - `src/rows_ab.rs` — the row-A/B driver (module docs = the exact flow).
  - `src/assertions.rs` — the row-A/B assertion suite (written first, test-first).
  - `src/evidence.rs` — `evidence.json` writer + log manifest (ERROR/WARN counts per service).
  - `src/bin/lnv1_rows_ab.rs` — the one-command gate run for this slice.
  - `src/bin/lnv_stack.rs` — supervised stack up/down.
  - `tests/rows_ab.rs` — the real-node E2E + 9 synthetic assertion negatives.
- Run artifacts (node data dirs, stores, keystores, logs, evidence) live under
  `local-node-data/` (gitignored; `*.log` additionally ignored globally).

## 5. Rows A/B — evidence (first supervised run)

Run: `local-node-data/lnv1/test-1523191-1783602101/` (VPS, 2026-07-09; fresh genesis; full logs
archived in that gitignored run root; `evidence.json` alongside).

### 5.1 Row A — deploy + recognize: **PASS**
- Faucet id `0x5216c6686823475162c973917e6466` (PUBLIC), deploy tx
  `0x3969f390b6fdc44a331f8ff830f04009d6c4227ae8b823910f7aa794be127a7d` committed at block **68**.
- `GetAccount` (direct RPC, node truth) returned the account: nonce **1**, id matches, public.
- The standardized network-account note-script allowlist slot is present, non-empty, and equals
  **EXACTLY the frozen 13-root set** (`XReserveStablecoinBuilder::allowed_note_scripts()`); the
  tx-script allowlist is present and **EXACTLY empty**.

### 5.2 Row B — `domain_init` init-once: **PASS**
- First `domain_init` (owner-sent note `0x907c9777…`, params: domain `1313`, source_domain `7`,
  xreserve_contract `0xC1×32`, identifier = `bytes32_to_key(0x1D×32)`) consumed by the deploy
  transaction; ALL FIVE §5.9 slots read back from on-chain storage at exactly the
  creator-committed values (domain, identifier, source_domain, xrc_hi, xrc_lo).
- Second `domain_init` (note `0x6b09c272…`, everywhere-different params) REJECTED by the
  transaction kernel against real chain state:
  `FailedAssertion { err_code: 6536834543449786862, err_msg: Some("domain config has already
  been initialized") }` — the exact `ERR_XRESERVE_DOMAIN_REINIT` gate.
- Post-attempt: nonce still 1, all five slots unchanged (first params, never the second note's),
  and the second note's nullifier is NOT in the node's spent set (unconsumed after a 3-block
  watch window).

### 5.3 Log triage (row-L discipline, applied early)
- `ntx-builder.log` — 6 ERROR lines = **two independent node-side attempts to execute the second
  `domain_init`** (`network transaction failed account_id=0x5216c668… err=all notes failed to be
  executed`), i.e. the node's own network-transaction pipeline hit the same init-once gate and
  gave up (account deactivated: "no viable notes"). Bonus row-B evidence, not a defect.
  5 WARN lines = block-subscription retries while the sequencer was still starting (start order)
  + one at teardown.
- `sequencer.log` — 1 ERROR = its own graceful-shutdown timeout during OUR teardown SIGTERM.
- `validator` / `tx-prover` / all three bootstraps — zero ERROR/WARN.
- **No ERROR/panic attributable to our transactions during the run window.**

## 6. Reproduction

```
# full row-A/B gate run (fresh stack, ~6 min: three Falcon proofs client-side + block waits)
cargo run -p xusdc-validation --bin lnv1_rows_ab
# or via the test suite (the real-node E2E + the 9 assertion negatives)
cargo test -p xusdc-validation --locked -- --include-ignored
# the DEFAULT suite (sandbox-safe, synthetic negatives only — NO real-node claim)
cargo test -p xusdc-validation --locked
# supervised manual stack
cargo run -p xusdc-validation --bin lnv_stack -- up   [label]
cargo run -p xusdc-validation --bin lnv_stack -- down <run-root>
```

**Audit-sandbox partition (2026-07-09, round 3).** The real-node E2E requires loopback LISTENER
binds for the four node services; the hermetic audit sandbox denies them (`bind: Operation not
permitted`, reproduced there with `nc -l 127.0.0.1 57294`). The E2E is therefore `#[ignore]`d in
the default suite and run explicitly via `-- --include-ignored` (or `lnv1_rows_ab`) on
network-enabled boxes. The partition is VISIBLE (the default run prints `1 ignored`), and the
gate claim is carried exclusively by real runs + the human gate — a green default suite proves
the assertion layer only. If the audit environment later permits loopback binds, reverting is
one attribute (`#[ignore]` on `lnv1_rows_ab_against_real_local_node`).

## 7. Open items carried forward (NOT resolved here)

- Circle-owned `DEV-*`/`Q-*` stay OPEN (domain values here are local test values).
- Row K (ntx-builder liveness verdict) is LNV-5 scope — the harness already runs the full
  pipeline (prover wired, token configured) so LNV-5 can exercise path N directly.
- The §3.2 posture finding (user-RPC block on post-deploy network-account txs) feeds the
  deployment-posture statement the authoritative spec requires; the F7/burn evidence rows are
  LNV-4.
- Promoting the shared k256/sha3/rand/miden-crypto versions to `[workspace.dependencies]` —
  cleanup slice.
